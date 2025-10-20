# [pep 0536](https://peps.python.org/pep-0563/) - Lazy annotation eval via
# stringification.
from __future__ import annotations

# Future imports for Python 2.7, mandatory in 3.0
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import errno
import logging
import os
import stat
import subprocess
import sys

from collections.abc import Iterable, Collection
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import Callable, TypeVar, Any, Optional, overload, Generic, Union, List
from typing_extensions import ParamSpec

import chutney.errors

logger = logging.getLogger(__name__)

P = ParamSpec("P")
T = TypeVar("T")
K = TypeVar("K")
V = TypeVar("V")


def memoized(fn: Callable[P, T]) -> Callable[P, T]:
    """Decorator: memoize a function."""
    # Keys are built from the arg and kwarg parameters passed to the function.
    # It might be nice to somewhow replace the `Any`s below with the actual
    # types derived from the parameter spec `P`, but probably not worth the
    # complexity.
    memory: dict[tuple[Iterable[Any], Iterable[tuple[Any, Any]]], T] = {}

    def memoized_fn(*args: P.args, **kwargs: P.kwargs) -> T:
        key = (args, tuple(sorted(kwargs.items())))
        try:
            result = memory[key]
        except KeyError:
            result = memory[key] = fn(*args, **kwargs)
        return result

    return memoized_fn


def addr_and_port_str(ip_addr: Union[IPv4Address, IPv6Address], port: int) -> str:
    """Format an ip address and port pair.

    Concretely, this surrounds ipv6 addresses with brackets, which is a common
    convention for separating an ipv6 address from a port number.
    """

    if ip_addr.version == 4:
        return f"{ip_addr}:{port}"
    if ip_addr.version == 6:
        return f"[{ip_addr}]:{port}"


class Option(Generic[T]):
    """A wrapper for values that may be None

    Modeled after Rust's Option type.  Unlike typing.Optional, this is a real
    object wrapper that provides methods for safely manipulating the value, and
    that forces to the user to explicitly extract the inner value.

    The default `__str__` method is overridden to fail at runtime, meaning e.g.
    `str(Option(val))` will also fail. Calling code must use methods to access
    the inner value to perform a string conversion. This is done to prevent
    accidental substitution of a value like "None" in string templates, and to
    force call-sites of such conversions to be explicit about how to handle the
    `None` case.
    """

    def __init__(self, val: Optional[T]):
        self._val = val

    def unwrap(
        self, failure_msg: Union[str, Callable[[], str]] = "Unwrapped None"
    ) -> T:
        """Asserts v is not None and returns it"""
        if self._val is not None:
            return self._val
        if callable(failure_msg):
            failure_msg = failure_msg()
        raise AssertionError(failure_msg)

    def as_optional(self) -> Optional[T]:
        """Returns the value, or None"""
        return self._val

    def unwrap_or(self, default: T) -> T:
        return self._val if self._val is not None else default

    def unwrap_or_raise(self, exc: Union[Exception, Callable[[], Exception]]) -> T:
        if self._val is not None:
            return self._val
        if callable(exc):
            exc = exc()
        raise exc

    def is_some(self) -> bool:
        return self._val is not None

    def is_none(self) -> bool:
        return self._val is None

    def replace(self, val: T) -> Optional[T]:
        """Assigns `val` and returns the previous value"""
        prev = self._val
        self._val = val
        return prev

    def map(self, f: Callable[[T], V]) -> Option[V]:
        if self._val is None:
            return Option(None)
        else:
            return Option(f(self._val))

    # Suppress string conversion to prevent unchecked usage
    # in templates, etc. (`repr` still works).
    #
    # Python allows assigning `__str__ = None` here, in which case string
    # conversions will fail at runtime. However doing so requires opting out of
    # mypy (which requires __str__ to be a callable with the expected
    # signature), and likewise doesn't have the benefit one might hope of mypy
    # statically preventing string conversions.
    def __str__(self) -> str:
        raise AssertionError(
            "Option doesn't support str conversion. Get the inner value instead."
        )


class OptionalConversionDescriptor(Generic[T]):
    """A Conversion Descriptor for Option-type fields

    A field of this type is *read* as `Option[T]`, but may be *assigned*
    from an `Option[T]`, `T`, or `None`.

    Will not work as expected with `T=Option[]`.

    Based on an example in the dataclasses documentation:
    <https://docs.python.org/3/library/dataclasses.html#descriptor-typed-fields>

    See also the more general documentation about such field descriptors:
    <https://docs.python.org/3/reference/datamodel.html#implementing-descriptors>
    """

    def __init__(self, *, default: Option[T]):
        self._default = default

    def __set_name__(self, owner: Any, name: str) -> None:
        # `name` is the name of this field, of type
        # `OptionalConversionDescriptor`, on the `owner`. We use this to derive
        # a `_name`, which we'll use to store the actual value of type
        # `Option[T]`.
        self._name = "_" + name

    def __get__(
        self, instance: Optional[Any], owner: Optional[Any] = None
    ) -> Option[T]:
        if instance is None:
            # This is a class-access, not an instance-access.
            # Return the default value.
            return self._default

        return getattr(instance, self._name, self._default)

    def __set__(self, obj: Any, value: Union[Option[T], Optional[T]]) -> None:
        # We need the conversion implemented by this function to be idempotent;
        # e.g. `obj.f = obj.f` shouldn't change the value of `f`.
        #
        # For that reason we can't unconditionally wrap with `Option`; we need to check
        # whether it's already been wrapped and not wrap it again.
        #
        # Unfortunately this means that using `T=Option[_]` won't work as
        # expected. (This is documented in the class doc).
        if not isinstance(value, Option):
            value = Option(value)
        setattr(obj, self._name, value)


@overload
def getenv_type(
    env_var: str,
    default: None,
    type_: Callable[[str], T],
    type_name: Optional[str] = None,
) -> Optional[T]: ...


@overload
def getenv_type(
    env_var: str, default: T, type_: Callable[[str], T], type_name: Optional[str] = None
) -> T: ...


def getenv_type(
    env_var: str,
    default: Optional[T],
    type_: Callable[[str], T],
    type_name: Optional[str] = None,
) -> Optional[T]:
    """
    Return the value of the environment variable 'envar' as type_,
    or 'default' if no such variable exists.

    Raise ValueError using type_name if the environment variable is set,
    but type_() raises a ValueError on its value. (If type_name is None
    or empty, the ValueError uses type_'s string representation instead.)
    """
    strval = os.environ.get(env_var)
    if strval is None:
        return default
    try:
        return type_(strval)
    except ValueError:
        if not type_name:
            type_name = str(type_)
        raise ValueError(
            (
                "Invalid value for environment variable '{}': "
                "expected {}, but got '{}'"
            ).format(env_var, type_name, strval)
        )


@overload
def getenv_int(env_var: str, default: None) -> Optional[int]: ...


@overload
def getenv_int(env_var: str, default: int) -> int: ...


def getenv_int(env_var: str, default: Optional[int]) -> Optional[int]:
    """
    Return the value of the environment variable 'envar' as an int,
    or 'default' if no such variable exists.

    Raise ValueError if the environment variable is set, but is not an int.
    """
    return getenv_type(env_var, default, int, type_name="an int")


def getenv_bool(env_var: str, default: bool) -> bool:
    """
    Return the value of the environment variable 'envar' as a bool,
    or 'default' if no such variable exists.

    Unlike bool(), converts 0, "False", and "No" to False.

    Raise ValueError if the environment variable is set, but is not a bool.
    """
    # TODO: consider simplifying this and:
    # * rejecting ints other than 0 or 1
    # * accepting 'yes' for True
    try:
        # Handle integer values
        return bool(getenv_int(env_var, int(default)))
    except ValueError:
        # Handle values that the user probably expects to be False
        strval = os.environ.get(env_var)
        # If the env var weren't set, the int path above would have succeeded,
        # returning the default.
        assert strval is not None
        if strval.lower() in ["false", "no"]:
            return False
        else:
            return getenv_type(env_var, default, bool, type_name="a bool")


def find_executable_on_path(
    basename: Union[str, Path], path: Optional[Iterable[Path]] = None
) -> Optional[Path]:
    """Find the first executable file named `basename` in `path`

    Roughly, mostly, emulates bash's PATH search:
    Returns the first file with *any* executable bit set on the given `path`.
    Does *not* attempt to fully validate that the current user actually has
    permission to execute it.

    Unlike bash, skips empty strings and other relative paths in the search
    path.

    Uses the `PATH` environment variable if `path` is not provided.
    """
    _path: Iterable[Path]
    if path is None:
        env_path = os.getenv("PATH")
        if env_path is None:
            _path = []
        else:
            _path = map(Path, env_path.split(":"))
    else:
        _path = path
    for location in _path:
        if not location.is_absolute():
            # Technically relative paths function in shell search of PATH
            # (at least for bash), including the empty string effectively
            # meaning "search the current directory".
            #
            # We probably don't want that behavior here.
            continue
        p = Path(location, basename)
        if not p.is_file():
            # Not a file
            continue
        mode = 0
        try:
            mode = p.stat().st_mode
        except OSError:
            pass
        if not (mode & (stat.S_IXOTH | stat.S_IXGRP | stat.S_IXUSR)):
            # Not executable
            continue
        return p
    return None


def launch_process(
    cmdline: List[str], tor_name: str = "tor", stdin: Optional[int] = None
) -> subprocess.Popen[str]:
    """Launch the command line cmdline, which must start with the path or
    name of a binary. Use tor_name as the canonical name of the binary in
    logs. Pass stdin to the Popen constructor.

    Returns the Popen object for the launched process.
    """
    if tor_name == "tor":
        if not logger.isEnabledFor(logging.DEBUG):
            cmdline.append("--hush")
    elif tor_name == "tor-gencert":
        if logger.isEnabledFor(logging.DEBUG):
            cmdline.append("-v")
    else:
        raise ValueError("Unknown tor_name: '{}'".format(tor_name))
    try:
        p = subprocess.Popen(
            cmdline,
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=-1,
        )
    except FileNotFoundError as e:
        raise chutney.errors.ChutneyMissingBinaryError.for_missing_tor(
            tor_name, cmdline
        ) from e
    return p


def mkdir_p(*d: Union[str, Path], mode: int = 448) -> None:
    """Create directory 'd' and all of its parents as needed.  Unlike
    os.makedirs, does not give an error if d already exists.

    448 is the decimal representation of the octal number 0700. Since
    python2 only supports 0700 and python3 only supports 0o700, we can use
    neither.

    Note that python2 and python3 differ in how they create the
    permissions for the intermediate directories.  In python3, 'mode'
    only sets the mode for the last directory created.
    """
    Path(*d).mkdir(mode=mode, parents=True, exist_ok=True)


def values_for_keys(d: dict[K, V], keys: Collection[K]) -> list[V]:
    return [kv[1] for kv in d.items() if kv[0] in keys]


def closerange(start: int, end: int) -> None:
    """
    Closes all file descriptors between start and end, inclusive.

    Works around that on systems with kernels that don't provide the close_range syscall,
    os.closerange iterates the full list of integers in the range, which can be quite slow,
    especially under shadow.
    """
    for fd_s in os.listdir("/proc/self/fd"):
        fd = int(fd_s)
        if fd in range(start, end + 1):
            try:
                os.close(fd)
            except OSError:
                pass
    # TODO: consider using os.closerange instead on systems that use the syscall.
    # However even if we check that the kernel version has it, we'd have to be
    # also be sure that the python runtime and/or libc actually use it.
    #
    # Alternatively we could just identify the smallest and largest actual open
    # fd and clamp the range we actually pass to os.closerange; that'd be fewer
    # syscalls in the common case but in theory could still blow up if there's
    # somehow one high-int-value fd open.


def launch_detached(
    cmd: Path,
    args: list[str],
    stdout_path: Path,
    stderr_path: Path,
    pid_path: Path,
    tor_name: str = "arti",
) -> None:
    """
    Launch a ~daemonized process.

    arti doesn't provide an alternative to tor's RunAsDaemon, and isn't planned
    to since the modern way is for daemonization to be done by an intermediate
    tool like systemd or daemonize.

    daemon(7) documents the full requirements for "proper" daemonization, but
    for our purposes, the main things we care about and actually do in this function are:

    * Replace stdout and stderr.
    * Detach from chutney's session (`setsid`), so that the process doesn't
      receive signals via chutney's terminal, outlives chutney's (terminal) session, etc.
    * Reparent to init by double-forking, so that the child doesn't become a zombie after
      death.

    Alternatives:

    * Use an external tool like `daemonize(1)`, but this adds a system dependency.
    * Use `subprocess.Popen` with `start_new_session`, but this doesn't support double-forking.
      Possibly we could live with that, but then since chutney supports running
      in multiple command-line invocations (`chutney start`; `chutney
      wait_for_bootstrap`; etc) we'd have to be a little careful to handle both
      cases where we are or aren't the parent. e.g. when checking if the process
      is still alive we'd need to try reaping it (with WNOHANG) before trying to
      signal it. That's not so bad, but there might be other surprising corner
      cases.
    """
    # We use this to signal back if exec failed.
    # TODO: Consider communicating via the sd_notify(3) protocol instead (e.g.
    # ERRNO=x), particularly if and when arti itself supports it.
    # <https://gitlab.torproject.org/tpo/core/arti/-/issues/1979>
    (execfail_r, execfail_w) = os.pipe()

    # Open all the files in this process, where errors will be reported most
    # loudly and obviously.
    with (
        stdout_path.open("wb") as stdout_file,
        stderr_path.open("wb") as stderr_file,
        pid_path.open("w") as pid_file,
    ):
        # flush these to ensure we don't inherit buffered data in the child
        # processes.
        sys.stdout.flush()
        sys.stderr.flush()

        child1 = os.fork()
        if child1 == 0:
            # running in child1

            # we don't need stdin.
            sys.stdin.close()

            # Reassign specified files to stdout and stderr.
            # We do this here instead of in child2 so that a failure will be
            # directly detectable in the chutney process by this process
            # failing.
            os.dup2(stdout_file.fileno(), 1, inheritable=True)
            os.dup2(stderr_file.fileno(), 2, inheritable=True)

            # Use fd=3 for execfail_w. Set to close on exec.
            if execfail_w != 3:
                os.dup2(execfail_w, 3, inheritable=False)
                execfail_w = 3
            else:
                # The dup2 call above fails with EINVAL if we pass the same descriptor twice.
                # We can just skip the call; the original descriptor returned from os.pipe
                # is already non-inheritable.
                pass

            # New session. This detaches the process from chutney's terminal, so that it
            # doesn't receive signals from it, etc.
            os.setsid()

            # Fork again so that we can orphan child2, reparenting it to init.
            child2 = os.fork()
            if child2 != 0:
                # (still) running in child1; parent of child2. record pid of child2 and exit.
                pid_file.write(str(child2))
                pid_file.close()
                # exit. don't use sys.exit to avoid cleaning up any system
                # resources inherited from the chutney process.
                os._exit(0)

            # running in child2.

            # Close all files after the ones we're explicitly passing.
            closerange(execfail_w + 1, 2**31 - 1)

            # replace ourselves with the specified process.
            try:
                os.execv(cmd, [str(cmd)] + args)
            except OSError as e:
                # exec failed. Write the errno as text into our pipe, using a
                # file object wrapper to (paranoid-ly) handle looping if somehow
                # needed.
                execfail_w_file = os.fdopen(execfail_w, mode="ta")
                execfail_w_file.write(str(e.errno))
                execfail_w_file.close()
                # exit. don't use sys.exit to avoid cleaning up any system
                # resources inherited from the chutney process.
                os._exit(1)

    # verify that child1 completed successfully
    (_, status) = os.waitpid(child1, 0)
    exitcode = os.waitstatus_to_exitcode(status)
    if exitcode != 0:
        raise chutney.errors.ChutneyError(f"Got exitcode {exitcode} launching {cmd}")

    # verify that exec in child2 succeeded.

    # close our copy of the execfail_w descriptor, so that no writers remain
    # after child1 has exited and child2 has either exited or successfully
    # exec'd.
    os.close(execfail_w)
    # read to end-of-file. if exec succeeds, the write-end will close and we'll
    # get nothing here. if the exec fails, we'll get a string-encoding of the
    # errno int.
    execfail_r_file = os.fdopen(execfail_r, mode="tr")
    exec_errno_str = execfail_r_file.read()
    execfail_r_file.close()
    if exec_errno_str:
        errno_int = int(exec_errno_str)
        if errno_int == errno.ENOENT:
            raise chutney.errors.ChutneyMissingBinaryError.for_missing_tor(
                tor_name, [str(cmd)] + args
            )
        else:
            errno_str = errno.errorcode[errno_int]
            raise chutney.errors.ChutneyError(f"exec failed with {errno_str}")
