# [pep 0536](https://peps.python.org/pep-0563/) - Lazy annotation eval via
# stringification.
from __future__ import annotations

# Future imports for Python 2.7, mandatory in 3.0
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import ipaddress
import logging
import os
import stat

from collections.abc import Iterable, Collection
from pathlib import Path
from typing import Callable, TypeVar, Any, Optional, Generic, Union, TypeAlias
from typing_extensions import ParamSpec, override

from chutney.jsonable import ToCustomJsonable, CustomJsonable

logger = logging.getLogger(__name__)

IPAddress: TypeAlias = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork: TypeAlias = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

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


def addr_and_port_str(ip_addr: IPAddress, port: int) -> str:
    """Format an ip address and port pair.

    Concretely, this surrounds ipv6 addresses with brackets, which is a common
    convention for separating an ipv6 address from a port number.
    """

    if ip_addr.version == 4:
        return f"{ip_addr}:{port}"
    if ip_addr.version == 6:
        return f"[{ip_addr}]:{port}"


CJ = TypeVar("CJ", bound=CustomJsonable)


class Option(Generic[T], ToCustomJsonable):
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

    @override
    def to_custom_jsonable(self: Option[CJ]) -> CustomJsonable:
        return self.as_optional()

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
