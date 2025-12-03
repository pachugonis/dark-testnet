
import enum
import errno
import logging
import os
import subprocess
import sys

import chutney.errors

from abc import ABC, abstractmethod
from pathlib import Path
from typing import IO, Union, Optional, Literal
from typing_extensions import TypeAlias, override

from chutney.known_bins import KnownBin

# These are basically just "dumb structs". We can just reuse directly.
CalledProcessError = subprocess.CalledProcessError
CompletedProcess = subprocess.CompletedProcess

# Probably ok to just reuse these. Explicitly declare with types so that
# typechecking will notice if the subprocess constants become something other
# than dumb ints.
PIPE: int = subprocess.PIPE
STDOUT: int = subprocess.STDOUT
DEVNULL: int = subprocess.DEVNULL

# Based on typeshed's _CMD, but more restrictive
CMD: TypeAlias = list[str]
TEXT_FILE: TypeAlias = Union[int, IO[str]]

_logger = logging.getLogger(__name__)


class Capture(enum.Enum):
    """How output of a process ought to be captured"""

    # Keep stdout and stderr separate.
    SEPARATE = enum.auto()
    # Merge stderr into stdout.
    MERGED = enum.auto()


class Popen(ABC):
    @abstractmethod
    def communicate(
        self, input: Optional[str] = None, timeout: Optional[float] = None
    ) -> CompletedProcess[str]: ...

    @abstractmethod
    def pid(self) -> int: ...

    @abstractmethod
    def running(self) -> bool: ...

    @abstractmethod
    def send_signal(self, sig: int) -> None: ...

    def terminate(self) -> None:
        self.send_signal(15)

    def kill(self) -> None:
        self.send_signal(9)


class Launcher(ABC):
    @abstractmethod
    def launch_detached(
        self,
        cmd: Path,
        args: list[str],
        *,
        stdout_path: Path,
        stderr_path: Path,
        pid_path: Path,
        known_bin: KnownBin,
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
        ...

    def run(
        self,
        args: CMD,
        *,
        # bufsize: int = -1,
        # executable: StrOrBytesPath | None = None,
        stdin: Optional[TEXT_FILE] = None,
        stdout: Optional[TEXT_FILE] = None,
        stderr: Optional[TEXT_FILE] = None,
        # preexec_fn: Callable[[], Any] | None = None,
        # close_fds: bool = True,
        # shell: bool = False,
        # cwd: StrOrBytesPath | None = None,
        # env: _ENV | None = None,
        # universal_newlines: Optional[bool] = None,
        # startupinfo: Any = None,
        # creationflags: int = 0,
        # restore_signals: bool = True,
        # start_new_session: bool = False,
        # pass_fds: Collection[int] = ...,
        capture_strategy: Optional[Capture] = None,
        check: bool = False,
        # encoding: str | None = None,
        # errors: str | None = None,
        input: Optional[str] = None,
        text: Literal[True],
        # timeout: float | None = None,
        # user: str | int | None = None,
        # group: str | int | None = None,
        # extra_groups: Iterable[str | int] | None = None,
        # umask: int = -1,
        # pipesize: int = -1,
        # process_group: int | None = None,
        known_bin: Optional[KnownBin],
    ) -> CompletedProcess[str]:
        """Run a process to completion and return the result.

        Analogous to `subprocess.run`, but doesn't support all of its options.

        Currently only supports text-mode. Since `subprocess.run`'s default is
        binary mode, to avoid confusion we currently *require* the `text`
        parameter, and require it to be `True`.

        The `capture_output` parameter has been replaced with
        `capture_strategy`.  If `capture_strategy` is set, then also setting
        `stdout` or `stderr` is an error. Setting `capture_strategy` to `Capture.SEPARATE`
        captures stdout and stderr separately, similarly to `capture_output=True`.
        Setting it to `Capture.MERGED` merges stderr into stdout and captures stdout.

        The `known_bin` parameter, if set, will be used to potentially add extra
        arguments, and add extra debug info if the binary isn't found.
        """
        if capture_strategy is not None:
            # As in subprocess.run, if capture_output is set, then
            # it is an error to have also set stdout or stderr.
            assert stdout is None
            assert stderr is None
            if capture_strategy is Capture.SEPARATE:
                stdout = PIPE
                stderr = PIPE
            elif capture_strategy is Capture.MERGED:
                stdout = PIPE
                stderr = STDOUT
            else:
                raise chutney.errors.ChutneyInternalError(
                    "Unhandled capture strategy " + capture_strategy
                )

        if input is not None:
            assert stdin is None
            stdin = PIPE

        popen = self.popen(
            args,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            text=text,
            known_bin=known_bin,
        )
        res = popen.communicate(input=input)
        if check and res.returncode != 0:
            raise CalledProcessError(
                returncode=res.returncode,
                cmd=args,
                output=res.stdout,
                stderr=res.stderr,
            )

        return CompletedProcess(
            args=args, returncode=res.returncode, stdout=res.stdout, stderr=res.stderr
        )

    @abstractmethod
    def popen(
        self,
        args: CMD,
        *,
        bufsize: int = -1,
        # executable: StrOrBytesPath | None = None,
        stdin: Optional[TEXT_FILE] = None,
        stdout: Optional[TEXT_FILE] = None,
        stderr: Optional[TEXT_FILE] = None,
        # preexec_fn: Callable[[], Any] | None = None,
        # close_fds: bool = True,
        # shell: bool = False,
        # cwd: StrOrBytesPath | None = None,
        # env: _ENV | None = None,
        # universal_newlines: bool | None = None,
        # startupinfo: Any | None = None,
        # creationflags: int = 0,
        # restore_signals: bool = True,
        # start_new_session: bool = False,
        # pass_fds: Collection[int] = (),
        # text: bool | None = None,
        text: Literal[True],
        # encoding: str,
        # errors: str | None = None,
        # user: str | int | None = None,
        # group: str | int | None = None,
        # extra_groups: Iterable[str | int] | None = None,
        # umask: int = -1,
        # pipesize: int = -1,
        # process_group: int | None = None
        known_bin: Optional[KnownBin],
    ) -> Popen:
        """Launch a process.

        Analogous `subprocess.Popen`, but doesn't support all of its options.

        Currently only supports text-mode. Since `subprocess.Popen`'s default is
        binary mode, to avoid confusion we currently *require* the `text`
        parameter, and require it to be `True`.

        The `known_bin` parameter, if set, will be used to potentially add extra
        arguments, and add extra debug info if the binary isn't found.
        """
        ...


class LocalPopen(Popen):
    """Specialization of Popen returnced by `LocalLauncher`"""

    def __init__(self, inner: subprocess.Popen[str]) -> None:
        self._inner = inner

    @override
    def communicate(
        self, input: Optional[str] = None, timeout: Optional[float] = None
    ) -> CompletedProcess[str]:
        try:
            stdout, stderr = self._inner.communicate(input=input, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise chutney.errors.ChutneyTimeoutError
        return CompletedProcess(
            args=self._inner.args,
            returncode=self._inner.returncode,
            stdout=stdout,
            stderr=stderr,
        )

    @override
    def pid(self) -> int:
        return self._inner.pid

    @override
    def running(self) -> bool:
        return self._inner.poll() is None

    @override
    def send_signal(self, sig: int) -> None:
        self._inner.send_signal(sig)


class LocalLauncher(Launcher):
    """A `Launcher` that launches processes locally, akin to the `subprocess` module"""

    @override
    def popen(
        self,
        args: CMD,
        *,
        bufsize: int = -1,
        stdin: Optional[TEXT_FILE] = None,
        stdout: Optional[TEXT_FILE] = None,
        stderr: Optional[TEXT_FILE] = None,
        text: Literal[True],
        known_bin: Optional[KnownBin],
    ) -> Popen:
        assert text is True
        try:
            inner = subprocess.Popen(
                args,
                bufsize=bufsize,
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                text=text,
            )
        except FileNotFoundError as e:
            raise chutney.errors.ChutneyMissingBinaryError(known_bin, args) from e
        return LocalPopen(inner)

    @override
    def launch_detached(
        self,
        cmd: Path,
        args: list[str],
        *,
        stdout_path: Path,
        stderr_path: Path,
        pid_path: Path,
        known_bin: KnownBin,
    ) -> None:
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
                _closerange(execfail_w + 1, 2**31 - 1)

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
            raise chutney.errors.ChutneyError(
                f"Got exitcode {exitcode} launching {cmd}"
            )

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
                raise chutney.errors.ChutneyMissingBinaryError(
                    known_bin, [str(cmd)] + args
                )
            else:
                errno_str = errno.errorcode[errno_int]
                raise chutney.errors.ChutneyError(f"exec failed with {errno_str}")


def _closerange(start: int, end: int) -> None:
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
