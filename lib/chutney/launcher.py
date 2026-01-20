# [pep 0536](https://peps.python.org/pep-0563/) - Lazy annotation eval via
# stringification.
from __future__ import annotations

import enum
import errno

import logging
import paramiko
import os
import selectors
import signal
import shlex
import subprocess
import sys
import time

import chutney.errors

from abc import ABC, abstractmethod
from pathlib import Path
from typing import IO, Union, Optional, Literal
from typing_extensions import TypeAlias, override

from chutney.known_bins import KnownBin

# These are basically just "dumb structs". We can just reuse directly.
CalledProcessError = subprocess.CalledProcessError
CompletedProcess = subprocess.CompletedProcess

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
    """
    An open process, modeled after `subprocess.Popen`.
    """

    @abstractmethod
    def communicate(
        self, input: Optional[str] = None, timeout: Optional[float] = None
    ) -> CompletedProcess[str]:
        """Handle inputs and outputs until `timeout` expires or process completes.

        After a non-`None` timeout expires, raises `ChutneyTimeoutError`.
        This does not lose data, and `communicate` can be safely called again.

        `input` may only be provided on the first call, and any leftover input
        not read by the program after first calls will be fed to the program on
        subsequent calls.
        """
        ...

    @abstractmethod
    def pid(self) -> int:
        """Return the process-id of the process"""
        ...

    @abstractmethod
    def launcher(self) -> Launcher:
        """Launcher used  to launch this process"""
        ...

    def running(self) -> bool:
        """Return whether the process is still running"""
        return self.launcher().running(self.pid())

    def send_signal(self, sig: int) -> None:
        """Sends the specified signal to the process"""
        return self.launcher().send_signal(self.pid(), sig)

    def terminate(self) -> None:
        """Sends SIGTERM to the process"""
        self.send_signal(signal.SIGTERM)

    def kill(self) -> None:
        """Sends SIGKILL to the process"""
        self.send_signal(signal.SIGKILL)


class Launcher(ABC):
    """Launches and manages processes"""

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
        cwd: Optional[Path] = None,
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
        # stdin: Optional[TEXT_FILE] = None,
        # stdout: Optional[TEXT_FILE] = None,
        # stderr: Optional[TEXT_FILE] = None,
        # preexec_fn: Callable[[], Any] | None = None,
        # close_fds: bool = True,
        # shell: bool = False,
        cwd: Optional[Path] = None,
        # env: _ENV | None = None,
        # universal_newlines: Optional[bool] = None,
        # startupinfo: Any = None,
        # creationflags: int = 0,
        # restore_signals: bool = True,
        # start_new_session: bool = False,
        # pass_fds: Collection[int] = ...,
        capture_strategy: Capture = Capture.SEPARATE,
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
        popen = self.popen(
            args, capture_strategy=capture_strategy, text=True, known_bin=known_bin
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
        # bufsize: int = -1,
        # executable: StrOrBytesPath | None = None,
        # stdin: Optional[TEXT_FILE] = None,
        # stdout: Optional[TEXT_FILE] = None,
        # stderr: Optional[TEXT_FILE] = None,
        capture_strategy: Capture = Capture.SEPARATE,
        # preexec_fn: Callable[[], Any] | None = None,
        # close_fds: bool = True,
        # shell: bool = False,
        cwd: Optional[Path] = None,
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

    def running(self, pid: int) -> bool:
        """Check whether a process previously started with this Launcher is still running.

        Should be preferred over directly calling python APIs like os.kill,
        since the process may be remote.

        If a Popen object is available, (i.e. the process isn't detached),
        then Popen.running should be preferred.
        """
        # On some systems, kill is only available a shell built-in,
        # so run it via a shell.
        # TODO: consider implementing `shell` kwarg for `run` and `popen`.
        shell_cmd = shlex.join(["kill", "-0", str(pid)])
        res = self.run(
            ["sh", "-c", shell_cmd],
            text=True,
            known_bin=None,
            capture_strategy=Capture.MERGED,
        )
        if res.returncode == 0:
            return True
        else:
            if "No such process" not in res.stdout:
                _logger.warning("Unexpected kill output: %s", res.stdout)
            return False

    def send_signal(self, pid: int, sig: int) -> None:
        """Signal a process previously started with this Launcher.

        Should be preferred over directly calling python APIs like os.kill,
        since the process may be remote.

        If a Popen object is available, (i.e. the process isn't detached),
        then Popen.send_signal should be preferred.
        """

        # On some systems, kill is only available a shell built-in,
        # so run it via a shell.
        # TODO: consider implementing `shell` kwarg for `run` and `popen`.
        shell_cmd = shlex.join(["kill", f"-{sig}", str(pid)])
        self.run(["sh", "-c", shell_cmd], text=True, known_bin=None)


class LocalPopen(Popen):
    """Specialization of Popen returnced by `LocalLauncher`"""

    def __init__(self, launcher: LocalLauncher, inner: subprocess.Popen[str]) -> None:
        self._launcher = launcher
        self._inner = inner

    @override
    def launcher(self) -> Launcher:
        """Launcher used  to launch this process"""
        return self._launcher

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
        # bufsize: int = -1,
        capture_strategy: Capture = Capture.SEPARATE,
        text: Literal[True],
        known_bin: Optional[KnownBin],
        cwd: Optional[Path] = None,
    ) -> Popen:
        assert text is True
        stdin = subprocess.PIPE
        stdout = subprocess.PIPE
        if capture_strategy is Capture.SEPARATE:
            stderr = subprocess.PIPE
        elif capture_strategy is Capture.MERGED:
            stderr = subprocess.STDOUT
        else:
            raise chutney.errors.ChutneyInternalError(
                "Unhandled capture strategy " + capture_strategy
            )
        try:
            inner = subprocess.Popen(
                args,
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                text=text,
                cwd=cwd,
            )
        except FileNotFoundError as e:
            raise chutney.errors.ChutneyMissingBinaryError(known_bin, args) from e
        return LocalPopen(self, inner)

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
        cwd: Optional[Path] = None,
    ) -> None:
        # We use this to signal back if exec failed.
        # TODO: Consider communicating via the sd_notify(3) protocol instead (e.g.
        # ERRNO=x), particularly if and when arti itself supports it.
        # <https://gitlab.torproject.org/tpo/core/arti/-/issues/1979>
        execfail_r, execfail_w = os.pipe()

        # Open all the files in this process, where errors will be reported most
        # loudly and obviously.
        with (
            open("/dev/null") as stdin_file,
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

                # Reassign specified files to stdin, stdout, and stderr.
                # We do this here instead of in child2 so that a failure will be
                # directly detectable in the chutney process by this process
                # failing.
                os.dup2(stdin_file.fileno(), 0, inheritable=True)
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
        _, status = os.waitpid(child1, 0)
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


class SshPopen(Popen):
    """A `Popen` for a process launched by `SshLauncher`"""

    def __init__(
        self,
        # The launcher used to launch this process.
        # We need it to launch auxiliary processes (e.g. `kill`) affecting this
        # process.
        launcher: SshLauncher,
        # The open paramikio Channel connected to the remote process.
        channel: paramiko.Channel,
        # The remote pid of the process.
        pid: int,
        # The original arguments used to launch the process.
        args: list[str],
        # Metadata about the program binary.
        known_bin: Optional[KnownBin],
        # Any already-captured stdout.
        buffered_stdout: bytes,
        # The channel window size.
        window_size: int,
        # The capture strategy for this process.
        capture_strategy: Capture,
    ) -> None:
        """
        "private" to `SshLauncher`.
        """
        self._launcher = launcher
        self._channel = channel
        self._pid = pid
        self._args = args
        self._known_bin = known_bin
        self._buffered_stdout = [buffered_stdout]
        self._buffered_stderr: list[bytes] = []
        # None initially; non-None after `communicate` is called.
        # Empty byte-sequence if no input was provided to `communicate`, or we've sent
        # all the input.
        self._pending_input: Optional[bytes] = None
        self._window_size = window_size
        self._capture_strategy = capture_strategy

    @override
    def launcher(self) -> Launcher:
        """Launcher used  to launch this process"""
        return self._launcher

    @override
    def communicate(
        self, input: Optional[str] = None, timeout: Optional[float] = None
    ) -> CompletedProcess[str]:
        if self._pending_input is None:
            # This is the first time `communicate` has been called, so we
            # initialize self._pending_input.
            if input is None:
                self._channel.shutdown_write()
                self._pending_input = b""
            else:
                self._pending_input = input.encode()
        else:
            # This is *not* the first time `communicate` has been called.
            # Providing input is an error.
            if input is not None:
                raise ValueError("Cannot send input after starting communication")

        with selectors.DefaultSelector() as sel:
            if self._pending_input:
                mask = selectors.EVENT_READ | selectors.EVENT_WRITE
            else:
                mask = selectors.EVENT_READ
            sel.register(self._channel.fileno(), mask)
            t0 = time.time()
            while True:
                did_something = False
                if self._channel.recv_ready():
                    data = self._channel.recv(self._window_size)
                    self._buffered_stdout.append(data)
                    did_something = True
                if self._channel.recv_stderr_ready():
                    assert self._capture_strategy != Capture.MERGED
                    data = self._channel.recv_stderr(self._window_size)
                    self._buffered_stderr.append(data)
                    did_something = True
                if (
                    # Program has exited and we've received the exit status
                    self._channel.exit_status_ready()
                    # No more buffered stdout to process
                    and not self._channel.recv_ready()
                    # No more buffered stderr to process
                    and not self._channel.recv_stderr_ready()
                ):
                    if self._pending_input:
                        _logger.debug(
                            "exited while we still had pending input: %s",
                            self._pending_input,
                        )
                    break
                if self._pending_input and self._channel.send_ready():
                    try:
                        n = self._channel.send(self._pending_input)
                    except OSError:
                        # We can get here if the program exited, closing the
                        # channel, in between calling `send_ready` and `send`.
                        # In any case it means we weren't able to send all
                        # input, but this isn't generally an error in itself.
                        _logger.debug(
                            "send failed while we still had pending input: %s",
                            self._pending_input,
                        )
                        self._pending_input = b""
                        sel.modify(self._channel.fileno(), selectors.EVENT_READ)
                        continue
                    self._pending_input = self._pending_input[n:]
                    did_something = True
                    if not self._pending_input:
                        sel.modify(self._channel.fileno(), selectors.EVENT_READ)
                        self._channel.shutdown_write()
                if did_something:
                    # Don't call select until we've verified nothing is ready,
                    # in particular to work around write-readiness bug described
                    # below.
                    continue
                if self._pending_input:
                    # On Linux, the fileno provided for use with selectors doesn't
                    # actually trigger on write-readiness
                    # <https://github.com/paramiko/paramiko/issues/695>.
                    #
                    # Nothing is ready so we're about to call `select`, but the target
                    # process becoming ready for more input won't wake us up again.
                    #
                    # If we need to solve this and it's still not fixed in
                    # paramiko, consider spawning threads instead of using a
                    # selector.
                    _logger.warning(
                        "Calling select with pending input '%s'."
                        " May deadlock due to https://github.com/paramiko/paramiko/issues/695",
                        self._pending_input,
                    )
                if timeout is not None:
                    elapsed = time.time() - t0
                    this_timeout = timeout - elapsed
                    if this_timeout <= 0:
                        raise chutney.errors.ChutneyTimeoutError
                else:
                    this_timeout = None
                sel.select(timeout=this_timeout)

        assert self._channel.exit_status_ready()
        returncode = self._channel.recv_exit_status()
        stdout = b"".join(self._buffered_stdout).decode()
        stderr: Optional[str]
        if self._capture_strategy == Capture.SEPARATE:
            stderr = b"".join(self._buffered_stderr).decode()
        elif self._capture_strategy == Capture.MERGED:
            assert len(self._buffered_stderr) == 0
            stderr = None
        else:
            raise chutney.errors.ChutneyInternalError(
                f"Unhandled capture mode: {self._capture_strategy}"
            )

        if returncode == 127:
            # 127 is command-not-found according to
            # [posix](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html#tag_18_08_02)
            # and [bash](https://www.gnu.org/software/bash/manual/html_node/Exit-Status.html)
            raise chutney.errors.ChutneyMissingBinaryError(self._known_bin, self._args)

        return CompletedProcess(
            args=self._args,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
        )

    @override
    def pid(self) -> int:
        return self._pid


class SshLauncher(Launcher):
    """
    A Launcher that acts on a remote host via ssh.
    """

    def __init__(self, host: str, port: Optional[int] = None) -> None:
        """
        Create a launcher that creates and uses an ssh connection to `host`:`port`.

        The connection is created lazily, making it cheap to create unused
        instances of this object.

        Assumes that it will be able to authenticate to the remote host using
        an unencrypted client key in ~/.ssh.

        Currently trusts host keys for hosts that don't already have an entry in
        the user's known-hosts files, but doesn't add them to those files.
        """
        # TODO: it looks like paramiko supports using an ssh agent, which would
        # be a bit nicer.
        # <https://docs.paramiko.org/en/stable/api/agent.html>

        self._host = host
        self._port = port
        # We use the paramiko ssh client.
        #
        # This is simpler and a bit more flexible than spawning `ssh` client
        # processes. Notably we can use a single persistent connection to spawn
        # multiple processes, saving noticeable overhead. openssh's `ssh` also
        # supports this via `ControlMaster` config option, but that would be
        # awkward to use here, and currently isn't supported under shadow due to
        # its reliance on named sockets. Using `ssh` subprocesses, it's also
        # difficult to distinguish between remote process output and output from
        # `ssh` itself in case of errors (though it might be awkwardly possible
        # via the `-E` flag).
        #
        # There is a higher-level python module `fabric` that *uses* paramiko.
        # I had initially implemented this class using that, but ran into
        # <https://github.com/fabric/fabric/issues/2351>, which doesn't appear
        # will be addressed any time soon. In general fabric might be a little
        # more opinionated and opaque than we really want, anyway.
        self._client = paramiko.client.SSHClient()
        # Load system host keys, so that we validate hosts that we do know about
        self._client.load_system_host_keys()
        # Silently auto-add keys for missing hosts, to our in-memory client.
        # This lets things "just work" when using unusual local addresses like 127.0.0.2,
        # or addresses inside shadow simulations, without having to add keys to our
        # "real" host key files.
        #
        # We should make this configurable if we ever want to support "real"
        # distributed chutney across a potentially-untrusted network.
        self._client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy())

    def _transport(self) -> paramiko.Transport:
        """Get the Transport, connecting to the target host if we haven't already"""
        t = self._client.get_transport()
        if t is not None:
            return t
        if self._port is not None:
            self._client.connect(self._host, port=self._port)
        else:
            self._client.connect(self._host)
        t = self._client.get_transport()
        if t is None:
            raise chutney.errors.ChutneyInternalError("Couldn't get transport")
        return t

    @override
    def popen(
        self,
        args: CMD,
        *,
        capture_strategy: Capture = Capture.SEPARATE,
        text: Literal[True],
        known_bin: Optional[KnownBin],
        cwd: Optional[Path] = None,
    ) -> Popen:
        assert text is True

        if cwd is not None:
            cwd_str = str(cwd)
        else:
            # Default to our local working directory. We may need to rethink
            # this to support "real" distributed chutney where nodes aren't
            # sharing the same file system.
            cwd_str = os.getcwd()

        # This is the documented default window size in paramiko.
        # Unfortunately they don't expose it as a public constant.
        #
        # We set and track it explicitly since this seems like a reasonable max
        # size to provide to the channel's `recv` functions. (A max size is
        # mandatory, and there's no documented member of channel that tells us
        # what the window size actually is, either).
        window_size = 2097152

        channel = self._transport().open_session(window_size=window_size)

        if capture_strategy is Capture.SEPARATE:
            channel.set_combine_stderr(False)
        elif capture_strategy == Capture.MERGED:
            channel.set_combine_stderr(True)
        else:
            raise chutney.errors.ChutneyInternalError(
                "Unhandled capture strategy " + capture_strategy
            )

        # Fail if any of the below "scaffolding" script commands go wrong.
        cmd_string = "set -eu\n"
        # Get the pid (`$$`)
        cmd_string += "echo $$\n"
        # Set the working directory
        cmd_string += "cd " + shlex.quote(cwd_str) + "\n"
        # Execute the actual command, using `exec` to ensure it gets
        # our `pid`, which we echo'd above.
        cmd_string += "exec " + shlex.join(args)
        channel.exec_command(cmd_string)

        # Read enough of stdout to get the first line,
        # which should be the output of our injected `echo $$`.
        buffered_stdout = b""
        while True:
            buffered_stdout += channel.recv(window_size)
            first_line, newline, addtl_stdout = buffered_stdout.partition(b"\n")
            if newline:
                break
            if len(buffered_stdout) > 100:
                _logger.warning(
                    "Unexpectedly long line before receiving pid. So far: %s",
                    buffered_stdout,
                )

        try:
            pid = int(first_line)
        except ValueError:
            raise chutney.errors.ChutneyError(
                f"Failed to parse pid string '{first_line!r}'"
            )

        # From here on we're careful to never perform an operation on the
        # channel that could block.  Set nonblocking so that we get an exception
        # instead of a deadlock if we mistakenly do.
        channel.setblocking(0)

        return SshPopen(
            launcher=self,
            channel=channel,
            pid=pid,
            args=args,
            known_bin=known_bin,
            buffered_stdout=addtl_stdout,
            window_size=window_size,
            capture_strategy=capture_strategy,
        )

    @override
    def launch_detached(
        self,
        cmd: Path,
        args: list[str],
        stdout_path: Path,
        stderr_path: Path,
        pid_path: Path,
        known_bin: KnownBin,
        cwd: Optional[Path] = None,
    ) -> None:
        args = [str(cmd)] + args

        # Since there's no easy way to validate that `exec`ing the target
        # command succeeds, do our best to validate that it *will* succeed.
        if (
            self.run(
                ["test", "-x", str(cmd), "-a", "-f", str(cmd)],
                text=True,
                cwd=cwd,
                known_bin=None,
            ).returncode
            != 0
        ):
            raise chutney.errors.ChutneyMissingBinaryError(known_bin, args)

        # shell script to execute the command while recording to the requested paths.
        # Note the use of `exec` to ensure the command's pid is the same as the recorded pid.
        inner_shell_script = (
            f"echo $$ > {shlex.quote(str(pid_path))};"
            f" exec {shlex.join(args)}"
            " </dev/null"
            f" >{shlex.quote(str(stdout_path))}"
            f" 2>{shlex.quote(str(stderr_path))}"
        )
        self.run(
            # Execute the above shell script using `setsid` to execute it in its
            # own session, s.t. it can outlive the ssh connection. We
            # also force it to fork to ensure that it's orphaned, which allows us
            # to test whether it's still running using `kill -0`.
            # (Conversely, if it weren't orphaned and weren't awaited it would
            # become a zombie on completion, and `kill -0` can't distinguish
            # between the zombie and running states)
            ["setsid", "-f", "sh", "-c", inner_shell_script],
            # We expect setsid to always succeed. It forks and exits
            # immediately, unfortunately without validating that the child is
            # even able to successfully exec, though in this case even that
            # wouldn't help us validate that the target process is successfully
            # exec'd, since the immediate child is a shell.
            check=True,
            text=True,
            known_bin=None,
            cwd=cwd,
        )
