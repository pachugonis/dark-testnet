# [pep 0536](https://peps.python.org/pep-0563/) - Lazy annotation eval via
# stringification.
from __future__ import annotations

import logging
import re
import signal
import sqlite3

from collections.abc import Collection
from pathlib import Path
from typing import Optional, TYPE_CHECKING
from typing_extensions import override

from chutney.dirinfo import DirInfoStatus, DirInfoStatusCode, DirFormat, HSV3_KEYWORD
from chutney.node_controller import NodeController

import chutney.errors
import chutney.known_bins
import chutney.launcher

from chutney.Util import (
    Option,
)

if TYPE_CHECKING:
    import chutney.TorNet as TorNet

logger = logging.getLogger(__name__)

# TODO: Consider merging NodeController and NodeBuilder so that this sort of
# thing can be shared more naturally. Currently the implementations unsafely
# assume that the associated counter-part is being used anyway.
_HS_NICKNAME = chutney.arti.builder._HS_NICKNAME


class LocalArtiNodeController(NodeController):
    def __init__(self, network: TorNet.Network, node: TorNet.Node):
        self._network = network
        self._node = node
        self._most_recent_bootstrap_status: Optional[DirInfoStatus] = None
        self._most_recent_oniondesc_status: Optional[DirInfoStatus] = None

    @property
    def _launcher(self) -> chutney.launcher.Launcher:
        return self._node._launcher

    @override
    def getPtExtra(self) -> Option[str]:
        if self._node._config.pt_bridge:
            raise chutney.errors.ChutneyUnimplementedError(
                "chutney pt_bridge unimplemented"
            )
        return Option(None)

    @override
    def getUncheckedDirInfoWaitTime(self) -> float:
        if self._node.is_hs:
            # We don't check for onion service descriptors before verifying.
            # See #33609 for details.
            return self._network.V3_AUTH_VOTING_INTERVAL + 10
        else:
            # The extra time after other descriptors have finished, and before
            # verifying.
            return 0

    def _get_pid(self) -> Optional[int]:
        """Read the pidfile, and return the pid of the running process.
        Returns None if the file doesn't exist.
        """
        if not self._node.pidfile.exists():
            return None

        with self._node.pidfile.open(mode="r") as f:
            return int(f.read())

    @override
    def isRunning(self) -> bool:
        pid = self._get_pid()
        if pid is None:
            return False
        return self._is_running_with_pid(pid)

    def _is_running_with_pid(self, pid: int) -> bool:
        """As for isRunning, but takes the pid, which should be the process ID for this node"""
        # TODO: check if this is really arti?
        return self._launcher.running(pid)

    @override
    def hup(self) -> bool:
        pid = self._get_pid()
        nick = self._node.nick
        if pid is not None and self._is_running_with_pid(pid):
            print("Sending sighup to {}".format(nick))
            self._launcher.send_signal(pid, signal.SIGHUP)
            return True
        else:
            print("{:12} is not running".format(nick))
            return False

    @override
    def start(self) -> None:
        if self.isRunning():
            print("{:12} is already running".format(self._node.nick))
            return
        self._launcher.launch_detached(
            cmd=Path(self._node._config.arti),
            args=[
                # Currently only client/proxy mode is supported
                "proxy",
                "--config",
                str(self._node.torrc_path),
                # Only available as a flag, not in config file.
                "--disable-fs-permission-checks",
            ],
            # In theory nothing should go here, since we configure
            # arti to log to files instead of stdout.
            stdout_path=self._node.dir.joinpath("arti.stdout"),
            # Some error messages can end up here, e.g. before setting up
            # logging.
            stderr_path=self._node.dir.joinpath("arti.stderr"),
            pid_path=self._node.pidfile,
            known_bin=chutney.known_bins.ArtiBin(),
        )

    @override
    def stop(self, sig: int = signal.SIGINT) -> None:
        pid = self._get_pid()
        if pid is None or not self._is_running_with_pid(pid):
            print("{:12} is not running".format(self._node.nick))
            return
        self._launcher.send_signal(pid, sig)

    @override
    def cleanupRunFiles(self) -> None:
        # move aside old pid files after arti stops running
        self.cleanup_pidfile()

    def cleanup_pidfile(self) -> None:
        """Move PID file to pidfile.old if this node is no longer running
        so that we don't try to stop the node again.
        """
        if not self.isRunning() and self._node.pidfile.exists():
            logging.debug("Renaming stale pid file for {} ...".format(self._node.nick))
            self._node.pidfile.rename(self._node.pidfile.with_suffix(".old"))

    def _info_log_path(self) -> Path:
        """Return the expected path to the logfile for this instance."""
        return self._node.dir.joinpath("info.log")

    def _debug_log_path(self) -> Path:
        """Return the expected path to the logfile for this instance."""
        return self._node.dir.joinpath("debug.log")

    def _getLastOnionServiceDescStatus(self) -> DirInfoStatus:
        status = self._most_recent_oniondesc_status
        # Caller is required to have set this via `updateLastStatus` first.
        # TODO: just call it ourselves if None, or use a default value?
        assert status is not None
        return status

    @override
    def getLastBootstrapStatus(self) -> DirInfoStatus:
        rv = self._most_recent_bootstrap_status
        # Caller is required to have set this via `updateLastStatus` first.
        # TODO: just call it ourselves if None, or use a default value?
        assert rv is not None
        return rv

    @override
    def updateLastStatus(self) -> None:
        logfname = self._debug_log_path()
        if not logfname.exists():
            self._most_recent_bootstrap_status = DirInfoStatus(
                percent_or_code=DirInfoStatusCode.MISSING_FILE,
                keyword="no_logfile",
                message="There is no logfile yet.",
            )
            return
        status = DirInfoStatus(
            percent_or_code=DirInfoStatusCode.NO_RECORDS,
            keyword="no_message",
            message="No bootstrap messages yet.",
        )
        self._most_recent_bootstrap_status = status
        self._most_recent_oniondesc_status = status
        with logfname.open(mode="r") as f:
            for line in f:
                m = re.search(r" arti_client::status: (\d+)%: (.*)", line)
                if m:
                    percent_s, message = m.groups()
                    self._most_recent_bootstrap_status = DirInfoStatus(
                        percent_or_code=(
                            DirInfoStatusCode.SUCCESS
                            if percent_s == "100"
                            else int(percent_s)
                        ),
                        keyword="",
                        message=message,
                    )
                if not self._node.is_hs:
                    # No need to scan for hs descriptor updates
                    continue
                m = re.search(
                    r" descriptor uploaded successfully to "
                    + r"\d+/\d+ HSDirs nickname="
                    + _HS_NICKNAME,
                    line,
                )
                if m:
                    self._most_recent_oniondesc_status = DirInfoStatus(
                        percent_or_code=DirInfoStatusCode.ONIONDESC_PUBLISHED,
                        keyword=HSV3_KEYWORD,
                        message=m.group(0),
                    )
                    continue
                m = re.search(
                    r"Restricted discovery is enabled,"
                    r" but no authorized clients are configured",
                    line,
                )
                if m:
                    self._most_recent_oniondesc_status = DirInfoStatus(
                        percent_or_code=DirInfoStatusCode.ONIONDESC_FAILED_TO_PUBLISH,
                        keyword=HSV3_KEYWORD,
                        message="Restricted discovery enabled, but no auth'd clients configured",
                    )
                    continue

    @override
    def isBootstrapped(self) -> bool:
        status = self.getLastBootstrapStatus()
        if status.percent_or_code != DirInfoStatusCode.SUCCESS:
            return False
        if self._node.is_hs:
            status = self._getLastOnionServiceDescStatus()
            if status.percent_or_code != DirInfoStatusCode.ONIONDESC_PUBLISHED:
                return False
        return True

    def _get_sqlite_conn(self) -> Optional[sqlite3.Connection]:
        db_path = self._node.dir.joinpath("cache", "dir.sqlite3")
        if not db_path.exists():
            return None
        return sqlite3.connect(self._node.dir.joinpath("cache", "dir.sqlite3"))

    def _get_md_consensus_path(self) -> Optional[Path]:
        con = self._get_sqlite_conn()
        if con is None:
            return None
        cur = con.cursor()
        # Get path to most recent microdesc consensus file.
        # TODO: verify that we're within the valid and fresh times?
        try:
            res = cur.execute("""
                SELECT filename
                FROM Consensuses
                    JOIN ExtDocs ON Consensuses.digest=ExtDocs.digest
                WHERE Consensuses.flavor="microdesc"
                ORDER BY Consensuses.valid_until DESC
                LIMIT 1
                """)
        except sqlite3.OperationalError as oe:
            # TODO: use sqlite_errorcode when we require python >= 3.11
            # https://docs.python.org/3/library/sqlite3.html#sqlite3.Error.sqlite_errorcode
            if str(oe).startswith("no such table"):
                # Table hasn't been created yet
                logging.debug("Looks like no such table Consensuses yet")
                return None
            raise
        filename = res.fetchone()
        con.close()
        if filename is None:
            return None
        return self._node.dir.joinpath("cache", "dir_blobs", filename[0])

    @override
    def getNodeDirInfoStatus(
        self,
        *,
        launch_phase: int,
    ) -> Optional[tuple[DirInfoStatusCode, Collection[str], Collection[DirFormat]]]:
        if self._node._config.consensus_member:
            raise chutney.errors.ChutneyUnimplementedError(
                "arti consensus members unimplemented"
            )
        return None

    @override
    def check_node_in_dirinfo(
        self, dir_fmt: DirFormat, other_node: TorNet.Node
    ) -> DirInfoStatusCode:
        """Check whether `other_node` is present in the specified directory type"""
        if dir_fmt == DirFormat.MD_CONS:
            path = self._get_md_consensus_path()
            if path is None:
                return DirInfoStatusCode.MISSING_FILE
            dir_pattern = dir_fmt.status_pattern(
                other_node.nick, other_node.fingerprint_ed25519
            )
            assert dir_pattern is not None
            with path.open(mode="r") as f:
                for line in f:
                    if re.search(dir_pattern, line):
                        return DirInfoStatusCode.SUCCESS
            return DirInfoStatusCode.NO_PROGRESS
        elif dir_fmt == DirFormat.MD:
            con = self._get_sqlite_conn()
            if con is None:
                return DirInfoStatusCode.MISSING_FILE
            cur = con.cursor()
            dir_pattern = dir_fmt.status_pattern(
                other_node.nick, other_node.fingerprint_ed25519
            )
            if dir_pattern is None:
                return DirInfoStatusCode.NOT_YET_IMPLEMENTED
            try:
                res = cur.execute("""
                    SELECT contents
                    FROM Microdescs
                    """)
            except sqlite3.OperationalError as oe:
                # TODO: use sqlite_errorcode when we require python >= 3.11
                # https://docs.python.org/3/library/sqlite3.html#sqlite3.Error.sqlite_errorcode
                if str(oe).startswith("no such table"):
                    # Table hasn't been created yet
                    logging.debug("Looks like no such table Microdescs yet")
                    return DirInfoStatusCode.MISSING_FILE
                raise
            for row in res:
                for line in row[0].splitlines():
                    if re.search(dir_pattern, line):
                        return DirInfoStatusCode.SUCCESS
            return DirInfoStatusCode.NO_PROGRESS
        return DirInfoStatusCode.NOT_YET_IMPLEMENTED
