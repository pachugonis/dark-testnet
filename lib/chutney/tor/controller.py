# [pep 0536](https://peps.python.org/pep-0563/) - Lazy annotation eval via
# stringification.
from __future__ import annotations

import logging
import os
import re
import signal
import time

from collections.abc import Collection
from pathlib import Path
from typeguard import check_type
from typing import TYPE_CHECKING, Optional
from typing_extensions import override

import chutney.errors
import chutney.known_bins
import chutney.launcher

from chutney.dirinfo import (
    DirInfoStatus,
    DirInfoStatusCode,
    DirFormat,
    HSV3_KEYWORD,
)
from chutney.node_controller import NodeController
from chutney.tor.util import get_tor_version
from chutney.Util import (
    values_for_keys,
)

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    import chutney.TorNet as TorNet


class LocalNodeController(NodeController):

    def __init__(self, network: TorNet.Network, node: TorNet.Node):
        NodeController.__init__(self)
        self._network = network
        self._node = node
        self.most_recent_oniondesc_status: Optional[DirInfoStatus] = None
        self.most_recent_bootstrap_status: Optional[DirInfoStatus] = None

    @property
    def _launcher(self) -> chutney.launcher.Launcher:
        return self._node._launcher

    # Older tor versions need extra time to bootstrap.
    # (And we're not sure exactly why -  maybe we fixed some bugs in 0.4.0?)
    #
    # This version prefix compares less than all 0.4-series, and any
    # future version series (for example, 0.5, 1.0, and 22.0)
    MIN_TOR_VERSION_FOR_TIMING_FIX = "Tor 0.4"

    def isLegacyTorVersion(self) -> bool:
        """Is the current Tor version 0.3.5 or earlier?"""
        tor = self._node._config.tor
        tor_version = get_tor_version(self._launcher, tor)
        min_version = LocalNodeController.MIN_TOR_VERSION_FOR_TIMING_FIX

        # We could compare the version components, but this works for now
        # (And if it's a custom Tor implementation, it shouldn't have this
        # particular timing bug.)
        if tor_version.startswith("Tor ") and tor_version < min_version:
            return True
        else:
            return False

    @override
    def getUncheckedDirInfoWaitTime(self) -> float:
        if self._node.is_hs:
            # This delay was originally added before we checked onion descriptor
            # publishing status at all. We now do check that some are published,
            # but it's a bit imprecise (see
            # `_update_last_onion_service_desc_status` and #33609), so we keep
            # this for now.
            return self._network.v3_auth_voting_interval_seconds + 10
        elif self.isLegacyTorVersion():
            # Let everything propagate for another consensus period before verifying.
            return self._network.v3_auth_voting_interval_seconds
        else:
            return 0

    def getPid(self) -> Optional[int]:
        """Read the pidfile, and return the pid of the running process.
        Returns None if there is no pid in the file.
        """
        pidfile = Path(self._node.pidfile)
        if not pidfile.exists():
            return None

        with pidfile.open(mode="r") as f:
            try:
                return int(f.read())
            except ValueError:
                return None

    @override
    def isRunning(self) -> bool:
        pid = self.getPid()
        if pid is None:
            return False
        return self._is_running_with_pid(pid)

    def _is_running_with_pid(self, pid: int) -> bool:
        """As for isRunning, but takes the pid, which should be the process ID for this node"""
        # TODO: check if this pid is really tor?
        return self._launcher.running(pid)

    @override
    def hup(self) -> bool:
        pid = self.getPid()
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
        cmd = Path(self._node._config.tor)
        args = [
            "-f",
            str(self._node.torrc_path),
        ]
        self._launcher.launch_detached(
            cmd=cmd,
            args=args,
            known_bin=chutney.known_bins.TorBin(),
            # In theory nothing should go here, since we configure
            # tor to log to files instead of stdout.
            stdout_path=self._node.dir.joinpath("tor.stdout"),
            # Some error messages can end up here, e.g. before setting up
            # logging.
            stderr_path=self._node.dir.joinpath("tor.stderr"),
            pid_path=self._node.pidfile,
        )
        poll_launch_time = self._node._config.poll_launch_time or 0.0
        time.sleep(poll_launch_time)
        if not self.isRunning():
            # Process unexpectedly exited
            raise chutney.errors.ChutneyError(
                f"'{self._node.nick:12}' unexpectedly exited."
                + f" command '{' '.join([str(cmd)] + args)}'"
                + f" after waiting {poll_launch_time} seconds for launch"
            )

    @override
    def stop(self, sig: int = signal.SIGINT) -> None:
        pid = self.getPid()
        if pid is None or not self._is_running_with_pid(pid):
            print("{:12} is not running".format(self._node.nick))
            return
        self._launcher.send_signal(pid, sig)

    @override
    def cleanupRunFiles(self) -> None:
        # check for stale lock files when Tor crashes
        self.cleanup_lockfile()
        # move aside old pid files after Tor stops running
        self.cleanup_pidfile()

    def cleanup_lockfile(self) -> None:
        """Remove lock file if this node is no longer running."""
        lf = Path(self._node.lockfile)
        if not self.isRunning() and lf.exists():
            logger.debug("Removing stale lock file for {} ...".format(self._node.nick))
            os.remove(lf)

    def cleanup_pidfile(self) -> None:
        """Move PID file to pidfile.old if this node is no longer running
        so that we don't try to stop the node again.
        """
        pidfile = Path(self._node.pidfile)
        if not self.isRunning() and pidfile.exists():
            logger.debug("Renaming stale pid file for {} ...".format(self._node.nick))
            pidfile.rename(pidfile.with_suffix(".old"))

    def getLogfile(self, info: bool = False) -> Path:
        """Return the expected path to the logfile for this instance."""
        datadir = check_type(self._node.dir, Path)
        if info:
            logname = "info.log"
        else:
            logname = "notice.log"
        return datadir.joinpath(logname)

    def _update_last_onion_service_desc_status(
        self,
        *,
        _created_pattern: re.Pattern[str] = re.compile(
            r"Service ([^\s]+ [^\s]+ descriptor of revision .*)"
        ),
        _want_current_pattern: re.Pattern[str] = re.compile(
            r"Service [^\s]+ just picked \d+ intro points"
            r" and wanted (\d+) for current descriptor."
            r" It currently has \d+ intro points.",
        ),
        _want_next_pattern: re.Pattern[str] = re.compile(
            r"Service [^\s]+ just picked \d+ intro points"
            r" and wanted (\d+) for next descriptor."
            r" It currently has \d+ intro points.",
        ),
        _completed_upload_pattern: re.Pattern[str] = re.compile(
            r"Uploading hidden service descriptor:"
            r' finished with status 200 \("HS descriptor stored successfully."\)'
        ),
    ) -> None:
        """Look through the logs and cache the last onion service
        descriptor status received.
        """
        logfname = self.getLogfile(info=True)
        if not os.path.exists(logfname):
            self.most_recent_oniondesc_status = DirInfoStatus(
                DirInfoStatusCode.MISSING_FILE,
                "no_logfile",
                "There is no logfile yet.",
            )
            return
        status = DirInfoStatus(
            percent_or_code=DirInfoStatusCode.NO_RECORDS,
            keyword="no_message",
            message="No onion service descriptor messages yet.",
        )
        with open(logfname, "r") as f:
            want_current: Optional[int] = None
            want_next: Optional[int] = None
            completed_uploads = 0
            for line in f:
                match = _created_pattern.search(line)
                if match:
                    status = DirInfoStatus(
                        percent_or_code=DirInfoStatusCode.ONIONDESC_CREATED,
                        keyword=HSV3_KEYWORD,
                        message=match.group(1),
                    )
                # Look for the first statement of how many current intro points
                # we want. Don't reset based on subsequent matching lines, since
                # we would have to also reset the corresponding "completed"
                # count, but we can't, since we can't separate the "current"
                # completed from the "next" completed.
                if (
                    want_current is None
                    and (match := _want_current_pattern.search(line)) is not None
                ):
                    want_current = int(match.group(1))
                    logger.debug(f"hs wants {want_current} current intro points")
                # Look for the first statement of how many next intro points we want.
                if (
                    want_next is None
                    and (match := _want_next_pattern.search(line)) is not None
                ):
                    want_next = int(match.group(1))
                    logger.debug(f"hs wants {want_next} next intro points")
                if _completed_upload_pattern.search(line):
                    completed_uploads += 1
                    logger.debug(
                        f"hs has completed {completed_uploads} descriptor uploads"
                    )
                if want_current is not None and want_next is not None:
                    wanted = want_current + want_next
                    if completed_uploads >= wanted:
                        # We've completed at least as many uploads as we initially wanted.
                        # It's possible that some of these are now-expired and we're not actually
                        # completely up to date, but this is about the best we can reasonably do
                        # with the available log messages.
                        # See #33609.
                        status = DirInfoStatus(
                            percent_or_code=DirInfoStatusCode.ONIONDESC_PUBLISHED,
                            keyword=HSV3_KEYWORD,
                            message="published",
                        )
                        break
                    status = DirInfoStatus(
                        percent_or_code=int(completed_uploads / wanted),
                        keyword=HSV3_KEYWORD,
                        message=f"published {completed_uploads}/{wanted}",
                    )

        self.most_recent_oniondesc_status = status

    @override
    def getLastOnionServiceDescStatus(self) -> DirInfoStatus:
        rv = self.most_recent_oniondesc_status
        # Caller is required to have set this via `updateLastStatus` first.
        # TODO: just call it ourselves if None, or use a default value?
        if rv is None:
            raise chutney.errors.ChutneyInternalError(
                "caller failed to call updateLastStatus"
            )
        return rv

    def _update_last_bootstrap_status(
        self,
        _bootstrap_pattern: re.Pattern[str] = re.compile(
            r"Bootstrapped (\d+)%(?: \(([^\)]*)\))?: (.*)"
        ),
    ) -> None:
        logfname = self.getLogfile()
        if not logfname.exists():
            self.most_recent_bootstrap_status = DirInfoStatus(
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
        with logfname.open(mode="r") as f:
            for line in f:
                m = _bootstrap_pattern.search(line)
                if m:
                    percent_s, keyword, message = m.groups()
                    status = DirInfoStatus(
                        percent_or_code=(
                            DirInfoStatusCode.SUCCESS
                            if percent_s == "100"
                            else int(percent_s)
                        ),
                        keyword=keyword,
                        message=message,
                    )
        self.most_recent_bootstrap_status = status

    @override
    def getLastBootstrapStatus(self) -> DirInfoStatus:
        rv = self.most_recent_bootstrap_status
        # Caller is required to have set this via `updateLastStatus` first.
        # TODO: just call it ourselves if None, or use a default value?
        if rv is None:
            raise chutney.errors.ChutneyInternalError(
                "caller failed to call updateLastStatus"
            )
        return rv

    @override
    def updateLastStatus(self) -> None:
        self._update_last_onion_service_desc_status()
        self._update_last_bootstrap_status()

    def getNodeCacheDirInfoPaths(self) -> dict[DirFormat, Path]:
        """Return a dict with the expected paths to this node's consensus files.

        Directory servers usually have both consensus flavours.
        Clients usually have the microdesc consensus, but they may have
        either flavour. (Or both flavours.)
        Only the bridge authority has the bridge networkstatus.

        The dict keys are:
          * NS_CONS, DESC, and DESC_NEW;
          * MD_CONS, MD, and MD_NEW; and
          * BR_STATUS.
        """
        datadir = self._node.dir
        paths = {
            DirFormat.DESC: Path(datadir, "cached-descriptors"),
            DirFormat.DESC_NEW: Path(datadir, "cached-descriptors.new"),
            DirFormat.NS_CONS: Path(datadir, "cached-consensus"),
            DirFormat.MD_CONS: Path(datadir, "cached-microdesc-consensus"),
            DirFormat.MD: Path(datadir, "cached-microdescs"),
            DirFormat.MD_NEW: Path(datadir, "cached-microdescs.new"),
        }
        if self._node._config.bridgeauthority:
            paths[DirFormat.BR_STATUS] = Path(datadir, "networkstatus-bridges")

        return paths

    @override
    def check_node_in_dirinfo(
        self, dir_fmt: DirFormat, other_node: TorNet.Node
    ) -> DirInfoStatusCode:
        paths = self.getNodeCacheDirInfoPaths()
        dir_path = paths.get(dir_fmt)
        if dir_path is None:
            return DirInfoStatusCode.NOT_YET_IMPLEMENTED
        if not dir_path.exists():
            return DirInfoStatusCode.MISSING_FILE
        dir_pattern = dir_fmt.status_pattern(
            other_node.nick, other_node.fingerprint_ed25519
        )
        line_count = 0
        with dir_path.open(mode="r") as f:
            for line in f:
                line_count = line_count + 1
                if dir_pattern:
                    m = dir_pattern.search(line)
                    if m:
                        return DirInfoStatusCode.SUCCESS
        if line_count == 0:
            return DirInfoStatusCode.NO_RECORDS
        if dir_pattern is None:
            return DirInfoStatusCode.NOT_YET_IMPLEMENTED
        if line_count < 8:
            # The minimum size of the bridge networkstatus is 3 lines,
            # and the minimum size of one bridge is 5 lines
            # Let the user know the dir file is unexpectedly small
            return DirInfoStatusCode.SHORT_FILE
        return DirInfoStatusCode.NO_PROGRESS

    def combineDirInfoStatuses(
        self,
        dir_status_list: list[tuple[DirInfoStatusCode, Collection[DirFormat]]],
        best: bool = True,
        ignore_missing: bool = False,
    ) -> Optional[tuple[DirInfoStatusCode, Collection[DirFormat]]]:
        """Combine the directory statuses in dir_status, if their keys
        appear in status_key_list. Keys may be directory formats, or
        node nicks.

        If best is True, choose the best status, otherwise, choose the
        worst status.

        If ignore_missing is True, ignore missing statuses, if there is any
        other status available.

        If statuses are equal, combine their format sets.

        Returns None if the status list is empty.
        """
        if len(dir_status_list) == 0:
            return None

        dir_status = None
        for new_status in dir_status_list:
            if dir_status is None:
                dir_status = new_status
                continue

            old_status_code, old_flav = dir_status
            new_status_code, new_flav = new_status
            if new_status_code == old_status_code:
                # We want to know all the flavours that have an
                # equal status, not just the latest one
                combined_flav = set(old_flav).union(new_flav)
                dir_status = (old_status_code, combined_flav)
            elif old_status_code == DirInfoStatusCode.MISSING_FILE and ignore_missing:
                # use the new status, which can't be MISSING_FILE_CODE,
                # because they're not equal
                dir_status = new_status
            elif new_status_code == DirInfoStatusCode.MISSING_FILE and ignore_missing:
                # ignore the new status
                pass
            elif old_status_code == DirInfoStatusCode.NOT_YET_IMPLEMENTED:
                # always ignore not yet implemented
                dir_status = new_status
            elif new_status_code == DirInfoStatusCode.NOT_YET_IMPLEMENTED:
                pass
            elif best and new_status_code.value > old_status_code.value:
                dir_status = new_status
            elif not best and new_status_code.value < old_status_code.value:
                dir_status = new_status
        return dir_status

    def summariseCacheDirInfoStatus(
        self,
        dir_status: dict[DirFormat, tuple[DirInfoStatusCode, Collection[DirFormat]]],
        to_dir_server: int,
        to_bridge_client: int,
    ) -> Optional[tuple[DirInfoStatusCode, Collection[DirFormat]]]:
        """Summarise the statuses for this node, among all the files used by
        the other node.

        to_dir_server is True if the other node is a directory server.
        to_bridge_client is True if the other node is a bridge client.

        Combine these alternate files by choosing the best status:
          * DESC_ALTS: DESC and DESC_NEW
          * MD_ALTS: MD and MD_NEW

        Handle these alternate formats by ignoring missing directory files,
        then choosing the worst status:
          * CONS_ALL: NS_CONS and MD_CONS
          * DESC_ALL: DESC/DESC_NEW and
                      MD/MD_NEW

        Add an "NODE_DIR" status that describes the overall status, which
        is the worst status among descriptors, consensuses, and the bridge
        networkstatus (if relevant). Return this status.

        Returns None if no status is expected.
        """
        from_bridge = self._node._config.bridge
        # Is this node a bridge, publishing to a bridge client?
        bridge_to_bridge_client = from_bridge and to_bridge_client
        # Is this node a consensus relay, publishing to a bridge client?
        relay_to_bridge_client = self._node._config.consensus_relay and to_bridge_client

        # We only need to be in one of these files to be successful
        desc_alts = self.combineDirInfoStatuses(
            values_for_keys(dir_status, [DirFormat.DESC, DirFormat.DESC_NEW]),
            best=True,
            ignore_missing=True,
        )
        if desc_alts:
            dir_status[DirFormat.DESC_ALTS] = desc_alts

        md_alts = self.combineDirInfoStatuses(
            values_for_keys(dir_status, [DirFormat.MD, DirFormat.MD_NEW]),
            best=True,
            ignore_missing=True,
        )
        if md_alts:
            dir_status[DirFormat.MD_ALTS] = md_alts

        if from_bridge:
            # Bridge clients fetch bridge descriptors directly from bridges
            # Bridges are not in the consensus
            cons_all = None
        elif to_dir_server:
            # Directory servers cache all flavours, so we want the worst
            # combined flavour status, and we want to treat missing files as
            # errors
            cons_all = self.combineDirInfoStatuses(
                values_for_keys(dir_status, [DirFormat.NS_CONS, DirFormat.MD_CONS]),
                best=False,
                ignore_missing=False,
            )
        else:
            # Clients usually only fetch one flavour, so we want the best
            # combined flavour status, and we want to ignore missing files
            cons_all = self.combineDirInfoStatuses(
                values_for_keys(dir_status, [DirFormat.NS_CONS, DirFormat.MD_CONS]),
                best=True,
                ignore_missing=True,
            )
        if cons_all:
            dir_status[DirFormat.CONS_ALL] = cons_all

        if bridge_to_bridge_client:
            # Bridge clients fetch bridge descriptors directly from bridges
            # Bridge clients fetch relay descriptors after fetching the consensus
            desc_all: Optional[tuple[DirInfoStatusCode, Collection[DirFormat]]] = (
                dir_status.get(DirFormat.DESC_ALTS)
            )
        elif relay_to_bridge_client:
            # Bridge clients usually fetch microdesc consensuses and
            # microdescs, but some fetch ns consensuses and full descriptors
            s = dir_status.get(DirFormat.MD_ALTS)
            if s is None:
                raise chutney.errors.ChutneyInternalError(
                    "Unexpectedly missing md_alts"
                )
            md_status_code = s[0]
            if md_status_code == DirInfoStatusCode.MISSING_FILE:
                # If there are no md files, we're using descs for relays and
                # bridges
                desc_all = dir_status.get(DirFormat.DESC_ALTS)
            else:
                # If there are md files, we're using mds for relays, and descs
                # for bridges, but we're looking for a relay right now
                desc_all = dir_status.get(DirFormat.MD_ALTS)
        elif to_dir_server:
            desc_all = self.combineDirInfoStatuses(
                values_for_keys(dir_status, [DirFormat.DESC_ALTS, DirFormat.MD_ALTS]),
                best=False,
                ignore_missing=False,
            )
        else:
            desc_all = self.combineDirInfoStatuses(
                values_for_keys(dir_status, [DirFormat.DESC_ALTS, DirFormat.MD_ALTS]),
                best=True,
                ignore_missing=True,
            )
        if desc_all:
            dir_status[DirFormat.DESC_ALL] = desc_all

        # Finally, get the worst status from all the combined statuses,
        # and the bridge status (if applicable)
        node_dir = self.combineDirInfoStatuses(
            values_for_keys(
                dir_status,
                [DirFormat.CONS_ALL, DirFormat.BR_STATUS, DirFormat.DESC_ALL],
            ),
            best=False,
            ignore_missing=True,
        )
        if node_dir:
            dir_status[DirFormat.NODE_DIR] = node_dir

        return node_dir

    def getNodeDirInfoStatusList(
        self, *, launch_phase: int
    ) -> Optional[dict[str, tuple[DirInfoStatusCode, Collection[DirFormat]]]]:
        """Look through the directories on each node, and work out if
        this node is in that directory.

        Returns a dict containing a status 2-tuple for each relevant node.
        The 2-tuple contains:
          * a status code,
          * a list of formats with that status
        See check_node_in_dirinfo() for more details.

        If this node is a directory authority, bridge authority, or relay
        (including exits), checks v3 directory consensuses, descriptors,
        microdesc consensuses, and microdescriptors.

        If this node is a bridge, checks bridge networkstatuses, and
        descriptors on bridge authorities and bridge clients.

        If this node is a client (including onion services), returns None.
        """
        if not self._node._config.consensus_member and not self._node._config.bridge:
            # Clients don't appear in any consensus
            return None
        dir_status_summaries: dict[
            str, tuple[DirInfoStatusCode, Collection[DirFormat]]
        ] = dict()
        for node in self._network._nodes:
            if node._config.launch_phase > launch_phase:
                continue
            dir_statuses: dict[
                DirFormat,
                tuple[DirInfoStatusCode, Collection[DirFormat]],
            ] = dict()
            for dir_format in self._node.expected_in_dir_formats(node):
                status = node._controller.check_node_in_dirinfo(dir_format, self._node)
                if status == DirInfoStatusCode.NOT_YET_IMPLEMENTED:
                    continue
                dir_statuses[dir_format] = (status, {dir_format})
            summary = self.summariseCacheDirInfoStatus(
                dir_statuses, node._config.relay, node._config.bridgeclient
            )
            if summary is not None:
                dir_status_summaries[node.nick] = summary
        return dir_status_summaries

    def summariseNodeDirInfoStatus(
        self,
        dir_status: dict[str, tuple[DirInfoStatusCode, Collection[DirFormat]]],
    ) -> Optional[
        dict[
            DirInfoStatusCode | str,
            tuple[DirInfoStatusCode, Collection[str], Collection[DirFormat]],
        ]
    ]:
        """Summarise the statuses for this node's descriptor, among all the
        directory files used by all other nodes.

        Returns a dict containing a status 4-tuple for each status code.
        The 4-tuple contains:
          * a status code,
          * a list of the other nodes which have directory files with that
            status,
          * a list of directory file formats which have that status, and
          * a status message string.
        See and getFileDirInfoStatus() for more details.

        Also add an "node_all" status that describes the overall status,
        which is the worst status among all the other nodes' directory
        files.

        Returns None if no status is expected.
        """
        node_status: dict[
            DirInfoStatusCode | str,
            tuple[DirInfoStatusCode, Collection[str], Collection[DirFormat]],
        ] = dict()

        # check if we expect this node to be published to other nodes
        status_code_set = {
            status[0]
            for (other_node_nick, status) in dir_status.items()
            if status is not None
        }

        for status_code in status_code_set:
            other_node_nick_list = [
                other_node_nick
                for (other_node_nick, status) in dir_status.items()
                if status is not None and status[0] == status_code
            ]

            comb_status = self.combineDirInfoStatuses(
                values_for_keys(dir_status, other_node_nick_list), best=False
            )

            if comb_status is not None:
                comb_code, comb_format_set = comb_status
                assert (
                    comb_code == status_code
                ), f"combineDirInfoStatuses returned {comb_code} instead of {status_code}"

                node_status[status_code] = (
                    status_code,
                    other_node_nick_list,
                    comb_format_set,
                )

        node_all: Optional[
            tuple[DirInfoStatusCode, Collection[str], Collection[DirFormat]]
        ] = None
        if len(node_status):
            # Finally, get the worst status from all the other nodes
            worst_status_code = min(status_code_set, key=lambda s: s.value)
            node_all = node_status[worst_status_code]
        else:
            # this node should be a client
            # (or a bridge in a network with no bridge authority,
            # and no bridge clients, but chutney doesn't have networks like
            # that)
            consensus_member = self._node._config.consensus_member
            bridge_member = self._node._config.bridge
            if consensus_member or bridge_member:
                raise chutney.errors.ChutneyInternalError(
                    "Expected {}{}{} dir info, but status is empty.".format(
                        "consensus" if consensus_member else "",
                        " and " if consensus_member and bridge_member else "",
                        "bridge" if bridge_member else "",
                    ),
                )
            else:
                # clients don't publish dir info
                node_all = None

        if node_all:
            node_status["node_all"] = node_all
            return node_status
        else:
            # client
            return None

    @override
    def getNodeDirInfoStatus(
        self,
        *,
        launch_phase: int,
    ) -> Optional[tuple[DirInfoStatusCode, Collection[str], Collection[DirFormat]]]:
        dir_status = self.getNodeDirInfoStatusList(launch_phase=launch_phase)
        if dir_status:
            summary = self.summariseNodeDirInfoStatus(dir_status)
            if summary:
                return summary["node_all"]

        # this node must be a client
        # (or a bridge in a network with no bridge authority,
        # and no bridge clients, but chutney doesn't have networks like
        # that)
        assert (
            not self._node._config.consensus_member
        ), f"Unexpected None dirinfo summary for consensus member {self._node.nick}"
        assert (
            not self._node._config.bridge
        ), f"Unexpected None dirinfo summary for bridge {self._node.nick}"
        return None

    def isInExpectedDirInfoDocs(self, *, launch_phase: int) -> Optional[bool]:
        """Return True if the descriptors for this node are in all expected
        directory documents.

        Return None if this node does not publish descriptors.
        """
        node_status = self.getNodeDirInfoStatus(launch_phase=launch_phase)
        if node_status:
            status_code, _, _ = node_status
            return status_code == DirInfoStatusCode.SUCCESS
        else:
            # Clients don't publish descriptors, so they are always ok.
            # (But we shouldn't print a descriptor status for them.)
            return None
