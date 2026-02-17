# [pep 0536](https://peps.python.org/pep-0563/) - Lazy annotation eval via
# stringification.
from __future__ import annotations

import signal

from abc import ABC, abstractmethod
from collections.abc import Collection
from typing import TYPE_CHECKING, Optional

from chutney.dirinfo import (
    DirInfoStatus,
    DirInfoStatusCode,
    DirFormat,
)
from chutney.Util import Option

if TYPE_CHECKING:
    from chutney.TorNet import Node


class NodeController(ABC):
    """Abstract base class.  A NodeController is responsible for running a
    node on the network.
    """

    @abstractmethod
    def isRunning(self) -> bool:
        """Return true iff this node is running."""
        ...

    @abstractmethod
    def start(self) -> None:
        """Try to start this node, if not already running. Raises `ChutneyError` on failure."""
        ...

    @abstractmethod
    def stop(self, sig: int = signal.SIGINT) -> None:
        """Try to stop this node by sending it the signal 'sig'."""
        ...

    @abstractmethod
    def getPtExtra(self) -> Option[str]:
        """Get extra bridge info to use this node as a PT bridge.

        Returns an empty string if there is no such info (e.g. this isn't a PT bridge).
        Returns None if we *expect* there to be such info but couldn't locate it (yet).
        """
        ...

    @abstractmethod
    def hup(self) -> bool:
        """Send a SIGHUP to this node, if it's running."""
        ...

    @abstractmethod
    def cleanupRunFiles(self) -> None:
        """Clean up any left-over run state, assuming the node has exited."""
        ...

    @abstractmethod
    def getUncheckedDirInfoWaitTime(self) -> float:
        """Returns the amount of time to wait before verifying, after the
        network has bootstrapped, and the dir info has been distributed.

        Based on whether this node has unchecked directory info, or other
        known timing issues.
        """
        ...

    @abstractmethod
    def updateLastStatus(self) -> None:
        """Update last messages this node has received, for use with
        isBootstrapped and the getLast* functions.
        """
        ...

    @abstractmethod
    def getLastBootstrapStatus(self) -> DirInfoStatus:
        """Return the last bootstrap message fetched by
        updateLastStatus as a 3-tuple of percentage
        complete, keyword (optional), and message.

        The return status depends on the last time updateLastStatus()
        was called; that function must be called before this one.
        """
        ...

    @abstractmethod
    def isBootstrapped(self) -> bool:
        """Return true iff the logfile says that this instance is
        bootstrapped.

        The return status depends on the last time updateLastStatus()
        was called; that function must be called before this one.
        """
        ...

    @abstractmethod
    def getNodeDirInfoStatus(
        self,
        *,
        launch_phase: int,
    ) -> Optional[tuple[DirInfoStatusCode, Collection[str], Collection[DirFormat]]]:
        """Return a 3-tuple describing the status of this node's descriptor, in
        all the directory documents of nodes with up through `launch_phase`
        across the network.

        If this node does not have a descriptor, returns None.
        """
        ...

    @abstractmethod
    def check_node_in_dirinfo(
        self, dir_fmt: DirFormat, other_node: Node
    ) -> DirInfoStatusCode:
        """Check whether `other_node` is present in the specified directory type"""
        ...
