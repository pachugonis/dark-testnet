#!/usr/bin/env python
#
# Copyright 2011 Nick Mathewson, Michael Stone
# Copyright 2013 The Tor Project
#
#  You may do anything with this work that copyright law would normally
#  restrict, so long as you retain the above notice(s) and this license
#  in all redistributed copies and derived works.  There is no warranty.

# [pep 0536](https://peps.python.org/pep-0563/) - Lazy annotation eval via
# stringification.
from __future__ import annotations

# Future imports for Python 2.7, mandatory in 3.0
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from abc import ABC, abstractmethod
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import List, Optional, Any, Iterable, Union
from typing_extensions import assert_never, override

import copy
import dataclasses
import errno
import importlib
import importlib.resources
import logging
import os
import platform
import re
import signal
import sys
import textwrap
import time
import tomli_w
import json

from chutney.known_bins import TorBin, TorGenCertBin, ArtiBin
from chutney.dirinfo import DirInfoStatus, DirInfoStatusCode, DirFormat
from chutney.errors import (
    ChutneyError,
    ChutneyErrorGroup,
    ChutneyTimeoutError,
)
from chutney.jsonable import ToCustomJsonable, FromDecodedJson, CustomJsonable
from chutney.launcher import Launcher, LocalLauncher, SshLauncher
from chutney.Util import (
    getenv_int,
    getenv_bool,
    mkdir_p,
    Option,
    OptionalConversionDescriptor,
)
from chutney.network_tests import NetworkTestFailure
from collections.abc import Collection

if sys.version_info >= (3, 11):
    # Added in Python 3.11
    from importlib.resources.abc import Traversable
else:
    # Deprecated since Python 3.12
    from importlib.abc import Traversable
from typeguard import check_type

import chutney.arti.config
import chutney.tor.torrc
import chutney.tor.util
import chutney.Host
import chutney.Util

logger = logging.getLogger(__name__ if __name__ != "__main__" else "chutney")

V3_AUTH_VOTING_INTERVAL = 20.0

_TOR_VERSIONS = None
_TORRC_OPTIONS = None


HSV2_KEYWORD = "hidden service v2"
HSV3_KEYWORD = "hidden service v3"


class LauncherBackend(FromDecodedJson, Enum):
    """Specifies class for launching processes for target node"""

    # Launch processes locally, e.g. using the subprocess module.
    LOCAL = 1
    # Connect to the (potentially remote) node via ssh and use that to run
    # processes.
    SSH = 2

    @override
    @classmethod
    def from_decoded_json(cls, o: object) -> LauncherBackend:
        return LauncherBackend[check_type(o, str)]


class NodeBackend(FromDecodedJson, Enum):
    """Specifies the backend used to run a node"""

    # c-tor (running locally)
    TOR = 1
    # arti (running locally)
    ARTI = 2

    @override
    @classmethod
    def from_decoded_json(cls, o: object) -> NodeBackend:
        return NodeBackend[check_type(o, str)]


class AddressAssignmentStrategy(FromDecodedJson, Enum):
    """How to assign addresses"""

    # Use exactly the addresses `ip` and `ipv6_addr`.
    # This is the legacy behavior.
    STATIC = 1
    # Use `ip` and `ipv6_addr` as base addresses, and add the node number.
    # This is primarily for future support of running nodes on different
    # (virtual, shadow) hosts, in different network namespaces, etc.
    OFFSET = 2

    @override
    @classmethod
    def from_decoded_json(cls, o: object) -> AddressAssignmentStrategy:
        return AddressAssignmentStrategy[check_type(o, str)]


def get_absolute_chutney_path() -> Path:
    """
    Returns the absolute path of the directory containing the chutney
    executable script.
    """
    # use the current directory as the default
    # (./chutney already sets CHUTNEY_PATH using the path to the script)
    # use tools/test-network.sh if you want chutney to try really hard to find
    # itself
    relative_chutney_path = Path(os.environ.get("CHUTNEY_PATH", os.getcwd()))
    return relative_chutney_path.resolve()


def get_absolute_net_path() -> Path:
    """
    Returns the absolute path of the "net" directory that chutney should
    use to store "node*" directories containing torrcs and tor runtime data.

    If the CHUTNEY_DATA_DIR environmental variable is an absolute path, it
    is returned unmodified, regardless of whether the path actually exists.
    (Chutney creates any directories that do not exist.)

    Otherwise, if it is a relative path, and there is an existing directory
    with that name in the directory containing the chutney executable
    script, return that path (this check exists for legacy reasons).

    Finally, return the path relative to the current working directory,
    regardless of whether the path actually exists.
    """
    data_dir = Path(os.environ.get("CHUTNEY_DATA_DIR", "net"))
    if data_dir.is_absolute():
        # if we are given an absolute path, we should use it
        # regardless of whether the directory exists
        return data_dir
    # use the chutney path as the default
    absolute_chutney_path = get_absolute_chutney_path()
    relative_net_path = Path(data_dir)
    # but what is it relative to?
    # let's check if there's an existing directory with this name in
    # CHUTNEY_PATH first, to preserve backwards-compatible behaviour
    chutney_net_path = Path(absolute_chutney_path, relative_net_path)
    if chutney_net_path.is_dir():
        return chutney_net_path
    # ok, it's relative to the current directory, whatever that is, and whether
    # or not the path actually exists
    return relative_net_path.resolve()


def get_absolute_nodes_path() -> Path:
    """
    Returns the absolute path of the "nodes" symlink that points to the
    "nodes*" directory that chutney should use to store the current
    network's torrcs and tor runtime data.

    This path is also used as a prefix for the unique nodes directory
    names.

    See get_new_absolute_nodes_path() for more details.
    """
    return Path(get_absolute_net_path(), "nodes")


def get_new_absolute_nodes_path(now: float = time.time()) -> Path:
    """
    Returns the absolute path of a unique "nodes*" directory that chutney
    should use to store the current network's torrcs and tor runtime data.

    The nodes directory suffix is based on the current timestamp,
    incremented if necessary to avoid collisions with existing directories.

    (The existing directory check contains known race conditions: running
    multiple simultaneous chutney instances on the same "net" directory is
    not supported. The uniqueness check is only designed to avoid
    collisions if the clock is set backwards.)
    """
    # automatically chosen to prevent path collisions, and result in an ordered
    # series of directory path names
    # should only be called by 'chutney configure', all other chutney commands
    # should use get_absolute_nodes_path()
    nodesdir = get_absolute_nodes_path()
    newdir = newdirbase = Path("%s.%d" % (nodesdir, now))
    # if the time is the same, fall back to a simple integer count
    # (this is very unlikely to happen unless the clock changes: it's not
    # possible to run multiple chutney networks at the same time)
    i = 0
    while newdir.exists():
        i += 1
        newdir = Path("%s.%d" % (newdirbase, i))
    return newdir


def get_familykey_path(ident: Optional[str], ext: bool = True) -> Path:
    """
    Return the absolute path for the secret family key identified with `ident`.

    If no ident is given, return the directory in which we store family keys.

    If `ext` is false, omit the "secret_family_key" exension.
    """
    family_key_dir = get_absolute_nodes_path().joinpath("family_keys")
    if ident is None:
        return family_key_dir
    if ext:
        fn = f"{ident}.secret_family_key"
    else:
        fn = ident
    return family_key_dir.joinpath(fn)


class Node(ToCustomJsonable):
    """A Node represents a Tor node or a set of Tor nodes.  It's created
    in a network configuration file.

    This class is responsible for holding the user's selected node
    configuration, and figuring out how the node needs to be
    configured and launched.
    """

    def __init__(self, network: Network, config: NodeConfig, nodenum: int):
        """Create a new Node.

        This should generally only be called by Network, to create a node as
        it's being added.
        """
        # chutney's internal node number for the node
        self.nodenum: int = nodenum

        # Validate some fields. NodeConfig permits these to be None
        # for use with templating; e.g. NodeConfig.specialize.
        self.tag: str = Option(config.tag).unwrap(
            lambda: f"Config is missing 'tag': {config}"
        )

        self._network = network
        self._config = config

        self._launcher: Launcher
        if config.launcher_backend == LauncherBackend.LOCAL:
            self._launcher = LocalLauncher()
        elif config.launcher_backend == LauncherBackend.SSH:
            host = self._config.ip.as_optional() or self._config.ipv6_addr.as_optional()
            assert host, f"No ip address for {self.nick}"
            self._launcher = SshLauncher(host)
        else:
            assert_never(config.launcher_backend)
        self._builder: NodeBuilder
        self._controller: NodeController
        if config.backend == NodeBackend.TOR:
            # We import these here instead of globally to avoid a circular reference.
            from chutney.tor.builder import LocalNodeBuilder
            from chutney.tor.controller import LocalNodeController

            self._builder = LocalNodeBuilder(self)
            self._controller = LocalNodeController(self._network, self)
        elif config.backend == NodeBackend.ARTI:
            import chutney.arti.builder
            import chutney.arti.controller

            self._builder = chutney.arti.builder.LocalArtiNodeBuilder(self)
            self._controller = chutney.arti.controller.LocalArtiNodeController(
                self._network, self
            )
        else:
            assert_never(config.backend)

    @property
    def fingerprint(self) -> Option[str]:
        """The base64-encoded ed25519 public key of this node."""
        return self._builder.get_fingerprint()

    @property
    def fingerprint_ed25519(self) -> Option[str]:
        """The base64-encoded ed25519 public key fingerprint of this node."""
        return self._builder.get_fingerprint_ed25519()

    @property
    def ip(self) -> Option[IPv4Address]:
        if self._config.ip.is_none():
            return Option(None)
        base = IPv4Address(self._config.ip.unwrap())
        strategy = self._config.address_assignment_strategy
        if strategy == AddressAssignmentStrategy.STATIC:
            return Option(base)
        elif strategy == AddressAssignmentStrategy.OFFSET:
            return Option(IPv4Address(int(base) + self.nodenum))
        else:
            assert_never(strategy)

    @property
    def ipv6_addr(self) -> Option[IPv6Address]:
        if self._config.ipv6_addr.is_none():
            return Option(None)
        base_str = self._config.ipv6_addr.unwrap()
        # The IPv6Address constructor doesn't recognize addresses enclosed in
        # brackets (e.g. `[::1]`), and indeed they aren't really part of the
        # address. We used to expect them though, so for now strip them out for
        # backwards compatibility.
        if base_str.startswith("[") and base_str.endswith("]"):
            base_str = base_str[1:-1]
        base = IPv6Address(base_str)
        strategy = self._config.address_assignment_strategy
        if strategy == AddressAssignmentStrategy.STATIC:
            return Option(base)
        elif strategy == AddressAssignmentStrategy.OFFSET:
            return Option(IPv6Address(int(base) + self.nodenum))
        else:
            raise ChutneyError(f"Unrecognized AddressAssignmentStrategy {strategy}")

    @property
    def orport(self) -> int:
        """OrPort that this node exposes"""
        return self._network.orport_base + self.nodenum

    @property
    def controlport(self) -> int:
        """ControlPort that this node exposes"""
        return self._network.controlport_base + self.nodenum

    @property
    def socksport(self) -> Option[int]:
        """SocksPort that this node exposes, if any."""
        if self._config.client:
            return Option(self._network.socksport_base + self.nodenum)
        else:
            return Option(None)

    @property
    def dnsport(self) -> Option[int]:
        """DnsPort that this node exposes, if any."""
        if self._config.enable_dnsport:
            return Option(self._network.dnsport_base + self.nodenum)
        else:
            return Option(None)

    @property
    def dirport(self) -> Option[int]:
        """DirPort that this node exposes"""
        if self._config.relay and not self._config.bridge:
            return Option(self._network.dirport_base + self.nodenum)
        else:
            return Option(None)

    @property
    def extorport(self) -> int:
        """Extended ORPort that this node exposes"""
        return self._network.extorport_base + self.nodenum

    @property
    def ptport(self) -> int:
        """Port to listen on as a pluggble transport bridge (ServerTransportListenAddr)"""
        return self._network.ptport_base + self.nodenum

    @property
    def hs_virtport(self) -> Option[int]:
        """Virtual hidden service port that this node exposes, if any."""
        if self._config.hs:
            # We can use the same port for multiple nodes, or hypothetically
            # even multiple hidden services on the same node. We would only need
            # to use multiple ports if we wanted to expose multiple ports on the
            # same onion address.
            return Option(5858)
        else:
            return Option(None)

    @property
    def hs_targetport(self) -> Option[int]:
        """Target port of this node's hidden service, if any."""
        if self._config.hs:
            # Currently all hidden services redirect to the same port,
            # for compatibility with the test in `network_tests/verify.py`
            import chutney.network_tests.verify

            return Option(chutney.network_tests.verify.LISTEN_PORT)
        else:
            return Option(None)

    @property
    def dir(self) -> Path:
        """Directory where this node stores its configuration and data (DataDirectory)"""
        return Path(
            self._network.dir,
            "%03d%s" % (self.nodenum, self._config.tag),
        ).resolve()

    @property
    def torrc_path(self) -> Path:
        return self.dir.joinpath("torrc")

    @property
    def controlsocket(self) -> Optional[Path]:
        """ControlSocket that this node exposes"""
        if self._config.enable_controlsocket:
            return self.dir.joinpath("control")
        else:
            return None

    @property
    def nick(self) -> str:
        """Nickname for this node on the network (debugging only)"""
        return "test%03d%s" % (self.nodenum, self._config.tag)

    @property
    def auth_passphrase(self) -> str:
        """Obsoleted by CookieAuthentication"""
        # TODO: remove?
        return self.nick  # OMG TEH SECURE!

    @property
    def lockfile(self) -> Path:
        """Path to this node's lockfile"""
        return Path(self.dir, "lock")

    @property
    def pidfile(self) -> Path:
        """Path to this node's PidFile"""
        return Path(self.dir, "pid")

    @property
    def is_client(self) -> bool:
        """Whether this node is configured as a client"""
        return self._config.client

    @property
    def is_hs(self) -> bool:
        """Is this node an onion service?"""
        return self._config.hs

    @property
    def hs_hostname(self) -> Option[str]:
        """Generated hostname for this hidden service.

        Should be available (non-None) if the node is configured as a hidden
        service (`Node.is_hs`), after the Node's builder's `preConfig` has been
        called (which the chutney `Network` does as part of this node's
        `config_phase`).
        """
        return self._builder.get_hs_hostname()

    ######
    # Chutney uses these:

    def expected_in_dir_formats(self, other_node: Node) -> Collection[DirFormat]:
        """Returns the set of `other_node`'s dir formats in which *this* node is
        expected to appear"""
        if self._config.consensus_member:
            return {
                DirFormat.DESC,
                DirFormat.DESC_NEW,
                DirFormat.NS_CONS,
                DirFormat.MD_CONS,
                DirFormat.MD,
                DirFormat.MD_NEW,
            }
        if self._config.bridge:
            if other_node._config.bridgeclient or other_node._config.bridgeauthority:
                formats = {DirFormat.DESC, DirFormat.DESC_NEW}
                if other_node._config.bridgeauthority:
                    formats.add(DirFormat.BR_STATUS)
                return formats
        return {}

    @override
    def to_custom_jsonable(self) -> CustomJsonable:
        """Return a dict describing this object using primitive types.

        Values are of types accepted by the json module's encoder."""
        # Careful when modifying - this is ultimately used to produce "public"
        # json output that is consumed by other tools.
        return dict(
            nick=self.nick,
            ip=self.ip.map(str).as_optional(),
            ipv6_addr=self.ipv6_addr.map(str).as_optional(),
            auth_passphrase=self.auth_passphrase,
            dir=str(self.dir.absolute()),
            fingerprint=self.fingerprint.as_optional(),
            fingerprint_ed25519=self.fingerprint_ed25519.as_optional(),
            orport=self.orport,
            controlport=self.controlport,
            socksport=self.socksport.as_optional(),
            dnsport=self.dnsport.as_optional(),
            dirport=self.dirport.as_optional(),
            extorport=self.extorport,
            ptport=self.ptport,
            torrc_path=str(self.torrc_path),
            controlsocket=str(self.controlsocket) if self.controlsocket else None,
            tag=self._config.tag,
            backend=self._config.backend.name,
            is_client=self.is_client,
            is_hs=self.is_hs,
            hs_virtport=self.hs_virtport.as_optional(),
            hs_targetport=self.hs_targetport.as_optional(),
            hs_hostname=self.hs_hostname.as_optional(),
            _config=self._config,
        )


class NodeBuilder(ABC):
    """Abstract base class.  A NodeBuilder is responsible for doing all the
    one-time prep needed to set up a node in a network.
    """

    @abstractmethod
    def checkConfig(self, net: Network) -> None:
        """Try to format our torrc; raise an exception if we can't."""
        ...

    @abstractmethod
    def preConfig(self, net: Network) -> None:
        """Called on all nodes of the current config phase before any nodes configure.

        Intended to generate configuration that doesn't depend on other nodes,
        particularly anything that *will* be needed in the configuration step of
        other nodes, such as public keys.
        """
        ...

    @abstractmethod
    def get_fingerprint(self) -> Option[str]:
        """Return the relay fingerprint, if applicable."""
        ...

    @abstractmethod
    def get_fingerprint_ed25519(self) -> Option[str]:
        """The base64-encoded ed25519 public key fingerprint of this node, if applicable."""
        ...

    @abstractmethod
    def config(self, net: Network) -> None:
        """Called to configure a node: creates a torrc file for it."""
        ...

    @abstractmethod
    def postConfig(self, net: Network) -> None:
        """Called on each nodes after all nodes configure."""
        ...

    @abstractmethod
    def isSupported(self, net: Network) -> bool:
        """Return true if this node appears to have everything it needs;
        false otherwise."""
        ...

    @abstractmethod
    def getAltAuthLines(self, hasbridgeauth: bool = False) -> Optional[AuthorityLine]:
        """Return the information needed to use this node as an authority,
        if it is configured as one.
        """
        ...

    @abstractmethod
    def getBridgeLines(self) -> list[BridgeLine]:
        """Return descriptors that a client can use to connect to this bridge.
        Non-bridge relays return [].
        """
        ...

    @abstractmethod
    def get_hs_hostname(self) -> Option[str]:
        """Return the hidden service hostname, if any.

        Should be available (non-None) if the node is configured as a hidden
        service (`Node.is_hs`), after `preConfig` has been called.
        """
        ...

    @abstractmethod
    def get_hs_client_pubkey(self, hs_address: str) -> str:
        """Get the hidden service "restricted discovery" key for the `hs_address`

        Generates the key, if it doesn't already exist. The returned string
        is of the form `descriptor:x25519:<base32-encoded-public-key>`.
        """
        ...

    @abstractmethod
    def set_hs_client_pubkey(self, client_id: str, client_pubkey: str) -> None:
        """Set the hidden service "restricted discovery" pubkey for `client_id`

        `client_pubkey` should be of the form
        `descriptor:x25519:<base32-encoded-public-key>`.
        """
        ...


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
    ) -> Optional[tuple[DirInfoStatusCode, Collection[str], Collection[DirFormat]]]:
        """Return a 3-tuple describing the status of this node's descriptor,
        in all the directory documents across the network.

        If this node does not have a descriptor, returns None.
        """
        ...

    @abstractmethod
    def check_node_in_dirinfo(
        self, dir_fmt: DirFormat, other_node: Node
    ) -> DirInfoStatusCode:
        """Check whether `other_node` is present in the specified directory type"""
        ...


# TODO: Consider getting rid of these globals, particularly since they're not
# contants; e.g. we change them at runtime in `Network.bootstrap`.
CUR_CONFIG_PHASE: int = getenv_int("CHUTNEY_CONFIG_PHASE", 1)
CUR_LAUNCH_PHASE: int = getenv_int("CHUTNEY_LAUNCH_PHASE", 1)


@dataclasses.dataclass
class NodeConfig(ToCustomJsonable, FromDecodedJson):
    """Properties of a Tor Node"""

    # Which backend to use to run the node.
    backend: NodeBackend = NodeBackend.TOR
    # Which process-launcher to use.
    launcher_backend: LauncherBackend = LauncherBackend.LOCAL
    # a short text string that represents the type of node.
    # Some special tag prefixes:
    # * 'h' configures it to run an onion service.
    # * 'c' and 'bc' cause the `verify` test to recognize it as a client.
    #   (as does setting the `client` attribute).
    # TODO: Get rid of these special tag meanings in favor of explicit attributes.
    tag: Optional[str] = None
    # Whether to configure this node to use a bridge.
    bridgeclient: bool = False
    # Whether to configure this node to act as a client.
    client: bool = False
    # Whether to configure this node to act as an exit.
    exit: bool = False

    # Whether to configure this node to act as an authority (or bridge authority).
    authority: bool = False
    # Whether to configure this node as a bridge authority
    bridgeauthority: bool = False
    # Whether to configure this node as a relay; including as an exit, or bridge
    relay: bool = False
    # Whether to configure this node as a bridge.
    bridge: bool = False
    # Whether to configure this node as a pluggable transport bridge.
    pt_bridge: bool = False
    # Name of pluggable transport to use for a bridge or bridge client.
    pt_transport: str = ""
    # Executable that implements the pluggable transport.
    pt_executable: Path = Path("obfs4proxy")
    # Whether to configure this node as a hidden service
    hs: bool = False
    # directory (relative to datadir) to store hidden service info
    hs_directory: str = "hidden_service"
    # if creating a hidden service, whether to configure it as single-hop.
    hs_singlehop: bool = False
    # if creating a hidden service, whether to enable restricted discovery.
    hs_restricted_discovery: bool = False
    # generate restricted-discovery client keys and register them with
    # hidden services having these tags.
    hs_client_restricted_discovery_server_tags: set[str] = dataclasses.field(
        default_factory=set
    )
    # subdirectory of data dir in which to store restricted discovery
    # client keys. aka ClientOnionAuthDir in torrc.
    # Unused in arti, which stores these keys opaquely.
    client_onion_auth_dir: Path = Path("client-onion-auth-dir")
    # value of ConnLimit torrc option
    connlimit: int = 60
    # path of the tor binary (for backend = NodeBackend.TOR)
    tor: str = os.environ.get(TorBin().config_envvar(), "tor")
    # path of the arti binary (for backend = NodeBackend.ARTI)
    arti: str = os.environ.get(ArtiBin().config_envvar(), "arti")
    # lifetime of authority certs, in months
    auth_cert_lifetime: int = 12
    # strategy for deriving concrete network addresses from the configuration
    # `ip` and `ipv6_addr`
    address_assignment_strategy: AddressAssignmentStrategy = (
        AddressAssignmentStrategy.STATIC
    )
    # primary IP address (usually IPv4) to listen on.
    # Setting to None disables ipv4.
    ip: OptionalConversionDescriptor[str] = OptionalConversionDescriptor(
        default=Option(os.environ.get("CHUTNEY_LISTEN_ADDRESS", "127.0.0.1"))
    )
    # secondary IP address (usually IPv6) to listen on. we default to
    # ipv6_addr=None to support IPv4-only systems.
    # We use OptionalConversionDescriptor here to get `Option[str]`'s
    # enforcement for our internal usage, but allow callers to initialize and
    # assign as if it were `Optional[str]`.
    ipv6_addr: OptionalConversionDescriptor[str] = OptionalConversionDescriptor(
        default=Option(os.environ.get("CHUTNEY_LISTEN_ADDRESS_V6", None))
    )
    # Whether to disable all ipv6 functionality
    disableipv6: bool = getenv_bool("CHUTNEY_DISABLE_IPV6", False)
    # Directory server flags. Used only if authority=True
    dirserver_flags: str = "no-v2"
    # None means wait on launch (requires RunAsDaemon),
    # otherwise, poll after that many seconds (can be fractional/decimal)
    poll_launch_time: Optional[float] = None
    # Used when poll_launch_time is None, but
    # RunAsDaemon is not set Set low so that we don't interfere with the
    # voting interval
    poll_launch_time_default: float = 0.1
    # The PID of the controlling script
    # (for __OwningControllerProcess)
    controlling_pid: int = getenv_int("CHUTNEY_CONTROLLING_PID", 0)
    # The path to a DNS config file for Tor Exits. If this file
    # is empty or unreadable, Tor will try 127.0.0.1:53.
    dns_conf: Optional[str] = (
        os.environ.get("CHUTNEY_DNS_CONF", "/etc/resolv.conf")
        if "CHUTNEY_DNS_CONF" in os.environ
        else None
    )
    # The phase at which this instance needs to be configured.
    config_phase: int = 1
    # The phase at which this instance needs to be launched.
    launch_phase: int = 1
    # The Sandbox torrc option value.
    # defaults to 1 on Linux, and 0 otherwise
    # Chutney users can disable the sandbox using:
    #    export CHUTNEY_TOR_SANDBOX=0
    # if it doesn't work on their version of glibc.
    sandbox: bool = getenv_bool("CHUTNEY_TOR_SANDBOX", platform.system() == "Linux")
    # Whether to enable a unix control socket (via ControlSocket in torrc)
    enable_controlsocket: bool = getenv_bool("CHUTNEY_ENABLE_CONTROLSOCKET", True)
    # Whether to use microdescriptors (via UseMicrodescriptors in torrc).
    use_microdescriptors: bool = True

    # A list of identifiers for the families that this node belongs to.
    # These identifiers are strings, and must be valid filename components.
    # Two relays are in the same family if they have any identifier in common.
    families: list[str] = dataclasses.field(default_factory=list)

    # Whether to open a port for DNS requests. (e.g. DnsPort directive for tor)
    enable_dnsport: bool = False

    # "Escape hatch" for injecting raw lines at the end of the generated torrc.
    # Generally this should only be used as a short-term workaround. For
    # long-term usage, prefer to add more-specific (and arti-compatible)
    # configuration options.
    extra_raw_torrc: str = ""

    @property
    def tor_gencert(self) -> str:
        """name or path of the tor-gencert binary (if present)"""
        return os.getenv(TorGenCertBin().config_envvar(), self.tor + "-gencert")

    # XXX Move template logic into template
    @property
    def owning_controller_process(self) -> str:
        """The __OwningControllerProcess torrc line,
        disabled if tor should continue after the script exits"""
        cpid = self.controlling_pid
        ocp_line = "__OwningControllerProcess %d" % (cpid)
        # if we want to leave the network running, or controlling_pid is 1
        # (or invalid)
        if (
            getenv_int("CHUTNEY_START_TIME", 0) < 0
            or getenv_int("CHUTNEY_BOOTSTRAP_TIME", 0) < 0
            or getenv_int("CHUTNEY_STOP_TIME", 0) < 0
            or cpid <= 1
        ):
            return "#" + ocp_line
        else:
            return ocp_line

    # the default resolv.conf path is set at compile time
    # there's no easy way to get it out of tor, so we use the typical value
    DEFAULT_DNS_RESOLV_CONF = Path("/etc/resolv.conf")
    # if we can't find the specified file, use this one as a substitute
    OFFLINE_DNS_RESOLV_CONF = Path("/dev/null")

    # XXX Move template logic into template
    @property
    def server_dns_resolv_conf(self) -> str:
        """the ServerDNSResolvConfFile torrc line,
        disabled if tor should use the default DNS conf.
        If the dns_conf file is missing, this option is also disabled:
        otherwise, exits would not work due to tor bug #21900."""
        my_dns_conf = self.dns_conf
        # To be set below
        dns_conf: Path

        if my_dns_conf == "":
            # if the user asked for tor's default
            return "#ServerDNSResolvConfFile using tor's compile-time default"
        elif my_dns_conf is None:
            # if there is no DNS conf file set
            logger.debug(
                "CHUTNEY_DNS_CONF not specified, using '{}'.".format(
                    NodeConfig.DEFAULT_DNS_RESOLV_CONF
                )
            )
            dns_conf = NodeConfig.DEFAULT_DNS_RESOLV_CONF
        else:
            dns_conf = Path(my_dns_conf)
        dns_conf = dns_conf.resolve()
        # work around Tor bug #21900, where exits fail when the DNS conf
        # file does not exist, or is a broken symlink
        # (Path.exists returns False for broken symbolic links)
        if not dns_conf.exists():
            # Issue a warning so the user notices
            logger.warning(
                "CHUTNEY_DNS_CONF '{}' does not exist, using '{}'.".format(
                    dns_conf, NodeConfig.OFFLINE_DNS_RESOLV_CONF
                )
            )
            dns_conf = NodeConfig.OFFLINE_DNS_RESOLV_CONF
        return "ServerDNSResolvConfFile %s" % (dns_conf)

    @property
    def consensus_authority(self) -> bool:
        """Is this node a consensus (V2 directory) authority?"""
        return self.authority and not self.bridgeauthority

    @property
    def consensus_member(self) -> bool:
        """Is this node listed in the consensus?"""
        return self.relay and not self.bridge

    @property
    def consensus_relay(self) -> bool:
        """Is this node published in the consensus?
        True for authorities and relays; False for bridges and clients.
        """
        return self.relay and not self.bridge

    def getN(self, N: int) -> list[NodeConfig]:
        """Generate 'N' duplicates of self"""
        return [copy.copy(self) for _ in range(N)]

    def specialize(self, **kwargs: Any) -> NodeConfig:
        """Return a new Node based on this node's value as its defaults,
        but with the values from 'kwargs' (if any) overriding them.

        DEPRECATED: use dataclasses.replace instead, which mypy knows how to type-check.
        """
        # mypy has a plugin to understand and properly type-check
        # dataclasses and dataclasses.replace:
        # <https://github.com/python/mypy/blob/bcd4ff231554102a6698615882074e440ebfc3c9/mypy/plugins/dataclasses.py#L202>.
        #
        # Conversely, I don't see a way to allow mypy to properly check *this*
        # function without either:
        # * spelling out the full argument list and types above, which would duplicate
        #   the class's field definitions and be a maintenance headache.
        # * creating our own mypy plugin.
        return dataclasses.replace(self, **kwargs)

    @override
    def to_custom_jsonable(self) -> CustomJsonable:
        return dataclasses.asdict(self)

    @override
    @classmethod
    def from_decoded_json(cls, obj: object) -> NodeConfig:
        d = check_type(obj, dict)
        d["backend"] = NodeBackend.from_decoded_json(d["backend"])
        d["launcher_backend"] = LauncherBackend.from_decoded_json(d["launcher_backend"])
        d["address_assignment_strategy"] = AddressAssignmentStrategy.from_decoded_json(
            d["address_assignment_strategy"]
        )
        return NodeConfig(**d)


@dataclasses.dataclass
class BridgeLine:
    ipaddr: Union[IPv4Address, IPv6Address]
    port: int
    fingerprint: str
    pt_transport: Option[str] = Option(None)
    pt_extra: Option[str] = Option(None)


@dataclasses.dataclass
class AuthorityLine:
    nick: str
    ipv4: IPv4Address
    ipv6: Option[IPv6Address]
    orport: int
    dirport: int
    v3id: str
    fingerprint: str
    fingerprint_ed25519: str
    extra_flags: list[str]
    alt_bridge_auth: bool = False
    alt_dir_auth: bool = False


KNOWN_REQUIREMENTS = {"IPV6": chutney.Host.is_ipv6_supported}


class Network(ToCustomJsonable, FromDecodedJson):
    """A network of Tor nodes, plus functions to manipulate them"""

    def __init__(self) -> None:
        self._nodes: list[Node] = []
        # Keys into `KNOWN_REQUIREMENTS`
        self._requirements: list[str] = []
        self._nextnodenum = 0
        # Use the "nodes" symlink by default. This is overwritten by
        # `create_new_nodes_dir` when we configure a new network.
        self.dir: Path = get_absolute_nodes_path()

        # Whether a bridge authority has been added.
        self.hasbridgeauth = False
        # authorities: combination of AlternateDirAuthority and
        # AlternateBridgeAuthority torrc lines. there is no default for this option
        self.authorities: list[AuthorityLine] = []
        # bridges: potential Bridge descriptors in this network.
        self.bridges: list[BridgeLine] = []
        # Map from family name to FamilyId hash
        self.family_ids: dict[str, str] = dict()
        # Map from family name to members of that family
        self.family_members: dict[str, list[Node]] = dict()

        # bootstrap_time: How long in seconds we should verify (and similar
        # commands) wait for a successful outcome. We check BOOTSTRAP_TIME for
        # compatibility with old versions of test-network.sh
        self.bootstrap_time: int = getenv_int(
            "CHUTNEY_BOOTSTRAP_TIME", getenv_int("BOOTSTRAP_TIME", 60)
        )

        # orport_base, dirport_base, controlport_base, socksport_base,
        # extorport_base, ptport_base: the initial port numbers used by nodenum 0.
        # Each additional node adds 1 to the port numbers.
        self.orport_base: int = 5100
        self.dirport_base: int = 7100
        self.controlport_base: int = 8000
        self.socksport_base: int = 9000
        self.extorport_base: int = 9500
        self.ptport_base: int = 9900
        self.dnsport_base: int = 10000

    @property
    def nodes(self) -> Iterable[Node]:
        """The nodes in this network"""
        return self._nodes

    @staticmethod
    def from_network_script_contents(network_script_contents: str) -> Network:
        """Create a Network object using the contents of a chutney network script.

        For examples of network scripts, see`chutney/data/networks`.
        """

        # Wrappers used from network scripts (`data`) that manipulate
        # an implicit network (`_THE_NETWORK`).
        _THE_NETWORK = Network()

        def Require(feature: str) -> None:
            _THE_NETWORK._addRequirement(feature)

        def ConfigureNodes(nodelist: list[NodeConfig]) -> None:
            for n in nodelist:
                _THE_NETWORK.addNode(n)

        def NodeWrapper(
            parent: Optional[NodeConfig] = None, **kwargs: Any
        ) -> NodeConfig:
            if parent is None:
                return NodeConfig(**kwargs)
            else:
                return parent.specialize(**kwargs)

        _GLOBALS = dict(
            # Note that in the network scripts "Node" is actually a factory function
            # for creating NodeConfig.
            # TODO: Some way to make this less confusing? Maybe we can update built-in
            # networks, and only use this path for "external" network configs if we want
            # to continue supporting them.
            Node=NodeWrapper,
            NodeBackend=NodeBackend,
            Require=Require,
            ConfigureNodes=ConfigureNodes,
            torrc_option_warn_count=0,
            TORRC_OPTION_WARN_LIMIT=10,
        )
        exec(network_script_contents, _GLOBALS)
        return _THE_NETWORK

    @staticmethod
    def _get_network_script_contents(network_cfg_name: str) -> str:
        # First look for built-in network with matching `name`
        try:
            return _NETWORKS.joinpath(network_cfg_name).read_text()
        except FileNotFoundError:
            # We'll try it as a path, below.
            pass
        try:
            with open(network_cfg_name) as f:
                return f.read()
        except OSError as e:
            raise ChutneyError(
                f"'{network_cfg_name}' matches neither a built-in network name nor a readable file"
            ) from e

    @staticmethod
    def from_network_script_name(network_cfg_name: str) -> Network:
        """Create a Network object using the contents of a chutney network script name.

        This can be either the name of a built-in network, such as "basic-min",
        or path to a file containing a network script. Built in networks are
        located in `chutney/data/networks`, and can be listed via the
        `getNetworks` function, or with `chutney --help` at the command-line.
        """
        network_script_contents = Network._get_network_script_contents(network_cfg_name)
        return Network.from_network_script_contents(network_script_contents)

    def addNode(self, config: NodeConfig) -> Node:
        """Create a node with the given config, add it to the network, and return it."""
        node = Node(self, config, self._nextnodenum)
        self._nextnodenum += 1
        self._nodes.append(node)
        if node._config.bridgeauthority:
            self.hasbridgeauth = True
        for family_name in node._config.families:
            self.family_members.setdefault(family_name, []).append(node)

        return node

    def addNodes(self, configs: List[NodeConfig]) -> List[Node]:
        """Add `nodes` to the network. `nodes` must have been created with this `Network`."""
        return [self.addNode(c) for c in configs]

    def _addRequirement(self, requirement: str) -> None:
        requirement = requirement.upper()
        if requirement not in KNOWN_REQUIREMENTS:
            raise RuntimeError(("Unrecognized requirement %r" % requirement))
        self._requirements.append(requirement)

    def move_aside_nodes_dir(self) -> None:
        """Move aside the nodes directory, if it exists and is not a link.
        Used for backwards-compatibility only: nodes is created as a link to
        a new directory with a unique name in the current implementation.
        """
        nodesdir = get_absolute_nodes_path()

        # only move the directory if it exists
        if not nodesdir.exists():
            return
        # and if it's not a link
        if nodesdir.is_symlink():
            return

        # subtract 1 second to avoid collisions and get the correct ordering
        newdir = get_new_absolute_nodes_path(time.time() - 1)

        logger.info("renaming '%s' to '%s'" % (nodesdir, newdir))
        nodesdir.rename(newdir)

    def create_new_nodes_dir(self) -> None:
        """Create a new directory with a unique name, and symlink it to nodes"""
        # for backwards compatibility, move aside the old nodes directory
        # (if it's not a link)
        self.move_aside_nodes_dir()

        # the unique directory we'll create
        newnodesdir = get_new_absolute_nodes_path()
        # the canonical name we'll link it to
        nodeslink = get_absolute_nodes_path()

        # this path should be unique and should not exist
        if newnodesdir.exists():
            raise RuntimeError(
                "get_new_absolute_nodes_path returned a path that exists"
            )

        # if this path exists, it must be a link
        if nodeslink.exists() and not nodeslink.is_symlink():
            raise RuntimeError(
                "get_absolute_nodes_path returned a path that exists and "
                "is not a link"
            )

        # create the new, uniquely named directory, and link it to nodes
        logger.info("creating '%s', linking to '%s'" % (newnodesdir, nodeslink))
        # this gets created with mode 0700, that's probably ok
        mkdir_p(newnodesdir)
        try:
            nodeslink.unlink()
        except OSError as e:
            # it's ok if the link doesn't exist, we're just about to make it
            if e.errno == errno.ENOENT:
                pass
            else:
                raise
        nodeslink.symlink_to(newnodesdir)
        self.dir = newnodesdir

    def create_family_keys(self) -> None:
        """Initialize family keys as needed for all of our nodes."""

        mkdir_p(get_familykey_path(None))
        all_family_ids = set()
        for n in self._nodes:
            if n._config.families:
                all_family_ids.update(n._config.families)
        for fid in all_family_ids:
            cmdline = [
                os.environ.get(TorBin().config_envvar(), "tor"),
                "--keygen-family",
                str(get_familykey_path(fid, ext=False)),
            ]
            launcher = chutney.launcher.LocalLauncher()
            output = chutney.tor.util.run_tor(launcher, cmdline, tolerate_error=True)
            if "Unknown option 'keygen-family'" in output:
                print("No support for --keygen-family; using legacy families only.")
                break
            m = re.search(r"^FamilyId (.*)$", output, re.M)
            if not m:
                raise ChutneyError("unexpected output from tor --keygen-family")
            self.family_ids[fid] = m.group(1)
        with get_familykey_path("map.json", ext=False).open("w") as f:
            json.dump(self.family_ids, f)

    def load_family_key_ids(self) -> None:
        """Load our family key identifiers from disk."""
        family_key_dir = get_familykey_path(None)
        self.family_ids = json.load(family_key_dir.joinpath("map.json").open())

    def supported(self) -> None:
        """Check whether this network is supported by the set of binaries
        and host information we have, and prints the result.
        Raises `ChutneyError` if anythign is missing.
        """
        missing_any = False
        for r in self._requirements:
            if not KNOWN_REQUIREMENTS[r]():
                print(f"Can't run this network: {r} is missing.")
                missing_any = True
        for n in self._nodes:
            if not n._builder.isSupported(self):
                missing_any = True

        if missing_any:
            raise ChutneyError("Missing requirements to run this network")

    def _exchange_restricted_discovery_keys(self) -> None:
        """Generate restricted discovery client keys and register the public keys
        with the corresponding hidden services.
        """
        nodes_by_tag: dict[str, list[Node]] = {}
        for n in self._nodes:
            if not n._config.tag:
                continue
            nodes_by_tag.setdefault(n._config.tag, []).append(n)

        for hs_client in (
            n
            for n in self._nodes
            if n._config.config_phase == CUR_CONFIG_PHASE
            and n._config.hs_client_restricted_discovery_server_tags
        ):
            for (
                server_tag
            ) in hs_client._config.hs_client_restricted_discovery_server_tags:
                servers = nodes_by_tag.get(server_tag)
                if not servers:
                    raise ChutneyError(
                        f"{n.nick}: No nodes found with tag {server_tag}"
                    )
                for server in servers:
                    if not server.is_hs:
                        raise ChutneyError(
                            f"{n.nick} can't authorize with {server.nick}; not a hs"
                        )
                    if not server._config.hs_restricted_discovery:
                        raise ChutneyError(
                            f"{n.nick} can't authorize with {server.nick};"
                            " restricted discovery disabled"
                        )
                    if server._config.config_phase > CUR_CONFIG_PHASE:
                        raise ChutneyError(
                            f"{n.nick} can't authorize with {server.nick},"
                            " which isn't configured yet"
                        )
                    hs_hostname = server.hs_hostname.unwrap()
                    hs_client_pubkey = hs_client._builder.get_hs_client_pubkey(
                        hs_hostname
                    )
                    server._builder.set_hs_client_pubkey(
                        hs_client.nick, hs_client_pubkey
                    )

    def configure(self) -> None:
        """Invoked from command line: Configure and prepare the network to be
        started.
        """
        if CUR_CONFIG_PHASE == 1:
            self.create_new_nodes_dir()
            self.create_family_keys()
        else:
            self.load_family_key_ids()

        network = self
        altauthlines = []
        bridgelines = []
        cur_phase_nodes = [
            n for n in self._nodes if n._config.config_phase == CUR_CONFIG_PHASE
        ]

        # XXX don't change node names or types or count if anything is
        # XXX running!

        for n in cur_phase_nodes:
            n._builder.preConfig(network)

        for n in self._nodes:
            auth_line = n._builder.getAltAuthLines(self.hasbridgeauth)
            if auth_line is not None:
                altauthlines.append(auth_line)
            bridgelines.extend(n._builder.getBridgeLines())

        self.authorities = altauthlines
        self.bridges = bridgelines

        n_dirauths = len([a for a in self.authorities if a.alt_dir_auth])
        if n_dirauths < 4:
            # Initially the authorities only know about each-other. They need 3
            # other relays to build circuits of length 3 that don't include
            # themselves.
            # <https://gitlab.torproject.org/tpo/core/chutney/-/issues/40035>
            logger.warning(
                f"Only configuring {n_dirauths} dirauths;"
                + " at least 4 recommended for reliable bootstrapping"
            )

        for n in cur_phase_nodes:
            n._builder.config(network)

        self._write_network_json()

        arti_tor_config = chutney.arti.config.tor_config(self)
        with get_absolute_nodes_path().joinpath("arti.toml").open("wb") as f:
            f.write(
                textwrap.dedent(
                    """
                # Base `arti_client::TorClientConfig` options for configuring
                # applications (not necessarily `arti`) that embed an arti
                # client. For `arti` processes, consider instead adding network
                # nodes with `backend=NodeBackend.ARTI`.
                """
                ).encode()
            )
            tomli_w.dump(arti_tor_config, f)

        for n in cur_phase_nodes:
            n._builder.postConfig(network)

        self._exchange_restricted_discovery_keys()

    def _write_network_json(self) -> None:
        """Write out the json file describing this network."""
        with get_absolute_nodes_path().joinpath("network.json").open("w") as f:
            json.dump(self, f, indent=2, cls=chutney.jsonable.CustomEncoder)

    @override
    def to_custom_jsonable(self) -> CustomJsonable:
        """Return a dict describing this object using primitive types.

        Values are of types accepted by the json module's encoder."""
        # Careful when modifying - this is ultimately used to produce "public"
        # json output that is consumed by other tools.
        return dict(
            nodes=[n for n in self.nodes],
            requirements=self._requirements,
        )

    @override
    @classmethod
    def from_decoded_json(cls, obj: object) -> Network:
        net = Network()
        d = check_type(obj, dict)
        for json_node in check_type(d["nodes"], list[dict[str, object]]):
            node_config = NodeConfig.from_decoded_json(json_node["_config"])
            net.addNode(node_config)
        for requirement in check_type(d["requirements"], list[str]):
            net._addRequirement(requirement)

        return net

    def status(self) -> bool:
        """Print how many nodes are running and how many are expected, and
        return True if all nodes are running.
        """
        total = 0
        running = 0
        for n in self._nodes:
            if n._config.launch_phase != CUR_LAUNCH_PHASE:
                continue
            total += 1
            if not n._controller.isRunning():
                print(f"{n.nick} is not running")
                continue
            running += 1
        print(f"{running}/{total} nodes are running")
        return running == total

    def restart(self) -> None:
        """Invoked from command line: Stop and subsequently start our
        network's nodes.
        """
        self.stop()
        self.start()

    def start(self) -> None:
        """Start all our network's nodes. Raises an `ChutneyErrorGroup` on errors"""
        # format polling correctly - avoid printing a newline
        print("Starting nodes", end="")
        errs = []
        for n in self._nodes:
            if n._config.launch_phase != CUR_LAUNCH_PHASE:
                continue
            try:
                n._controller.start()
            except ChutneyError as e:
                errs.append(e)
        if len(errs) > 0:
            raise ChutneyErrorGroup("Some nodes couldn't start", errs)
        # now print a newline unconditionally - this stops poll()ing
        # output from being squashed together, at the cost of a blank
        # line in wait()ing output
        print("")

    def hup(self) -> bool:
        """Send SIGHUP to all our network's running nodes and return True on no
        errors.
        """
        print("Sending SIGHUP to nodes")
        return all([n._controller.hup() for n in self._nodes])

    def print_bootstrap_status(
        self,
        nodes: Iterable[Node],
        most_recent_desc_status: dict[
            str, tuple[DirInfoStatusCode, Collection[str], Collection[DirFormat]]
        ],
        elapsed: Optional[float] = None,
        msg: str = "Bootstrap in progress",
    ) -> None:
        nick_set = set()
        cons_auth_nick_set = set()
        elapsed_msg = ""
        if elapsed:
            elapsed_msg = ": {} seconds".format(int(elapsed))
        if msg:
            header = "{}{}".format(msg, elapsed_msg)
        print(header)
        print("Node status:")
        for n in nodes:
            if not n._controller.isRunning():
                print(f"{n.nick} is not running")
            nick_set.add(n.nick)
            if n._config.consensus_authority:
                cons_auth_nick_set.add(n.nick)
            status = n._controller.getLastBootstrapStatus()
            # Support older tor versions without bootstrap keywords
            kwd = status.keyword or "None"
            print(
                "{:13}: {:19}, {:25}, {}".format(
                    n.nick, status.percent_or_code, kwd, status.message
                )
            )
        cache_client_nick_set = nick_set.difference(cons_auth_nick_set)
        print("Published dir info:")
        for n in nodes:
            if n.nick in most_recent_desc_status:
                desc_status = most_recent_desc_status[n.nick]
                code, desc_nodes, docs = desc_status
                node_set = set(desc_nodes)
                if node_set == nick_set:
                    desc_nodes = "all nodes"
                elif node_set == cons_auth_nick_set:
                    desc_nodes = "dir auths"
                elif node_set == cache_client_nick_set:
                    desc_nodes = "caches and clients"
                else:
                    desc_nodes = [node.nick.replace("test", "") for node in nodes]
                    desc_nodes = " ".join(sorted(desc_nodes))
                if len(docs) >= self.getDocTypeDisplayLimit():
                    docs_string = "all formats"
                else:
                    # Fold desc_new into desc, and md_new into md
                    docs_set = set(d for d in docs)
                    if DirFormat.DESC_NEW in docs_set:
                        docs_set.discard(DirFormat.DESC_NEW)
                        docs_set.add(DirFormat.DESC)
                    if DirFormat.MD_NEW in docs:
                        docs_set.discard(DirFormat.MD_NEW)
                        docs_set.add(DirFormat.MD)
                    docs_string = " ".join(sorted([str(d) for d in docs_set]))
                print(
                    "{:13}: {:19}, {:25}, {:30}".format(
                        n.nick, code, desc_nodes, docs_string
                    )
                )
        print()

    CHECK_NETWORK_STATUS_DELAY = 1.0
    PRINT_NETWORK_STATUS_DELAY = V3_AUTH_VOTING_INTERVAL / 2.0
    CHECKS_PER_PRINT = PRINT_NETWORK_STATUS_DELAY / CHECK_NETWORK_STATUS_DELAY

    # By default, there is no minimum start time.
    MIN_START_TIME_DEFAULT = 0

    # There are 7 v3 directory document types, but some networks only use 6,
    # because they don't have a bridge authority
    DOC_TYPE_DISPLAY_LIMIT_BRIDGEAUTH = 7
    DOC_TYPE_DISPLAY_LIMIT_NO_BRIDGEAUTH = 6

    def getDocTypeDisplayLimit(self) -> int:
        """Return the expected number of document types in this network."""
        if self.hasbridgeauth:
            return Network.DOC_TYPE_DISPLAY_LIMIT_BRIDGEAUTH
        else:
            return Network.DOC_TYPE_DISPLAY_LIMIT_NO_BRIDGEAUTH

    def getMinStartTime(self) -> int:
        """Returns the minimum start time before verifying, regardless of
        whether the network has bootstrapped, or the dir info has been
        distributed.

        The default can be overridden by the $CHUTNEY_MIN_START_TIME env
        var.
        """
        # User overrode the dynamic time
        env_min_time = getenv_int("CHUTNEY_MIN_START_TIME", None)
        if env_min_time is not None:
            return env_min_time
        return Network.MIN_START_TIME_DEFAULT

    def wait_for_bootstrap(
        self, limit_secs: int = getenv_int("CHUTNEY_START_TIME", 300)
    ) -> None:
        """
        Wait for the network to bootstrap. Raises `TimeoutException` on timeout.
        """
        print("Waiting for nodes to bootstrap...\n")
        start = time.time()
        limit = start + limit_secs
        next_print_status = start + Network.PRINT_NETWORK_STATUS_DELAY
        bootstrap_upto = CUR_LAUNCH_PHASE

        nodes = [n for n in self._nodes if n._config.launch_phase <= bootstrap_upto]
        min_time = self.getMinStartTime()
        wait_time_list = [n._controller.getUncheckedDirInfoWaitTime() for n in nodes]
        wait_time = max(wait_time_list)

        checks_since_last_print = 0

        while True:
            all_bootstrapped = True
            most_recent_desc_status = dict()
            for n in nodes:
                n._controller.updateLastStatus()

                if not n._controller.isBootstrapped():
                    all_bootstrapped = False

                desc_status = n._controller.getNodeDirInfoStatus()
                if desc_status:
                    code, desc_nodes, docs = desc_status
                    most_recent_desc_status[n.nick] = (code, desc_nodes, docs)
                    if code != DirInfoStatusCode.SUCCESS:
                        all_bootstrapped = False

            now = time.time()
            elapsed = now - start
            if all_bootstrapped:
                print("Everything bootstrapped after {} sec".format(int(elapsed)))
                self.print_bootstrap_status(
                    nodes,
                    most_recent_desc_status,
                    elapsed=elapsed,
                    msg="Bootstrap finished",
                )

                # Wait for unchecked bridge or onion service dir info.
                # (See #33581 and #33609.)
                # Also used to work around a timing bug in Tor 0.3.5.
                print(
                    "Waiting {} seconds for the network to be ready...\n".format(
                        int(wait_time)
                    )
                )
                time.sleep(wait_time)
                now = time.time()
                elapsed = now - start

                # Wait for a minimum amount of run time, to avoid a race
                # condition where:
                #  - all the directory info that chutney checks is present,
                #  - but some unchecked dir info is missing
                #    (perhaps onion service descriptors, see #33609)
                #    or some other state or connection isn't quite ready, and
                #  - chutney's SOCKS connection puts tor in a failing state,
                #    which affects tor for at least 10 seconds.
                #
                # We have only seen this race condition in 0.3.5. The fixes to
                # microdescriptor downloads in 0.4.0 or 0.4.1 likely resolve
                # this issue.
                if elapsed < min_time:
                    sleep_time = min_time - elapsed
                    print(
                        (
                            "Waiting another {} seconds for legacy tor "
                            "microdesc downloads...\n"
                        ).format(int(sleep_time))
                    )
                    time.sleep(sleep_time)
                    now = time.time()
                    elapsed = now - start

                # Write out json metadata, which may include details that were
                # missing before, such as hidden service hostnames.
                self._write_network_json()

                return
            if now >= limit:
                break
            if now >= next_print_status:
                if checks_since_last_print <= Network.CHECKS_PER_PRINT / 2:
                    logger.warning(
                        "checks_since_last_print: {} (expected: {})".format(
                            checks_since_last_print, Network.CHECKS_PER_PRINT
                        )
                    )
                    logger.warning("start: {} limit: {}".format(start, limit))
                    logger.warning(
                        "next_print_status: {} now: {}".format(
                            next_print_status, time.time()
                        )
                    )
                self.print_bootstrap_status(
                    nodes, most_recent_desc_status, elapsed=elapsed
                )
                next_print_status = now + Network.PRINT_NETWORK_STATUS_DELAY
                checks_since_last_print = 0

            time.sleep(Network.CHECK_NETWORK_STATUS_DELAY)

            # macOS Travis has some weird hangs, make sure we're not hanging
            # in this loop due to clock skew
            checks_since_last_print += 1
            if checks_since_last_print >= Network.CHECKS_PER_PRINT * 2:
                self.print_bootstrap_status(
                    nodes,
                    most_recent_desc_status,
                    elapsed=elapsed,
                    msg="Internal timing error",
                )
                print(
                    "checks_since_last_print: {} (expected: {})".format(
                        checks_since_last_print, Network.CHECKS_PER_PRINT
                    )
                )
                print("start: {} limit: {}".format(start, limit))
                print(
                    "next_print_status: {} now: {}".format(
                        next_print_status, time.time()
                    )
                )
                raise ChutneyTimeoutError()

        self.print_bootstrap_status(
            nodes,
            most_recent_desc_status,
            elapsed=elapsed,
            msg="Bootstrap failed",
        )
        raise ChutneyTimeoutError()

    # Keep in sync with ShutdownWaitLength in common.i
    SHUTDOWN_WAIT_LENGTH = 2
    # Wait for at least two event loops to elapse
    EVENT_LOOP_SLOP = 3
    # Wait for this long after signalling tor
    STOP_WAIT_TIME = SHUTDOWN_WAIT_LENGTH + EVENT_LOOP_SLOP

    def final_cleanup(
        self, wrote_dot: bool, any_tor_was_running: bool, cleanup_runfiles: bool
    ) -> None:
        """Perform final cleanup actions, based on the arguments:
        - wrote_dot: end a series of logged dots with a newline
        - any_tor_was_running: wait for STOP_WAIT_TIME for tor to stop
        - cleanup_runfiles: delete old lockfiles from crashed tors
                            rename old pid files from stopped tors
        """
        # make the output clearer by adding a newline
        if wrote_dot:
            sys.stdout.write("\n")
            sys.stdout.flush()

        # wait for tor to actually exit
        if any_tor_was_running:
            print("Waiting for nodes to cleanup and exit.")
            time.sleep(Network.STOP_WAIT_TIME)

        # clean up unwanted left-over file system state
        if cleanup_runfiles:
            for n in self._nodes:
                n._controller.cleanupRunFiles()

    def stop(self) -> None:
        """Stop our network's running tor nodes."""
        any_tor_was_running = False
        for sig, desc in [
            (signal.SIGINT, "SIGINT"),
            (signal.SIGINT, "another SIGINT"),
            (signal.SIGKILL, "SIGKILL"),
        ]:
            print("Sending %s to nodes" % desc)
            for n in self._nodes:
                if n._controller.isRunning():
                    any_tor_was_running = True
                    n._controller.stop(sig=sig)
            print("Waiting for nodes to finish.")
            wrote_dot = False
            for _ in range(15):
                time.sleep(1)
                if all(not n._controller.isRunning() for n in self._nodes):
                    self.final_cleanup(wrote_dot, any_tor_was_running, True)
                    return
                sys.stdout.write(".")
                wrote_dot = True
                sys.stdout.flush()
            for n in self._nodes:
                if n._controller.isRunning():
                    print(f"{n.nick} is running")
            # cleanup chutney's logging, but don't wait or cleanup files
            self.final_cleanup(wrote_dot, False, False)
        # wait for tor to exit, but don't cleanup logging
        self.final_cleanup(False, any_tor_was_running, True)

    def bootstrap(self) -> None:
        """Bootstrap the network.

        Configures, starts, and waits for bootstrap, for all of the network
        nodes' configure and launch phases."""

        cfg_phase_max = max(n._config.config_phase for n in self._nodes)
        launch_phase_max = max(n._config.launch_phase for n in self._nodes)
        phase_max = max(cfg_phase_max, launch_phase_max)
        for phase in range(1, phase_max + 1):
            if phase <= cfg_phase_max:
                print("Starting configure-phase ", phase)
                global CUR_CONFIG_PHASE
                CUR_CONFIG_PHASE = phase
                self.configure()
            if phase <= launch_phase_max:
                print("Starting launch-phase ", phase)
                global CUR_LAUNCH_PHASE
                CUR_LAUNCH_PHASE = phase
                self.start()
                self.wait_for_bootstrap()


class CLICommands:
    """
    Methods invokable from CLI.

    All methods that don't start with `_` are invocable from the command-line.
    """

    def __init__(self, network: Network):
        self._net = network

    def print_phases(self) -> None:
        """Print the total number of phases in which the network is
        initialized, configured, or bootstrapped."""

        cfg_max = max(n._config.config_phase for n in self._net._nodes)
        launch_max = max(n._config.launch_phase for n in self._net._nodes)
        print("CHUTNEY_CONFIG_PHASES={}".format(cfg_max))
        print("CHUTNEY_LAUNCH_PHASES={}".format(launch_max))

    def final_cleanup(
        self, wrote_dot: bool, any_tor_was_running: bool, cleanup_runfiles: bool
    ) -> None:
        """Perform final cleanup actions, based on the arguments:
        - wrote_dot: end a series of logged dots with a newline
        - any_tor_was_running: wait for STOP_WAIT_TIME for tor to stop
        - cleanup_runfiles: delete old lockfiles from crashed tors
                            rename old pid files from stopped tors
        """
        self._net.final_cleanup(wrote_dot, any_tor_was_running, cleanup_runfiles)

    def create_new_nodes_dir(self) -> None:
        """Create a new directory with a unique name, and symlink it to nodes"""
        self._net.create_new_nodes_dir()

    def supported(self) -> None:
        """Check whether this network is supported by the set of binaries
        and host information we have, and prints the result.
        """
        self._net.supported()

    def configure(self) -> None:
        """Invoked from command line: Configure and prepare the network to be
        started.
        """
        self._net.configure()

    def status(self) -> bool:
        """Print how many nodes are running and how many are expected, and
        return True if all nodes are running.
        """
        return self._net.status()

    def restart(self) -> None:
        """Invoked from command line: Stop and subsequently start our
        network's nodes.
        """
        self._net.restart()

    def start(self) -> None:
        """Start all our network's nodes and return True on no errors."""
        return self._net.start()

    def hup(self) -> bool:
        """Send SIGHUP to all our network's running nodes and return True on no
        errors.
        """
        return self._net.hup()

    def wait_for_bootstrap(self) -> None:
        """Invoked from tools/test-network.sh to wait for the network to
        bootstrap.
        """
        self._net.wait_for_bootstrap()

    def stop(self) -> None:
        """Stop our network's running tor nodes."""
        self._net.stop()

    def bootstrap(self) -> None:
        """Bootstrap the network.

        Configures, starts, and waits for bootstrap, for all of the network
        nodes' configure and launch phases."""
        self._net.bootstrap()


def getTests() -> list[str]:
    chutney_tests_path = importlib.resources.files("chutney.network_tests")

    return [
        test.name.removesuffix(".py")
        for test in chutney_tests_path.iterdir()
        if test.name.endswith(".py") and not test.name.startswith("_")
    ]


def usage() -> str:
    return "\n".join(
        [
            "Usage: chutney {command/test} {networkfile}",
            "Known commands are: %s"
            % (" ".join(x for x in dir(CLICommands) if not x.startswith("_"))),
            "Known tests are: %s" % (" ".join(getTests())),
            "Known networks are: %s" % (" ".join(getNetworks())),
        ]
    )


def runConfigFile(network: Network, verb: str) -> Optional[bool]:
    # let's check if the verb is a valid test and run it
    if verb in getTests():
        test_module = importlib.import_module("chutney.network_tests.{}".format(verb))
        try:
            run_test = test_module.run_test
        except AttributeError as e:
            print("Error running test {!r}: {}".format(verb, e))
            return False
        try:
            run_test(network)
        except NetworkTestFailure as e:
            raise ChutneyError(f"Test '{verb}' failed") from e
        return None

    cli_cmds = CLICommands(network)

    # tell the user we don't know what their verb meant
    if not hasattr(cli_cmds, verb):
        print(usage())
        print("Error: I don't know how to %s." % verb)
        return None

    res: Optional[bool] = check_type(getattr(cli_cmds, verb)(), Optional[bool])
    return res


_NETWORKS: Traversable = (
    importlib.resources.files("chutney").joinpath("data").joinpath("networks")
)


def getNetworks() -> list[str]:
    """Get names of built-in networks."""
    return [s.name for s in _NETWORKS.iterdir()]


def main(action: str, network_cfg_name: str) -> None:
    """A slightly more hermetic main could be called reasonably from python

    Raises an exception derived from `ChutneyError` on failure.
    """
    level = logging.DEBUG if os.environ.get("CHUTNEY_DEBUG", "") != "" else logging.INFO
    logging.basicConfig(level=level)
    network = Network.from_network_script_name(network_cfg_name)
    result = runConfigFile(network, action)
    if result is False:
        # TODO: eliminate this case. Have all commands
        # return a more informative error instead of `False`
        raise ChutneyError("Unspecified failure")


def __main__() -> None:
    """Raw main, suitable for use with `project.scripts` in `pyproject.toml`"""
    import traceback

    try:
        (action, network_cfg) = sys.argv[1:]
    except ValueError:
        print("Wrong number of arguments.")
        print(usage())
        sys.exit(1)
    try:
        main(action, network_cfg)
    except ChutneyError as e:
        traceback.print_exception(None, value=e, tb=None, limit=0)
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    __main__()
