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
from typing import (
    ClassVar,
    List,
    Optional,
    Any,
    Iterable,
    Sequence,
    Iterator,
    Protocol,
    Tuple,
)
from typing_extensions import assert_never, override

import argparse
import copy
import dataclasses
import errno
import importlib
import importlib.resources
import ipaddress
import logging
import platform
import re
import signal
import sys
import textwrap
import time
import tomli_w
import json

import chutney.network_tests.verify

from chutney.node_builder import NodeBuilder
from chutney.node_controller import NodeController
from chutney.known_bins import TorBin, TorGenCertBin, ArtiBin
from chutney import envvars
from chutney.dirinfo import (
    DirInfoStatusCode,
    DirFormat,
    BridgeLine,
    AuthorityLine,
)
from chutney.errors import (
    ChutneyError,
    ChutneyErrorGroup,
    ChutneyTimeoutError,
)
from chutney.jsonable import ToCustomJsonable, FromDecodedJson, CustomJsonable
from chutney.launcher import Launcher, LocalLauncher, SshLauncher
from chutney.Util import (
    addr_and_port_str,
    mkdir_p,
    IPAddress,
    IPNetwork,
    Option,
)
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

_TOR_VERSIONS = None
_TORRC_OPTIONS = None


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


def _get_absolute_nodes_path(data_dir: Path) -> Path:
    """
    Returns the absolute path of the "nodes" symlink that points to the
    "nodes*" directory that chutney should use to store the current
    network's torrcs and tor runtime data.

    This path is also used as a prefix for the unique nodes directory
    names.

    See get_new_absolute_nodes_path() for more details.
    """
    return Path(data_dir.resolve(), "nodes")


def _get_new_absolute_nodes_path(data_dir: Path, now: Optional[float] = None) -> Path:
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
    now = now or time.time()
    # automatically chosen to prevent path collisions, and result in an ordered
    # series of directory path names
    # should only be called by 'chutney configure', all other chutney commands
    # should use get_absolute_nodes_path()
    nodesdir = _get_absolute_nodes_path(data_dir)
    newdir = newdirbase = Path("%s.%d" % (nodesdir, now))
    # if the time is the same, fall back to a simple integer count
    # (this is very unlikely to happen unless the clock changes: it's not
    # possible to run multiple chutney networks at the same time)
    i = 0
    while newdir.exists():
        i += 1
        newdir = Path("%s.%d" % (newdirbase, i))
    return newdir


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
            host = self.ip.as_optional() or self.ipv6_addr.as_optional()
            assert host, f"No ip address for {self.nick}"
            self._launcher = SshLauncher(str(host))
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
        if self._config.ip is None:
            return Option(None)
        base = IPv4Address(self._config.ip)
        strategy = self._config.address_assignment_strategy
        if strategy == AddressAssignmentStrategy.STATIC:
            return Option(base)
        elif strategy == AddressAssignmentStrategy.OFFSET:
            return Option(IPv4Address(int(base) + self.nodenum))
        else:
            assert_never(strategy)

    @property
    def ipv6_addr(self) -> Option[IPv6Address]:
        base_str = self._config.ipv6_addr
        if base_str is None:
            return Option(None)
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

    def _address_in_trusted_net(self, addr: IPAddress) -> bool:
        """Return whether `addr` is an any of the configured trusted networks"""
        return any(map(lambda net: addr in net, self._config.trusted_networks))

    def _internal_addrs(self) -> Iterator[IPAddress]:
        """Listening addresses for "internal" services, e.g. socks.

        This returns localhost address(es) (including ipv6 if enabled), and
        other assigned addresses iff they fall within the configured trusted
        networks.
        """
        localhost_addrs: list[IPAddress] = [IPv4Address("127.0.0.1")]
        if not self._config.disableipv6:
            localhost_addrs.append(IPv6Address("::1"))

        # Emit non-localhost addresses first, since clients should generally
        # prefer to connect via those.
        a: Optional[IPAddress]
        for a in [self.ip.as_optional(), self.ipv6_addr.as_optional()]:
            if a is None:
                continue
            if a in localhost_addrs:
                # localhost addrs emitted separately, below.
                continue
            if not self._address_in_trusted_net(a):
                # This might be a bit easy to miss in the case that the user
                # intended the address to be an internal one, and thus used as a
                # socks port etc.  OTOH this would be overly noisy in the case
                # that the user *wants* the address to be used for "public"
                # ports like orport, but not "internal" ports like socks.
                #
                # If we want a louder failure here, consider adding some other
                # config parameter to convey the user intent.
                logger.debug(
                    f"Excluding {a} from internal addrs; not in trusted networks"
                )
                continue
            yield a

        for a in localhost_addrs:
            yield a

    @property
    def orport(self) -> int:
        """OrPort that this node exposes"""
        return self._network.orport_base + self.nodenum

    def controlport_endpoints(
        self,
    ) -> Iterator[Tuple[IPAddress, int]]:
        """ControlPort endpoints (address, port) that this node exposes, if any."""
        port = self._network.controlport_base + self.nodenum
        return map(lambda a: (a, port), self._internal_addrs())

    def socksport_endpoints(
        self,
    ) -> Iterator[Tuple[IPAddress, int]]:
        """SocksPort endpoints (address, port) that this node exposes, if any."""
        if not self._config.client:
            return iter([])
        port = self._network.socksport_base + self.nodenum
        return map(lambda a: (a, port), self._internal_addrs())

    def dnsport_endpoints(self) -> Iterator[Tuple[IPAddress, int]]:
        """DnsPort that this node exposes, if any."""
        if not self._config.enable_dnsport:
            return iter([])
        port = self._network.dnsport_base + self.nodenum
        return map(lambda a: (a, port), self._internal_addrs())

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
            controlport_endpoints=[
                addr_and_port_str(a, p) for (a, p) in self.controlport_endpoints()
            ],
            socksport_endpoints=[
                addr_and_port_str(a, p) for (a, p) in self.socksport_endpoints()
            ],
            dnsport_endpoints=[
                addr_and_port_str(a, p) for (a, p) in self.dnsport_endpoints()
            ],
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
            _nodenum=self.nodenum,
        )


@dataclasses.dataclass
class NodeConfig(ToCustomJsonable, FromDecodedJson):
    """Properties of a Tor Node"""

    # Which backend to use to run the node.
    backend: NodeBackend = NodeBackend.TOR
    # Which process-launcher to use.
    _LAUNCHER_BACKEND_ENV: ClassVar[envvars.EnvVarEnum[LauncherBackend]] = (
        envvars.EnvVarEnum(
            "CHUTNEY_LAUNCHER_BACKEND",
            LauncherBackend.LOCAL,
            "Which process-launcher to use",
        )
    )
    launcher_backend: LauncherBackend = dataclasses.field(
        default_factory=lambda: NodeConfig._LAUNCHER_BACKEND_ENV.get()
    )
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
    tor: str = dataclasses.field(default_factory=lambda: TorBin().config_envvar().get())
    # path of the tor-gencert binary (for backend = NodeBackend.TOR)
    tor_gencert: str = dataclasses.field(
        default_factory=lambda: TorGenCertBin().config_envvar().get()
    )
    # path of the arti binary (for backend = NodeBackend.ARTI)
    arti: str = dataclasses.field(
        default_factory=lambda: ArtiBin().config_envvar().get()
    )
    # lifetime of authority certs, in months
    auth_cert_lifetime: int = 12
    # strategy for deriving concrete network addresses from the configuration
    # `ip` and `ipv6_addr`
    _ADDRESS_ASSIGNMENT_ENV: ClassVar[envvars.EnvVarEnum[AddressAssignmentStrategy]] = (
        envvars.EnvVarEnum(
            "CHUTNEY_ADDRESS_ASSIGNMENT",
            AddressAssignmentStrategy.STATIC,
            "Strategy for deriving concrete node network addresses from base template",
        )
    )
    address_assignment_strategy: AddressAssignmentStrategy = dataclasses.field(
        default_factory=lambda: NodeConfig._ADDRESS_ASSIGNMENT_ENV.get()
    )
    # trusted networks. unsecured services, such as socks, dns, and the tor
    # controlport, will be bound to the node's assigned IP addresses if they
    # fall within one of these (in addition to binding them to localhost).
    _TRUSTED_NETWORKS_ENV: ClassVar[envvars.EnvVarIPNetworkList] = (
        envvars.EnvVarIPNetworkList(
            "CHUTNEY_TRUSTED_NETWORKS",
            [],
            "Comma-separated list of trusted subnets. e.g. '192.168.0.0/24,fc00::/8'"
            + " Nodes with IPs on these will bind unsecured services to those IPs.",
        )
    )
    trusted_networks: list[IPNetwork] = dataclasses.field(
        default_factory=lambda: NodeConfig._TRUSTED_NETWORKS_ENV.get()
    )
    # primary IP address (usually IPv4) to listen on.
    # Setting to None disables ipv4.
    _LISTEN_ADDRESS_ENV: ClassVar[envvars.EnvVarStr] = envvars.EnvVarStr(
        "CHUTNEY_LISTEN_ADDRESS",
        "127.0.0.1",
        "IPv4 address to listen on, if any.",
    )
    ip: Optional[str] = dataclasses.field(
        default_factory=lambda: NodeConfig._LISTEN_ADDRESS_ENV.get() or None
    )
    _LISTEN_ADDRESS_V6_ENV: ClassVar[envvars.EnvVarStr] = envvars.EnvVarStr(
        "CHUTNEY_LISTEN_ADDRESS_V6",
        "",
        "IPv6 address to listen on, if any.",
    )
    # secondary IP address (usually IPv6) to listen on. we default to
    # ipv6_addr=None to support IPv4-only systems.
    ipv6_addr: Optional[str] = dataclasses.field(
        default_factory=lambda: NodeConfig._LISTEN_ADDRESS_V6_ENV.get() or None
    )
    # Whether to disable all ipv6 functionality
    _DISABLE_IPV6_ENV: ClassVar[envvars.EnvVarBool] = envvars.EnvVarBool(
        "CHUTNEY_DISABLE_IPV6", False, "Whether to disable ipv6 support"
    )
    disableipv6: bool = dataclasses.field(
        default_factory=lambda: NodeConfig._DISABLE_IPV6_ENV.get()
    )
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
    _CONTROLLING_PID_ENV: ClassVar[envvars.EnvVarInt] = envvars.EnvVarInt(
        "CHUTNEY_CONTROLLING_PID",
        0,
        "PID of controlling script (for __OwningControllerProcess)",
    )
    controlling_pid: int = dataclasses.field(
        default_factory=lambda: NodeConfig._CONTROLLING_PID_ENV.get()
    )
    # The path to a DNS config file for Tor Exits. If this file
    # is empty or unreadable, Tor will try 127.0.0.1:53.
    #
    # the default resolv.conf path is set at compile time
    # there's no easy way to get it out of tor, so we use the typical value
    _DNS_CONF_ENV: ClassVar[envvars.EnvVarStr] = envvars.EnvVarStr(
        "CHUTNEY_DNS_CONF",
        "/etc/resolv.conf",
        "Path to resolver config file; e.g. for ServerDNSResolvConfFile."
        + " Set to empty-string to not set explicitly.",
    )
    dns_conf: str = dataclasses.field(
        default_factory=lambda: NodeConfig._DNS_CONF_ENV.get()
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
    _TOR_SANDBOX_ENV: ClassVar[envvars.EnvVarBool] = envvars.EnvVarBool(
        "CHUTNEY_TOR_SANDBOX",
        platform.system() == "Linux",
        "Whether to enable tor's sandbox",
    )
    sandbox: bool = dataclasses.field(
        default_factory=lambda: NodeConfig._TOR_SANDBOX_ENV.get()
    )
    # Whether to enable a unix control socket (via ControlSocket in torrc)
    _ENABLE_CONTROLSOCKET_ENV: ClassVar[envvars.EnvVarBool] = envvars.EnvVarBool(
        "CHUTNEY_ENABLE_CONTROLSOCKET",
        True,
        "Whether to enable a unix control socket (via ControlSocket in torrc)",
    )
    enable_controlsocket: bool = dataclasses.field(
        default_factory=lambda: NodeConfig._ENABLE_CONTROLSOCKET_ENV.get()
    )
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

    # XXX Move template logic into template
    @property
    def owning_controller_process(self) -> str:
        """The __OwningControllerProcess torrc line,
        disabled if tor should continue after the script exits"""
        cpid = self.controlling_pid
        ocp_line = "__OwningControllerProcess %d" % (cpid)
        # if we want to leave the network running, or controlling_pid is 1
        # (or invalid)
        if cpid <= 1:
            return "#" + ocp_line
        else:
            return ocp_line

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
        d = dataclasses.asdict(self)
        d["trusted_networks"] = [str(n) for n in d["trusted_networks"]]
        return d

    @override
    @classmethod
    def from_decoded_json(cls, obj: object) -> NodeConfig:
        d = check_type(obj, dict)
        d["backend"] = NodeBackend.from_decoded_json(d["backend"])
        d["launcher_backend"] = LauncherBackend.from_decoded_json(d["launcher_backend"])
        d["address_assignment_strategy"] = AddressAssignmentStrategy.from_decoded_json(
            d["address_assignment_strategy"]
        )
        d["trusted_networks"] = [ipaddress.ip_network(n) for n in d["trusted_networks"]]
        return NodeConfig(**d)

    @staticmethod
    def register_argparser(parser: argparse.ArgumentParser) -> None:
        """Add command-line options to `parser` to override some defaults.

        The subsequent parse result can be provided to `TorNet.from_envargs`
        to allow any user-provided command-line options to override the
        environment-variable defaults."""
        NodeConfig._TRUSTED_NETWORKS_ENV.register_argparser(parser)
        NodeConfig._LISTEN_ADDRESS_ENV.register_argparser(parser)
        NodeConfig._LISTEN_ADDRESS_V6_ENV.register_argparser(parser)
        NodeConfig._DISABLE_IPV6_ENV.register_argparser(parser)
        NodeConfig._CONTROLLING_PID_ENV.register_argparser(parser)
        NodeConfig._DNS_CONF_ENV.register_argparser(parser)
        NodeConfig._TOR_SANDBOX_ENV.register_argparser(parser)
        NodeConfig._ENABLE_CONTROLSOCKET_ENV.register_argparser(parser)
        NodeConfig._LAUNCHER_BACKEND_ENV.register_argparser(parser)
        NodeConfig._ADDRESS_ASSIGNMENT_ENV.register_argparser(parser)
        # We already register KnownBin envvars globally

    @staticmethod
    def from_envargs(ns: Optional[argparse.Namespace] = None) -> NodeConfig:
        """Create a default NodeConfig, optionally overridden with args from `ns`

        The intent is for `ns` to be the result of parsing command-line arguments,
        using a parser previously passed to `NodeConfig.register_argparser`.
        """
        return NodeConfig(
            trusted_networks=NodeConfig._TRUSTED_NETWORKS_ENV.get(ns=ns),
            ip=NodeConfig._LISTEN_ADDRESS_ENV.get(ns=ns) or None,
            ipv6_addr=NodeConfig._LISTEN_ADDRESS_V6_ENV.get(ns=ns) or None,
            disableipv6=NodeConfig._DISABLE_IPV6_ENV.get(ns=ns),
            controlling_pid=NodeConfig._CONTROLLING_PID_ENV.get(ns=ns),
            dns_conf=NodeConfig._DNS_CONF_ENV.get(ns=ns),
            sandbox=NodeConfig._TOR_SANDBOX_ENV.get(ns=ns),
            enable_controlsocket=NodeConfig._ENABLE_CONTROLSOCKET_ENV.get(ns=ns),
            launcher_backend=NodeConfig._LAUNCHER_BACKEND_ENV.get(ns=ns),
            address_assignment_strategy=NodeConfig._ADDRESS_ASSIGNMENT_ENV.get(ns=ns),
            tor=TorBin().config_envvar().get(ns=ns),
            tor_gencert=TorGenCertBin().config_envvar().get(ns=ns),
            arti=ArtiBin().config_envvar().get(ns=ns),
        )


KNOWN_REQUIREMENTS = {"IPV6": chutney.Host.is_ipv6_supported}


@dataclasses.dataclass
class NetworkConfig(ToCustomJsonable, FromDecodedJson):
    # Tor bin used for non-Node-specific purposes, such as for
    # generating family keys.
    tor_bin: str

    @staticmethod
    def register_argparser(parser: argparse.ArgumentParser) -> None:
        # We already register TorBin.config_envvar() globally
        pass

    @staticmethod
    def from_envargs(ns: Optional[argparse.Namespace] = None) -> NetworkConfig:
        return NetworkConfig(tor_bin=TorBin().config_envvar().get(ns=ns))

    @override
    def to_custom_jsonable(self) -> CustomJsonable:
        """Convert to a json-encodable object."""
        return dataclasses.asdict(self)

    @classmethod
    def from_decoded_json(cls, obj: object) -> NetworkConfig:
        d = check_type(obj, dict)
        return NetworkConfig(**d)


class Network(ToCustomJsonable, FromDecodedJson):
    """A network of Tor nodes, plus functions to manipulate them"""

    V3_AUTH_VOTING_INTERVAL: float = 20.0

    def __init__(self, config: Optional[NetworkConfig] = None) -> None:
        self._config = config or NetworkConfig.from_envargs()
        self._nodes: list[Node] = []
        # Keys into `KNOWN_REQUIREMENTS`
        self._requirements: list[str] = []
        self._nextnodenum = 0

        # "Nodes" directory where we'll persist the network's state.
        # Initialized in `init` for a fresh network, or in `from_nodes_dir`
        # when loading from an existing directory.
        self._dir: Optional[Path] = None

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
        # commands) wait for a successful outcome.
        self.bootstrap_time: int = envvars.BOOTSTRAP_TIME.get()

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
    def dir(self) -> Path:
        """The nodes in this network"""
        if self._dir is None:
            raise ChutneyError("No directory. Use `init` to create one.")

        return self._dir

    @property
    def nodes(self) -> Iterable[Node]:
        """The nodes in this network"""
        return self._nodes

    @staticmethod
    def from_nodes_dir(nodes_dir: Path) -> Network:
        json_str = nodes_dir.joinpath("network.json").read_text()
        json_obj = json.loads(json_str)
        net = Network.from_decoded_json(json_obj)
        net._dir = nodes_dir
        return net

    @staticmethod
    def from_network_script_contents(
        network_script_contents: str,
        *,
        config: Optional[NetworkConfig] = None,
        node_config_defaults: Optional[NodeConfig] = None,
    ) -> Network:
        """Create a Network object using the contents of a chutney network script.

        For examples of network scripts, see`chutney/data/networks`.
        """
        # If not provided defaults, generate them from environment
        non_optional_config_defaults = node_config_defaults or NodeConfig.from_envargs()

        # Wrappers used from network scripts (`data`) that manipulate
        # an implicit network (`_THE_NETWORK`).
        _THE_NETWORK = Network(config=config)

        def Require(feature: str) -> None:
            _THE_NETWORK._addRequirement(feature)

        def ConfigureNodes(nodelist: list[NodeConfig]) -> None:
            _THE_NETWORK.addNodes(nodelist)

        def NodeWrapper(
            parent: NodeConfig = non_optional_config_defaults, **kwargs: Any
        ) -> NodeConfig:
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
    def from_network_script_name(
        network_cfg_name: str,
        *,
        config: Optional[NetworkConfig] = None,
        node_config_defaults: Optional[NodeConfig] = None,
    ) -> Network:
        """Create a Network object using a built-in chutney network script.

        Built in networks are located in `chutney/data/networks`, and can be
        listed via the `getNetworks` function, or with `chutney --help` at the
        command-line.
        """
        contents = _NETWORKS.joinpath(network_cfg_name).read_text()
        return Network.from_network_script_contents(
            contents, config=config, node_config_defaults=node_config_defaults
        )

    @staticmethod
    def from_network_script_path(
        network_cfg_path: Path,
        *,
        config: Optional[NetworkConfig] = None,
        node_config_defaults: Optional[NodeConfig] = None,
    ) -> Network:
        """Create a Network object using a chutney network script by path."""
        contents = network_cfg_path.read_text()
        return Network.from_network_script_contents(
            contents, config=config, node_config_defaults=node_config_defaults
        )

    def _add_node(self, config: NodeConfig, nodenum: int) -> None:
        """Create a node with the given config, add it to the network"""
        node = Node(self, config, nodenum)
        self._nodes.append(node)
        if node._config.bridgeauthority:
            self.hasbridgeauth = True
        for family_name in node._config.families:
            self.family_members.setdefault(family_name, []).append(node)

    def addNodes(self, configs: List[NodeConfig]) -> None:
        """Create nodes from `configs` and add them to the network."""
        if self._nodes:
            next_num = max(map(lambda n: n.nodenum, self._nodes)) + 1
        else:
            next_num = 0
        for c in configs:
            self._add_node(c, next_num)
            next_num += 1

    def _addRequirement(self, requirement: str) -> None:
        requirement = requirement.upper()
        if requirement not in KNOWN_REQUIREMENTS:
            raise RuntimeError(("Unrecognized requirement %r" % requirement))
        self._requirements.append(requirement)

    def _create_new_nodes_dir(self, data_dir: Path) -> None:
        """Create a new directory with a unique name, and symlink it to nodes"""
        # the unique directory we'll create
        newnodesdir = _get_new_absolute_nodes_path(data_dir)

        # the canonical name we'll link it to
        nodeslink = _get_absolute_nodes_path(data_dir)

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
        self._dir = newnodesdir

    def get_familykey_path(self, ident: Optional[str], ext: bool = True) -> Path:
        """
        Return the absolute path for the secret family key identified with `ident`.

        If no ident is given, return the directory in which we store family keys.

        If `ext` is false, omit the "secret_family_key" exension.
        """
        family_key_dir = self.dir.joinpath("family_keys")
        if ident is None:
            return family_key_dir
        if ext:
            fn = f"{ident}.secret_family_key"
        else:
            fn = ident
        return family_key_dir.joinpath(fn)

    def create_family_keys(self) -> None:
        """Initialize family keys as needed for all of our nodes."""

        mkdir_p(self.get_familykey_path(None))
        all_family_ids = set()
        for n in self._nodes:
            if n._config.families:
                all_family_ids.update(n._config.families)
        for fid in all_family_ids:
            cmdline = [
                self._config.tor_bin,
                "--keygen-family",
                str(self.get_familykey_path(fid, ext=False)),
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
        with self.get_familykey_path("map.json", ext=False).open("w") as f:
            json.dump(self.family_ids, f)

    def load_family_key_ids(self) -> None:
        """Load our family key identifiers from disk."""
        family_key_dir = self.get_familykey_path(None)
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

    def _exchange_restricted_discovery_keys(self, *, config_phase: int) -> None:
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
            if n._config.config_phase == config_phase
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
                    if server._config.config_phase > config_phase:
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

    def init(self, data_dir: Optional[Path] = None) -> None:
        """Create a nodes directory and metadata"""
        data_dir = data_dir or envvars.DATA_DIR.get()
        self._create_new_nodes_dir(data_dir=data_dir)
        self._write_network_json()

    def configure(self, *, config_phase: int) -> None:
        """Generate config files, keys, etc for the given `config_phase`."""
        if config_phase == 1:
            self.create_family_keys()
        else:
            self.load_family_key_ids()

        network = self
        altauthlines = []
        bridgelines = []
        cur_phase_nodes = [
            n for n in self._nodes if n._config.config_phase == config_phase
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
        with self.dir.joinpath("arti.toml").open("wb") as f:
            f.write(textwrap.dedent("""
                # Base `arti_client::TorClientConfig` options for configuring
                # applications (not necessarily `arti`) that embed an arti
                # client. For `arti` processes, consider instead adding network
                # nodes with `backend=NodeBackend.ARTI`.
                """).encode())
            tomli_w.dump(arti_tor_config, f)

        for n in cur_phase_nodes:
            n._builder.postConfig(network)

        self._exchange_restricted_discovery_keys(config_phase=config_phase)

    def _write_network_json(self) -> None:
        """Write out the json file describing this network."""
        with self.dir.joinpath("network.json").open("w") as f:
            json.dump(self, f, indent=2, cls=chutney.jsonable.CustomEncoder)

    @override
    def to_custom_jsonable(self) -> CustomJsonable:
        """Return a dict describing this object using primitive types.

        Values are of types accepted by the json module's encoder."""
        # Careful when modifying - this is ultimately used to produce "public"
        # json output that is consumed by other tools.
        return dict(
            config=self._config.to_custom_jsonable(),
            nodes=[n for n in self.nodes],
            requirements=self._requirements,
        )

    @override
    @classmethod
    def from_decoded_json(cls, obj: object) -> Network:
        d = check_type(obj, dict)
        net_config = NetworkConfig.from_decoded_json(d["config"])
        net = Network(config=net_config)
        for json_node in check_type(d["nodes"], list[dict[str, object]]):
            node_config = NodeConfig.from_decoded_json(json_node["_config"])
            nodenum = check_type(json_node["_nodenum"], int)
            net._add_node(node_config, nodenum)
        for requirement in check_type(d["requirements"], list[str]):
            net._addRequirement(requirement)

        return net

    def status(self, *, launch_phase: int) -> bool:
        """Check status of nodes with the given `launch_phase`.

        Print how many nodes are running and how many are expected, and return
        True if all nodes are running.
        """
        total = 0
        running = 0
        for n in self._nodes:
            if n._config.launch_phase != launch_phase:
                continue
            total += 1
            if not n._controller.isRunning():
                print(f"{n.nick} is not running")
                continue
            running += 1
        print(f"{running}/{total} nodes are running")
        return running == total

    def restart(self, *, launch_phase: int) -> None:
        """Invoked from command line: Stop and subsequently start our
        network's nodes.
        """
        self.stop()
        # XXX: It probably makes more sense to start all nodes with phase <=
        # launch_phase, not just launch_phase itself.
        self.start(launch_phase=launch_phase)

    def start(self, *, launch_phase: int) -> None:
        """Start network nodes with the given `launch_phase`.

        Raises an `ChutneyErrorGroup` on errors"""
        # format polling correctly - avoid printing a newline
        print("Starting nodes", end="")
        errs = []
        for n in self._nodes:
            if n._config.launch_phase != launch_phase:
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

    def wait_for_bootstrap(
        self,
        *,
        launch_phase: int,
        limit_secs: int = envvars.START_TIME.get(),
        min_time: int = envvars.MIN_START_TIME.get(),
    ) -> None:
        """
        Wait for nodes with up through the given `launch_phase` to bootstrap.

        Raises `TimeoutException` on timeout.
        """
        print("Waiting for nodes to bootstrap...\n")
        start = time.time()
        limit = start + limit_secs
        next_print_status = start + Network.PRINT_NETWORK_STATUS_DELAY

        nodes = [n for n in self._nodes if n._config.launch_phase <= launch_phase]
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

                desc_status = n._controller.getNodeDirInfoStatus(
                    launch_phase=launch_phase
                )
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

    def _final_cleanup(
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
                    self._final_cleanup(wrote_dot, any_tor_was_running, True)
                    return
                sys.stdout.write(".")
                wrote_dot = True
                sys.stdout.flush()
            for n in self._nodes:
                if n._controller.isRunning():
                    print(f"{n.nick} is running")
            # cleanup chutney's logging, but don't wait or cleanup files
            self._final_cleanup(wrote_dot, False, False)
        # wait for tor to exit, but don't cleanup logging
        self._final_cleanup(False, any_tor_was_running, True)

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
                self.configure(config_phase=phase)
            if phase <= launch_phase_max:
                print("Starting launch-phase ", phase)
                self.start(launch_phase=phase)
                self.wait_for_bootstrap(launch_phase=phase)


# This is the type returned by `ArgumentParser.add_subparsers`. Unfortunately
# the argparse module doesn't expose a public named type. We refer to it using
# the internal _SubParsersAction type that it gets, encapsulating that bit of
# ugliness into this alias.
class _SubParsers(Protocol):
    # Since we can't name a lot of the kwarg types either, we just use Any.
    # This means mypy etc. won't statically catch type errors when calling this
    # method via this type. In practice such errors will be found on any run of
    # the chutney CLI though, so will be found quickly.
    def add_parser(self, name: str, **kwargs: Any) -> argparse.ArgumentParser: ...


class CLICommand(ABC):
    """A CLI command"""

    def __init__(
        self, subparsers: _SubParsers, *, require_net_spec_group: Optional[bool] = None
    ) -> None:
        self._subparser = subparsers.add_parser(self.name(), help=self.help())
        if require_net_spec_group is not None:
            # This command supports specifying the network config.

            # Add support for overriding envvars that effect Network creation.
            # TODO: these are ignored in the `--net-from-data-dir` case. This
            # might be confusing, but I'm not sure how better to arrange things.
            NetworkConfig.register_argparser(self._subparser)
            NodeConfig.register_argparser(self._subparser)
            TorBin().config_envvar().register_argparser(self._get_subparser())
            TorGenCertBin().config_envvar().register_argparser(self._get_subparser())
            ArtiBin().config_envvar().register_argparser(self._get_subparser())

            # We add a group of mutually exclusive flags, one for each method of
            # specifying the config.
            method_group = self._subparser.add_mutually_exclusive_group(
                required=require_net_spec_group
            )
            method_group.add_argument(
                "--net",
                choices=getNetworks(),
                help="Configure a network using a built-in network script, by name.",
            )
            method_group.add_argument(
                "--net-from-script-path",
                help="Configure a network using a chutney network script, by path.",
                type=Path,
            )
            method_group.add_argument(
                "--net-from-data-dir",
                action="store_true",
                # If the group isn't required, then make this the default option.
                default=not require_net_spec_group,
                help="Load network config from directory $CHUTNEY_DATA_DIR/nodes."
                " The loaded configuration is *not* altered by other options like"
                " `--tor`/`CHUTNEY_TOR`.",
            )
        else:
            # User isn't permitted to specify; always get from data dir.
            self._subparser.set_defaults(net_from_data_dir=True)
        self._subparser.set_defaults(cmd=self)

    @staticmethod
    @abstractmethod
    def name() -> str:
        """Name of the command"""
        ...

    @staticmethod
    @abstractmethod
    def help() -> str:
        """Help string of the command"""
        ...

    @abstractmethod
    def run(self, network: Network, ns: argparse.Namespace) -> None:
        """Run the command"""
        ...

    def _get_subparser(self) -> argparse.ArgumentParser:
        """Return the subparser registered for this command.

        Intended for usage by child classes, to register additional arguments.
        """
        return self._subparser


class PrintPhasesCLICommand(CLICommand):
    @staticmethod
    @override
    def name() -> str:
        return "print_phases"

    @staticmethod
    @override
    def help() -> str:
        return textwrap.dedent("""
            Print the total number of phases in which the network is
            initialized, configured, or bootstrapped.
            """)

    @override
    def run(self, network: Network, ns: argparse.Namespace) -> None:
        cfg_max = max(n._config.config_phase for n in network._nodes)
        launch_max = max(n._config.launch_phase for n in network._nodes)
        print("CHUTNEY_CONFIG_PHASES={}".format(cfg_max))
        print("CHUTNEY_LAUNCH_PHASES={}".format(launch_max))


class SupportedCLICommand(CLICommand):
    @staticmethod
    @override
    def name() -> str:
        return "supported"

    @staticmethod
    @override
    def help() -> str:
        return textwrap.dedent(
            """Check whether this network is supported by the set of binaries
        and host information we have, and prints the result."""
        )

    @override
    def run(self, network: Network, ns: argparse.Namespace) -> None:
        network.supported()


class InitCLICommand(CLICommand):
    @staticmethod
    @override
    def name() -> str:
        return "init"

    @staticmethod
    @override
    def help() -> str:
        return "Save the network configuration to a fresh nodes directory."

    @override
    def run(self, network: Network, ns: argparse.Namespace) -> None:
        network.init(data_dir=envvars.DATA_DIR.get(ns=ns))


class ConfigureCLICommand(CLICommand):
    def __init__(
        self,
        subparsers: _SubParsers,
        *,
        config_phase_env: envvars.EnvVarInt,
        require_net_spec_group: Optional[bool] = None,
    ) -> None:
        super().__init__(subparsers, require_net_spec_group=require_net_spec_group)
        self._config_phase_env = config_phase_env
        self._config_phase_env.register_argparser(self._get_subparser())

    @staticmethod
    @override
    def name() -> str:
        return "configure"

    @staticmethod
    @override
    def help() -> str:
        return "Generate node config files etc for phase CHUTNEY_CONFIG_PHASE."

    @override
    def run(self, network: Network, ns: argparse.Namespace) -> None:
        network.configure(config_phase=self._config_phase_env.get(ns=ns))


class StatusCLICommand(CLICommand):
    def __init__(
        self,
        subparsers: _SubParsers,
        *,
        launch_phase_env: envvars.EnvVarInt,
        require_net_spec_group: Optional[bool] = None,
    ) -> None:
        super().__init__(subparsers, require_net_spec_group=require_net_spec_group)
        self._launch_phase_env = launch_phase_env
        self._launch_phase_env.register_argparser(self._get_subparser())

    @staticmethod
    @override
    def name() -> str:
        return "status"

    @staticmethod
    @override
    def help() -> str:
        return textwrap.dedent(
            """Print how many nodes are running and how many are expected for
        CHUTNEY_LAUNCH_PHASE. Fails if not all expected nodes are running.
        """
        )

    @override
    def run(self, network: Network, ns: argparse.Namespace) -> None:
        if not network.status(launch_phase=self._launch_phase_env.get(ns=ns)):
            # TODO: have Network.status raise an informative Exception
            # instead of returning a bool.
            raise ChutneyError("status failed")


class RestartCLICommand(CLICommand):
    def __init__(
        self,
        subparsers: _SubParsers,
        *,
        launch_phase_env: envvars.EnvVarInt,
        require_net_spec_group: Optional[bool] = None,
    ) -> None:
        super().__init__(subparsers, require_net_spec_group=require_net_spec_group)
        self._launch_phase_env = launch_phase_env
        self._launch_phase_env.register_argparser(self._get_subparser())

    @staticmethod
    @override
    def name() -> str:
        return "restart"

    @staticmethod
    @override
    def help() -> str:
        return "Stop and subsequently start our network's nodes."

    @override
    def run(self, network: Network, ns: argparse.Namespace) -> None:
        network.restart(launch_phase=self._launch_phase_env.get(ns=ns))


class StartCLICommand(CLICommand):
    def __init__(
        self,
        subparsers: _SubParsers,
        *,
        launch_phase_env: envvars.EnvVarInt,
        require_net_spec_group: Optional[bool] = None,
    ) -> None:
        super().__init__(subparsers, require_net_spec_group=require_net_spec_group)
        self._launch_phase_env = launch_phase_env
        self._launch_phase_env.register_argparser(self._get_subparser())

    @staticmethod
    @override
    def name() -> str:
        return "start"

    @staticmethod
    @override
    def help() -> str:
        return "Start all our network's nodes and return True on no errors."

    @override
    def run(self, network: Network, ns: argparse.Namespace) -> None:
        network.start(launch_phase=self._launch_phase_env.get(ns=ns))


class HupCLICommand(CLICommand):
    @staticmethod
    @override
    def name() -> str:
        return "hup"

    @staticmethod
    @override
    def help() -> str:
        return "Send SIGHUP to all our network's running nodes."

    @override
    def run(self, network: Network, ns: argparse.Namespace) -> None:
        if not network.hup():
            # TODO: have controller.hup raise an informative Exception
            # instead of returning a bool.
            raise ChutneyError("hup failed")


class WaitForBootstrapCLICommand(CLICommand):
    def __init__(
        self,
        subparsers: _SubParsers,
        *,
        launch_phase_env: envvars.EnvVarInt,
        require_net_spec_group: Optional[bool] = None,
    ) -> None:
        super().__init__(subparsers, require_net_spec_group=require_net_spec_group)
        self._launch_phase_env = launch_phase_env
        self._launch_phase_env.register_argparser(self._get_subparser())

    @staticmethod
    @override
    def name() -> str:
        return "wait_for_bootstrap"

    @staticmethod
    @override
    def help() -> str:
        return "Wait for CHUTNEY_LAUNCH_PHASE of the network to bootstrap."

    @override
    def run(self, network: Network, ns: argparse.Namespace) -> None:
        network.wait_for_bootstrap(launch_phase=self._launch_phase_env.get(ns=ns))


class StopCLICommand(CLICommand):
    @staticmethod
    @override
    def name() -> str:
        return "stop"

    @staticmethod
    @override
    def help() -> str:
        return "Stop the network's running processes."

    @override
    def run(self, network: Network, ns: argparse.Namespace) -> None:
        network.stop()


class BootstrapCLICommand(CLICommand):
    @staticmethod
    @override
    def name() -> str:
        return "bootstrap"

    @staticmethod
    @override
    def help() -> str:
        return textwrap.dedent("""Bootstrap the network.

        Configures, starts, and waits for bootstrap, for all of the network
        nodes' configure and launch phases.""")

    @override
    def run(self, network: Network, ns: argparse.Namespace) -> None:
        network.bootstrap()


class VerifyCLICommand(CLICommand):
    def __init__(
        self,
        subparsers: _SubParsers,
        *,
        require_net_spec_group: Optional[bool] = None,
    ) -> None:
        super().__init__(subparsers, require_net_spec_group=require_net_spec_group)
        chutney.network_tests.verify.VerifyConfig.register_argparser(
            self._get_subparser()
        )

    @staticmethod
    @override
    def name() -> str:
        return "verify"

    @staticmethod
    @override
    def help() -> str:
        return textwrap.dedent("""Run the "verify" connectivity test.

        Assumes the network is already bootstrapped.""")

    @override
    def run(self, network: Network, ns: argparse.Namespace) -> None:
        chutney.network_tests.verify.run_test(
            network,
            config=chutney.network_tests.verify.VerifyConfig.from_envargs(ns=ns),
        )


_NETWORKS: Traversable = (
    importlib.resources.files("chutney").joinpath("data").joinpath("networks")
)


def getNetworks() -> list[str]:
    """Get names of built-in networks."""
    networks = [s.name for s in _NETWORKS.iterdir()]
    networks.sort()
    return networks


def _parse_args(
    argv: Optional[Sequence[str]],
    *,
    # Scoped environment variables that we pass explicitly to the commands that
    # use them. Implemented as default param values to emulate "static locals".
    _config_phase_env: envvars.EnvVarInt = envvars.EnvVarInt(
        "CHUTNEY_CONFIG_PHASE", 1, "(initial) node config phase"
    ),
    _launch_phase_env: envvars.EnvVarInt = envvars.EnvVarInt(
        "CHUTNEY_LAUNCH_PHASE", 1, "(initial) node launch phase"
    ),
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="chutney",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=envvars.EnvVar.help_all(),
    )
    # Register environment variables to be overridable via command-line.
    envvars.DATA_DIR.register_argparser(parser)
    subparsers: _SubParsers = parser.add_subparsers(dest="cmd")

    PrintPhasesCLICommand(subparsers, require_net_spec_group=False)
    SupportedCLICommand(subparsers, require_net_spec_group=False)
    InitCLICommand(subparsers, require_net_spec_group=True)
    ConfigureCLICommand(subparsers, config_phase_env=_config_phase_env)
    StatusCLICommand(subparsers, launch_phase_env=_launch_phase_env)
    RestartCLICommand(subparsers, launch_phase_env=_launch_phase_env)
    StartCLICommand(subparsers, launch_phase_env=_launch_phase_env)
    HupCLICommand(subparsers)
    WaitForBootstrapCLICommand(subparsers, launch_phase_env=_launch_phase_env)
    StopCLICommand(subparsers)
    BootstrapCLICommand(subparsers)
    VerifyCLICommand(subparsers)

    return parser.parse_args(argv)


def _network_from_args(ns: argparse.Namespace) -> Network:
    data_dir = envvars.DATA_DIR.get(ns=ns)
    node_config_defaults = NodeConfig.from_envargs(ns=ns)
    net_config = NetworkConfig.from_envargs(ns=ns)
    net_name = check_type(getattr(ns, "net", None), Optional[str])
    if net_name is not None:
        logger.info(f"Loading network config from built-in network name: '{net_name}'")
        return Network.from_network_script_name(
            net_name, config=net_config, node_config_defaults=node_config_defaults
        )
    script_path = check_type(getattr(ns, "net_from_script_path", None), Optional[Path])
    if script_path is not None:
        logger.info(
            f"Loading network config from chutney network script path: '{script_path}'"
        )
        return Network.from_network_script_path(
            script_path, config=net_config, node_config_defaults=node_config_defaults
        )

    assert ns.net_from_data_dir

    unresolved_nodes_dir = _get_absolute_nodes_path(data_dir=data_dir)
    nodes_dir = unresolved_nodes_dir.resolve()
    if nodes_dir == unresolved_nodes_dir:
        logger.info(f"Loading network from nodes dir: '{nodes_dir}'")
    else:
        logger.info(
            f"Loading network from nodes dir: '{unresolved_nodes_dir}'->'{nodes_dir}"
        )
    if not nodes_dir.exists():
        raise ChutneyError(
            f"Nodes dir '{nodes_dir}' doesn't exist."
            " Try providing a network name or setting CHUTNEY_DATA_DIR."
        )
    try:
        return Network.from_nodes_dir(nodes_dir)
    except Exception as e:
        raise ChutneyError(f"Couldn't load network from f'{nodes_dir}'") from e


def main(argv: Optional[Sequence[str]] = None) -> None:
    """A slightly more hermetic main could be called reasonably from python

    Raises an exception derived from `ChutneyError` on failure.
    """
    level = logging.DEBUG if envvars.DEBUG.get() else logging.INFO
    logging.basicConfig(level=level)

    args = _parse_args(argv)
    network = _network_from_args(args)
    cmd = check_type(args.cmd, CLICommand)
    cmd.run(network, args)


def __main__() -> None:
    """Raw main, suitable for use with `project.scripts` in `pyproject.toml`"""
    import traceback

    try:
        main()
    except ChutneyError as e:
        traceback.print_exception(None, value=e, tb=None, limit=0)
        sys.exit(1)
    sys.exit(0)
