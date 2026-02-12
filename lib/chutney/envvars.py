from __future__ import annotations

import ipaddress
import os
import platform

from abc import ABC, abstractmethod
from pathlib import Path
from typing import TypeVar, Generic
from typing_extensions import override

from chutney.Util import IPNetwork

C = TypeVar("C", covariant=True)


class EnvVar(Generic[C], ABC):
    # Track all instances, which we can use to generate documentation of all
    # environment variables.
    _all_instances: list[EnvVar[object]] = []

    def __init__(self, varname: str, default: C, help: str) -> None:
        self._varname = varname
        self._default = default
        self._help = help
        self._all_instances.append(self)

    def get(self) -> C:
        strval = os.environ.get(self._varname)
        if strval is None:
            return self._default
        try:
            return self.parse(strval)
        except ValueError:
            raise ValueError(
                f"Invalid value '{strval}' for environment variable '{self._varname}'"
            )

    def varname(self) -> str:
        return self._varname

    def help(self) -> str:
        return self._help

    @staticmethod
    def help_all() -> str:
        lines = []
        lines.append("Environment Variables:")
        for x in EnvVar._all_instances:
            lines.append(f"  {x._varname}: {x.help()} (default={x._default})")
        return "\n".join(lines)

    @staticmethod
    @abstractmethod
    def parse(x: str) -> C: ...


class EnvVarBool(EnvVar[bool]):
    @staticmethod
    @override
    def parse(x: str) -> bool:
        low = x.lower()
        if low in ["0", "false", "no", "n"]:
            return False
        if low in ["1", "true", "yes", "y"]:
            return True
        raise ValueError(f"invalid bool string: {x}")


class EnvVarInt(EnvVar[int]):
    @staticmethod
    @override
    def parse(x: str) -> int:
        return int(x)


class EnvVarStr(EnvVar[str]):
    @staticmethod
    @override
    def parse(x: str) -> str:
        return x


class EnvVarPath(EnvVar[Path]):
    @staticmethod
    @override
    def parse(x: str) -> Path:
        return Path(x)


class EnvVarIPNetworkList(EnvVar[list[IPNetwork]]):
    @staticmethod
    @override
    def parse(x: str) -> list[IPNetwork]:
        if not x:
            return []
        return [ipaddress.ip_network(n) for n in x.split(",")]


DEBUG = EnvVarBool("CHUTNEY_DEBUG", False, "Enable additional debug output")
CHUTNEY_PATH = EnvVarPath(
    "CHUTNEY_PATH",
    Path(os.getcwd()),
    "Path to the chutney source directory."
    + " Used as base of CHUTNEY_DATA_DIR if not already absolute."
    + " Default is current working dir.",
)
DATA_DIR = EnvVarPath(
    "CHUTNEY_DATA_DIR",
    Path("net"),
    "Directory in which 'nodes' directories are stored. (Absolute, or relative to CHUTNEY_PATH)",
)

CONFIG_PHASE = EnvVarInt("CHUTNEY_CONFIG_PHASE", 1, "(initial) node config phase")
LAUNCH_PHASE = EnvVarInt("CHUTNEY_LAUNCH_PHASE", 1, "(initial) node launch phase")

TRUSTED_NETWORKS = EnvVarIPNetworkList(
    "CHUTNEY_TRUSTED_NETWORKS",
    [],
    "Comma-separated list of trusted subnets. e.g. '192.168.0.0/24,fc00::/8'"
    + " Nodes with IPs on these will bind unsecured services to those IPs.",
)
LISTEN_ADDRESS = EnvVarStr(
    "CHUTNEY_LISTEN_ADDRESS",
    "127.0.0.1",
    "IPv4 address to listen on, if any.",
)
LISTEN_ADDRESS_V6 = EnvVarStr(
    "CHUTNEY_LISTEN_ADDRESS_V6",
    "",
    "IPv6 address to listen on, if any.",
)
DISABLE_IPV6 = EnvVarBool(
    "CHUTNEY_DISABLE_IPV6", False, "Whether to disable ipv6 support"
)
CONTROLLING_PID = EnvVarInt(
    "CHUTNEY_CONTROLLING_PID",
    0,
    "PID of controlling script (for __OwningControllerProcess)",
)
DNS_CONF = EnvVarStr(
    "CHUTNEY_DNS_CONF",
    "/etc/resolv.conf",
    "Path to resolver config file; e.g. for ServerDNSResolvConfFile."
    + " Set to empty-string to not set explicitly.",
)
TOR_SANDBOX = EnvVarBool(
    "CHUTNEY_TOR_SANDBOX",
    platform.system() == "Linux",
    "Whether to enable tor's sandbox",
)
ENABLE_CONTROLSOCKET = EnvVarBool(
    "CHUTNEY_ENABLE_CONTROLSOCKET",
    True,
    "Whether to enable a unix control socket (via ControlSocket in torrc)",
)
TOR = EnvVarStr("CHUTNEY_TOR", "tor", "Path to the tor executable.")
TOR_GENCERT = EnvVarStr(
    "CHUTNEY_TOR_GENCERT", "tor-gencert", "Path to the tor-gencert executable."
)
ARTI = EnvVarStr("CHUTNEY_ARTI", "arti", "Path to the arti executable.")
MIN_START_TIME = EnvVarInt(
    "CHUTNEY_MIN_START_TIME", 0, "Minimum start time before verifying"
)
BOOTSTRAP_TIME = EnvVarInt(
    "CHUTNEY_BOOTSTRAP_TIME",
    60,
    "How long in seconds should verify (and similar commands) wait for success",
)
START_TIME = EnvVarInt(
    "CHUTNEY_START_TIME",
    300,
    # You'd think *this* would be CHUTNEY_BOOTSTRAP_TIME. Maybe consolidate/fix
    # these sometime.
    "How long to wait for a launch-phase to bootstrap, e.g. in wait_for_bootstrap",
)
DATA_BYTES = EnvVarInt(
    "CHUTNEY_DATA_BYTES",
    5_000_000,
    "The amount of data to send between each source-sink pair in `verify`",
)
CONNECTIONS = EnvVarInt(
    "CHUTNEY_CONNECTIONS",
    1,
    "The number of times each client will connect in `verify`",
)
HS_MULTI_CLIENT = EnvVarBool(
    "CHUTNEY_HS_MULTI_CLIENT",
    False,
    "Whether *every* client connects to each HS in `verify`",
)
