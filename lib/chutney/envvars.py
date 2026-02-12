from __future__ import annotations

import platform

from abc import ABC, abstractmethod
from typing import Callable, TypeVar, Optional, Generic
from typing_extensions import override

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
        return getenv_type(
            self._varname, self._default, self.parse, str(type(self._default))
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
        return parse_boolenv(x)


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


# XXX wrapper to break circular import.
# Will be moved from chutney.Util.
def parse_boolenv(x: str) -> bool:
    import chutney.Util

    return chutney.Util.parse_boolenv(x)


T = TypeVar("T")


# XXX wrapper to break circular import.
# Will be moved from chutney.Util.
def getenv_type(
    env_var: str,
    default: T,
    type_: Callable[[str], T],
    type_name: Optional[str] = None,
) -> T:
    import chutney.Util

    return chutney.Util.getenv_type(env_var, default, type_, type_name)


CONFIG_PHASE = EnvVarInt("CHUTNEY_CONFIG_PHASE", 1, "(initial) node config phase")
LAUNCH_PHASE = EnvVarInt("CHUTNEY_LAUNCH_PHASE", 1, "(initial) node launch phase")

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
