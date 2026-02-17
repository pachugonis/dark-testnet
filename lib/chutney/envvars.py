from __future__ import annotations

import argparse
import ipaddress
import os
import platform

from abc import ABC, abstractmethod
from pathlib import Path
from typing import TypeVar, Generic, Optional, cast
from typing_extensions import override

from chutney.Util import IPNetwork

C = TypeVar("C", covariant=True)


class EnvVar(Generic[C], ABC):
    # Track all instances, which we can use to generate documentation of all
    # environment variables.
    _all_instances: list[EnvVar[object]] = []

    # Mandatory prefix. We require the caller to include this rather than
    # adding it ourselves to make the individual env-var names grep-able.
    _PREFIX = "CHUTNEY_"

    def __init__(self, varname: str, default: C, help: str) -> None:
        assert varname.startswith(EnvVar._PREFIX)
        self._varname = varname
        self._default = default
        self._help = help

        # Multiple instances with the same variable name would defeat the
        # purpose a bit. Especially if they have conflicting types, help
        # strings, etc.
        assert not any(
            (iv._varname == varname for iv in self._all_instances)
        ), f"{varname} is already registered"

        # Register this instance
        EnvVar._all_instances.append(self)

        # Initialized in `register_argparser`
        self._flag_name: Optional[str] = None
        self._ns_name: Optional[str] = None

    def register_argparser(self, parser: argparse.ArgumentParser) -> None:
        """Register this environment variable with an argparse.ArgumentParser

        This registers a command-line flag to support overriding the environment
        variable. Pass the namespace resulting from parsing the command-line
        parameters to `get` to actually do so.
        """
        self._flag_name = "--" + self._varname.removeprefix(
            EnvVar._PREFIX
        ).lower().replace("_", "-")
        parser.add_argument(
            self._flag_name,
            type=self.parse,
            help=self.help() + f" (overrides {self._varname})",
        )
        # The name of the attribute where we expect the parser to store the
        # provided argument, if any.
        self._ns_name = self._flag_name.removeprefix("--").replace("-", "_")

    def get(self, ns: Optional[argparse.Namespace] = None) -> C:
        """Retrieve the effective value.

        `ns` should only be provided if `register_argparser` was previously
        called, in which case `ns` is expected to be the resulting namespace
        after parsing the arguments. If `ns` has a value for this variable, it
        takes precedence over the environment variable.
        """
        if (ns_name := self._ns_name) is not None and (
            val := getattr(ns, ns_name, None)
        ) is not None:
            # Tell mypy to trust that val is of type `C`.
            # It *should* be, *assuming* that the namespace provided to us was
            # actually generated from a parser previously passed to
            # `register_argparser`.  It'd be nice to use `isinstance` or
            # `check_type` to validate it, but those don't support using a type
            # variable.
            return cast("C", val)
        if (strval := os.environ.get(self._varname)) is not None:
            try:
                return self.parse(strval)
            except ValueError:
                raise ValueError(
                    f"Invalid value '{strval}' for environment variable '{self._varname}'"
                )
        return self._default

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
DATA_DIR = EnvVarPath(
    "CHUTNEY_DATA_DIR",
    Path("net"),
    "Directory in which 'nodes' directories are stored. (Absolute, or relative to CHUTNEY_PATH)",
)

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
