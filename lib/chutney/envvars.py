from __future__ import annotations

import argparse
import enum
import ipaddress
import logging
import os

from abc import ABC, abstractmethod
from pathlib import Path
from typing import TypeVar, Generic, Optional, cast
from typing_extensions import override

from chutney.Util import IPAddress, IPNetwork

logger = logging.getLogger(__name__)

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
        self._registered_argparser = False
        self._fetched = False

        # Multiple instances with the same variable name would defeat the
        # purpose a bit. Especially if they have conflicting types, help
        # strings, etc.
        assert not any(
            (iv._varname == varname for iv in self._all_instances)
        ), f"{varname} is already registered"

        # Register this instance
        EnvVar._all_instances.append(self)

    def _ns_name(self) -> str:
        """When registering an ArgumentParser, attribute name where result will be stored"""
        return self._flag_name().removeprefix("--").replace("-", "_")

    def _flag_name(self) -> str:
        """Flag name, when registering with an ArgumentParser"""
        return "--" + self._varname.removeprefix(EnvVar._PREFIX).lower().replace(
            "_", "-"
        )

    def register_argparser(self, parser: argparse.ArgumentParser) -> None:
        """Register this environment variable with an argparse.ArgumentParser

        This registers a command-line flag to support overriding the environment
        variable. Pass the namespace resulting from parsing the command-line
        parameters to `get` to actually do so.
        """
        if self._fetched:
            logger.warning(
                f"EnvVar {self.varname()}: Registering argparser, but already fetched value"
            )
        parser.add_argument(
            self._flag_name(),
            type=self.parse,
            dest=self._ns_name(),
            help=self.help() + f" (overrides {self._varname})",
        )
        self._registered_argparser = True

    def get(self, ns: Optional[argparse.Namespace] = None) -> C:
        """Retrieve the effective value.

        `ns` should only be provided if `register_argparser` was previously
        called, in which case `ns` is expected to be the resulting namespace
        after parsing the arguments. If `ns` has a value for this variable, it
        takes precedence over the environment variable.
        """
        self._fetched = True
        if self._registered_argparser:
            if ns is None:
                logger.warning(
                    f"EnvVar {self.varname()}: Registered argparser,"
                    " but retrieving without applying parse-result"
                )
            elif (val := getattr(ns, self._ns_name(), None)) is not None:
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

    def default(self) -> C:
        return self._default

    @staticmethod
    def help_all() -> str:
        lines = []
        lines.append("Environment Variables:")
        EnvVar._all_instances.sort(key=EnvVar.varname)
        for x in EnvVar._all_instances:
            lines.append(f"  {x._varname}: {x.help()} (default={x._default})")
        return "\n".join(lines)

    @abstractmethod
    def parse(self, x: str) -> C: ...


class EnvVarBool(EnvVar[bool]):
    @override
    def parse(self, x: str) -> bool:
        low = x.lower()
        if low in ["0", "false", "no", "n"]:
            return False
        if low in ["1", "true", "yes", "y"]:
            return True
        raise ValueError(f"invalid bool string: {x}")


class EnvVarInt(EnvVar[int]):
    @override
    def parse(self, x: str) -> int:
        return int(x)


class EnvVarStr(EnvVar[str]):
    @override
    def parse(self, x: str) -> str:
        return x


class EnvVarPath(EnvVar[Path]):
    @override
    def parse(self, x: str) -> Path:
        return Path(x)


class EnvVarIPAddress(EnvVar[IPAddress]):
    @override
    def parse(self, x: str) -> IPAddress:
        return ipaddress.ip_address(x)


class EnvVarIPNetworkList(EnvVar[list[IPNetwork]]):
    @override
    def parse(self, x: str) -> list[IPNetwork]:
        if not x:
            return []
        return [ipaddress.ip_network(n) for n in x.split(",")]


ENUM = TypeVar("ENUM", bound=enum.Enum)


class EnvVarEnum(Generic[ENUM], EnvVar[ENUM]):
    @override
    def help(self) -> str:
        t = type(self.default())
        return super().help() + " (choices: " + ",".join(x.name for x in t) + ")"

    @override
    def parse(self, x: str) -> ENUM:
        t = type(self.default())
        try:
            return t[x]
        except KeyError as ke:
            raise ValueError from ke


DEBUG = EnvVarBool("CHUTNEY_DEBUG", False, "Enable additional debug output")
DATA_DIR = EnvVarPath(
    "CHUTNEY_DATA_DIR",
    Path("net"),
    "Directory in which 'nodes' directories are stored. (Absolute, or relative to CHUTNEY_PATH)",
)

# TODO: it might be nice to register these with the command-line parser.
# Since they're relevant for multiple subcommands though, it's a little bit of
# work to scope them appropriately, ensure any command-line overrides are propagated
# correctly, etc. Leaving these for the moment.

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
