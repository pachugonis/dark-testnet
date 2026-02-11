from __future__ import annotations

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
