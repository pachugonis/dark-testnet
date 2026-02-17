import logging

from abc import ABC, abstractmethod
from typing import Optional
from typing_extensions import override

from chutney import envvars

_logger = logging.getLogger(__name__)


class KnownBin(ABC):
    """Metadata about an executable that we use.

    Encodes some information about how to configure the path of a particular
    executable. Used to generate user-friendly error messages in
    `errors.ChutneyMissingBinaryError`.
    """

    @abstractmethod
    def name(self) -> str:
        """User-friendly name for this bin"""
        ...

    @abstractmethod
    def config_envvar(self) -> envvars.EnvVar[str]:
        """Environment variable that can be set to location of this bin"""
        ...

    @abstractmethod
    def test_network_sh_hint(self) -> Optional[str]:
        """Alternative way(s) to set this bin when running test-network.sh"""
        ...


class TorBin(KnownBin):
    @override
    def name(self) -> str:
        return "tor"

    _TOR_ENV: envvars.EnvVarStr = envvars.EnvVarStr(
        "CHUTNEY_TOR", "tor", "Path to the tor executable."
    )

    @override
    def config_envvar(self) -> envvars.EnvVar[str]:
        return TorBin._TOR_ENV

    @override
    def test_network_sh_hint(self) -> Optional[str]:
        return "set TOR_DIR, --tor-path, or --tor"


class TorGenCertBin(KnownBin):
    @override
    def name(self) -> str:
        return "tor-gencert"

    _TOR_GENCERT_ENV: envvars.EnvVarStr = envvars.EnvVarStr(
        "CHUTNEY_TOR_GENCERT", "tor-gencert", "Path to the tor-gencert executable."
    )

    @override
    def config_envvar(self) -> envvars.EnvVar[str]:
        return TorGenCertBin._TOR_GENCERT_ENV

    @override
    def test_network_sh_hint(self) -> Optional[str]:
        return "set TOR_DIR, --tor-path, or --tor-gencert"


class ArtiBin(KnownBin):
    @override
    def name(self) -> str:
        return "arti"

    _ARTI_ENV: envvars.EnvVarStr = envvars.EnvVarStr(
        "CHUTNEY_ARTI", "arti", "Path to the arti executable."
    )

    @override
    def config_envvar(self) -> envvars.EnvVar[str]:
        return ArtiBin._ARTI_ENV

    @override
    def test_network_sh_hint(self) -> Optional[str]:
        # TODO: we probably ought to add a test-network.sh command-line argument
        return None
