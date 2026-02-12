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

    @override
    def config_envvar(self) -> envvars.EnvVar[str]:
        return envvars.TOR

    @override
    def test_network_sh_hint(self) -> Optional[str]:
        return "set TOR_DIR, --tor-path, or --tor"


class TorGenCertBin(KnownBin):
    @override
    def name(self) -> str:
        return "tor-gencert"

    @override
    def config_envvar(self) -> envvars.EnvVar[str]:
        return envvars.TOR_GENCERT

    @override
    def test_network_sh_hint(self) -> Optional[str]:
        return "set TOR_DIR, --tor-path, or --tor-gencert"


class ArtiBin(KnownBin):
    @override
    def name(self) -> str:
        return "arti"

    @override
    def config_envvar(self) -> envvars.EnvVar[str]:
        return envvars.ARTI

    @override
    def test_network_sh_hint(self) -> Optional[str]:
        # TODO: we probably ought to add a test-network.sh command-line argument
        return None
