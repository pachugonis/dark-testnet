# [pep 0536](https://peps.python.org/pep-0563/) - Lazy annotation eval via
# stringification.
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional

from chutney.dirinfo import (
    AuthorityLine,
    BridgeLine,
)
from chutney.Util import Option

if TYPE_CHECKING:
    from chutney.TorNet import Network


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
