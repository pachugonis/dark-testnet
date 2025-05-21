# [pep 0536](https://peps.python.org/pep-0563/) - Lazy annotation eval via
# stringification.
from __future__ import annotations

import tomli_w

from typing_extensions import override
from typing import Optional

import chutney.TorNet as TorNet

from chutney.errors import (
    ChutneyError,
    ChutneyInternalError,
)
from chutney.Util import (
    mkdir_p,
    Option,
)


class LocalArtiNodeBuilder(TorNet.NodeBuilder):
    def __init__(self, node: TorNet.Node):
        TorNet.NodeBuilder.__init__(self)
        self._node = node

    def _gen_config_str(self, net: TorNet.Network) -> str:
        if not self._node._config.client:
            raise ChutneyInternalError("Arti non-client unimplemented")
        if self._node._config.exit:
            raise ChutneyInternalError("Arti exit unimplemented")
        if self._node._config.authority:
            raise ChutneyInternalError("Arti authority unimplemented")
        if self._node._config.relay:
            raise ChutneyInternalError("Arti relay unimplemented")
        if self._node._config.bridge:
            raise ChutneyInternalError("Arti bridge unimplemented")
        if self._node._config.pt_bridge:
            raise ChutneyInternalError("Arti pt_bridge unimplemented")
        config = {
            "application": {
                "allow_running_as_root": True,
            },
            "storage": {
                "cache_dir": str(self._node.dir.joinpath("cache")),
                "state_dir": str(self._node.dir.joinpath("state")),
            },
            "path_rules": {
                # These values disable enforce_distance entirely; we can replace them
                # with something like Tor's "EnforceDistinctSubnets 0" if Arti ever
                # implements it.
                "ipv4_subnet_family_prefix": 33,
                "ipv6_subnet_family_prefix": 129,
            },
            "address_filter": {
                # Allow the client to accept requests to connect to e.g. 127.0.0.1
                "allow_local_addrs": True
            },
            "proxy": {
                "socks_listen": self._node.socksport.unwrap(),
                "dns_listen": self._node.dnsport.unwrap_or(0),
            },
            "logging": {
                "files": [
                    {
                        "path": str(self._node.dir.joinpath("debug.log")),
                        "filter": "debug",
                    },
                    {
                        "path": str(self._node.dir.joinpath("info.log")),
                        "filter": "info",
                    },
                ],
            },
            "tor_network": {
                "fallback_caches": [
                    {
                        "rsa_identity": auth.fingerprint.replace(" ", ""),
                        "ed_identity": auth.fingerprint_ed25519,
                        "orports": (
                            [f"{auth.ipv4}:{auth.orport}"]
                            + (
                                [f"{auth.ipv6.unwrap()}:{auth.orport}"]
                                if auth.ipv6.is_some()
                                else []
                            )
                        ),
                    }
                    for auth in net.authorities
                    if auth.alt_dir_auth
                ],
                "authorities": [
                    {
                        "name": auth.nick,
                        "v3ident": auth.v3id,
                    }
                    for auth in net.authorities
                    if auth.alt_dir_auth
                ],
            },
        }
        if self._node._config.bridgeclient:
            config["bridges"] = {
                "enabled": "auto",
                "bridges": [
                    (
                        "{transport} {ip}:{port} {fp} {pt_extra}".format(
                            transport=bd.pt_transport.unwrap(),
                            ip=bd.ipaddr,
                            port=bd.port,
                            fp=bd.fingerprint,
                            pt_extra=bd.pt_extra.unwrap_or_raise(
                                ChutneyError("Missing pt_extra")
                            ),
                        )
                        if bd.pt_transport.is_some()
                        else "{ip}:{port} {fp}".format(
                            ip=bd.ipaddr,
                            port=bd.port,
                            fp=bd.fingerprint,
                        )
                    )
                    for bd in net.bridges
                ],
            }
        return tomli_w.dumps(config)

    @override
    def checkConfig(self, net: TorNet.Network) -> None:
        self._gen_config_str(net)

    @override
    def preConfig(self, net: TorNet.Network) -> None:
        pass

    @override
    def get_fingerprint(self) -> Option[str]:
        return Option(None)

    @override
    def get_fingerprint_ed25519(self) -> Option[str]:
        return Option(None)

    @override
    def config(self, net: TorNet.Network) -> None:
        config_str = self._gen_config_str(net)
        mkdir_p(self._node.dir)
        with self._node.torrc_path.open("w") as f:
            f.write(config_str)

    @override
    def postConfig(self, net: TorNet.Network) -> None:
        pass

    @override
    def isSupported(self, net: TorNet.Network) -> bool:
        # We don't implement any arti feature-probing yet
        return True

    @override
    def getAltAuthLines(
        self, hasbridgeauth: bool = False
    ) -> Optional[TorNet.AuthorityLine]:
        if self._node._config.authority:
            raise ChutneyInternalError("arti authorities unimplemented")
        return None

    @override
    def getBridgeLines(self) -> list[TorNet.BridgeLine]:
        if self._node._config.bridge:
            raise ChutneyInternalError("arti bridges unimplemented")
        return []
