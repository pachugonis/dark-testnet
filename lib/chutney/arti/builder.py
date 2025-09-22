# [pep 0536](https://peps.python.org/pep-0563/) - Lazy annotation eval via
# stringification.
from __future__ import annotations

import logging
import subprocess
import tomli_w

from pathlib import Path
from typeguard import check_type
from typing_extensions import override
from typing import Optional

import chutney.TorNet as TorNet
import chutney.arti.config as arti_config

from chutney.errors import (
    ChutneyError,
    ChutneyInternalError,
)
from chutney.Util import (
    mkdir_p,
    Option,
)

_HS_NICKNAME = "chutney_onion_service"

logger = logging.getLogger(__name__)


class LocalArtiNodeBuilder(TorNet.NodeBuilder):
    def __init__(self, node: TorNet.Node):
        TorNet.NodeBuilder.__init__(self)
        self._node = node

    def _debug_log_path(self) -> Path:
        return self._node.dir.joinpath("debug.log")

    def _info_log_path(self) -> Path:
        return self._node.dir.joinpath("info.log")

    def _gen_config_str(self, net: TorNet.Network) -> str:
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
        config = arti_config.tor_config(net)

        # We're adding several sections that we expect not to exist in `config`.
        # If they do exist, then we need to consider how to merge our updates here.
        def get_new_section(d: dict[str, object], name: str) -> dict[str, object]:
            assert name not in d
            return check_type(d.setdefault(name, {}), dict[str, object])

        get_new_section(config, "application").update(
            {
                "allow_running_as_root": True,
                "permit_debugging": True,
            }
        )
        get_new_section(config, "proxy").update(
            {
                "socks_listen": self._node.socksport.unwrap_or(0),
                "dns_listen": self._node.dnsport.unwrap_or(0),
            }
        )
        get_new_section(config, "logging").update(
            {
                "log_sensitive_information": True,
                "files": [
                    {
                        "path": str(self._debug_log_path()),
                        "filter": "debug",
                    },
                    {
                        "path": str(self._info_log_path()),
                        "filter": "info",
                    },
                ],
            }
        )
        if self._node.is_hs:
            ip = (
                self._node._config.ip.as_optional()
                or self._node._config.ipv6_addr.as_optional()
            )
            if not ip:
                raise ChutneyError("No usable local address")
            get_new_section(config, "onion_services").update(
                {
                    _HS_NICKNAME: {
                        "proxy_ports": [
                            [
                                self._node.hs_virtport.unwrap(),
                                f"{ip}:{self._node.hs_targetport.unwrap()}",
                            ]
                        ]
                    }
                }
            )

        # the storage section *does* exist in the base config, and we
        # intentionally overwrite it.
        config["storage"] = {
            "cache_dir": str(self._node.dir.joinpath("cache")),
            "state_dir": str(self._node.dir.joinpath("state")),
        }
        # The "tor_network.bridges" section may exist in the base config, and may contain
        # bridge entries.  Here we just override whether bridges are enabled at
        # all and leave the other settings in place.
        bridges = check_type(config.setdefault("bridges", {}), dict)
        bridges["enabled"] = bool(self._node._config.bridgeclient)

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

    @override
    def get_hs_hostname(self) -> Option[str]:
        if not self._node._config.hs:
            return Option(None)
        sp = subprocess.run(
            [
                self._node._config.arti,
                # Only available as a flag, not in config file.
                "--disable-fs-permission-checks",
                # Disable console logging, which otherwise goes to
                # stdout along with the actual output we want.
                # <https://gitlab.torproject.org/tpo/core/arti/-/issues/2024>
                "--log-level=",
                f"--config={str(self._node.torrc_path)}",
                "hss",
                f"--nickname={_HS_NICKNAME}",
                "onion-address",
                "--generate=if-needed",
            ],
            capture_output=True,
            text=True,
        )
        # TODO: recognize specific return codes?
        if sp.returncode != 0:
            logger.debug(
                f"Couldn't get onion address. stdout:{sp.stdout}\n\tstderr:{sp.stderr}"
            )
            return Option(None)
        return Option(sp.stdout.strip())
