# [pep 0536](https://peps.python.org/pep-0563/) - Lazy annotation eval via
# stringification.
from __future__ import annotations

import logging
import tomli_w

from pathlib import Path
from typeguard import check_type
from typing_extensions import override
from typing import TYPE_CHECKING, Optional

import chutney.arti.config as arti_config
import chutney.launcher

from chutney.dirinfo import AuthorityLine, BridgeLine
from chutney.errors import (
    ChutneyError,
    ChutneyInternalError,
)
from chutney.known_bins import ArtiBin
from chutney.node_builder import NodeBuilder
from chutney.Util import (
    addr_and_port_str,
    mkdir_p,
    Option,
)

if TYPE_CHECKING:
    import chutney.TorNet as TorNet

_HS_NICKNAME = "chutney_onion_service"

logger = logging.getLogger(__name__)


class LocalArtiNodeBuilder(NodeBuilder):
    def __init__(self, node: TorNet.Node):
        self._node = node

    @property
    def _launcher(self) -> chutney.launcher.Launcher:
        return self._node._launcher

    def _debug_log_path(self) -> Path:
        return self._node.dir.joinpath("debug.log")

    def _info_log_path(self) -> Path:
        return self._node.dir.joinpath("info.log")

    def _hs_client_key_dir(self) -> Path:
        return self._node.dir.joinpath("client-keys")

    def _gen_config(self, net: TorNet.Network) -> dict[str, object]:
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
                "socks_listen": [
                    addr_and_port_str(addr, port)
                    for (addr, port) in self._node.socksport_endpoints()
                ],
                "dns_listen": [
                    addr_and_port_str(addr, port)
                    for (addr, port) in self._node.dnsport_endpoints()
                ],
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
            ip = self._node.ip.as_optional() or self._node.ipv6_addr.as_optional()
            if not ip:
                raise ChutneyError("No usable local address")
            svc: dict[str, object] = {}
            svc["proxy_ports"] = [
                [
                    self._node.hs_virtport.unwrap(),
                    addr_and_port_str(ip, self._node.hs_targetport.unwrap()),
                ]
            ]
            if self._node._config.hs_restricted_discovery:
                svc["restricted_discovery"] = {
                    "enabled": True,
                    # We use a key dir here rather than static keys, so that we
                    # don't need to rewrite the config when adding individual
                    # keys.
                    "key_dirs": [{"path": str(self._hs_client_key_dir())}],
                }
            onion_services = get_new_section(config, "onion_services")
            onion_services[_HS_NICKNAME] = svc

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

        return config

    @override
    def checkConfig(self, net: TorNet.Network) -> None:
        # Just check that it doesn't fail to generate.
        self._gen_config(net)

    def _early_config_path(self) -> Path:
        return self._node.dir.joinpath("early_config.toml")

    def _generate_early_config(self, net: TorNet.Network) -> None:
        early_config: dict[str, object] = self._gen_config(net)
        early_config_str: str = tomli_w.dumps(early_config)
        with self._early_config_path().open("w") as f:
            f.write(
                "# Early version of config that doesn't depend on other node configs.\n"
            )
            f.write(
                "# Used e.g. when running arti during configuration to generate keys.\n"
            )
            f.write(early_config_str)

    @override
    def preConfig(self, net: TorNet.Network) -> None:
        mkdir_p(self._node.dir)
        self._generate_early_config(net)
        if self._node._config.hs_restricted_discovery:
            client_key_dir = self._hs_client_key_dir()
            client_key_dir.mkdir(mode=0o700)

    @override
    def get_fingerprint(self) -> Option[str]:
        return Option(None)

    @override
    def get_fingerprint_ed25519(self) -> Option[str]:
        return Option(None)

    @override
    def config(self, net: TorNet.Network) -> None:
        self._node.torrc_path.write_text(tomli_w.dumps(self._gen_config(net)))

    @override
    def postConfig(self, net: TorNet.Network) -> None:
        pass

    @override
    def isSupported(self, net: TorNet.Network) -> bool:
        # We don't implement any arti feature-probing yet
        return True

    @override
    def getAltAuthLines(self, hasbridgeauth: bool = False) -> Optional[AuthorityLine]:
        if self._node._config.authority:
            raise ChutneyInternalError("arti authorities unimplemented")
        return None

    @override
    def getBridgeLines(self) -> list[BridgeLine]:
        if self._node._config.bridge:
            raise ChutneyInternalError("arti bridges unimplemented")
        return []

    @override
    def get_hs_hostname(self) -> Option[str]:
        if not self._node._config.hs:
            return Option(None)
        sp = self._launcher.run(
            [
                self._node._config.arti,
                # Only available as a flag, not in config file.
                "--disable-fs-permission-checks",
                # Disable console logging, which otherwise goes to
                # stdout along with the actual output we want.
                # <https://gitlab.torproject.org/tpo/core/arti/-/issues/2024>
                "--log-level=",
                f"--config={str(self._early_config_path())}",
                "hss",
                f"--nickname={_HS_NICKNAME}",
                "onion-address",
                "--generate=if-needed",
            ],
            capture_strategy=chutney.launcher.Capture.SEPARATE,
            text=True,
            known_bin=ArtiBin(),
        )
        # TODO: recognize specific return codes?
        if sp.returncode != 0:
            logger.debug(
                f"Couldn't get onion address. stdout:{sp.stdout}\n\tstderr:{sp.stderr}"
            )
            return Option(None)
        return Option(sp.stdout.strip())

    @override
    def get_hs_client_pubkey(self, hs_address: str) -> str:
        # TODO: use `arti hsc key get`, as per
        # <https://gitlab.torproject.org/tpo/core/arti/-/blob/main/doc/hsc.md?ref_type=heads#generating-a-service-discovery-key>.
        sp = self._launcher.run(
            [
                self._node._config.arti,
                # Only available as a flag, not in config file.
                "--disable-fs-permission-checks",
                f"--config={str(self._node.torrc_path)}",
                "--log-level=warn",
                "hsc",
                "key",
                "get",
                "--batch",
                "--output=-",
            ],
            input=hs_address,
            capture_strategy=chutney.launcher.Capture.SEPARATE,
            text=True,
            known_bin=ArtiBin(),
        )
        if sp.returncode != 0:
            logger.warning(
                f"Couldn't get client pubkey.\n\tstdout:{sp.stdout}\n\tstderr:{sp.stderr}"
            )
            logger.warning("hint: was arti compiled with feature 'hsc'?")
            raise ChutneyError("Couldn't generate hs client pubkey")
        res = sp.stdout.strip()
        logger.debug("%s hs client key for %s: %s", self._node.nick, hs_address, res)
        return res

    @override
    def set_hs_client_pubkey(self, client_id: str, client_pubkey: str) -> None:
        path = self._hs_client_key_dir().joinpath(client_id + ".auth")
        if path.exists():
            logger.warning(f"Overwriting existing client key at {path}")
        path.write_text(client_pubkey)
