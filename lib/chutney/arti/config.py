from __future__ import annotations

from typing import TYPE_CHECKING

from chutney.errors import ChutneyError
from chutney.Util import addr_and_port_str

if TYPE_CHECKING:
    import chutney.TorNet as TorNet


def tor_config(net: TorNet.Network) -> dict[str, object]:
    """Returns an configuration `arti-client` configuration for connecting to `net`.

    The returned configuration represents an `arti_client::TorClientConfig`
    suitable for clients of `net`.

    i.e. these are common options used by applications embedding arti via the
    `arti-client` Rust crate. It does
    *not* include configuration options specific to the `arti` command-line tool
    (Rust crate `arti::cfg::ArtiConfig`).
    """
    # From
    # <https://gitlab.torproject.org/tpo/core/tor/-/blob/d8ca300d5aa0e5727366f626fc692e34957ba4dc/src/feature/hs_common/shared_random_client.h#L33>
    SHARED_RANDOM_N_ROUNDS = 12
    # From
    # <https://gitlab.torproject.org/tpo/core/tor/-/blob/d8ca300d5aa0e5727366f626fc692e34957ba4dc/src/feature/hs_common/shared_random_client.h#L35>
    SHARED_RANDOM_N_PHASES = 2
    return {
        "storage": {
            "cache_dir": str(net.dir.joinpath("arti", "cache")),
            "state_dir": str(net.dir.joinpath("arti", "state")),
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
        "tor_network": {
            "fallback_caches": [
                {
                    "rsa_identity": auth.fingerprint.replace(" ", ""),
                    "ed_identity": auth.fingerprint_ed25519,
                    "orports": (
                        [addr_and_port_str(auth.ipv4, auth.orport)]
                        + (
                            [addr_and_port_str(auth.ipv6.unwrap(), auth.orport)]
                            if auth.ipv6.is_some()
                            else []
                        )
                    ),
                }
                for auth in net.authorities
                if auth.alt_dir_auth
            ],
            "authorities": {
                "v3idents": [
                    auth.v3id for auth in net.authorities if auth.alt_dir_auth
                ],
                "uploads": [
                    [addr_and_port_str(auth.ipv4, auth.dirport)]
                    + (
                        [addr_and_port_str(auth.ipv6.unwrap(), auth.dirport)]
                        if auth.ipv6.is_some()
                        else []
                    )
                    for auth in net.authorities
                    if auth.alt_dir_auth
                ],
                "downloads": [
                    [addr_and_port_str(auth.ipv4, auth.dirport)]
                    + (
                        [addr_and_port_str(auth.ipv6.unwrap(), auth.dirport)]
                        if auth.ipv6.is_some()
                        else []
                    )
                    for auth in net.authorities
                    if auth.alt_dir_auth
                ],
                "votes": [
                    [addr_and_port_str(auth.ipv4, auth.dirport)]
                    + (
                        [addr_and_port_str(auth.ipv6.unwrap(), auth.dirport)]
                        if auth.ipv6.is_some()
                        else []
                    )
                    for auth in net.authorities
                    if auth.alt_dir_auth
                ],
            },
        },
        "bridges": {
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
            ]
        },
        "override_net_params": {
            # When TestingTorNetwork is set, tor internally overrides hsdir_interval:
            # <https://gitlab.torproject.org/tpo/core/tor/-/blob/d8ca300d5aa0e5727366f626fc692e34957ba4dc/src/feature/hs/hs_common.c#L253>
            #
            # See also <https://gitlab.torproject.org/tpo/core/chutney/-/issues/40038>.
            "hsdir_interval": int(
                SHARED_RANDOM_N_ROUNDS
                * SHARED_RANDOM_N_PHASES
                * net.V3_AUTH_VOTING_INTERVAL
                / 60
            ),
        },
    }
