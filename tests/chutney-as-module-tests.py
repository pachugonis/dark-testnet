#!/usr/bin/env python3

"""
Test chutney as a module.
"""

import dataclasses
import ipaddress
import os
import unittest

from ipaddress import IPv4Address, IPv6Address
from typing_extensions import override

from chutney import TorNet
from chutney.TorNet import NodeConfig, AddressAssignmentStrategy
from chutney.network_tests import verify

_LOOPBACK_IPV4_NET = ipaddress.IPv4Network("127.0.0.0/8")
assert _LOOPBACK_IPV4_NET.is_private
assert _LOOPBACK_IPV4_NET.is_loopback

_PRIVATE_IPV4_NET = ipaddress.IPv4Network("192.168.0.0/16")
assert _PRIVATE_IPV4_NET.is_private
assert not _PRIVATE_IPV4_NET.is_loopback

_PRIVATE_IPV6_NET = ipaddress.IPv6Network("fc00::/7")
assert _PRIVATE_IPV6_NET.is_private
assert not _PRIVATE_IPV6_NET.is_loopback


def basic_net_configs(base: NodeConfig) -> list[NodeConfig]:
    """Return list of node configs for a ~minimal network"""
    Authority = dataclasses.replace(base, tag="a", authority=True, relay=True)
    ExitRelay = dataclasses.replace(base, tag="r", relay=True, exit=True)
    Client = dataclasses.replace(base, tag="c", client=True)
    return Authority.getN(4) + ExitRelay.getN(1) + Client.getN(1)


class Tests(unittest.TestCase):
    @override
    def setUp(self) -> None:
        self.network = TorNet.Network()
        self.network.init()

    @override
    def tearDown(self) -> None:
        self.network.stop()

    def _test_basic_with_launcher(
        self, launcher_backend: TorNet.LauncherBackend
    ) -> None:
        base = NodeConfig(
            controlling_pid=os.getpid(), launcher_backend=launcher_backend
        )
        self.network.addNodes(basic_net_configs(base))
        self.network.bootstrap()
        verify.run_test(self.network)

    def test_basic_local(self) -> None:
        self._test_basic_with_launcher(launcher_backend=TorNet.LauncherBackend.LOCAL)

    def test_basic_ssh(self) -> None:
        # This test assumes that sshd is running on localhost, and that the current
        # user has a locally unencrypted key authorized on localhost.
        #
        # e.g.:
        # ```
        # $ ssh-keygen
        # $ cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
        # ```
        self._test_basic_with_launcher(launcher_backend=TorNet.LauncherBackend.SSH)

    def test_offset_addresses_v4only(self) -> None:
        base = NodeConfig(
            # Override default of STATIC
            address_assignment_strategy=AddressAssignmentStrategy.OFFSET,
            ip=str(next(iter(_LOOPBACK_IPV4_NET.hosts()))),
            trusted_networks=[_LOOPBACK_IPV4_NET],
            controlling_pid=os.getpid(),
        )
        self.network.addNodes(basic_net_configs(base))

        # Verify that nodes got different addresses
        addresses: set[IPv4Address] = set()
        for node in self.network.nodes:
            ip = node.ip.as_optional()
            self.assertIsNotNone(ip)
            assert ip is not None  # for mypy
            self.assertNotIn(ip, addresses)
            addresses.add(ip)

        # ipv4-only networks typically work ok "out of the box" offsetting
        # addresses from the default node ip of localhost=127.0.0.1.
        # The 127.0.0.0/8 block is designated as loopback, and typically any
        # addresses in that block can be used without additional system
        # configuration.
        self.network.bootstrap()
        verify.run_test(self.network)

    def test_offset_addresses_v4v6(self) -> None:
        base = NodeConfig(
            # Override default of STATIC
            address_assignment_strategy=AddressAssignmentStrategy.OFFSET,
            controlling_pid=os.getpid(),
            # ipv6 only has a single loopback address; use a private address
            # range instead.
            ipv6_addr=str(next(iter(_PRIVATE_IPV6_NET.hosts()))),
        )
        self.network.addNodes(basic_net_configs(base))

        v6addresses: set[IPv6Address] = set()
        for node in self.network.nodes:
            ipv6 = node.ipv6_addr.as_optional()
            self.assertIsNotNone(ipv6)
            assert ipv6 is not None  # for mypy
            self.assertNotIn(ipv6, v6addresses)
            v6addresses.add(ipv6)

        self.network.configure(config_phase=1)
        # we *don't* attempt to bootstrap or use the network here, since the private
        # address space we're using is probably not set up on the host system.

    def test_services_unexposed_on_untrusted_nets(self) -> None:
        base = NodeConfig(
            address_assignment_strategy=AddressAssignmentStrategy.OFFSET,
            controlling_pid=os.getpid(),
            ip=str(next(iter(_PRIVATE_IPV4_NET.hosts()))),
            ipv6_addr=str(next(iter(_PRIVATE_IPV6_NET.hosts()))),
        )
        self.network.addNodes(basic_net_configs(base))
        for node in self.network.nodes:
            for endpoint_iter in [
                node.socksport_endpoints(),
                node.controlport_endpoints(),
                node.dnsport_endpoints(),
            ]:
                endpoints = list(endpoint_iter)
                # should *not* be bound to the assigned IPs, only the localhost IPs.
                for ip, _port in endpoints:
                    self.assertNotIn(ip, _PRIVATE_IPV4_NET)
                    self.assertNotIn(ip, _PRIVATE_IPV6_NET)
                    self.assertTrue(
                        ip.is_loopback,
                        f"Unsecured service bound to non-loopback ip {ip}",
                    )

    def test_services_exposed_on_trusted_private_nets(self) -> None:
        base = NodeConfig(
            address_assignment_strategy=AddressAssignmentStrategy.OFFSET,
            controlling_pid=os.getpid(),
            ip=str(next(iter(_PRIVATE_IPV4_NET.hosts()))),
            ipv6_addr=str(next(iter(_PRIVATE_IPV6_NET.hosts()))),
            trusted_networks=[_PRIVATE_IPV4_NET, _PRIVATE_IPV6_NET],
        )
        self.network.addNodes(basic_net_configs(base))
        for node in self.network.nodes:
            for endpoint_iter in [
                node.socksport_endpoints(),
                node.controlport_endpoints(),
                node.dnsport_endpoints(),
            ]:
                endpoints = list(endpoint_iter)
                # should be bound to the assigned IPs and the localhost IPs.
                for ip, _port in endpoints:
                    self.assertTrue(
                        ip.is_loopback
                        or ip in _PRIVATE_IPV4_NET
                        or ip in _PRIVATE_IPV6_NET
                    )


if __name__ == "__main__":
    unittest.main()
