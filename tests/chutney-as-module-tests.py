#!/usr/bin/env python3

"""
Test chutney as a module.
"""

import dataclasses
import os
import unittest

from ipaddress import IPv4Address, IPv6Address
from typing_extensions import override

from chutney import TorNet
from chutney.TorNet import NodeConfig, AddressAssignmentStrategy
from chutney.network_tests import verify


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

    @override
    def tearDown(self) -> None:
        self.network.stop()

    def test_basic(self) -> None:
        base = NodeConfig(controlling_pid=os.getpid())
        self.network.addNodes(basic_net_configs(base))
        self.network.configure()
        self.network.bootstrap()
        verify.run_test(self.network)

    def test_offset_addresses_v4only(self) -> None:
        base = NodeConfig(
            # Override default of STATIC
            address_assignment_strategy=AddressAssignmentStrategy.OFFSET,
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
        # addresses from 127.0.0.1. i.e. 127.0.0.2, 127.0.0.3, etc. are additional
        # working "localhost" addresses.
        self.network.configure()
        self.network.bootstrap()
        verify.run_test(self.network)

    def test_offset_addresses_v4v6(self) -> None:
        base = NodeConfig(
            # Override default of STATIC
            address_assignment_strategy=AddressAssignmentStrategy.OFFSET,
            controlling_pid=os.getpid(),
            ipv6_addr="::1",
        )
        self.network.addNodes(basic_net_configs(base))

        v6addresses: set[IPv6Address] = set()
        for node in self.network.nodes:
            ipv6 = node.ipv6_addr.as_optional()
            self.assertIsNotNone(ipv6)
            assert ipv6 is not None  # for mypy
            self.assertNotIn(ipv6, v6addresses)
            v6addresses.add(ipv6)

        self.network.configure()
        # we *don't* attempt to bootstrap or use the network here.
        # Experimentally, offsetting from ipv6 `::1` doesn't work out of the box
        # the way that offsetting from ipv4 127.0.0.1 does.
        #
        # We might still want this offsetting functionality for ipv6, but for it
        # to actually work would require some additional network setup.


if __name__ == "__main__":
    unittest.main()
