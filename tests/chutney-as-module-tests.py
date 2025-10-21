#!/usr/bin/env python3

"""
Test chutney as a module.
"""

import dataclasses
import os
import unittest

from ipaddress import IPv4Address
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

    def test_offsetted_addresses(self) -> None:
        base = NodeConfig(
            # Override default of STATIC
            address_assignment_strategy=AddressAssignmentStrategy.OFFSETTED,
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

        # verify that the network actually works, as usual
        self.network.configure()
        self.network.bootstrap()
        verify.run_test(self.network)


if __name__ == "__main__":
    unittest.main()
