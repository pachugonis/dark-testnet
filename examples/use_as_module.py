#!/usr/bin/env python3
"""
Attempt to use chutney as a module.
"""

import dataclasses
import os

from chutney import TorNet
from chutney.TorNet import NodeConfig
from chutney.network_tests import verify

network = TorNet.Network()

base = NodeConfig(controlling_pid=os.getpid())
Authority = dataclasses.replace(base, tag="a", authority=True, relay=True)
ExitRelay = dataclasses.replace(base, tag="r", relay=True, exit=True)
Client = dataclasses.replace(base, tag="c", client=True)
network.addNodes(Authority.getN(4) + ExitRelay.getN(1) + Client.getN(1))

network.init()
network.configure(config_phase=1)
network.start(launch_phase=1)

# This has a tendency to timeout with the default of 60s.
network.wait_for_bootstrap(launch_phase=1, limit_secs=300)

verify.run_test(network)
network.stop()
