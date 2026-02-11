#!/usr/bin/env python3

# Tests that a chutney built-in network configurations can be configured.
#
# This could be done a little more nicely using chutney as a module, but using
# the command-line interface isn't too bad, and tests a bit more end-to-end.
#
# Going through the `configure` step is sufficient to exercise that chutney
# generates at least legal configuration files. Going further (e.g. starting the
# network and waiting for bootstrap) would add substantial run time and
# potential flakiness.

import argparse
import os
import subprocess
import sys


def max_config_phase(network_name: str) -> int:
    prefix = "CHUTNEY_CONFIG_PHASES="
    output = subprocess.check_output(
        ["chutney", "print_phases", "--net", network_name], text=True
    )
    for line in output.splitlines():
        if line.startswith(prefix):
            return int(line.removeprefix(prefix))
    print("Couldn't parse print_phases output: ", output)
    sys.exit(1)


parser = argparse.ArgumentParser(
    prog="network-config-test",
    description="Generate and validate config files for a chutney network",
)
parser.add_argument("network")
args = parser.parse_args()
network_name = args.network

base_data_dir = os.environ.get("CHUTNEY_DATA_DIR", "net")

print("Testing network:", network_name)

env = dict(os.environ)
# Needed for mixed+hs-v3[-ipv6]; ignored for others.
env["CHUTNEY_OLD_TOR"] = env.get("CHUTNEY_TOR", "tor")
# Needed for networks with pluggable transports.
env["CHUTNEY_TOR_SANDBOX"] = "0"
# Put output into a directory named after the network, for easier
# debugging.
env["CHUTNEY_DATA_DIR"] = f"{base_data_dir}/{network_name}"

subprocess.check_call(["chutney", "init", "--net", network_name], env=env)

for phase in range(1, max_config_phase(network_name) + 1):
    print("Configure phase:", phase)

    env["CHUTNEY_CONFIG_PHASE"] = str(phase)

    # Flush to avoid child process output appearing out of order
    sys.stdout.flush()
    sys.stderr.flush()

    subprocess.check_call(["chutney", "configure"], env=env)
