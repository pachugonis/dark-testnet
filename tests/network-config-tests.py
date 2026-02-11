#!/usr/bin/env python3

# Tests that all of chutney's built-in network configurations can be configured.
#
# This could be done a little more nicely using chutney as a module, but using
# the command-line interface isn't too bad, and tests a bit more end-to-end.
#
# Going through the `configure` step is sufficient to exercise that chutney
# generates at least legal configuration files. Going further (e.g. starting the
# network and waiting for bootstrap) would add substantial run time and
# potential flakiness.

import glob
import os
import subprocess

from pathlib import Path

network_names = [Path(s).name for s in glob.glob("lib/chutney/data/networks/*")]
# Use a consistent order, instead of the arbitrary order returned by glob.
network_names.sort()
# Verify that an arbitrary one is present, to validate that the above glob gave
# us something like what we expect.
assert "basic-min" in network_names

base_data_dir = os.environ.get("CHUTNEY_DATA_DIR", "net")

for network_name in network_names:
    subprocess.check_call(["./tests/network-config-test", network_name])
