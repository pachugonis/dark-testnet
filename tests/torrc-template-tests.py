#!/usr/bin/env python3

import textwrap

from chutney import TorNet
from chutney.TorNet import NodeConfig

network = TorNet.Network()

# Generate configs for all torrc templates, using their legacy names.
# TODO: Drop the 'torrc' parameters, which are no longer required.
# Keeping them in the MR that removes the need for it, to keep the validatation
# they currently enable that the generated torrc is consistent with the legacy
# template name.
configs = [
    # Was: "authority-orport-v6.tmpl"
    NodeConfig(
        tag="a",
        authority=True,
        relay=True,
        ipv6_addr="[::1]",
    ),
    # Was: "authority.tmpl"
    NodeConfig(
        tag="a",
        authority=True,
        relay=True,
    ),
    # Was: "bridgeauthority.tmpl"
    NodeConfig(
        tag="ba",
        authority=True,
        relay=True,
        bridgeauthority=True,
    ),
    # Was: bridgeclient-obfs4.tmpl
    NodeConfig(
        tag="bc",
        client=True,
        bridgeclient=True,
        pt_transport="obfs4",
        # Managed proxies are incompatible with sandboxing
        sandbox=False,
    ),
    # Was: "bridgeclient.tmpl",
    NodeConfig(
        tag="bc",
        client=True,
        bridgeclient=True,
        # Managed proxies are incompatible with sandboxing
        sandbox=False,
    ),
    # Was: "bridge-obfs4.tmpl"
    NodeConfig(
        tag="br",
        bridge=True,
        pt_bridge=True,
        relay=True,
        pt_transport="obfs4",
        # Managed proxies are incompatible with sandboxing
        sandbox=False,
    ),
    # Was: "bridge.tmpl"
    NodeConfig(
        tag="br",
        bridge=True,
        relay=True,
    ),
    # Was: "bridge-v6.tmpl"
    NodeConfig(
        tag="br",
        bridge=True,
        relay=True,
        ipv6_addr="[::1]",
    ),
    # Was: "client_bwscanner.tmpl"
    NodeConfig(
        tag="c",
        client=True,
        use_microdescriptors=False,
        extra_raw_torrc=textwrap.dedent("""
            UseEntryGuards 0
            FetchDirInfoEarly 1
            FetchDirInfoExtraEarly 1
            FetchUselessDescriptors 1
            LearnCircuitBuildTimeout 0
            CircuitBuildTimeout 60
            ConnectionPadding 0
            __DisablePredictedCircuits 1
            __LeaveStreamsUnattached 1
            """),
    ),
    # Was: client-only-v6-md.tmpl
    NodeConfig(
        tag="c",
        client=True,
        ip=None,
        ipv6_addr="[::1]",
    ),
    # Was: client-only-v6.tmpl
    NodeConfig(
        tag="c",
        client=True,
        ip=None,
        ipv6_addr="[::1]",
        use_microdescriptors=False,
    ),
    # Was: "client.tmpl"
    NodeConfig(
        tag="c",
        client=True,
    ),
    # client, but with dns enabled
    NodeConfig(
        tag="c",
        client=True,
        enable_dnsport=True,
    ),
    # Was: hs-v3-only-v6-md.tmpl
    NodeConfig(
        tag="h",
        hs=True,
        ip=None,
        ipv6_addr="[::1]",
    ),
    # Was: "hs-v3-only-v6.tmpl"
    NodeConfig(
        tag="h",
        hs=True,
        ip=None,
        ipv6_addr="[::1]",
        use_microdescriptors=False,
    ),
    # Was: "hs-v3.tmpl"
    NodeConfig(
        tag="h",
        hs=True,
    ),
    # Was: "relay-MAB.tmpl"
    NodeConfig(
        tag="relayMAB",
        relay=True,
        extra_raw_torrc=textwrap.dedent("""
            MaxAdvertisedBandwidth 1 MBytes
            """),
    ),
    # Was: "relay-MBR.tmpl"
    NodeConfig(
        tag="relayMBR",
        relay=True,
        extra_raw_torrc=textwrap.dedent("""
            RelayBandwidthRate 1 MBytes
            """),
    ),
    # Was: "relay-non-dir.tmpl"
    NodeConfig(
        tag="r",
        relay=True,
    ),
    # Was: "relay-non-exit.tmpl"
    NodeConfig(
        tag="r",
        relay=True,
        exit=False,
    ),
    # Was: "relay-exit-v6-only.tmpl"
    NodeConfig(
        tag="r",
        relay=True,
        exit=True,
        # XXX clear ip?
        # do we really support v6-only exits?
        ipv6_addr="[::1]",
    ),
    # Was: "relay-orport-v6-non-exit.tmpl"
    NodeConfig(
        tag="r",
        relay=True,
        exit=False,
        ipv6_addr="[::1]",
    ),
    # Was: "relay.tmpl"
    NodeConfig(
        tag="r",
        relay=True,
        exit=True,
    ),
    # Was: "relay-v6.tmpl",
    NodeConfig(
        tag="r",
        relay=True,
        exit=True,
        ipv6_addr="[::1]",
    ),
    # Was: "single-onion-v3.tmpl"
    NodeConfig(
        tag="h",
        hs=True,
        hs_singlehop=True,
    ),
    # Was: "single-onion-v3-only-v6-md.tmpl"
    NodeConfig(
        tag="h",
        hs=True,
        ip=None,
        ipv6_addr="[::1]",
        hs_singlehop=True,
    ),
]

# Add the configs to the network, getting their corresponding Nodes.
network.addNodes(configs)
# Initialize a directory.
network.init()
# Configure the first phase of the network, generating the torrc files, and
# validating that they are well-formed.
# (It'd be nice to do all phases, but that may require *starting* launch_phase=1 nodes
# before we could configure config_phase=2 nodes, etc, which is heavier weight than
# we want this test to be)
network.configure(config_phase=1)

print("Passed")
