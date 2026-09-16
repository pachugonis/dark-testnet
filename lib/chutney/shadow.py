"""
Utilities for setting up shadow simulations for chutney networks.

Also provides a CLI for generating chutney networks compatible with a multi-host
shadow configuration, the corresponding configuration, and running it under
shadow.  See --help.

For non-chutney-specific shadow functionality, see `chutney.util.shadow`.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import shlex
import shutil
import sys
import textwrap
import time
from pathlib import Path
from typing import Optional, Sequence
from typing_extensions import override

import shadowtools.config as scfg
from shadowtools import shadow_exec
from typeguard import check_type

import chutney.chutney_logging
import chutney.envvars
import chutney.network_tests.verify
import chutney.util.shadow as shadow_util
import chutney.TorNet

logger = logging.getLogger(__name__ if __name__ != "__main__" else __file__)


def _wrap_cmd_in_running_network(
    args: list[str], *, cwd: Optional[str] = None
) -> list[str]:
    """Wrap command `args` to be executed in the context of a running chutney network.

    Wraps the single command `args` in a shell script that changes to `cwd`,
    bootstraps a chutney network, executes the original `args`, tears down
    the chutney network, and exits with the exit code of `args`.

    This is useful for wrapping a command to be executed inside a shadow simulation.
    """
    cwd = cwd or os.getcwd()
    shell_script = f"""
    set -eu
    cd {cwd}
    teardown() {{
        chutney stop
    }}
    trap teardown EXIT
    chutney bootstrap
    {shlex.join(args)}
    """
    return ["sh", "-c", shell_script]


def generate_shadow_config(
    net: chutney.TorNet.Network,
    *,
    controller_hostname: str,
    controller_args: list[str],
    controller_ip: ipaddress.IPv4Address,
    network_graph: shadow_util.ShadowNetworkGraph,
) -> scfg.Config:
    """Generate a shadow configuration for the given network.

    A shadow host is generated for each chutney node, using the node's nick
    as the hostname. Each host runs an rpyc server (so that nodes using the
    RPYC_INSECURE launcher backend can be remotely started there).

    A "controller" host is also generated, and configured to run the command
    specified by `controller_args`.
    """
    hosts = {}

    rpyc_server = "rpyc_classic"
    if not shutil.which(rpyc_server):
        logger.warning(
            f"Couldn't find '{rpyc_server}' on PATH;"
            " simulation will most likely fail."
            " Try install python package 'rpyc'"
        )

    # Each host just runs the `rpyc_classic` server, which we use to start
    # processes etc. from the controlling host.
    for node in net.nodes:
        # Configure a Host in the shadow simulation for each chutney node.
        ip = str(node.ip.unwrap("missing IP"))
        hosts[node.nick] = scfg.Host(
            # All use the same network "node". shadow network nodes are
            # analogous to a router or ASN.
            network_node_id=network_graph.network_node_id_for_hostname(node.nick),
            ip_addr=ip,
            processes=[
                scfg.Process(
                    path=rpyc_server,
                    args=[f"--host={ip}"],
                    environment=dict(os.environ),
                    start_time=0,
                    expected_final_state="running",
                ),
            ],
        )
    # The "controller" host, from which we'll run chutney etc.
    hosts[controller_hostname] = scfg.Host(
        network_node_id=network_graph.network_node_id_for_hostname(controller_hostname),
        ip_addr=str(controller_ip),
        processes=[
            scfg.Process(
                path=controller_args[0],
                args=controller_args[1:],
                environment=dict(
                    **os.environ,
                    CHUTNEY_DATA_DIR=str(net.dir.parent),
                    SHADOW_HOSTNAME=controller_hostname,
                    SHADOW_IP=str(controller_ip),
                ),
                # Give a little (simulated) time for the rpyc servers to start listening
                start_time="1m",
            ),
        ],
    )
    return scfg.Config(
        general=scfg.General(
            stop_time="30m",
            # Work around busy loops and timing edge cases e.g. in python
            # stdlib.
            model_unblocked_syscall_latency=True,
            # Show progress
            progress=True,
            # Use a different seed each time to avoid getting deterministically
            # stuck into a flaky failure.
            # TODO: more-loudly expose what seed was used and add a CLI flag for
            # overriding.
            seed=int(time.time()),
        ),
        experimental=scfg.Experimental(
            # Increasing this from the default value improves performance a bit,
            # and improves stability of determinism (e.g. when adding a few
            # `write` syscalls for debugging)
            max_unapplied_cpu_latency="1ms",
            # These optimizations are intended for large simulations running on
            # dedicated hardware; they generally aren't suitable for smaller
            # simulations and on shared hardware.
            use_cpu_pinning=False,
            use_worker_spinning=False,
        ),
        network=scfg.Network(graph=scfg.Graph(type="gml", inline=network_graph.gml())),
        hosts=hosts,
    )


def _shadow_multihost_node_config_overrides(
    *,
    controller_ip: ipaddress.IPv4Address,
    starting_ip: ipaddress.IPv4Address,
    ip_network: ipaddress.IPv4Network,
) -> dict[str, object]:
    """NodeConfig params needed for multihost shadow compatibility

    `starting_ip` is the base IP address to use when allocating addresses.
    It must be contained in `ip_network`, which all nodes will mark as trusted
    (and therefore eligible to expose socks ports etc to).
    """
    assert starting_ip in ip_network
    return dict(
        # shadow doesn't support IPV6.
        disableipv6=True,
        ipv6_addr=None,
        # shadow doesn't support process sandboxing (seccomp).
        sandbox=False,
        # shadow doesn't support named sockets.
        enable_controlsocket=False,
        # We're putting each node on their own host, so we'll launch processes
        # via rpyc.
        launcher_backend=chutney.TorNet.LauncherBackend.RPYC_INSECURE,
        # We're putting each node on their own host, with their own listening IP.
        ip=str(starting_ip),
        address_assignment_strategy=chutney.TorNet.AddressAssignmentStrategy.OFFSET,
        # Assure chutney that we're ok with exposing insecure ports to this
        # network.
        trusted_networks=[ip_network],
        # Forward hidden service connections to the controller IP, which is
        # where we'll be running the `verify` test.
        hs_target_address=controller_ip,
    )


def _rewrite_network_for_shadow_multihost(
    network: chutney.TorNet.Network,
    *,
    ip_network: ipaddress.IPv4Network,
    controller_ip: ipaddress.IPv4Address,
    starting_ip: ipaddress.IPv4Address,
) -> chutney.TorNet.Network:
    """Rewrite a Network to be compatible with a shadow multihost simulation.

    `ip_network` should contain the IP addresses that the controller and
    host nodes will be assigned inside the simulation. It will be configured
    as a trusted network.
    `controller_ip` is meant to be the IP address of a host inside the simulation
    from which additional tests will be run. Any hidden services in the network
    will be configured to forward connections to this address.
    `starting_ip` is the base IP address that will be assigned to chutney nodes.
    """
    overrides = _shadow_multihost_node_config_overrides(
        ip_network=ip_network, controller_ip=controller_ip, starting_ip=starting_ip
    )
    # *Try* to detect if we're clobbering something that was explicitly set.
    # We won't detect if we're overwriting an option that was explicitly set to
    # the same value as the default value.
    default_node_config = chutney.TorNet.NodeConfig()
    for n in network.nodes:
        for k, override_value in overrides.items():
            orig_value = getattr(n.config, k)
            default_value = getattr(default_node_config, k)
            if orig_value != default_value and orig_value != override_value:
                logger.warning(
                    f"For node {n.nick},"
                    f" overriding key {k}"
                    f" from non-default value {orig_value}"
                    f" to {override_value}"
                )

    node_configs = [n.config for n in network.nodes]
    net_config = network.config

    node_configs = [c.specialize(**overrides) for c in node_configs]
    network = chutney.TorNet.Network(net_config)
    network.addNodes(node_configs)

    return network


def _generate_shadow_network_graph(
    network: chutney.TorNet.Network,
    *,
    controller_hostname: str,
    controller_ip: ipaddress.IPv4Address,
    node_latency: str,
    node_bandwidth: str,
    node_packet_loss: float,
    controller_latency: str = "1 ms",
    controller_bandwidth: str = "1 Gbit",
    controller_packet_loss: float = 0.0,
) -> shadow_util.ShadowNetworkGraph:
    """Generate a ShadowNetworkGraph for `network`.

    chutney network nodes are all assigned to a single shadow network node,
    such that they communicate with themselves and each-other with
    `node_latency`, `node_bandwidth`, and `node_packet_loss`.

    The `controller_hostname` is assigned to a separate shadow network node,
    such that it communicates with itself and with the chutney network nodes
    with `controller_latency`, `controller_bandwidth`, and `controller_packet_loss`.
    """
    default_net_label = "default-net"
    controller_net_label = "controller-net"
    # We let each chutney node be assigned to the default network node, which has
    # configurable link properties for communicating with other network nodes.
    #
    # The "controller" node, from which we run chutney and remotely
    # orchestrate the other nodes, is hard coded to have high bandwidth, and
    # low latency to itself and other nodes.
    return shadow_util.ShadowNetworkGraph(
        default_network_node=shadow_util.ShadowNetworkNode(
            label=default_net_label,
            host_bandwidth_up=node_bandwidth,
            host_bandwidth_down=node_bandwidth,
            self_edge_properties=shadow_util.ShadowNetworkEdgeProperties(
                latency=node_latency,
                packet_loss=node_packet_loss,
            ),
        ),
        addtl_network_nodes=[
            (
                shadow_util.ShadowNetworkNode(
                    label=controller_net_label,
                    host_bandwidth_up=controller_bandwidth,
                    host_bandwidth_down=controller_bandwidth,
                    self_edge_properties=shadow_util.ShadowNetworkEdgeProperties(
                        latency=controller_latency,
                        packet_loss=controller_packet_loss,
                    ),
                ),
                [controller_hostname],
            ),
        ],
        edges=[
            shadow_util.ShadowNetworkEdge(
                src_label=controller_net_label,
                dst_label=default_net_label,
                properties=shadow_util.ShadowNetworkEdgeProperties(
                    latency=controller_latency,
                    packet_loss=controller_packet_loss,
                ),
            ),
        ],
    )


def _run_e2e(
    network: chutney.TorNet.Network,
    node_latency: str,
    node_bandwidth: str,
    node_packet_loss: float,
    controller_args: list[str],
    data_dir: Optional[Path] = None,
) -> None:
    ip_network: ipaddress.IPv4Network = ipaddress.IPv4Network("192.168.0.0/24")
    host_ips = iter(ip_network.hosts())
    controller_ip = next(host_ips)
    starting_ip = next(host_ips)
    network = _rewrite_network_for_shadow_multihost(
        network,
        ip_network=ip_network,
        controller_ip=controller_ip,
        starting_ip=starting_ip,
    )

    # Init the *new* network, creating a new nodes directory as usual.
    # In principle it might be nice to support overwriting the
    # previous nodes directory in-place, to avoid creating an "extra" one
    # when the previous was generated specifically for this purpose, but
    # would probably open the door to subtle bugs and footguns.
    network.init(data_dir=data_dir)

    controller_hostname = "controller-host"
    network_graph = _generate_shadow_network_graph(
        network,
        controller_ip=controller_ip,
        controller_hostname=controller_hostname,
        node_latency=node_latency,
        node_bandwidth=node_bandwidth,
        node_packet_loss=node_packet_loss,
    )
    shadow_config = generate_shadow_config(
        network,
        controller_hostname=controller_hostname,
        controller_ip=controller_ip,
        controller_args=_wrap_cmd_in_running_network(controller_args),
        network_graph=network_graph,
    )
    shadow_config_path = network.dir.joinpath("shadow.yaml")

    with shadow_config_path.open("w") as shadow_yaml:
        # We avoid the 'pyyaml' serializer because shadow parses as yaml
        # 1.2, and pyyaml generates output compliant with yaml 1.1, but not
        # always yaml 1.2.
        # <https://github.com/yaml/pyyaml/issues/860>
        #
        # yaml 1.2 is designed to be a strict superset of json, so we can
        # use the json encoder instead.
        json.dump(
            shadow_config,
            shadow_yaml,
            indent=4,
        )
    shadow_path = Path("shadow")
    try:
        shadow_exec.run_shadow_watching_process(
            shadow_bin=shadow_path,
            shadow_config_path=shadow_config_path,
            watch_host=controller_hostname,
            dstdir=network.dir,
        )
    except FileNotFoundError:
        logger.error(
            f"shadow executable '{shadow_path}' not found."
            " Try installing from <https://github.com/shadow/shadow/>"
            " and ensuring it's on your path."
        )
        sys.exit(1)


class E2ECLICommand(chutney.TorNet.CLICommand):
    def __init__(self, subparsers: chutney.TorNet.SubParsers) -> None:
        super().__init__(
            subparsers=subparsers,
            require_net_spec_group=None,
        )
        subparser = self._get_subparser()
        subparser.add_argument(
            "--latency",
            help="network latency between chutney nodes",
            # Some not-entirely-trivial latency to exercise less-than-ideal
            # conditions. Experimentally, more than this starts causing failures
            # for some networks (which perhaps ought to be debugged).
            default="10 ms",
        )
        subparser.add_argument(
            "--host-bandwidth",
            help="bandwidth (up and down) for chutney nodes",
            # Experimentally, less than this starts causing failures for some
            # networks (which perhaps ought to be debugged).
            default="1 Gbit",
        )
        subparser.add_argument(
            "--packet-loss",
            type=float,
            help="packet loss between chutney nodes [0, 1]",
            default=0.0,
        )
        subparser.add_argument(
            "--controller-shell-code",
            type=str,
            help=(
                "shell code to run on 'controller' shadow virtual host."
                " It may make use of the following environment variables,"
                " which will already be set: "
                " CHUTNEY_DATA_DIR to point to the parent of the generated network dir;"
                " SHADOW_IP to the 'public' IP of the controller host;"
                " SHADOW_HOSTNAME to the hostname of the controller host."
            ),
            default="chutney verify --verify-listen-address=$SHADOW_IP --hs-multi-client=true",
        )

    @staticmethod
    @override
    def name() -> str:
        return "e2e"

    @staticmethod
    @override
    def help() -> str:
        return "Runs a chutney network and some given shell code under shadow."

    @classmethod
    @override
    def description(cls) -> str:
        # Note that argparse removes extra whitespace on display, so we can't do
        # multiple paragraphs, lists, etc.
        return textwrap.dedent("""
            Loads the "current" chutney network (CHUTNEY_DATA_DIR/nodes), writes
            a modified version and a shadow configuration file (shadow.yaml) to
            a *new* nodes directory, with a virtual host associated with each
            chutney node, as well as a "controller" host, which is configured to
            bootstrap the network and run the provided shell code. Finally,
            executes shadow using the generated configuration, with outputs
            saved to 'shadow.log' and 'shadow.data' in the network directory.
            """)

    @override
    def run(self, network: chutney.TorNet.Network, ns: argparse.Namespace) -> None:
        _run_e2e(
            network,
            node_latency=check_type(ns.latency, str),
            node_bandwidth=check_type(ns.host_bandwidth, str),
            node_packet_loss=check_type(ns.packet_loss, float),
            controller_args=["sh", "-c", check_type(ns.controller_shell_code, str)],
            data_dir=chutney.envvars.DATA_DIR.get(ns=ns),
        )


def main(argv: Optional[Sequence[str]] = None) -> None:
    argv = argv or sys.argv
    chutney.chutney_logging.logging_basic_config()

    parser = argparse.ArgumentParser(description=textwrap.dedent(f"""
            Test a chutney network under the shadow simulator.

            Normal usage should use the subcommand "e2e". See:
            `{argv[0]} e2e --help`
            """))
    chutney.envvars.DATA_DIR.register_argparser(parser)
    subparsers = chutney.TorNet.CLICommand.add_subparsers(parser)
    E2ECLICommand(subparsers)
    ns = parser.parse_args(args=argv[1:])
    chutney.TorNet.CLICommand.run_selected_subcommand(ns)


if __name__ == "__main__":
    main()
