#!/usr/bin/env python3
"""
A CLI for generating chutney networks compatible with a multi-host shadow configuration,
the corresponding configuration, and running it under shadow.
See --help.
"""

import atexit
import argparse
import ipaddress
import logging
import os
import shutil
import subprocess
import sys
import textwrap
import time
import yaml
from typing import Optional, Sequence
from typing_extensions import override

import shadowtools.config as scfg

import chutney.chutney_logging
import chutney.envvars
import chutney.network_tests.verify
import chutney.TorNet
from chutney.Util import IPAddress

logger = logging.getLogger(__name__ if __name__ != "__main__" else __file__)


def configure_shadow(
    net: chutney.TorNet.Network,
    controller_ip: ipaddress.IPv4Address,
) -> scfg.Config:
    current_script = os.path.abspath(__file__)
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
    for node in net._nodes:
        # Configure a Host in the shadow simulation for each chutney node.
        ip = str(node.ip.unwrap("missing IP"))
        hosts[node.nick] = scfg.Host(
            # All use the same network "node". shadow network nodes are
            # analogous to a router or ASN.
            network_node_id=0,
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
    hosts["controller"] = scfg.Host(
        network_node_id=0,
        ip_addr=str(controller_ip),
        processes=[
            scfg.Process(
                # Start *this script*, invoking `ControllerNodeCLICommand`
                path=current_script,
                args=[
                    f"--data-dir={net.dir.parent}",
                    ControllerNodeCLICommand.name(),
                    f"--verify-listen-address={str(controller_ip)}",
                ],
                environment=dict(os.environ),
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
        network=scfg.Network(graph=scfg.Graph(type="1_gbit_switch")),
        hosts=hosts,
    )


def _shadow_multihost_node_config_overrides(
    controller_ip: IPAddress,
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


class ControllerNodeCLICommand(chutney.TorNet.CLICommand):
    def __init__(self, subparsers: chutney.TorNet.SubParsers) -> None:
        super().__init__(
            subparsers=subparsers,
            require_net_spec_group=None,
        )
        chutney.network_tests.verify.VerifyConfig.register_argparser(
            self._get_subparser()
        )

    @staticmethod
    @override
    def name() -> str:
        return "controller-node"

    @staticmethod
    @override
    def help() -> str:
        return "From inside shadow, run the test"

    @override
    def run(self, network: chutney.TorNet.Network, ns: argparse.Namespace) -> None:
        atexit.register(network.stop)
        network.bootstrap()

        verify_config = chutney.network_tests.verify.VerifyConfig.from_envargs(ns=ns)
        verify_config.hs_multi_client = True
        chutney.network_tests.verify.run_test(network, config=verify_config)


class E2ECLICommand(chutney.TorNet.CLICommand):
    def __init__(self, subparsers: chutney.TorNet.SubParsers) -> None:
        ip_network = ipaddress.IPv4Network("192.168.0.0/24")
        host_ips = iter(ip_network.hosts())
        controller_ip = next(host_ips)
        starting_ip = next(host_ips)
        overrides = _shadow_multihost_node_config_overrides(
            controller_ip=controller_ip, starting_ip=starting_ip, ip_network=ip_network
        )
        super().__init__(
            subparsers=subparsers,
            require_net_spec_group=True,
            node_config_overrides=overrides,
        )
        self._controller_ip = controller_ip

    @staticmethod
    @override
    def name() -> str:
        return "e2e"

    @staticmethod
    @override
    def help() -> str:
        return "Run the test"

    @override
    def run(self, network: chutney.TorNet.Network, ns: argparse.Namespace) -> None:
        network.init(data_dir=chutney.envvars.DATA_DIR.get(ns=ns))
        shadow_config = configure_shadow(
            network,
            controller_ip=self._controller_ip,
        )
        shadow_config_path = network.dir.joinpath("shadow.yaml")
        with shadow_config_path.open("w") as shadow_yaml:
            yaml.dump(shadow_config, stream=shadow_yaml)
        shadow_path = "shadow"
        try:
            subprocess.check_call(
                [
                    shadow_path,
                    "--data-directory=" + str(network.dir.joinpath("shadow.data")),
                    str(shadow_config_path),
                ],
                stdout=network.dir.joinpath("shadow.log").open("w"),
            )
        except FileNotFoundError:
            logger.error(
                f"shadow executable '{shadow_path}' not found."
                " Try installing from <https://github.com/shadow/shadow/>"
                " and ensuring it's on your path."
            )
            raise


def main(argv: Optional[Sequence[str]] = None) -> None:
    argv = argv or sys.argv
    chutney.chutney_logging.logging_basic_config()

    parser = argparse.ArgumentParser(description=textwrap.dedent(f"""
            Test a chutney network under the shadow simulator.

            Normal usage should use the subcommand "e2e". e.g.
            `{argv[0]} e2e --net basic`
            """))
    chutney.envvars.DATA_DIR.register_argparser(parser)
    subparsers = chutney.TorNet.CLICommand.add_subparsers(parser)
    E2ECLICommand(subparsers)
    ControllerNodeCLICommand(subparsers)
    ns = parser.parse_args(args=argv[1:])
    chutney.TorNet.CLICommand.run_selected_subcommand(ns)


if __name__ == "__main__":
    main()
