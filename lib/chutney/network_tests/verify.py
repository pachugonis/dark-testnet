# [pep 0536](https://peps.python.org/pep-0563/) - Lazy annotation eval via
# stringification.
from __future__ import annotations

# Future imports for Python 2.7, mandatory in 3.0
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import time

import chutney
import chutney.Traffic

from ipaddress import ip_address
from typing import TYPE_CHECKING, Union

from . import NetworkTestFailure
from chutney.Util import IPAddress
from chutney.errors import ChutneyInternalError
from chutney import envvars

if TYPE_CHECKING:
    import chutney.TorNet as TorNet


LISTEN_PORT = 4747  # FIXME: Do better! Note the default exit policy.


def run_test(network: TorNet.Network) -> None:
    # Try to verify twice each consensus, but don't verify too fast
    V3_AUTH_VOTING_INTERVAL = network.V3_AUTH_VOTING_INTERVAL
    VERIFY_ATTEMPT_INTERVAL = V3_AUTH_VOTING_INTERVAL / 2.0 - 1.0
    TIMEOUT_INTERVAL = max(VERIFY_ATTEMPT_INTERVAL - 1.0, 5.0)

    wait_time = network.bootstrap_time
    start_time = time.time()
    end_time = start_time + wait_time
    print("Verifying data transmission: (retrying for up to %d seconds)" % wait_time)
    status = False
    # Keep on retrying the verify until it succeeds or times out
    now = start_time
    while not status and now < end_time:
        # TrafficTester connections time out after ~3 seconds
        # a TrafficTester times out after ~6 seconds if no data is being sent
        last_attempt_time = now
        status = _verify_traffic(network, timeout=TIMEOUT_INTERVAL)
        now = time.time()
        elapsed_attempt_time = now - last_attempt_time
        # Avoid madly spewing output if we fail immediately each time
        if not status:
            # We want at least 2 verify attempts per consensus interval
            sleep_time = VERIFY_ATTEMPT_INTERVAL - elapsed_attempt_time
            if sleep_time > 0:
                time.sleep(sleep_time)
                now = time.time()
    print("Transmission: %s" % ("Success" if status else "Failure"))
    if not status:
        print("Set CHUTNEY_DEBUG to diagnose.")
        raise NetworkTestFailure("All attempts failed")


def _verify_traffic(network: TorNet.Network, timeout: float = 5.0) -> bool:
    """Verify (parts of) the network by sending traffic through it
    and verify what is received."""
    # TODO: IPv6 SOCKSPorts, SOCKSPorts with IPv6Traffic, and IPv6 Exits
    # XXX don't hard-code this.
    # LISTEN_ADDR = network._dfltEnv["ip"]
    LISTEN_ADDR = ip_address("127.0.0.1")
    # The amount of data to send between each source-sink pair,
    # each time the source connects.
    # We create a source-sink pair for each (bridge) client to an exit,
    # and a source-sink pair for a (bridge) client to each hidden service.
    #
    # Default value of 5 MB should be large enough to exercise SENDMEs.
    DATALEN: int = envvars.DATA_BYTES.get()
    # Calculate the amount of random data we should use
    randomlen = _calculate_randomlen(DATALEN)
    reps = _calculate_reps(DATALEN, randomlen)
    # connection_count: the number of times each client will connect
    connection_count = envvars.CONNECTIONS.get()
    # sanity check
    if reps == 0:
        DATALEN = 0
    # Get the random data
    if randomlen > 0:
        with open("/dev/urandom", "rb") as randfp:
            tmpdata = randfp.read(randomlen)
    else:
        tmpdata = b""
    # now make the connections
    bind_to = (LISTEN_ADDR, LISTEN_PORT)
    tt = chutney.Traffic.TrafficTester(
        bind_to,
        data=tmpdata,
        timeout=timeout,
        repetitions=reps,
    )
    client_list = list(
        filter(
            lambda n: n.tag.startswith("c")
            or n.tag.startswith("bc")
            or n._config.client,
            network._nodes,
        )
    )
    exit_list = list(filter(lambda n: n._config.exit, network._nodes))
    hs_list = list(
        filter(
            lambda n: n.tag.startswith("h") or n._config.hs,
            network._nodes,
        )
    )
    if len(client_list) == 0:
        print("  Unable to verify network: no client nodes available")
        return False
    if len(exit_list) == 0 and len(hs_list) == 0:
        print("  Unable to verify network: no exit/hs nodes available")
        print("  Exit nodes must be declared 'relay=1, exit=1'")
        print("  HS nodes must be declared 'tag=\"hs\"'")
        return False
    print("Connecting:")
    # the number of tor nodes in paths which will send DATALEN data
    # if a node is used in two paths, we count it twice
    # this is a lower bound, as cannabilised circuits are one node longer
    total_path_node_count = 0
    total_path_node_count += _configure_exits(
        tt,
        bind_to,
        tmpdata,
        reps,
        client_list,
        exit_list,
        LISTEN_ADDR,
        LISTEN_PORT,
        connection_count,
    )
    # If 1, every client connects to every HS. If 0, one client connects to each
    # HS. (Clients choose an exit at random, so this doesn't apply to exits.)
    hs_multi_client = envvars.HS_MULTI_CLIENT.get()
    total_path_node_count += _configure_hs(
        tt,
        tmpdata,
        reps,
        client_list,
        hs_list,
        LISTEN_ADDR,
        LISTEN_PORT,
        connection_count,
        hs_multi_client,
    )
    print("Transmitting Data:")
    start_time = time.time()
    status = tt.run()
    end_time = time.time()
    # if we fail, don't report the bandwidth
    if not status:
        return status
    # otherwise, report bandwidth used, if sufficient data was transmitted
    _report_bandwidth(DATALEN, total_path_node_count, start_time, end_time)
    return status


# In order to performance test a tor network, we need to transmit
# several hundred megabytes of data or more. Passing around this
# much data in Python has its own performance impacts, so we provide
# a smaller amount of random data instead, and repeat it to DATALEN
def _calculate_randomlen(datalen: int) -> int:
    MAX_RANDOMLEN = 128 * 1024  # Octets.
    if datalen > MAX_RANDOMLEN:
        return MAX_RANDOMLEN
    else:
        return datalen


def _calculate_reps(datalen: int, replen: int) -> int:
    # sanity checks
    if datalen == 0 or replen == 0:
        return 0
    # effectively rounds datalen up to the nearest replen
    if replen < datalen:
        return int((datalen + replen - 1) / replen)
    else:
        return 1


# if there are any exits, each client / bridge client transmits
# via 4 nodes (including the client) to an arbitrary exit
# Each client binds directly to <CHUTNEY_LISTEN_ADDRESS>:LISTEN_PORT
# via an Exit relay
def _configure_exits(
    tt: chutney.Traffic.TrafficTester,
    bind_to: chutney.Traffic.HostPortTuple,
    tmpdata: bytes,
    reps: int,
    client_list: list[TorNet.Node],
    exit_list: list[TorNet.Node],
    LISTEN_ADDR: Union[str, IPAddress],
    LISTEN_PORT: int,
    connection_count: int,
) -> int:
    CLIENT_EXIT_PATH_NODES = 4
    exit_path_node_count = 0
    if len(exit_list) > 0:
        exit_path_node_count += (
            len(client_list) * CLIENT_EXIT_PATH_NODES * connection_count
        )
        for op in client_list:
            proxy = next(op.socksport_endpoints())
            print("  Exit to %s:%d via client %s" % (LISTEN_ADDR, LISTEN_PORT, proxy))
            for _ in range(connection_count):
                tt.add_client(f"exit via {op.nick}", bind_to, proxy)
    return exit_path_node_count


# The HS redirects .onion connections made to hs_hostname:hs_virtport
# to the Traffic Tester's CHUTNEY_LISTEN_ADDRESS:LISTEN_PORT
# an arbitrary client / bridge client transmits via 8 nodes
# (including the client and hs) to each hidden service
# Instead of binding directly to LISTEN_PORT via an Exit relay,
# we bind to hs_hostname:hs_virtport via a hidden service connection
def _configure_hs(
    tt: chutney.Traffic.TrafficTester,
    tmpdata: bytes,
    reps: int,
    client_list: list[TorNet.Node],
    hs_list: list[TorNet.Node],
    LISTEN_ADDR: Union[str, IPAddress],
    LISTEN_PORT: int,
    connection_count: int,
    hs_multi_client: bool,
) -> int:
    CLIENT_HS_PATH_NODES = 8
    hs_path_node_count = 0
    # Setup the connections from each client in hs_client_list to each hs
    for hs in hs_list:
        hs_client_list = client_list
        if hs._config.hs_restricted_discovery:
            hs_client_list = [
                c
                for c in hs_client_list
                if hs._config.tag
                in c._config.hs_client_restricted_discovery_server_tags
            ]
        if not hs_multi_client:
            # only use the first client in the list
            hs_client_list = hs_client_list[:1]
        hs_path_node_count += (
            len(hs_client_list) * CLIENT_HS_PATH_NODES * connection_count
        )

        hs_bind_to = (hs.hs_hostname.unwrap(), hs.hs_virtport.unwrap())
        # We currently require that all hidden services use the same port as `LISTEN_PORT`.
        # Otherwise we would need to extend the `TrafficTester` to bind to multiple ports,
        # or run multiple `TrafficTester`s.
        if hs.hs_targetport.as_optional() != LISTEN_PORT:
            raise ChutneyInternalError(
                f"Node {hs.nick} uses unsupported hs targetport {hs.hs_targetport}; "
                + f"expected {LISTEN_PORT}"
            )
        for client in hs_client_list:
            proxy = next(client.socksport_endpoints())
            print(
                "  HS to %s:%d (%s:%d) via client %s"
                % (
                    hs.hs_hostname.unwrap(),
                    hs.hs_virtport.unwrap(),
                    LISTEN_ADDR,
                    LISTEN_PORT,
                    proxy,
                )
            )
            for _ in range(connection_count):
                tt.add_client(f"{hs.nick} via {client.nick}", hs_bind_to, proxy)

    return hs_path_node_count


# calculate the single stream bandwidth and overall tor bandwidth
# the single stream bandwidth is the bandwidth of the
# slowest stream of all the simultaneously transmitted streams
# the overall bandwidth estimates the simultaneous bandwidth between
# all tor nodes over all simultaneous streams, assuming:
# * minimum path lengths (no cannibalized circuits)
# * unlimited network bandwidth (that is, localhost)
# * tor performance is CPU-limited
# This be used to estimate the bandwidth capacity of a CPU-bound
# tor relay running on this machine
def _report_bandwidth(
    data_length: int, total_path_node_count: int, start_time: float, end_time: float
) -> None:
    # otherwise, if we sent at least 5 MB cumulative total, and
    # it took us at least a second to send, report bandwidth
    MIN_BWDATA = 5 * 1024 * 1024  # Octets.
    MIN_ELAPSED_TIME = 1.0  # Seconds.
    cumulative_data_sent = total_path_node_count * data_length
    elapsed_time = end_time - start_time
    if cumulative_data_sent >= MIN_BWDATA and elapsed_time >= MIN_ELAPSED_TIME:
        # Report megabytes per second
        BWDIVISOR = 1024 * 1024
        single_stream_bandwidth = data_length / elapsed_time / BWDIVISOR
        overall_bandwidth = cumulative_data_sent / elapsed_time / BWDIVISOR
        print("Single Stream Bandwidth: %.2f MBytes/s" % single_stream_bandwidth)
        print("Overall tor Bandwidth: %.2f MBytes/s" % overall_bandwidth)
