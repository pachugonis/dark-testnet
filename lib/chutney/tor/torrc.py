from __future__ import annotations

import textwrap

from typing import TYPE_CHECKING, Iterable, Iterator, Tuple

from chutney.errors import ChutneyError
from chutney.Util import find_executable_on_path, addr_and_port_str, IPAddress

if TYPE_CHECKING:
    import chutney.TorNet as TorNet


def _family_member_fps(node: TorNet.Node) -> Iterable[str]:
    fp_set: set[str] = set()
    for family_name in node._config.families:
        fp_set.update(
            (
                other.fingerprint.unwrap()
                for other in node._network.family_members[family_name]
            )
        )
    return fp_set


def _directive_for_endpoints(
    directive: str, endpoints: Iterator[Tuple[IPAddress, int]]
) -> str:
    res = ""
    for addr, port in endpoints:
        res += f"{directive} {addr_and_port_str(addr, port)}\n"
    if not res:
        # Explicitly disable
        return f"{directive} 0\n"
    return res


def format(n: TorNet.Node, tor_version: str) -> str:
    """
    Returns the contents of a torrc config file for the given node.
    """
    res = textwrap.dedent(f"""
        TestingTorNetwork 1

        ## Rapid Bootstrap Testing Options ##
        # These typically launch a working minimal Tor network in ~20s
        # These parameters make tor networks bootstrap fast,
        # but can cause consensus instability and network unreliability
        # (Some are also bad for security.)
        #
        # We need at least 3 descriptors to build circuits.
        # In a 3 relay network, 0.67 > 2/3, so we try hard to get 3 descriptors.
        # In larger networks, 0.67 > 2/N, so we try hard to get >=3 descriptors.
        PathsNeededToBuildCircuits 0.67
        TestingDirAuthVoteExit *
        TestingDirAuthVoteHSDir *
        V3AuthNIntervalsValid 2

        ## Always On Testing Options ##
        # We enable TestingDirAuthVoteGuard to avoid Guard stability requirements
        TestingDirAuthVoteGuard *
        # We set TestingMinExitFlagThreshold to 0 to avoid Exit bandwidth requirements
        TestingMinExitFlagThreshold 0
        # VoteOnHidServDirectoriesV2 needs to be set for HSDirs to get the HSDir flag
        #Default VoteOnHidServDirectoriesV2 1

        ## Options that we always want to test ##
        DataDirectory {n.dir}
        ConnLimit {n._config.connlimit}
        Nickname {n.nick}
        # Let tor close connections gracefully before exiting
        ShutdownWaitLength 2
        DisableDebuggerAttachment 0

        AddressDisableIPv6 {int(n._config.disableipv6)}
        # Use ControlSocket rather than ControlPort unix: to support older tors
        ControlSocket {n.controlsocket or 0}
        CookieAuthentication 1
        PidFile {n.pidfile}

        Log notice file {n.dir}/notice.log
        Log info file {n.dir}/info.log
        # Turn this off to save space
        #Log debug file {n.dir}/debug.log
        ProtocolWarnings 1
        SafeLogging 0
        LogTimeGranularity 1

        # Options that we can disable at runtime, based on n vars

        # Use tor's sandbox. Defaults to 1 on Linux, and 0 on other platforms.
        # Use CHUTNEY_TOR_SANDBOX=0 to disable, if tor's sandbox doesn't work with
        # your glibc.
        Sandbox {int(n._config.sandbox)}

        # Ask all child tor processes to exit when chutney's test-network.sh exits
        # (if the CHUTNEY_*_TIME options leave the network running, this option is
        # disabled)
        {n._config.owning_controller_process}

        UseMicrodescriptors {int(n._config.use_microdescriptors)}
        """)
    res += _directive_for_endpoints("SocksPort", n.socksport_endpoints())
    res += _directive_for_endpoints("DnsPort", n.dnsport_endpoints())
    res += _directive_for_endpoints("ControlPort", n.controlport_endpoints())
    if (
        "0.4.9.1-alpha-dev" in tor_version or "0.4.9.2-alpha-dev" in tor_version
    ) and n._config.pt_transport:
        res += "# Work around tor#41088\n"
        res += "RunAsDaemon 0\n"
    else:
        res += "RunAsDaemon 1\n"
    if n.ip.is_some():
        if n._config.hs or n._config.relay:
            res += f"Address {n.ip.unwrap()}\n"
    else:
        if n._config.client or n._config.hs:
            res += "ClientUseIPv4 0\n"
    if n._config.relay:
        ip = n.ip.unwrap_or_raise(
            lambda: ChutneyError("'relay' set with no ipv4 address")
        )
        # Note that explicitly specifying the ipv4 address instead of just the
        # port means that this will only bind to this *ipv4* address.
        # We potentially enable ipv6 separately below.
        res += f"OrPort {addr_and_port_str(ip, n.orport)}\n"
        if n.ipv6_addr.is_some():
            res += f"OrPort {addr_and_port_str(n.ipv6_addr.unwrap(), n.orport)}\n"
    if n._config.hs:
        res += textwrap.dedent(f"""
            HiddenServiceDir {n.dir.joinpath(n._config.hs_directory)}

            # Redirect requests to the port used by chutney verify
            HiddenServicePort {n.hs_virtport.unwrap()} 127.0.0.1:{n.hs_targetport.unwrap()}

            # v3 is the only current supported version.
            HiddenServiceVersion 3
            """)
        if n._config.hs_singlehop:
            res += textwrap.dedent(f"""
                # Make this hidden service instance a Single Onion Service
                HiddenServiceSingleHopMode 1
                HiddenServiceNonAnonymousMode 1

                # Log only the messages we need to confirm that the Single Onion server is
                # making one-hop circuits, and to see any errors or major issues
                # To confirm one-hop intro and rendezvous circuits, look for
                # rend_service_intro_has_opened and rend_service_rendezvous_has_opened, and
                # check the length of the circuit in the next line.
                Log notice [rend,bug]info file {n.dir}/single-onion.log

                # Disable preemtive circuits, a Single Onion doesn't need them (except for
                # descriptor posting).
                # This stalls at bootstrap due to #17359.
                #__DisablePredictedCircuits 1
                # A workaround is to set:
                LongLivedPorts
                # This disables everything except hidden service preemptive 3-hop circuits.
                # See #17360.
                """)
    for auth in n._network.authorities:
        directive: str
        if auth.alt_dir_auth and (auth.alt_bridge_auth or not n._network.hasbridgeauth):
            # Generally 'DirAuthority' means to treat as both a dir-auth and a
            # bridge-auth.
            #
            # tor rejects configurations with TestingTorNetwork that don't have
            # some 'DirAuthority' or both of 'AlternateBridgeAuthority' and
            # 'AlternateDirAuthority', so if there are no true bridge auths in
            # the network we use 'DirAuthority' here.
            #
            # We *don't* artificially add the 'bridge' flag below though. It
            # appears to be unnecessary and results in logged warnings due to
            # the authority not actually being configured as a bridge auth.
            directive = "DirAuthority"
        elif auth.alt_bridge_auth:
            directive = "AlternateBridgeAuthority"
        else:
            assert auth.alt_dir_auth
            directive = "AlternateDirAuthority"
        # This is currently ~always "no-v2"; none of the built-in templates or
        # networks override it.
        flags = auth.extra_flags.copy()
        flags.append(f"orport={auth.orport}")
        if auth.alt_bridge_auth:
            flags.append("bridge")
        if auth.alt_dir_auth:
            flags.append(f"v3ident={auth.v3id}")
        if auth.ipv6.is_some():
            flags.append(f"ipv6={addr_and_port_str(auth.ipv6.unwrap(), auth.orport)}")
        res += f"{directive} {auth.nick} {' '.join(flags)}"
        res += f" {addr_and_port_str(auth.ipv4, auth.dirport)} {auth.fingerprint}\n"
    if n._config.relay:
        res += textwrap.dedent(f"""
            ExitRelay {int(n._config.exit)}

            # These options are set here so they apply to IPv4 and IPv6 Exits
            #
            # Tell Exits to avoid using DNS: otherwise, chutney will fail if DNS fails
            # (Chutney only accesses 127.0.0.1 and ::1, so it doesn't need DNS)
            ServerDNSDetectHijacking 0
            ServerDNSTestAddresses
            # If this option is /dev/null, or any other empty or unreadable file, tor exits
            # will not use DNS. Otherwise, DNS is enabled with this config.
            # (If the following line is commented out, tor uses /etc/resolv.conf.)
            {n._config.server_dns_resolv_conf}

            DirPort {n.dirport.unwrap_or(0)}
            """)
    family_member_fps = _family_member_fps(n)
    if family_member_fps:
        res += "MyFamily {}\n".format(", ".join(family_member_fps))
    if n._network.family_ids:
        for fid in n._config.families:
            res += f"FamilyId {n._network.family_ids[fid]}\n"
    if n._config.exit:
        if not n._config.relay:
            raise ChutneyError("'exit' set without 'relay'")
        res += textwrap.dedent("""
            # 1. Allow exiting to IPv4 localhost and private networks by default
            # -------------------------------------------------------------

            # Each IPv4 tor instance is configured with Address 127.0.0.1 by default
            ExitPolicy accept 127.0.0.0/8:*

            # If you only want tor to connect to localhost, disable these lines:
            # This may cause network failures in some circumstances
            ExitPolicyRejectPrivate 0
            ExitPolicy accept private:*

            # 2. Optionally: Allow exiting to the entire IPv4 internet on HTTP(S)
            # -------------------------------------------------------------------

            # 2. or 3. are required to work around #11264 with microdescriptors enabled
            # "The core of this issue appears to be that the Exit flag code is
            #  optimistic (just needs a /8 and 2 ports), but the microdescriptor
            #  exit policy summary code is pessimistic (needs the entire internet)."
            # An alternative is to disable microdescriptors and use regular
            # descriptors, as they do not suffer from this issue.
            #ExitPolicy accept *:80
            #ExitPolicy accept *:443

            # 3. Optionally: Accept all IPv4 addresses, that is, the public internet
            # ----------------------------------------------------------------------
            ExitPolicy accept *:*

            # 4. Finally, reject all IPv4 addresses which haven't been permitted
            # ------------------------------------------------------------------
            ExitPolicy reject *:*
            """)
    if n._config.exit and n.ipv6_addr.is_some():
        if not n._config.relay:
            raise ChutneyError(f"'exit' set without 'relay' in node {n.nick}")
        res += textwrap.dedent("""
            # 1. Allow exiting to IPv6 localhost and private networks by default
            # ------------------------------------------------------------------
            IPv6Exit 1

            # Each IPv6 tor instance is configured with Address [::1] by default
            # This currently only applies to bridges
            ExitPolicy accept6 [::1]:*

            # If you only want tor to connect to localhost, disable these lines:
            # This may cause network failures in some circumstances
            ExitPolicyRejectPrivate 0
            ExitPolicy accept6 private:*

            # 2. Optionally: Accept all IPv6 addresses, that is, the public internet
            # ----------------------------------------------------------------------
            # ExitPolicy accept6 *:*

            # 3. Finally, reject all IPv6 addresses which haven't been permitted
            # ------------------------------------------------------------------
            ExitPolicy reject6 *:*
            """)
    if n._config.authority:
        res += textwrap.dedent(f"""
            AuthoritativeDirectory 1
            ContactInfo auth{n.nodenum}@test.test
            """)
        if n.ipv6_addr.is_some() and not n._config.disableipv6:
            res += textwrap.dedent("""
                # And has IPv6 connectivity
                AuthDirHasIPv6Connectivity 1
                """)
    if n._config.authority and not n._config.bridgeauthority:
        res += textwrap.dedent(f"""
            V3AuthoritativeDirectory 1

            # Disable authority to relay/bridge reachability checks
            # These checks happen every half hour, even in testing networks
            # As of tor 0.4.3, there is no way to speed up these checks
            AssumeReachable 1

            # Speed up the consensus cycle as fast as it will go.
            # If clock desynchronisation is an issue, increase these voting times.

            # V3AuthVotingInterval and TestingV3AuthInitialVotingInterval can be:
            #   10, 12, 15, 18, 20, ...
            # TestingV3AuthInitialVotingInterval can also be:
            #    5, 6, 8, 9
            # They both need to evenly divide 24 hours.

            # Initial Vote + Initial Dist must be less than Initial Interval
            #
            # Mixed 0.3.3 and 0.3.4 networks are unstable, due to timing changes.
            # When all 0.3.3 and earlier versions are obsolete, we may be able to revert to
            # TestingV3AuthInitialVotingInterval 5
            TestingV3AuthInitialVotingInterval 20
            TestingV3AuthInitialVoteDelay 4
            TestingV3AuthInitialDistDelay 4
            # Vote + Dist must be less than Interval/2, because when there's no consensus,
            # tor uses Interval/2 as the voting interval
            #
            V3AuthVotingInterval {n._network.V3_AUTH_VOTING_INTERVAL}
            V3AuthVoteDelay 4
            V3AuthDistDelay 4

            ConsensusParams cc_alg=2
            """)
    if n._config.bridgeauthority:
        if not n._config.authority:
            raise ChutneyError(
                f"'bridgeauthority' set without 'authority' in node {n.nick}"
            )
        res += "BridgeAuthoritativeDir 1\n"
    if n._config.bridge:
        res += textwrap.dedent("""
            BridgeRelay 1
            # Nor do we have GEOIP files in any reliable location
            BridgeRecordUsageByCountry 0
            """)
    if n._config.pt_bridge:
        ip = n.ip.unwrap_or_raise(ChutneyError("ip is mandatory for bridges"))
        pt_executable = find_executable_on_path(n._config.pt_executable)
        if pt_executable is None:
            raise ChutneyError(
                "pt_bridge is set, but couldn't locate pt_executable "
                + f"'{n._config.pt_executable}'"
            )
        res += textwrap.dedent(f"""
            ServerTransportPlugin {n._config.pt_transport} exec {pt_executable}
            ExtOrPort {n.extorport}
            ServerTransportListenAddr obfs4 {addr_and_port_str(ip, n.ptport)}
            """)
    if n._config.bridgeclient:
        res += "UseBridges 1\n"
        for bd in n._network.bridges:
            if bd.pt_transport.is_some():
                res += "Bridge {transport} {ip}:{port} {fp} {pt_extra}\n".format(
                    transport=bd.pt_transport.unwrap(),
                    ip=bd.ipaddr,
                    port=bd.port,
                    fp=bd.fingerprint,
                    pt_extra=bd.pt_extra.unwrap_or_raise(
                        ChutneyError("bridge descriptor is missing pt_extra")
                    ),
                )
            else:
                res += "Bridge {ip}:{port} {fp}\n".format(
                    ip=bd.ipaddr,
                    port=bd.port,
                    fp=bd.fingerprint,
                )
        if n._config.pt_transport:
            pt_executable = find_executable_on_path(n._config.pt_executable)
            if pt_executable is None:
                raise ChutneyError(
                    "'pt_transport' is set, but couldn't locate pt_executable "
                    + f"'{n._config.pt_executable}'"
                )
            res += (
                f"ClientTransportPlugin {n._config.pt_transport} exec {pt_executable}\n"
            )

    if n._config.hs_client_restricted_discovery_server_tags:
        res += f"ClientOnionAuthDir {n.dir.joinpath(n._config.client_onion_auth_dir)}"

    res += n._config.extra_raw_torrc + "\n"

    return res
