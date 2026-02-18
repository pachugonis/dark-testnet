from __future__ import annotations

import base64
import logging
import re
import shutil
import time

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization as crypto_serialization
from pathlib import Path
from typeguard import check_type
from typing import List, Optional, Union, TYPE_CHECKING
from typing_extensions import override

import chutney
import chutney.known_bins
import chutney.launcher

from chutney.dirinfo import AuthorityLine, BridgeLine
from chutney.errors import ChutneyError, ChutneyInternalError
from chutney.node_builder import NodeBuilder
from chutney.tor.util import get_tor_version, run_tor
from chutney.Util import (
    mkdir_p,
    Option,
)

if TYPE_CHECKING:
    import chutney.TorNet as TorNet

logger = logging.getLogger(__name__)

TORRC_OPTION_WARN_LIMIT = 10
torrc_option_warn_count = 0


@chutney.Util.memoized
def get_torrc_options(launcher: chutney.launcher.Launcher, tor: str) -> list[str]:
    """Return the torrc options supported by the tor binary.
    Options are cached for each unique tor path.
    """
    cmdline = [
        tor,
        "--list-torrc-options",
    ]
    opts = run_tor(launcher, cmdline)
    # check we received a list of options, and nothing else
    assert re.match(r"(^\w+$)+", opts, flags=re.MULTILINE)
    torrc_opts = opts.split()

    return torrc_opts


@chutney.Util.memoized
def tor_exists(launcher: chutney.launcher.Launcher, tor: str) -> bool:
    """Return true iff this tor binary exists."""
    try:
        run_tor(launcher, [tor, "--hush", "--version"])
        return True
    except chutney.errors.ChutneyMissingBinaryError:
        return False


@chutney.Util.memoized
def tor_gencert_exists(launcher: chutney.launcher.Launcher, gencert: str) -> bool:
    """Return true iff this tor-gencert binary exists."""
    try:
        launcher.run(
            [gencert, "--help"],
            known_bin=chutney.known_bins.TorGenCertBin(),
            capture_strategy=chutney.launcher.Capture.MERGED,
            text=True,
        )
        return True
    except chutney.errors.ChutneyMissingBinaryError:
        return False


@chutney.Util.memoized
def get_tor_modules(launcher: chutney.launcher.Launcher, tor: str) -> dict[str, bool]:
    """Check the list of compile-time modules advertised by the given
    'tor' binary, and return a map from module name to a boolean
    describing whether it is supported.

    Unlisted modules are ones that Tor did not treat as compile-time
    optional modules.
    """
    cmdline = [tor, "--list-modules", "--hush"]
    try:
        mods = run_tor(launcher, cmdline)
    except chutney.launcher.CalledProcessError:
        # Tor doesn't support --list-modules; act as if it said nothing.
        mods = ""

    supported = {}
    for line in mods.split("\n"):
        m = re.match(r"^(\S+): (yes|no)", line)
        if not m:
            continue
        supported[m.group(1)] = m.group(2) == "yes"

    return supported


def tor_has_module(
    launcher: chutney.launcher.Launcher, tor: str, modname: str, default: bool = True
) -> bool:
    """Return true iff the given tor binary supports a given compile-time
    module.  If the module is not listed, return 'default'.
    """
    return get_tor_modules(launcher, tor).get(modname, default)


def make_datadir_subdirectory(
    datadir: Union[str, Path], subdir: Union[str, Path]
) -> None:
    """
    Create a datadirectory (if necessary) and a subdirectory of
    that datadirectory.  Ensure that both are mode 700.
    """
    mkdir_p(datadir)
    mkdir_p(datadir, subdir)


def run_tor_gencert(
    launcher: chutney.launcher.Launcher, cmdline: List[str], passphrase: str
) -> str:
    """Run the tor-gencert command line cmdline, which must start with the
    path or name of a tor-gencert binary.
    Then send passphrase to the stdin of the process.

    Returns the combined stdout and stderr of the process.
    """
    p = launcher.run(
        cmdline,
        known_bin=chutney.known_bins.TorGenCertBin(),
        input=passphrase + "\n",
        capture_strategy=chutney.launcher.Capture.MERGED,
        text=True,
        check=True,
    )
    logger.debug(p.stdout)
    return p.stdout


class LocalNodeBuilder(NodeBuilder):
    # Environment members used:
    # torrc -- which torrc file to use
    # authority -- bool -- are we an authority? (includes bridge authorities)
    # bridgeauthority -- bool -- are we a bridge authority?
    # relay -- bool -- are we a relay? (includes exits and bridges)
    # bridge -- bool -- are we a bridge?
    # hs -- bool -- are we a hidden service?
    # nodenum -- int -- set by chutney -- which unique node index is this?
    # dir -- path -- set by chutney -- data directory for this tor
    # tor_gencert -- path to tor_gencert binary
    # tor -- path to tor binary
    # auth_cert_lifetime -- lifetime of authority certs, in months.
    # ip -- primary IP address (usually IPv4) to listen on
    # ipv6_addr -- secondary IP address (usually IPv6) to listen on
    # orport, dirport -- used on authorities, relays, and bridges. The orport
    #                    is used for both IPv4 and IPv6, if present
    # fingerprint, fingerprint_ed -- used only if authority
    # dirserver_flags -- used only if authority
    # nick -- nickname of this router

    # Environment members set
    # fingerprint -- hex router key fingerprint
    # fingerprint_ed -- base64 router key ed25519 fingerprint
    # nodenum -- int -- set by chutney -- which unique node index is this?

    def __init__(self, node: TorNet.Node):
        self._node = node

    @property
    def _launcher(self) -> chutney.launcher.Launcher:
        return self._node._launcher

    def _createTorrcFile(self, checkOnly: bool = False) -> None:
        """Write the torrc file for this node, disabling any options
        that are not supported by config's tor binary using comments.
        If checkOnly, just make sure that the formatting is indeed
        possible.
        """
        global torrc_option_warn_count

        output = self._getTorrcContents()
        if checkOnly:
            # XXXX Is it time-consuming to format? If so, cache here.
            return
        # now filter the options we're about to write, commenting out
        # the options that the current tor binary doesn't support
        tor = self._node._config.tor
        tor_version = get_tor_version(self._launcher, tor)
        torrc_opts = get_torrc_options(self._launcher, tor)
        # check if each option is supported before writing it
        # Unsupported option values may need special handling.
        with self._node.torrc_path.open("w") as f:
            # we need to do case-insensitive option comparison
            lower_opts = [opt.lower() for opt in torrc_opts]
            # keep ends when splitting lines, so we can write them out
            # using writelines() without messing around with "\n"s
            for line in output.splitlines(True):
                # check if the first word on the line is a supported option,
                # preserving empty lines and comment lines
                sline = line.strip()
                if (
                    len(sline) == 0
                    or sline[0] == "#"
                    or sline.split()[0].lower() in lower_opts
                ):
                    pass
                else:
                    warn_msg = (
                        "The tor binary at {} does not support "
                        + "the option in the torrc line:\n{}"
                    ).format(tor, line.strip())
                    if torrc_option_warn_count < TORRC_OPTION_WARN_LIMIT:
                        logger.warning(warn_msg)
                        torrc_option_warn_count += 1
                    else:
                        logger.debug(warn_msg)
                    # always dump the full output to the torrc file
                    line = "# {} version {} does not support: {}".format(
                        tor, tor_version, line
                    )
                f.writelines([line])
        # Verify that the resulting config parses.  If we move or remove this
        # check, ensure that `tests/torrc-template-tests` and `tests/network-config-tests`
        # still actually validate the generated config files.
        run_tor(
            self._launcher,
            [
                str(self._node._config.tor),
                "-f",
                str(self._node.torrc_path),
                "--verify-config",
            ],
        )

    def _getTorrcContents(self) -> str:
        """Return the filled template used to write the torrc for this node."""
        return chutney.tor.torrc.format(
            self._node, get_tor_version(self._launcher, self._node._config.tor)
        )

    @override
    def checkConfig(self, net: TorNet.Network) -> None:
        self._createTorrcFile(checkOnly=True)

    @override
    def preConfig(self, net: TorNet.Network) -> None:
        self._makeDataDir()
        if self._node._config.authority:
            self._genAuthorityKey()
        if self._node._config.relay:
            self._genRouterKey()
        if self._node._config.hs:
            self._makeHiddenServiceDir()
            self._generate_hs_state()
        if net.family_ids:
            for fid in self._node._config.families:
                shutil.copy(net.get_familykey_path(fid), Path(self._node.dir, "keys"))
        if self._node._config.hs_client_restricted_discovery_server_tags:
            mkdir_p(self._client_onion_auth_dir())

    def _generate_hs_state(self) -> None:
        # Force generation of the hidden service key and address.
        p = self._launcher.popen(
            [
                str(self._node._config.tor),
                "-f",
                # Read config from stdin; we don't need or want most of the
                # generated torrc, and this function may be called before we've
                # generated it.
                "-",
                # Don't try to connect to the network
                "-DisableNetwork",
                "1",
                # Do use our DataDirectory. It shouldn't do much with it
                # with the network disabled, but otherwise tor will
                # try to set up a data directory in default locations
                # under HOME or system-wide.
                # <https://gitlab.torproject.org/tpo/core/chutney/-/issues/40042>
                "-DataDirectory",
                str(self._node.dir),
                # Do generate our hidden service state
                "-HiddenServiceDir",
                str(self._node.dir.joinpath(self._node._config.hs_directory)),
                # Dummy ports; tor won't try to bind to them since the
                # network is disabled.
                "-HiddenServicePort",
                "1 1",
            ],
            known_bin=chutney.known_bins.TorBin(),
            text=True,
        )
        start_time = time.time()
        last_warn_time = start_time
        while True:
            if not p.running():
                res = p.communicate()
                # Process exited unexpectedly.
                logger.error("tor exited: %s", res.stdout if res.stdout else "<None>")
                raise ChutneyError(
                    f"tor exited unexpectedly with returncode={res.returncode}"
                )
            if self._hs_hostname_path().exists():
                logger.debug("Generated hostname %s", self.get_hs_hostname().unwrap())
                # Done. Terminate and wait for process to exit.
                p.terminate()
                res = p.communicate()
                logger.debug(
                    "tor exited with returncode %d, after terminating", res.returncode
                )
                break
            logger.debug(f"waiting for tor {p.pid()} to generate hidden service state")
            now = time.time()
            if (now - last_warn_time) > 5:
                total_seconds = round(now - start_time, 1)
                logger.warning(
                    f"{self._node.nick} has been waiting {total_seconds} seconds for"
                    f" tor process {p.pid()} to generate {self._hs_hostname_path()}"
                )
                last_warn_time = now
            try:
                p.communicate(timeout=0.01)
            except chutney.errors.ChutneyTimeoutError:
                pass

    @override
    def config(self, net: TorNet.Network) -> None:
        self._createTorrcFile()

    @override
    def postConfig(self, net: TorNet.Network) -> None:
        pass

    @override
    def isSupported(self, net: TorNet.Network) -> bool:
        if not tor_exists(self._launcher, self._node._config.tor):
            print("No binary found for %r" % self._node._config.tor)
            return False

        if self._node._config.authority:
            if not tor_has_module(self._launcher, self._node._config.tor, "dirauth"):
                print("No dirauth support in %r" % self._node._config.tor)
                return False
            if not tor_gencert_exists(self._launcher, self._node._config.tor_gencert):
                print(
                    "No binary found for tor-gencert %r"
                    % self._node._config.tor_gencert
                )
                return False

        return True

    def _makeDataDir(self) -> None:
        """Create the data directory (with keys subdirectory) for this node."""
        datadir = check_type(self._node.dir, Path)
        make_datadir_subdirectory(datadir, "keys")

    def _makeHiddenServiceDir(self) -> None:
        """Create the hidden service subdirectory for this node.

        The directory name is stored under the 'hs_directory' environment
        key. It is combined with the 'dir' data directory key to yield the
        path to the hidden service directory.
        """
        datadir = self._node.dir
        make_datadir_subdirectory(datadir, self._node._config.hs_directory)

    def _genAuthorityKey(self) -> None:
        """Generate an authority identity and signing key for this authority,
        if they do not already exist."""
        datadir = self._node.dir
        tor_gencert = self._node._config.tor_gencert
        lifetime = self._node._config.auth_cert_lifetime
        idfile = Path(datadir, "keys", "authority_identity_key")
        skfile = Path(datadir, "keys", "authority_signing_key")
        certfile = Path(datadir, "keys", "authority_certificate")
        addr = f"{self._node.ip.unwrap()}:{self._node.dirport.unwrap()}"
        passphrase = self._node.auth_passphrase
        if all(f.exists() for f in [idfile, skfile, certfile]):
            return
        cmdline = [
            tor_gencert,
            "--create-identity-key",
            "--passphrase-fd",
            "0",
            "-i",
            str(idfile),
            "-s",
            str(skfile),
            "-c",
            str(certfile),
            "-m",
            str(lifetime),
            "-a",
            addr,
        ]
        # nicknames are testNNNaa[OLD], but we want them to look tidy
        print(
            "Creating identity key for {:12} with {}".format(
                self._node.nick, cmdline[0]
            )
        )
        logger.debug(
            "Identity key path '{}', command '{}'".format(idfile, " ".join(cmdline))
        )
        run_tor_gencert(self._launcher, cmdline, passphrase)

    def _genRouterKey(self) -> None:
        """Generate an identity key for this router"""
        datadir = self._node.dir
        tor = self._node._config.tor
        cmdline: list[str] = [
            tor,
            "--ignore-missing-torrc",
            "-f",
            str(self._node.torrc_path),
            "--orport",
            "1",
            "--datadirectory",
            str(datadir),
            "--list-fingerprint",
        ]
        run_tor(self._launcher, cmdline)

    @override
    def get_fingerprint_ed25519(self) -> Option[str]:
        if not self._node._config.relay:
            return Option(None)
        try:
            s = self._node.dir.joinpath("fingerprint-ed25519").read_text()
        except FileNotFoundError:
            return Option(None)
        m = re.match(r"^\w+ (\S{43})$", s)
        if not m:
            raise chutney.errors.ChutneyError(
                f"Malformed fingerprint file contents: {s}"
            )
        return Option(m.group(1))

    @override
    def get_fingerprint(self) -> Option[str]:
        if not self._node._config.relay:
            return Option(None)
        try:
            s = self._node.dir.joinpath("fingerprint").read_text()
        except FileNotFoundError:
            return Option(None)
        m = re.match(r"^\w+ ([A-F0-9]{40})$", s)
        if not m:
            raise chutney.errors.ChutneyError(
                f"Malformed fingerprint file contents: {s}"
            )
        return Option(m.group(1))

    @override
    def getAltAuthLines(self, hasbridgeauth: bool = False) -> Optional[AuthorityLine]:
        if not self._node._config.authority:
            return None

        datadir = self._node.dir
        certfile = Path(datadir, "keys", "authority_certificate")
        v3id = None
        with certfile.open(mode="r") as f:
            for line in f:
                if line.startswith("fingerprint"):
                    v3id = line.split()[1].strip()
                    break

        assert v3id is not None

        return AuthorityLine(
            nick=self._node.nick,
            ipv4=self._node.ip.unwrap(),
            ipv6=self._node.ipv6_addr,
            orport=self._node.orport,
            dirport=self._node.dirport.unwrap(),
            v3id=v3id,
            fingerprint=self._node.fingerprint.unwrap(),
            fingerprint_ed25519=self._node.fingerprint_ed25519.unwrap(),
            alt_bridge_auth=self._node._config.bridgeauthority,
            alt_dir_auth=not self._node._config.bridgeauthority,
            extra_flags=self._node._config.dirserver_flags.split(),
        )

    @override
    def getBridgeLines(self) -> list[BridgeLine]:
        if not self._node._config.bridge:
            return []

        if self._node._config.pt_bridge:
            port = self._node.ptport
            pt_transport = Option(self._node._config.pt_transport)
            pt_extra = self._node._controller.getPtExtra()
            if pt_extra.is_none():
                # obfs4 pt bridges (and possibly others) don't generate their
                # `pt_extra` until after they've *started*.  We should probably
                # return `[]` here, or avoid calling this function at all for a
                # pt bridge that hasn't started yet.  For now we preserve legacy
                # behavior of just setting pt_extra to an empty string, which
                # causes validation to pass, but a pt bridge client won't
                # actually be able to connect.
                # TODO(#40023): Once #40023 is fixed, revisit doing something else here.
                logger.debug(f"Couldn't load pt_extra from {self._node.dir}")
                pt_extra = Option("")
        else:
            # the orport is the same on IPv4 and IPv6
            port = self._node.orport
            pt_transport = Option(None)
            pt_extra = Option(None)

        res = [
            BridgeLine(
                ipaddr=self._node.ip.unwrap(),
                port=port,
                fingerprint=self._node.fingerprint.unwrap(),
                pt_transport=pt_transport,
                pt_extra=pt_extra,
            ),
        ]
        if self._node.ipv6_addr.is_some():
            res.append(
                BridgeLine(
                    ipaddr=self._node.ipv6_addr.unwrap(),
                    port=port,
                    fingerprint=self._node.fingerprint.unwrap(),
                    pt_transport=pt_transport,
                    pt_extra=pt_extra,
                )
            )
        return res

    def _hs_hostname_path(self) -> Path:
        """The path to the hostname file, if this node has a hidden service"""
        return self._node.dir.joinpath(self._node._config.hs_directory, "hostname")

    @override
    def get_hs_hostname(self) -> Option[str]:
        if not self._node._config.hs:
            return Option(None)
        hs_hostname_file = self._hs_hostname_path()
        try:
            hostname_file_contents = hs_hostname_file.read_text()
        except FileNotFoundError:
            # We're not a hidden service, or the file isn't ready yet.
            logger.debug(f"hostname file {hs_hostname_file} not found")
            return Option(None)
        except IOError as e:
            # Unexpected error
            raise ChutneyError(f"Error opening hostname file {hs_hostname_file}") from e
        # the hostname file ends with a newline
        hostname = hostname_file_contents.strip()
        # shouldn't be empty
        if not hostname:
            raise ChutneyInternalError(
                f"Unexpectedly empty hostname in {hs_hostname_file}"
            )
        return Option(hostname)

    def _client_onion_auth_dir(self) -> Path:
        return self._node.dir.joinpath(self._node._config.client_onion_auth_dir)

    @override
    def get_hs_client_pubkey(self, hs_address: str) -> str:
        # Our docs for expected output:
        # https://2019.www.torproject.org/docs/tor-manual-dev.html.en#_client_authorization
        priv_key_path = self._client_onion_auth_dir().joinpath(
            hs_address + ".auth_private"
        )
        if not priv_key_path.exists():
            private_key = x25519.X25519PrivateKey.generate()
            private_key_bytes = private_key.private_bytes(
                crypto_serialization.Encoding.Raw,
                crypto_serialization.PrivateFormat.Raw,
                crypto_serialization.NoEncryption(),
            )
            private_key32 = base64.b32encode(private_key_bytes).decode("ascii")
            # As per <https://spec.torproject.org/intro/conventions.html#binascii>
            private_key32 = private_key32.strip("=")
            priv_key_path.write_text(
                hs_address.removesuffix(".onion")
                + ":descriptor:x25519:"
                + private_key32
            )
        private_key_descriptor = priv_key_path.read_text()
        private_key_descriptor_parts = private_key_descriptor.split(":")
        assert private_key_descriptor_parts[1] == "descriptor"
        assert private_key_descriptor_parts[2] == "x25519"
        # `b32decode` insists on the padding suffix, which we removed when saving
        # the private key. So add it back.
        private_key32 = private_key_descriptor_parts[3] + "===="
        private_key_bytes = base64.b32decode(private_key32)
        private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(
            crypto_serialization.Encoding.Raw,
            crypto_serialization.PublicFormat.Raw,
        )
        public_key32 = base64.b32encode(public_key_bytes).decode("ascii")
        # As per <https://spec.torproject.org/intro/conventions.html#binascii>
        public_key32 = public_key32.strip("=")
        return "descriptor:x25519:" + public_key32

    @override
    def set_hs_client_pubkey(self, client_id: str, client_pubkey: str) -> None:
        path = self._node.dir.joinpath(
            self._node._config.hs_directory, "authorized_clients", client_id + ".auth"
        )
        path.write_text(client_pubkey)
