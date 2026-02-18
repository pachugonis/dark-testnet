import dataclasses
import enum
import re

from ipaddress import IPv4Address, IPv6Address
from typing import Optional, Union

import chutney.errors

from chutney.Util import Option, IPAddress

HSV2_KEYWORD = "hidden service v2"
HSV3_KEYWORD = "hidden service v3"


class DirInfoStatusCode(enum.Enum):
    ONIONDESC_FAILED_TO_PUBLISH = -600
    INTERNAL_ERROR = -500
    # No dir file
    MISSING_FILE = -400
    # Empty dir file
    NO_RECORDS = -300
    NOT_YET_IMPLEMENTED = -200
    # File appears to be truncated/incomplete
    SHORT_FILE = -100
    # Specified entry isn't in dir file
    # TODO: rename
    NO_PROGRESS = 0
    SUCCESS = 100
    ONIONDESC_PUBLISHED = 200

    def __str__(self) -> str:
        return f"{self.value} ({self.name})"


@dataclasses.dataclass
class DirInfoStatus:
    percent_or_code: Union[int, DirInfoStatusCode]
    keyword: str
    message: str


class DirFormat(enum.Enum):
    # cached-descriptors in c-tor
    DESC = enum.auto()
    # cached-descriptors.new in c-tor
    DESC_NEW = enum.auto()
    # cached-consensus in c-tor
    NS_CONS = enum.auto()
    # cached-microdesc-consensus in c-tor
    MD_CONS = enum.auto()
    # cached-microdescs in c-tor
    MD = enum.auto()
    # cached-microdescs.new in c-tor
    MD_NEW = enum.auto()
    # networkstatus-bridges in c-tor
    BR_STATUS = enum.auto()

    # The following represent aggregates of the former when summarizing
    # descriptor statuses.
    # TODO: Maybe move to a separate type/enum?

    # DESC or DESC_NEW
    DESC_ALTS = enum.auto()
    # MD or MD_NEW
    MD_ALTS = enum.auto()
    # NS_CONS or MD_CONS
    CONS_ALL = enum.auto()
    # DESC, DESC_NEW, MD, MD_NEW
    DESC_ALL = enum.auto()
    # Overall
    NODE_DIR = enum.auto()

    def __str__(self) -> str:
        return self.name

    def status_pattern(self, nick: str, ed25519_key: Option[str]) -> Optional[str]:
        """Returns a regular expression pattern for finding a node with the given nick and key
        in this format's file. Returns None if the requested pattern is not
        available.
        """
        cons = self in [DirFormat.NS_CONS, DirFormat.MD_CONS, DirFormat.BR_STATUS]
        desc = self in [DirFormat.DESC, DirFormat.DESC_NEW]
        md = self in [DirFormat.MD, DirFormat.MD_NEW]

        assert cons or desc or md

        if cons:
            # Disabled due to bug #33407: chutney bridge authorities don't
            # publish bridge descriptors in the bridge networkstatus file
            if self == DirFormat.BR_STATUS:
                return None
            else:
                # ns_cons and md_cons work
                return r"^r " + nick + " "
        elif desc:
            return r"^router " + nick + " "
        elif md:
            return ed25519_key.map(
                lambda s: r"^id ed25519 " + re.escape(s)
            ).as_optional()
        else:
            raise chutney.errors.ChutneyError(
                f"status_pattern unimplemented for {self}"
            )


@dataclasses.dataclass
class BridgeLine:
    ipaddr: IPAddress
    port: int
    fingerprint: str
    pt_transport: Option[str] = Option(None)
    pt_extra: Option[str] = Option(None)


@dataclasses.dataclass
class AuthorityLine:
    nick: str
    ipv4: IPv4Address
    ipv6: Option[IPv6Address]
    orport: int
    dirport: int
    v3id: str
    fingerprint: str
    fingerprint_ed25519: str
    extra_flags: list[str]
    alt_bridge_auth: bool = False
    alt_dir_auth: bool = False
