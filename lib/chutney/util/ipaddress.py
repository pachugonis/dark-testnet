# [pep 0536](https://peps.python.org/pep-0563/) - Lazy annotation eval via
# stringification.
from __future__ import annotations

import ipaddress
from typing import TypeAlias

IPAddress: TypeAlias = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork: TypeAlias = ipaddress.IPv4Network | ipaddress.IPv6Network


def addr_and_port_str(ip_addr: IPAddress, port: int) -> str:
    """Format an ip address and port pair.

    Concretely, this surrounds ipv6 addresses with brackets, which is a common
    convention for separating an ipv6 address from a port number.
    """

    if ip_addr.version == 4:
        return f"{ip_addr}:{port}"
    if ip_addr.version == 6:
        return f"[{ip_addr}]:{port}"
