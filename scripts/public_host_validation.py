#!/usr/bin/env python3
"""Public-host validation helpers for release and hosted-repository tooling."""

from __future__ import annotations

import ipaddress
from collections.abc import Callable


ErrorFactory = Callable[[str], BaseException]


def is_loopback_host(host: str) -> bool:
    trimmed = host.strip(".").lower()
    if trimmed in {"localhost", "127.0.0.1", "::1"} or trimmed.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(trimmed).is_loopback
    except ValueError:
        return False


def validate_public_host(
    host: str,
    label: str,
    *,
    error_factory: ErrorFactory = ValueError,
) -> None:
    trimmed = host.strip(".").lower()
    if (
        not trimmed
        or trimmed == "localhost"
        or trimmed.endswith(".localhost")
        or trimmed.endswith(".local")
    ):
        raise error_factory(f"{label} host must be public")
    try:
        ip = ipaddress.ip_address(trimmed)
    except ValueError:
        return
    if not is_public_ip(ip):
        raise error_factory(f"{label} host must be public")


def is_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv4Address):
        return is_public_ipv4(ip)
    return is_public_ipv6(ip)


def is_public_ipv4(ip: ipaddress.IPv4Address) -> bool:
    first, second, third, _fourth = ip.packed
    return not (
        first == 0
        or ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or first == 255
        or (first == 100 and 64 <= second <= 127)
        or (first == 192 and second == 0 and third == 0)
        or (first == 192 and second == 88 and third == 99)
        or (first == 198 and second in {18, 19})
        or first >= 240
    )


def is_public_ipv6(ip: ipaddress.IPv6Address) -> bool:
    if (
        ip.is_loopback
        or ip.is_unspecified
        or ip.is_multicast
        or is_ipv6_unique_local(ip)
        or is_ipv6_link_local(ip)
        or is_ipv6_site_local(ip)
        or is_ipv6_documentation(ip)
        or is_ipv6_3fff_documentation(ip)
        or is_ipv6_discard_only(ip)
        or is_ipv6_dummy_prefix(ip)
        or is_ipv6_protocol_assignment(ip)
        or is_ipv6_nat64_local_use(ip)
        or is_ipv6_segment_routing_sid(ip)
        or is_ipv6_6to4(ip)
    ):
        return False
    if ip.ipv4_mapped is not None:
        return is_public_ipv4(ip.ipv4_mapped)
    compatible = ipv4_compatible_address(ip)
    if compatible is not None:
        return is_public_ipv4(compatible)
    well_known_nat64 = ipv6_well_known_nat64_address(ip)
    if well_known_nat64 is not None:
        return is_public_ipv4(well_known_nat64)
    return True


def is_ipv6_unique_local(ip: ipaddress.IPv6Address) -> bool:
    return (int(ip) >> 121) == 0b1111110


def is_ipv6_link_local(ip: ipaddress.IPv6Address) -> bool:
    return (int(ip) >> 118) == 0b1111111010


def is_ipv6_site_local(ip: ipaddress.IPv6Address) -> bool:
    return (int(ip) >> 118) == 0b1111111011


def is_ipv6_documentation(ip: ipaddress.IPv6Address) -> bool:
    return int(ip) >> 96 == int(ipaddress.IPv6Address("2001:db8::")) >> 96


def is_ipv6_3fff_documentation(ip: ipaddress.IPv6Address) -> bool:
    return int(ip) >> 108 == int(ipaddress.IPv6Address("3fff::")) >> 108


def is_ipv6_discard_only(ip: ipaddress.IPv6Address) -> bool:
    return int(ip) >> 64 == int(ipaddress.IPv6Address("100::")) >> 64


def is_ipv6_dummy_prefix(ip: ipaddress.IPv6Address) -> bool:
    return int(ip) >> 64 == int(ipaddress.IPv6Address("100:0:0:1::")) >> 64


def is_ipv6_protocol_assignment(ip: ipaddress.IPv6Address) -> bool:
    segments = ip.exploded.split(":")
    return int(segments[0], 16) == 0x2001 and int(segments[1], 16) <= 0x01FF


def is_ipv6_nat64_local_use(ip: ipaddress.IPv6Address) -> bool:
    return int(ip) >> 80 == int(ipaddress.IPv6Address("64:ff9b:1::")) >> 80


def is_ipv6_segment_routing_sid(ip: ipaddress.IPv6Address) -> bool:
    return int(ip) >> 112 == int(ipaddress.IPv6Address("5f00::")) >> 112


def is_ipv6_6to4(ip: ipaddress.IPv6Address) -> bool:
    return ip.exploded.startswith("2002:")


def ipv6_well_known_nat64_address(
    ip: ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | None:
    value = int(ip)
    if value >> 32 != int(ipaddress.IPv6Address("64:ff9b::")) >> 32:
        return None
    return ipaddress.IPv4Address(value & 0xFFFFFFFF)


def ipv4_compatible_address(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    value = int(ip)
    if value >> 32 != 0:
        return None
    if value in {0, 1}:
        return None
    return ipaddress.IPv4Address(value & 0xFFFFFFFF)
