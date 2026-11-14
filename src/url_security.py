"""URL validation helpers for server-side outbound requests."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


_INTERNAL_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata",
    "metadata.google.internal",
}

_INTERNAL_SUFFIXES = (
    ".localhost",
    ".localdomain",
    ".local",
    ".internal",
    ".lan",
    ".intranet",
    ".home.arpa",
    ".home",
    ".corp",
    ".private",
    ".svc",
)

# Refused outright, whatever the running CPython's ``ipaddress`` flags say:
# the non-globally-reachable blocks of the IANA IPv4/IPv6 special-purpose
# address registries, plus deprecated site-local IPv6 and the 6to4/Teredo
# transition blocks (an address there reaches whatever IPv4 host it wraps).
_BLOCKED_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    # IPv4
    "0.0.0.0/8",        # "this network"
    "10.0.0.0/8",       # private
    "100.64.0.0/10",    # RFC 6598 shared space (CGNAT)
    "127.0.0.0/8",      # loopback
    "169.254.0.0/16",   # link-local
    "172.16.0.0/12",    # private
    "192.0.0.0/24",     # IETF protocol assignments
    "192.0.2.0/24",     # documentation (TEST-NET-1)
    "192.88.99.0/24",   # deprecated 6to4 relay anycast
    "192.168.0.0/16",   # private
    "198.18.0.0/15",    # benchmarking
    "198.51.100.0/24",  # documentation (TEST-NET-2)
    "203.0.113.0/24",   # documentation (TEST-NET-3)
    "224.0.0.0/4",      # multicast
    "240.0.0.0/4",      # reserved, incl. 255.255.255.255
    # IPv6
    "::/128",           # unspecified
    "::1/128",          # loopback
    "64:ff9b:1::/48",   # local-use NAT64 (RFC 8215)
    "100::/64",         # discard-only
    "2001::/32",        # Teredo
    "2001:2::/48",      # benchmarking
    "2001:10::/28",     # deprecated ORCHID
    "2001:db8::/32",    # documentation
    "2002::/16",        # 6to4
    "3fff::/20",        # documentation
    "5f00::/16",        # segment routing SIDs
    "fc00::/7",         # unique local
    "fe80::/10",        # link-local
    "fec0::/10",        # deprecated site-local
    "ff00::/8",         # multicast
))


def _resolve_hostname_ips(hostname: str) -> list[ipaddress._BaseAddress]:
    ips: list[ipaddress._BaseAddress] = []
    for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
        if family in (socket.AF_INET, socket.AF_INET6):
            ips.append(ipaddress.ip_address(sockaddr[0]))
    return ips


# RFC 6052 Well-Known Prefix (NAT64). Decoded like src/url_safety.py does: on a
# DNS64/NAT64 network an IPv4-only host resolves into this /96, and the
# translator connects to the IPv4 address in the low 32 bits.
_NAT64_WELL_KNOWN_PREFIX = ipaddress.ip_network("64:ff9b::/96")

# ISATAP interface identifiers (RFC 5214): 0000:5efe:a.b.c.d or, with the
# universal/local bit set, 0200:5efe:a.b.c.d. The IPv4 address is the low 32 bits.
_ISATAP_MARKERS = (0x00005EFE, 0x02005EFE)


def is_blocked_ip(addr: ipaddress._BaseAddress) -> bool:
    """Return True when an outbound request must not go to ``addr``.

    Takes an ``ipaddress.IPv4Address``/``IPv6Address``. IPv6 addresses that
    carry an IPv4 address (mapped, NAT64 well-known prefix, ISATAP) are judged
    by the IPv4 address they carry as well.
    """
    if isinstance(addr, ipaddress.IPv6Address):
        # ::ffff:a.b.c.d reaches the IPv4 host a.b.c.d. CPython reports the
        # mapped form of most private ranges as private, but not e.g. RFC 6598
        # shared space (::ffff:100.64.1.1), which _BLOCKED_NETWORKS lists only
        # in its IPv4 form — so judge the embedded address, not the wrapper.
        if addr.ipv4_mapped is not None:
            return is_blocked_ip(addr.ipv4_mapped)
        if addr in _NAT64_WELL_KNOWN_PREFIX:
            return is_blocked_ip(ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF))
    if (
        any(addr in net for net in _BLOCKED_NETWORKS)
        or addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
    ):
        return True
    if isinstance(addr, ipaddress.IPv6Address):
        if (int(addr) >> 32) & 0xFFFFFFFF in _ISATAP_MARKERS:
            return is_blocked_ip(ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF))
    return False


# Kept for existing callers and tests.
_blocked_ip = is_blocked_ip


def _normalize_host(hostname: str) -> str:
    """Lowercase and drop trailing dots: ``localhost.`` names ``localhost``."""
    return (hostname or "").strip().lower().rstrip(".")


def _internal_hostname(host: str) -> bool:
    """True for a (normalised, non-literal) name that targets an internal host.
    A single-label name is resolved through the server's search domains or
    /etc/hosts, so it names a host on the server's own network."""
    return (
        host in _INTERNAL_HOSTNAMES
        or host.endswith(_INTERNAL_SUFFIXES)
        or "." not in host
    )


def _public_ips_for_host(hostname: str) -> list[ipaddress._BaseAddress] | None:
    """Resolve ``hostname`` once; return its addresses only if every one is public."""
    host = _normalize_host(hostname)
    if not host:
        return None
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return None if is_blocked_ip(literal) else [literal]
    if _internal_hostname(host):
        return None
    try:
        addrs = _resolve_hostname_ips(host)
    except OSError:
        return None
    if not addrs or any(is_blocked_ip(addr) for addr in addrs):
        return None
    return addrs


_NOT_PUBLIC = "URL must point to a public HTTP(S) endpoint"
_HAS_QUERY_OR_FRAGMENT = "URL must not include a query string or fragment"


def _check_public_http_url(
    url: str, *, max_length: int
) -> tuple[str, list[ipaddress._BaseAddress]]:
    """Shared rule for the public helpers; raises ``ValueError`` on refusal."""
    cleaned = (url or "").strip()
    if len(cleaned) > max_length:
        raise ValueError("URL is too long")
    # urlparse silently drops tabs and newlines, so the URL returned would not
    # be the URL judged; a backslash is read as "/" by some clients.
    if any(
        ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F or ch == "\\"
        for ch in cleaned
    ):
        raise ValueError(_NOT_PUBLIC)
    parsed = urlparse(cleaned)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(_NOT_PUBLIC)
    # Userinfo ("user:pass@host") misleads readers about the real host; an
    # authority ending in ":" has an empty port.
    if "@" in parsed.netloc or parsed.netloc.endswith(":"):
        raise ValueError(_NOT_PUBLIC)
    try:
        port = parsed.port
    except ValueError:
        raise ValueError(_NOT_PUBLIC) from None
    if port is not None and not 1 <= port <= 65535:
        raise ValueError(_NOT_PUBLIC)
    ips = _public_ips_for_host(parsed.hostname)
    if not ips:
        raise ValueError(_NOT_PUBLIC)
    # A base URL gets endpoint paths appended (build_chat_url), which refuses
    # a query or fragment; refuse it here so it is a 400, not a later 500.
    # Checked on the raw text: urlparse drops an empty "?" or "#".
    if "?" in cleaned or "#" in cleaned:
        raise ValueError(_HAS_QUERY_OR_FRAGMENT)
    return cleaned, ips


def _host_resolves_publicly(hostname: str) -> bool:
    return _public_ips_for_host(hostname) is not None


def is_public_http_url(url: str) -> bool:
    try:
        _check_public_http_url(url, max_length=len((url or "").strip()))
    except ValueError:
        return False
    return True


def validate_public_http_url(url: str, *, max_length: int = 2048) -> str:
    """Validate a user/API-token supplied server-side HTTP(S) endpoint.

    This is for untrusted outbound URLs, not admin-created model endpoints
    that are intentionally allowed to point at private model providers. DNS
    failures fail closed, and DNS checks reduce obvious private-network
    targets but do not eliminate every DNS rebinding race by themselves.
    """
    return _check_public_http_url(url, max_length=max_length)[0]


def resolve_public_http_url(
    url: str, *, max_length: int = 2048
) -> tuple[str, list[ipaddress._BaseAddress]]:
    """Validate an untrusted outbound URL and return it with the addresses checked.

    Same rules and errors as ``validate_public_http_url``, but the host is
    resolved exactly once and the vetted addresses are returned so the caller
    can pin its connection to them (``webhook_manager._PinnedAsyncTransport``).
    Connecting by hostname afterwards would resolve again and reopen the DNS
    rebinding window between this check and the request.
    """
    return _check_public_http_url(url, max_length=max_length)
