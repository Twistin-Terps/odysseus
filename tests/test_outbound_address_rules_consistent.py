"""Every guard for an untrusted outbound request refuses the same addresses.

One shared matrix of addresses that must be refused, run through each strict
checker both as an IP-literal URL and as a hostname that resolves to the
address (the checker's resolver is monkeypatched; no real DNS). The address
rule each checker must at least enforce is ``src.url_security.is_blocked_ip``.
"""

import ipaddress

import pytest

import services.search.content as search_content
from src import outbound_fetch, url_safety, url_security, webhook_manager

REFUSED = [
    "100.64.0.1",                       # RFC 6598 shared space
    "100.100.100.200",                  # cloud instance-metadata, shared space
    "::ffff:100.64.0.1",                # IPv4-mapped shared space
    "fec0::1",                          # deprecated site-local
    "192.88.99.1",                      # deprecated 6to4 relay anycast
    "10.0.0.1",
    "127.0.0.1",
    "169.254.169.254",
    "::1",
    "fe80::1",
    "fc00::1",
    "64:ff9b::a00:1",                   # NAT64 of 10.0.0.1
    "2002:0a00:0001::1",                # 6to4 of 10.0.0.1
    "2606:4700::5efe:7f00:1",           # ISATAP wrapping 127.0.0.1
    "2606:4700::200:5efe:a9fe:a9fe",    # ISATAP wrapping 169.254.169.254
    "2606:4700::5efe:a00:1",            # ISATAP wrapping 10.0.0.1
    "2606:4700::5efe:6440:1",           # ISATAP wrapping 100.64.0.1
]

ACCEPTED = ["93.184.216.34", "2606:4700:4700::1111"]

HOSTNAME = "attacker.example.com"


def _literal_url(addr: str) -> str:
    host = f"[{addr}]" if ":" in addr else addr
    return f"https://{host}/hook"


def _ip(addr: str):
    return ipaddress.ip_address(addr)


# --- each strict checker as "accepts(url, monkeypatch, resolved_to) -> bool" ---

def _webhook_validate(url, monkeypatch, resolved_to):
    monkeypatch.setattr(webhook_manager, "_resolve_hostname_ips",
                        lambda host: [_ip(resolved_to)])
    try:
        webhook_manager.validate_webhook_url(url)
    except ValueError:
        return False
    return True


def _webhook_pinned_ips(url, monkeypatch, resolved_to):
    monkeypatch.setattr(webhook_manager, "_resolve_hostname_ips",
                        lambda host: [_ip(resolved_to)])
    try:
        webhook_manager._validated_public_ips(url)
    except ValueError:
        return False
    return True


def _outbound_public_url(url, monkeypatch, resolved_to):
    return outbound_fetch._public_http_url(url, resolver=lambda host: [_ip(resolved_to)])


def _outbound_resolve_public(url, monkeypatch, resolved_to):
    import httpx
    try:
        outbound_fetch._resolve_public_ips(url, resolver=lambda host: [_ip(resolved_to)])
    except httpx.RequestError:
        return False
    return True


def _string_resolver(resolved_to):
    # Like getaddrinfo: an IP literal resolves to itself, a name to resolved_to.
    def resolve(host):
        try:
            return [str(ipaddress.ip_address(host))]
        except ValueError:
            return [resolved_to]
    return resolve


def _url_safety_strict(url, monkeypatch, resolved_to):
    ok, _reason = url_safety.check_outbound_url(
        url, block_private=True, resolver=_string_resolver(resolved_to))
    return ok


def _url_safety_strict_host(url, monkeypatch, resolved_to):
    from urllib.parse import urlparse
    ok, _reason = url_safety.check_outbound_host(
        urlparse(url).hostname, block_private=True, resolver=_string_resolver(resolved_to))
    return ok


def _search_content(url, monkeypatch, resolved_to):
    monkeypatch.setattr(search_content, "_resolve_hostname_ips",
                        lambda host: [_ip(resolved_to)])
    return search_content._public_http_url(url)


def _search_content_resolve(url, monkeypatch, resolved_to):
    import httpx
    monkeypatch.setattr(search_content, "_resolve_hostname_ips",
                        lambda host: [_ip(resolved_to)])
    try:
        search_content._resolve_public_ips(url)
    except httpx.RequestError:
        return False
    return True


def _url_security(url, monkeypatch, resolved_to):
    monkeypatch.setattr(url_security, "_resolve_hostname_ips",
                        lambda host: [_ip(resolved_to)])
    return url_security.is_public_http_url(url)


CHECKERS = {
    "webhook_manager.validate_webhook_url": _webhook_validate,
    "webhook_manager._validated_public_ips": _webhook_pinned_ips,
    "outbound_fetch._public_http_url": _outbound_public_url,
    "outbound_fetch._resolve_public_ips": _outbound_resolve_public,
    "url_safety.check_outbound_url(strict)": _url_safety_strict,
    "url_safety.check_outbound_host(strict)": _url_safety_strict_host,
    "search.content._public_http_url": _search_content,
    "search.content._resolve_public_ips": _search_content_resolve,
    "url_security.is_public_http_url": _url_security,
}


@pytest.mark.parametrize("addr", REFUSED)
def test_shared_rule_refuses_matrix(addr):
    assert url_security.is_blocked_ip(_ip(addr))


@pytest.mark.parametrize("addr", ACCEPTED)
def test_shared_rule_accepts_controls(addr):
    assert not url_security.is_blocked_ip(_ip(addr))


@pytest.mark.parametrize("checker", sorted(CHECKERS))
@pytest.mark.parametrize("addr", REFUSED)
def test_refused_as_ip_literal(checker, addr, monkeypatch):
    # The resolver answers with a public address: only the literal can refuse.
    assert not CHECKERS[checker](_literal_url(addr), monkeypatch, ACCEPTED[0])


@pytest.mark.parametrize("checker", sorted(CHECKERS))
@pytest.mark.parametrize("addr", REFUSED)
def test_refused_via_dns(checker, addr, monkeypatch):
    assert not CHECKERS[checker](f"https://{HOSTNAME}/hook", monkeypatch, addr)


@pytest.mark.parametrize("checker", sorted(CHECKERS))
@pytest.mark.parametrize("addr", ACCEPTED)
def test_controls_accepted_as_ip_literal(checker, addr, monkeypatch):
    assert CHECKERS[checker](_literal_url(addr), monkeypatch, addr)


@pytest.mark.parametrize("checker", sorted(CHECKERS))
@pytest.mark.parametrize("addr", ACCEPTED)
def test_controls_accepted_via_dns(checker, addr, monkeypatch):
    assert CHECKERS[checker](f"https://{HOSTNAME}/hook", monkeypatch, addr)


@pytest.mark.parametrize("url,resolved", [
    ("http://127.0.0.1:8080/v1/embeddings", "127.0.0.1"),
    ("http://gpu-box.example.com:8000/v1", "192.168.1.10"),
])
def test_url_safety_default_mode_still_allows_local_services(url, resolved):
    ok, reason = url_safety.check_outbound_url(url, resolver=lambda host: [resolved])
    assert ok, reason
    ok, reason = url_safety.check_outbound_host(
        "gpu-box.example.com", resolver=lambda host: [resolved])
    assert ok, reason
