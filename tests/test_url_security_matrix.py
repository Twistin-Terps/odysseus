"""Rule matrix for ``src.url_security``, the check on token-supplied base URLs.

Each refused case is tried as an IP literal in the URL and as the address a
hostname resolves to (``_resolve_hostname_ips`` is patched; no real DNS).
THREAT_MODEL.md ("Token-Supplied LLM Endpoints") describes the same rules.
"""

import ipaddress

import pytest

from src import url_security

PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:4700:4700::1111"


@pytest.fixture
def resolver(monkeypatch):
    """Patch DNS: every name resolves to ``resolver.answer``; calls are recorded."""

    class _Resolver:
        answer = [PUBLIC_V4]
        calls = []

        def __call__(self, host):
            self.calls.append(host)
            return [ipaddress.ip_address(a) for a in self.answer]

    r = _Resolver()
    r.calls = []
    monkeypatch.setattr(url_security, "_resolve_hostname_ips", r)
    return r


def _literal_url(addr):
    host = f"[{addr}]" if ":" in addr else addr
    return f"https://{host}/v1"


def _refused(url):
    with pytest.raises(ValueError):
        url_security.resolve_public_http_url(url)
    with pytest.raises(ValueError):
        url_security.validate_public_http_url(url)
    assert url_security.is_public_http_url(url) is False


# --- Item 1: special-purpose address blocks --------------------------------

ITEM1_ADDRESSES = [
    "fec0::1",                # deprecated site-local
    "fefe::1",                # top of fec0::/10
    "192.88.99.1",            # deprecated 6to4 relay anycast
]


@pytest.mark.parametrize("addr", ITEM1_ADDRESSES)
def test_special_purpose_literal_is_refused(resolver, addr):
    _refused(_literal_url(addr))
    assert resolver.calls == []


@pytest.mark.parametrize("addr", ITEM1_ADDRESSES)
def test_name_resolving_to_special_purpose_address_is_refused(resolver, addr):
    resolver.answer = [addr]
    _refused("https://api.example.com/v1")


# These blocks must be refused by the explicit table, not only by whichever
# ``ipaddress`` flags the running CPython happens to set.
EXPLICIT_BLOCKS = [
    "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    "64:ff9b:1::/48", "100::/64", "2001:db8::/32", "2001:2::/48",
    "2001:10::/28", "3fff::/20", "5f00::/16", "ff00::/8", "fec0::/10",
    "2001::/32", "2002::/16",
]


@pytest.mark.parametrize("block", EXPLICIT_BLOCKS)
def test_block_is_in_the_explicit_table(block):
    net = ipaddress.ip_network(block)
    assert any(
        net.version == b.version and net.subnet_of(b)
        for b in url_security._BLOCKED_NETWORKS
    ), block


@pytest.mark.parametrize("block", EXPLICIT_BLOCKS)
def test_block_first_and_last_address_are_refused(block):
    net = ipaddress.ip_network(block)
    assert url_security.is_blocked_ip(net[0]) is True
    assert url_security.is_blocked_ip(net[-1]) is True


# --- Item 2: IPv6 forms that wrap an IPv4 address ---------------------------

WRAPPED_INTERNAL = [
    "2002:7f00:1::1",                          # 6to4 of 127.0.0.1
    "2002:a00:1::1",                           # 6to4 of 10.0.0.1
    "2001:0:4136:e378:8000:63bf:80ff:fffe",    # Teredo, client 127.0.0.1
    "2001:0:a00:1::a247:2ddd",                 # Teredo, server 10.0.0.1
    "2600:1f18::5efe:7f00:1",                  # ISATAP 0000:5efe, 127.0.0.1
    "2600:1f18::200:5efe:a00:1",               # ISATAP 0200:5efe, 10.0.0.1
    "2600:1f18::5efe:a9fe:a9fe",               # ISATAP, 169.254.169.254
    "2600:1f18::5efe:6440:101",                # ISATAP, 100.64.1.1 (CGNAT)
]


@pytest.mark.parametrize("addr", WRAPPED_INTERNAL)
def test_wrapped_internal_ipv4_literal_is_refused(resolver, addr):
    _refused(_literal_url(addr))


@pytest.mark.parametrize("addr", WRAPPED_INTERNAL)
def test_name_resolving_to_wrapped_internal_ipv4_is_refused(resolver, addr):
    resolver.answer = [addr]
    _refused("https://api.example.com/v1")


# --- Item 3: trailing dots --------------------------------------------------

TRAILING_DOT_NAMES = [
    "localhost.", "foo.local.", "x.internal.", "x.lan.", "metadata.",
    "metadata.google.internal.", "localhost..", "LOCALHOST.",
]


@pytest.mark.parametrize("host", TRAILING_DOT_NAMES)
def test_internal_name_with_trailing_dot_is_refused(resolver, host):
    _refused(f"http://{host}/v1")
    assert resolver.calls == []


def test_name_of_only_dots_is_refused(resolver):
    _refused("http://./v1")
    _refused("http://../v1")
    assert resolver.calls == []


def test_trailing_dot_is_stripped_before_resolving(resolver):
    url_security.resolve_public_http_url("https://api.example.com./v1")
    assert resolver.calls == ["api.example.com"]


# --- Item 4: names the rule did not know ------------------------------------

UNKNOWN_INTERNAL_NAMES = [
    "localhost.localdomain", "ip6-localhost", "ip6-loopback",
    "kubernetes.default.svc", "x.corp", "x.home.arpa", "intranet", "router",
    "x.home", "x.private", "db.localdomain",
]


@pytest.mark.parametrize("host", UNKNOWN_INTERNAL_NAMES)
def test_internal_name_is_refused_even_if_it_resolves_publicly(resolver, host):
    _refused(f"http://{host}/v1")
    assert resolver.calls == []


# --- Item 5: ports ----------------------------------------------------------

@pytest.mark.parametrize("port", ["0", "99999", "65536", "abc", "-1", "+80"])
def test_invalid_port_is_refused(resolver, port):
    url = f"https://api.example.com:{port}/v1"
    _refused(url)
    with pytest.raises(ValueError) as exc:
        url_security.resolve_public_http_url(url)
    assert str(exc.value) == "URL must point to a public HTTP(S) endpoint"


# --- Query and fragment (item 6, validator side) ----------------------------

@pytest.mark.parametrize("url", [
    "http://api.example.com/v1?x=1",
    "http://api.example.com#@127.0.0.1/",
    "http://api.example.com/v1?",
    "http://api.example.com/v1#",
])
def test_query_or_fragment_is_refused_without_echoing_it(resolver, url):
    _refused(url)
    with pytest.raises(ValueError) as exc:
        url_security.resolve_public_http_url(url)
    assert "x=1" not in str(exc.value) and "127.0.0.1" not in str(exc.value)


# --- Accepted controls ------------------------------------------------------

def test_public_name_is_accepted_with_its_addresses(resolver):
    url, ips = url_security.resolve_public_http_url("https://api.example.com/v1")
    assert url == "https://api.example.com/v1"
    assert ips == [ipaddress.ip_address(PUBLIC_V4)]


def test_name_resolving_to_global_ipv6_is_accepted(resolver):
    resolver.answer = [PUBLIC_V6]
    _, ips = url_security.resolve_public_http_url("https://api.example.com/v1")
    assert ips == [ipaddress.ip_address(PUBLIC_V6)]


@pytest.mark.parametrize("addr", [
    PUBLIC_V6,
    PUBLIC_V4,
    "2600:1f18::5efe:5db8:d822",      # ISATAP with global IPv4 93.184.216.34
    "2600:1f18::200:5efe:5db8:d822",
])
def test_global_literal_is_accepted(resolver, addr):
    url = _literal_url(addr)
    assert url_security.resolve_public_http_url(url) == (url, [ipaddress.ip_address(addr)])
    assert url_security.is_public_http_url(url) is True


@pytest.mark.parametrize("port", ["443", "8443", "1", "65535"])
def test_valid_port_is_accepted(resolver, port):
    url = f"https://api.example.com:{port}/v1"
    assert url_security.validate_public_http_url(url) == url


def test_every_resolved_address_must_pass(resolver):
    resolver.answer = [PUBLIC_V4, "fec0::1"]
    _refused("https://api.example.com/v1")


def test_exactly_one_resolver_call_per_validation(resolver):
    resolver.answer = [PUBLIC_V4, PUBLIC_V6]
    url_security.resolve_public_http_url("https://api.example.com/v1")
    assert resolver.calls == ["api.example.com"]


# --- Authority and character rules ------------------------------------------

@pytest.mark.parametrize("url", [
    "https://api.example.com:/v1",
    "https://[2606:4700:4700::1111]:/v1",
])
def test_empty_port_is_refused(resolver, url):
    _refused(url)


@pytest.mark.parametrize("url", [
    "https://api.openai.com@evil.tld/v1",
    "https://user:secret@api.example.com/v1",
    "https://:secret@api.example.com/v1",
    "https://@api.example.com/v1",
])
def test_userinfo_is_refused_without_echoing_it(resolver, url):
    _refused(url)
    with pytest.raises(ValueError) as exc:
        url_security.resolve_public_http_url(url)
    assert str(exc.value) == url_security._NOT_PUBLIC


@pytest.mark.parametrize("url", [
    "http://api.exa\nmple.com/v1",
    "http://api.exa\tmple.com/v1",
    "http://api.exa\rmple.com/v1",
    "https://api.example.com/v\x001",
    "https://api.example.com/v\x7f1",
    "https://api.example.com/v 1",
    "https://api.example.com\\@127.0.0.1/v1",
    "https://api.example.com/v1\\x",
])
def test_control_whitespace_or_backslash_is_refused(resolver, url):
    _refused(url)
    with pytest.raises(ValueError) as exc:
        url_security.resolve_public_http_url(url)
    assert str(exc.value) == url_security._NOT_PUBLIC


def test_refused_authority_makes_no_resolver_call(resolver):
    for url in ("https://api.openai.com@evil.tld/v1", "https://api.example.com:/v1",
                "http://api.exa\nmple.com/v1"):
        _refused(url)
    assert resolver.calls == []


@pytest.mark.parametrize("url", [
    "https://api.example.com/v1",
    "https://api.example.com:8443/v1",
    "https://[2606:4700:4700::1111]:8443/v1",
])
def test_plain_authority_still_accepted(resolver, url):
    returned, ips = url_security.resolve_public_http_url(url)
    assert returned == url and ips
    assert url_security.is_public_http_url(url) is True


@pytest.mark.parametrize("url", [
    "https://example.com/v1?x=1",
    "https://example.com/v1#f",
])
def test_query_or_fragment_is_refused_without_resolving(resolver, url):
    with pytest.raises(ValueError) as exc:
        url_security.resolve_public_http_url(url)
    assert str(exc.value) == url_security._HAS_QUERY_OR_FRAGMENT
    assert url_security.is_public_http_url(url) is False
    assert resolver.calls == []
