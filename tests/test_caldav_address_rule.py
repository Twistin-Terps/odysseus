"""The CalDAV URL guard applies the shared address rule when private hosts are off.

With ODYSSEUS_ALLOW_PRIVATE_CALDAV unset, addresses refused by
``url_security.is_blocked_ip`` (RFC 6598 shared space, site-local IPv6,
ISATAP-wrapped internal IPv4, ...) are refused, whether given as an IP
literal or reached through a hostname. With the opt-in on, LAN addresses
the user opted into are still accepted.
"""

import ipaddress

import pytest

from src import caldav_sync

REFUSED = [
    "100.64.0.1",
    "100.100.100.200",
    "::ffff:100.64.0.1",
    "fec0::1",
    "2606:4700::5efe:7f00:1",
]


def _literal_url(addr: str) -> str:
    host = f"[{addr}]" if ":" in addr else addr
    return f"https://{host}/dav"


def _resolve_to(monkeypatch, addr: str) -> None:
    monkeypatch.setattr(
        caldav_sync,
        "_resolve_caldav_host_ips",
        lambda host: [ipaddress.ip_address(addr)],
    )


@pytest.fixture
def opt_in_off(monkeypatch):
    monkeypatch.delenv("ODYSSEUS_ALLOW_PRIVATE_CALDAV", raising=False)


@pytest.fixture
def opt_in_on(monkeypatch):
    monkeypatch.setenv("ODYSSEUS_ALLOW_PRIVATE_CALDAV", "1")


@pytest.mark.parametrize("addr", REFUSED)
def test_ip_literal_refused_when_opt_in_off(opt_in_off, monkeypatch, addr):
    _resolve_to(monkeypatch, "93.184.216.34")  # never reached for literals
    with pytest.raises(ValueError):
        caldav_sync.validate_caldav_url(_literal_url(addr))


@pytest.mark.parametrize("addr", REFUSED)
def test_hostname_resolving_to_internal_refused_when_opt_in_off(opt_in_off, monkeypatch, addr):
    _resolve_to(monkeypatch, addr)
    with pytest.raises(ValueError):
        caldav_sync.validate_caldav_url("https://calendar.example.com/dav")


def test_public_address_accepted_when_opt_in_off(opt_in_off, monkeypatch):
    _resolve_to(monkeypatch, "93.184.216.34")
    assert caldav_sync.validate_caldav_url("https://93.184.216.34/dav") == "https://93.184.216.34/dav"
    assert (
        caldav_sync.validate_caldav_url("https://calendar.example.com/dav")
        == "https://calendar.example.com/dav"
    )


# Accepted at fc3f7f1 with the opt-in on; must stay accepted.
@pytest.mark.parametrize("addr", ["192.168.1.10", "10.0.0.5"])
def test_opted_in_lan_address_still_accepted(opt_in_on, monkeypatch, addr):
    _resolve_to(monkeypatch, addr)
    assert caldav_sync.validate_caldav_url(f"https://{addr}/dav") == f"https://{addr}/dav"
    assert (
        caldav_sync.validate_caldav_url("http://nas.lan:5232/dav")
        == "http://nas.lan:5232/dav"
    )
