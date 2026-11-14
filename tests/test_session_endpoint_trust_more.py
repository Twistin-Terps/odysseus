"""session_endpoint_is_trusted with no owner sees only shared endpoints.

Same rule as tests/test_session_endpoint_trust.py: a URL is trusted when it is
a built-in provider URL or an enabled ModelEndpoint the owner can see. With an
empty owner that means shared (null-owner) rows only, as in sync_chat.
"""
from types import SimpleNamespace

import pytest

import core.database as cdb
import src.session_endpoint_trust as trust
from tests.helpers.database import disposable_database

OWNER = "alice"
CONFIGURED_BASE = "http://192.168.1.50:8080/v1"
CONFIGURED = CONFIGURED_BASE + "/chat/completions"
SHARED_BASE = "http://shared.example.test/v1"
SHARED = SHARED_BASE + "/chat/completions"
BOB = "https://bob.example.test/v1/chat/completions"
BUILTIN = "https://api.openai.com/v1/chat/completions"


@pytest.fixture
def db(tmp_path, monkeypatch):
    with disposable_database(tmp_path) as factory:
        for module in (cdb, trust):
            monkeypatch.setattr(module, "SessionLocal", factory)
        with factory() as s:
            s.add(cdb.ModelEndpoint(id="ep1", owner=OWNER, name="lan", base_url=CONFIGURED_BASE, is_enabled=True))
            s.add(cdb.ModelEndpoint(id="ep2", owner="bob", name="bob", base_url="https://bob.example.test/v1",
                                    is_enabled=True))
            s.add(cdb.ModelEndpoint(id="ep3", owner=None, name="shared", base_url=SHARED_BASE, is_enabled=True))
            s.commit()
        yield factory


def _sess(url):
    return SimpleNamespace(endpoint_url=url, endpoint_id=None)


@pytest.mark.parametrize("owner", [None, ""])
@pytest.mark.parametrize("url, expected", [(BOB, False), (CONFIGURED, False), (SHARED, True), (BUILTIN, True)])
def test_empty_owner_sees_only_shared_endpoints(db, owner, url, expected):
    assert trust.session_endpoint_is_trusted(_sess(url), owner) is expected



# --- session_url_matches_endpoint: the base must name a host -----------------

IMDS = "http://169.254.169.254/latest/chat/completions"
CORP = "https://llm.corp.example/v1"


@pytest.mark.parametrize("session_url, base", [
    (IMDS, "http://"),
    (IMDS, "http:"),
    ("https://evil.example/v1/chat/completions", "https://"),
    ("https://evil.example/v1/chat/completions", "https:"),
    ("https://evil.example/v1/chat/completions", "https:///v1"),
    ("https://llm.corp.example/v1/chat/completions", "llm.corp.example/v1"),
    ("ftp://llm.corp.example/v1/chat/completions", "ftp://llm.corp.example/v1"),
])
def test_base_without_http_host_matches_nothing(session_url, base):
    assert trust.session_url_matches_endpoint(session_url, base) is False


@pytest.mark.parametrize("session_url", [
    CORP,
    CORP + "/",
    CORP + "/chat/completions",
    "https://LLM.Corp.Example/v1/chat/completions",
    "https://llm.corp.example./v1/chat/completions",
    "https://llm.corp.example:443/v1/chat/completions",
])
@pytest.mark.parametrize("base", [CORP, CORP + "/", "https://LLM.CORP.EXAMPLE/v1", CORP + "/chat/completions"])
def test_ordinary_matches_still_work(session_url, base):
    assert trust.session_url_matches_endpoint(session_url, base) is True


@pytest.mark.parametrize("session_url", [
    "http://llm.corp.example/v1/chat/completions",
    "https://llm.corp.example:8443/v1/chat/completions",
    "https://llm.corp.example.evil/v1/chat/completions",
    "https://evil.example/v1/chat/completions",
    "https://llm.corp.example/v10/chat/completions",
    "https://llm.corp.example/chat/completions",
    "not a url",
])
def test_different_origin_or_path_is_refused(session_url):
    assert trust.session_url_matches_endpoint(session_url, CORP) is False


@pytest.mark.parametrize("base", [
    CORP + "?x=1",
    CORP + "?",
    CORP + "#frag",
    "https://llm.corp.example:99999/v1",
    "https://[::1/v1",
    "http:///v1",
])
def test_malformed_base_matches_nothing_and_does_not_raise(base):
    assert trust.session_url_matches_endpoint(CORP + "/chat/completions", base) is False


def test_malformed_row_does_not_lock_owner_out(db):
    with db() as s:
        s.add(cdb.ModelEndpoint(id="bad", owner=OWNER, name="bad", base_url="https://h.example/v1?x=1",
                                is_enabled=True))
        s.add(cdb.ModelEndpoint(id="bad2", owner=OWNER, name="bad2", base_url="https://[::1/v1",
                                is_enabled=True))
        s.add(cdb.ModelEndpoint(id="good", owner=OWNER, name="good", base_url="https://good.example/v1",
                                is_enabled=True))
        s.commit()
    # The bad rows are checked before the good one; they must not raise.
    assert trust.session_endpoint_is_trusted(_sess("https://good.example/v1/chat/completions"), OWNER) is True
    assert trust.session_endpoint_is_trusted(_sess("https://h.example/v1/chat/completions"), OWNER) is False

