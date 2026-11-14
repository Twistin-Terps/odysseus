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

