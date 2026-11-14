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


# --- session_url_matches_endpoint: no path tricks -----------------------------

@pytest.mark.parametrize("session_url", [
    CORP + "/../../admin/chat/completions",
    CORP + "/./chat/completions",
    CORP + "/%2e%2e/%2e%2e/admin/chat/completions",
    CORP + "/%2E%2E/admin",
    CORP + "/.%2e/admin",
    CORP + "/..",
    CORP + "/..?x=1",
    CORP + "\\..\\admin",
    CORP + "/chat\\..\\..\\admin",
    CORP + "//chat/completions",
    CORP + "/chat//completions",
    CORP + "/..%2fadmin",
    CORP + "/chat%5c..%5cadmin",
])
def test_path_tricks_are_refused(session_url):
    assert trust.session_url_matches_endpoint(session_url, CORP) is False


@pytest.mark.parametrize("session_url", [
    CORP + "/chat/completions",
    CORP + "/chat/completions?api-version=1",
    CORP + "/other/chat/completions",
    CORP + "/v1.5/chat/completions",
])
def test_plain_sub_paths_still_match(session_url):
    assert trust.session_url_matches_endpoint(session_url, CORP) is True


# --- task-name generation only calls a trusted session URL -------------------

TOKEN_URL = "http://attacker.example.test/v1/chat/completions"


@pytest.fixture
def task_routes_db(db, monkeypatch):
    import routes.task.task_routes as task_routes

    monkeypatch.setattr(task_routes, "SessionLocal", db)
    return task_routes


def _add_session(factory, sid, url, owner, minutes_ago):
    from datetime import datetime, timedelta

    with factory() as s:
        s.add(cdb.Session(id=sid, name=sid, owner=owner, endpoint_url=url, model="m-" + sid,
                          created_at=datetime.utcnow() - timedelta(minutes=minutes_ago)))
        s.commit()


async def _create_named_task(task_routes, monkeypatch, user, prompt):
    from unittest.mock import MagicMock

    from routes.task.task_routes import TaskCreate

    calls = []

    async def recorder(**kwargs):
        calls.append(kwargs)
        return "Generated Title"

    monkeypatch.setattr("src.llm_core.llm_call_async", recorder)
    monkeypatch.setattr(task_routes, "get_current_user", lambda request: user)
    router = task_routes.setup_task_routes(MagicMock())
    create = next(r.endpoint for r in router.routes
                  if getattr(r, "path", None) == "/api/tasks" and "POST" in getattr(r, "methods", set()))
    created = await create(SimpleNamespace(state=SimpleNamespace(current_user=user), headers={}),
                           TaskCreate(prompt=prompt, task_type="llm", trigger_type="webhook"))
    return created, calls


@pytest.mark.asyncio
async def test_task_name_skips_untrusted_newest_session(task_routes_db, db, monkeypatch):
    _add_session(db, "token", TOKEN_URL, OWNER, minutes_ago=0)
    created, calls = await _create_named_task(task_routes_db, monkeypatch, OWNER, "Summarize the weekly report")
    assert calls == []
    assert created["name"] == "Summarize the weekly report"


@pytest.mark.asyncio
async def test_task_name_uses_older_trusted_session(task_routes_db, db, monkeypatch):
    _add_session(db, "trusted", CONFIGURED, OWNER, minutes_ago=10)
    _add_session(db, "token", TOKEN_URL, OWNER, minutes_ago=0)
    created, calls = await _create_named_task(task_routes_db, monkeypatch, OWNER, "Summarize the weekly report")
    assert [c["url"] for c in calls] == [CONFIGURED]
    assert calls[0]["model"] == "m-trusted"
    assert created["name"] == "Generated Title"


@pytest.mark.asyncio
@pytest.mark.parametrize("user", [None, ""])
async def test_task_name_with_empty_owner_uses_no_session(task_routes_db, db, monkeypatch, user):
    # A shared endpoint is trusted even for an empty owner; it still must not
    # pick some user's session.
    _add_session(db, "bob-shared", SHARED, "bob", minutes_ago=0)
    _add_session(db, "builtin", BUILTIN, "carol", minutes_ago=1)
    created, calls = await _create_named_task(task_routes_db, monkeypatch, user, "Summarize the weekly report")
    assert calls == []
    assert created["name"] == "Summarize the weekly report"


# --- email ai-reply fails closed when the trust lookup raises ----------------

UNTRUSTED = "https://rebind.example.test/v1/chat/completions"


def test_ai_reply_makes_no_call_when_trust_lookup_raises(db, monkeypatch):
    import asyncio

    import routes.email.email_routes as email_routes
    import src.endpoint_resolver as endpoint_resolver
    import src.llm_core as llm_core

    monkeypatch.setattr(cdb, "SessionLocal", db)
    with db() as s:
        s.add(cdb.Session(id="s1", name="t", owner=OWNER, endpoint_url=UNTRUSTED, model="gpt-4o"))
        s.commit()
    monkeypatch.setattr(email_routes, "_load_settings", lambda: {})
    monkeypatch.setattr(email_routes, "_get_email_writing_style_for_account", lambda settings, account_id: "")

    def broken_lookup(*args, **kwargs):
        raise RuntimeError("trust lookup failed")

    monkeypatch.setattr(trust, "uses_untrusted_session_url", broken_lookup)
    monkeypatch.setattr(endpoint_resolver, "resolve_endpoint", lambda *a, **k: (None, None, None))
    calls = []

    def record(*args, **kwargs):
        calls.append(("list_model_ids", args))
        return []

    async def record_async(*args, **kwargs):
        calls.append(("llm", args, kwargs.get("url")))
        return ""

    monkeypatch.setattr(llm_core, "list_model_ids", record)
    monkeypatch.setattr(llm_core, "llm_call_async_with_fallback", record_async)
    monkeypatch.setattr(llm_core, "llm_call_async", record_async)
    router = email_routes.setup_email_routes()
    reply = next(r.endpoint for r in router.routes if r.path == "/api/email/ai-reply")
    result = asyncio.run(reply({"original_body": "Hello there", "session_id": "s1", "fast": True}, owner=OWNER))

    assert calls == []
    # The session URL is dropped and no fallback endpoint is configured.
    assert result == {"success": False, "error": "No LLM endpoint configured"}


# --- the chat URL the server builds is trusted (Tailscale host) --------------

TAILSCALE_BASE = "http://gpubox:8080/v1"


@pytest.fixture
def tailscale_gpubox(monkeypatch):
    """gpubox has no DNS entry; `tailscale status` maps it to 100.100.1.5."""
    import json
    import socket
    import types

    from src import endpoint_resolver as er

    def _no_dns(*a, **k):
        raise socket.gaierror("no DNS")

    peers = {"Peer": {"x": {"HostName": "gpubox", "DNSName": "gpubox.tail.ts.net.",
                            "TailscaleIPs": ["100.100.1.5"]}}}
    monkeypatch.setattr(er, "_tailscale_cache", {})
    monkeypatch.setattr(er.socket, "getaddrinfo", _no_dns)
    monkeypatch.setattr(er.subprocess, "run",
                        lambda *a, **k: types.SimpleNamespace(returncode=0, stdout=json.dumps(peers)))
    return er


def test_server_built_chat_url_on_tailscale_host_is_trusted(tailscale_gpubox):
    built = tailscale_gpubox.build_chat_url(TAILSCALE_BASE)
    assert built == "http://100.100.1.5:8080/v1/chat/completions"
    assert trust.session_url_matches_endpoint(built, TAILSCALE_BASE) is True


def test_other_address_on_same_port_and_path_is_not_trusted(tailscale_gpubox):
    assert trust.session_url_matches_endpoint(
        "http://100.100.1.6:8080/v1/chat/completions", TAILSCALE_BASE) is False
