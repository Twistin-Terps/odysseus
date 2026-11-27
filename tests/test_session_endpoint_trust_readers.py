"""Readers outside the chat routes must not call a token-supplied session URL.

Follows tests/test_session_endpoint_trust.py: a session created through
POST /api/v1/chat may store a URL that is neither a built-in provider nor an
enabled ModelEndpoint of its owner. ``_resolve_research_endpoint`` (which
falls back to the session URL when no research/utility endpoint is set) and
the background-job follow-up in ``src.bg_monitor`` must refuse such a URL
before any outbound call. Outbound functions are replaced by recorders.
"""
import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import core.database as cdb
import src.endpoint_resolver as endpoint_resolver
import src.session_endpoint_trust as trust
import src.settings as settings_mod
from routes.research import research_routes
from src import bg_jobs, bg_monitor
from tests.test_background_resource_identity import seed, store  # noqa: F401  (fixture)

OWNER = "alice"
UNTRUSTED = "https://rebind.example.test/v1/chat/completions"
CONFIGURED_BASE = "http://192.168.1.50:8080/v1"
CONFIGURED = CONFIGURED_BASE + "/chat/completions"
BUILTIN = "https://api.openai.com/v1/chat/completions"


@pytest.fixture
def db(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    cdb.Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    for module in (trust, endpoint_resolver):
        monkeypatch.setattr(module, "SessionLocal", factory)
    with factory() as s:
        s.add(cdb.ModelEndpoint(id="ep1", owner=OWNER, name="lan", base_url=CONFIGURED_BASE,
                                is_enabled=True, cached_models='["lan-model"]'))
        s.commit()
    yield factory
    engine.dispose()


def _settings(monkeypatch, values):
    monkeypatch.setattr(settings_mod, "load_settings", lambda: dict(values))
    monkeypatch.setattr(settings_mod, "get_user_setting", lambda key, owner="", default=None: default)


def _session(url, sid="s1"):
    return SimpleNamespace(
        id=sid, owner=OWNER, endpoint_url=url, endpoint_id=None, model="session-model",
        headers={"Authorization": "Bearer session"},
        get_context_messages=lambda: [{"role": "user", "content": "hi"}],
    )


# --- _resolve_research_endpoint -------------------------------------------

def test_research_refuses_untrusted_session_url_without_configured_endpoint(db, monkeypatch):
    _settings(monkeypatch, {})
    with pytest.raises(HTTPException) as exc:
        research_routes._resolve_research_endpoint(_session(UNTRUSTED))
    assert exc.value.status_code == 400
    assert exc.value.detail == trust.UNTRUSTED_ENDPOINT_MESSAGE
    assert UNTRUSTED not in str(exc.value.detail)


def test_research_uses_configured_endpoint_for_untrusted_session(db, monkeypatch):
    _settings(monkeypatch, {"research_endpoint_id": "ep1", "research_model": "lan-model"})
    url, model, _headers = research_routes._resolve_research_endpoint(_session(UNTRUSTED))
    assert url == CONFIGURED
    assert model == "lan-model"


@pytest.mark.parametrize("url", [CONFIGURED, BUILTIN])
def test_research_returns_trusted_session_url_as_before(db, monkeypatch, url):
    _settings(monkeypatch, {})
    sess = _session(url)
    assert research_routes._resolve_research_endpoint(sess) == (url, "session-model", sess.headers)


# --- bg_monitor background follow-up --------------------------------------

@pytest.fixture
def followup(monkeypatch):
    calls = []
    state = {}

    def install(sess):
        state["messages"] = []
        sm = SimpleNamespace(get_session=lambda sid: sess,
                             add_message=lambda *args: state["messages"].append(args),
                             save_sessions=lambda: None)
        import src.ai_interaction as ai
        import src.agent_runs
        monkeypatch.setattr(ai, "get_session_manager", lambda: sm)
        monkeypatch.setattr(src.agent_runs, "is_active", lambda sid: False)
        return state

    async def recorder(sess, messages, request_authority=None):
        calls.append(sess.endpoint_url)
        return "continued", []

    monkeypatch.setattr(bg_monitor, "_drain_agent", recorder)
    return install, calls


def test_bg_followup_refuses_untrusted_session_url(db, store, followup):  # noqa: F811
    install, calls = followup
    state = install(_session(UNTRUSTED, sid="thread"))
    _, rec = seed(store, status="done")
    outcome = asyncio.run(bg_monitor._process_followup(rec))
    assert outcome is bg_monitor.FollowupResult.TERMINAL_UNFOLLOWABLE
    assert calls == []
    assert state["messages"] == []
    assert not bg_jobs.pending_followups()


@pytest.mark.parametrize("url", [CONFIGURED, BUILTIN])
def test_bg_followup_still_continues_trusted_session_url(db, store, followup, url):  # noqa: F811
    install, calls = followup
    state = install(_session(url, sid="thread"))
    _, rec = seed(store, status="done")
    outcome = asyncio.run(bg_monitor._process_followup(rec))
    assert outcome is bg_monitor.FollowupResult.COMPLETED
    assert calls == [url]
    assert state["messages"]
