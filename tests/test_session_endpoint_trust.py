"""Routes other than POST /api/v1/chat must not call a token-supplied session URL.

A session created through /api/v1/chat with a token's own ``base_url`` keeps
that URL (``endpoint_id`` NULL). /api/v1/chat checks and pins it on every
turn; the routes here do not pin, so they may only call a stored URL that is a
built-in provider URL or an enabled ModelEndpoint the owner can see. Each
untrusted case replaces the outbound function with a recorder that fails the
test if it is called.
"""
import ast
import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import APIRouter, HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import core.database as cdb
import routes.chat_routes as chat_routes
import routes.history.history_routes as history_routes
import routes.session_routes as session_routes
import src.model_context as model_context
import src.session_endpoint_trust as trust

ROOT = Path(__file__).resolve().parents[1]
OWNER = "alice"
UNTRUSTED = "https://rebind.example.test/v1/chat/completions"
CONFIGURED_BASE = "http://192.168.1.50:8080/v1"
CONFIGURED = CONFIGURED_BASE + "/chat/completions"
BUILTIN = "https://api.openai.com/v1/chat/completions"
KNOWN_MODEL = "gpt-4o"


@pytest.fixture
def db(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    cdb.Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    for module in (trust, chat_routes):
        monkeypatch.setattr(module, "SessionLocal", factory)
    with factory() as s:
        s.add(cdb.ModelEndpoint(id="ep1", owner=OWNER, name="lan", base_url=CONFIGURED_BASE, is_enabled=True))
        s.add(cdb.ModelEndpoint(id="ep2", owner="bob", name="bob", base_url="https://bob.example.test/v1",
                                is_enabled=True))
        s.commit()
    model_context._context_cache.clear()
    yield factory
    model_context._context_cache.clear()
    engine.dispose()


def _session(url):
    return SimpleNamespace(
        id="s1", owner=OWNER, endpoint_url=url, endpoint_id=None, model=KNOWN_MODEL,
        headers={}, history=[], cwd="", get_context_messages=lambda: [{"role": "user", "content": "hi"}],
    )


class _Manager:
    def __init__(self, sess):
        self.sess = sess

    def get_session(self, session_id):
        return self.sess

    def save_sessions(self):
        pass


def _request(body=None):
    async def json():
        return body or {}
    return SimpleNamespace(json=json, state=SimpleNamespace(current_user=OWNER, api_token=False),
                           headers={}, cookies={}, query_params={})


def _endpoint(router, path):
    return next(r.endpoint for r in router.routes if r.path == path)


def _forbidden(*args, **kwargs):
    raise AssertionError("outbound request made to an untrusted session URL")


# ---------------------------------------------------------------- helper


@pytest.mark.parametrize("url, expected", [
    ("", True), (BUILTIN, True), (CONFIGURED, True),
    (UNTRUSTED, False), ("https://bob.example.test/v1/chat/completions", False),
])
def test_helper_rule(db, url, expected):
    assert trust.session_endpoint_is_trusted(_session(url), OWNER) is expected


def test_helper_fails_closed_on_database_error(monkeypatch):
    class _Broken:
        def query(self, *a, **k):
            raise RuntimeError("database is locked")

        def close(self):
            pass

    monkeypatch.setattr(trust, "SessionLocal", _Broken)
    assert trust.session_endpoint_is_trusted(_session(CONFIGURED), OWNER) is False


def test_builtin_list_matches_sync_chat_known_providers():
    tree = ast.parse((ROOT / "routes/webhook/webhook_routes.py").read_text(encoding="utf-8"))
    node = next(n for n in ast.walk(tree) if isinstance(n, ast.Assign)
                and any(getattr(t, "id", None) == "KNOWN_PROVIDERS" for t in n.targets))
    assert set(ast.literal_eval(node.value).values()) == set(trust.BUILTIN_PROVIDER_BASES)


# ---------------------------------------------------------------- /api/rewrite


def _rewrite(monkeypatch, sess, stream):
    monkeypatch.setattr(chat_routes, "_verify_session_owner", lambda *a, **k: None)
    monkeypatch.setattr(chat_routes, "effective_user", lambda request: OWNER)
    monkeypatch.setattr(chat_routes, "stream_llm", stream)
    router = chat_routes.setup_chat_routes(_Manager(sess), None, None, None, None, None)
    endpoint = _endpoint(router, "/api/rewrite")
    body = {"session_id": "s1", "original_text": "long text", "instruction": "shorter"}

    async def run():
        response = await endpoint(_request(body))
        return [chunk async for chunk in response.body_iterator]
    return asyncio.run(run())


def test_rewrite_refuses_untrusted_session_url(db, monkeypatch):
    with pytest.raises(HTTPException) as exc:
        _rewrite(monkeypatch, _session(UNTRUSTED), _forbidden)
    assert exc.value.status_code == 400
    assert "rebind" not in exc.value.detail


@pytest.mark.parametrize("url", [CONFIGURED, BUILTIN])
def test_rewrite_still_works_for_trusted_urls(db, monkeypatch, url):
    calls = []

    async def stream(endpoint_url, *args, **kwargs):
        calls.append(endpoint_url)
        yield 'data: {"delta": "short"}\n\n'

    _rewrite(monkeypatch, _session(url), stream)
    assert calls == [url]


# ---------------------------------------------------------------- context_info


def _context_info(monkeypatch, sess):
    monkeypatch.setattr(session_routes, "_verify_session_owner", lambda *a, **k: None)
    monkeypatch.setattr(session_routes, "effective_user", lambda request: OWNER)
    monkeypatch.setattr(session_routes, "router", APIRouter(prefix="/api"))
    router = session_routes.setup_session_routes(_Manager(sess), {})
    endpoint = _endpoint(router, "/api/session/{session_id}/context_info")
    return asyncio.run(endpoint(_request(), "s1", cwd=None))


def test_context_info_does_not_probe_untrusted_url(db, monkeypatch):
    monkeypatch.setattr(model_context, "get_context_length", _forbidden)
    monkeypatch.setattr(model_context.httpx, "get", _forbidden)
    result = _context_info(monkeypatch, _session(UNTRUSTED))
    assert result["context_length"] == trust.known_context_length(KNOWN_MODEL)


@pytest.mark.parametrize("url", [CONFIGURED, BUILTIN])
def test_context_info_still_probes_trusted_urls(db, monkeypatch, url):
    calls = []
    monkeypatch.setattr(model_context, "get_context_length", lambda u, m: calls.append(u) or 4242)
    assert _context_info(monkeypatch, _session(url))["context_length"] == 4242
    assert calls == [url]


# ---------------------------------------------------------------- /context


def _history_context(monkeypatch, sess):
    monkeypatch.setattr(history_routes, "_verify_session_owner", lambda *a, **k: None)
    monkeypatch.setattr(history_routes, "effective_user", lambda request: OWNER)
    router = history_routes.setup_history_routes(_Manager(sess))
    endpoint = _endpoint(router, "/api/session/{session_id}/context")
    return asyncio.run(endpoint(_request(), "s1"))


def test_history_context_does_not_probe_untrusted_url(db, monkeypatch):
    monkeypatch.setattr(model_context, "get_context_length", _forbidden)
    monkeypatch.setattr(model_context.httpx, "get", _forbidden)
    result = _history_context(monkeypatch, _session(UNTRUSTED))
    assert result["context_length"] == trust.known_context_length(KNOWN_MODEL)


@pytest.mark.parametrize("url", [CONFIGURED, BUILTIN])
def test_history_context_still_probes_trusted_urls(db, monkeypatch, url):
    calls = []
    monkeypatch.setattr(model_context, "get_context_length", lambda u, m: calls.append(u) or 4242)
    assert _history_context(monkeypatch, _session(url))["context_length"] == 4242
    assert calls == [url]


# ---------------------------------------------------------------- chat fail-closed


def test_chat_orphan_check_refuses_on_database_error(monkeypatch):
    rolled_back = []

    class _Broken:
        def query(self, *a, **k):
            raise RuntimeError("database is locked")

        def rollback(self):
            rolled_back.append(True)

        def close(self):
            pass

    monkeypatch.setattr(chat_routes, "SessionLocal", _Broken)
    sess = _session(CONFIGURED)
    with pytest.raises(HTTPException) as exc:
        chat_routes._clear_orphaned_session_endpoint(sess, OWNER)
    assert exc.value.status_code == 503
    assert sess.endpoint_url == CONFIGURED and rolled_back


def test_chat_orphan_check_normal_cases_unchanged(db):
    assert chat_routes._clear_orphaned_session_endpoint(_session(CONFIGURED), OWNER) is False
    orphan = _session(UNTRUSTED)
    assert chat_routes._clear_orphaned_session_endpoint(orphan, OWNER) is True
    assert orphan.endpoint_url == "" and orphan.model == ""


# ---------------------------------------------------------------- compact

UTILITY = "http://192.168.1.60:8080/v1/chat/completions"


def _compact(monkeypatch, db, route, sess, llm, utility=False):
    """POST /session/{id}/compact (session_routes) or /api/session/{id}/compact
    (history_routes). The resolver returns the fallback (no utility endpoint)
    unless ``utility`` is set."""
    import src.agent_runs as agent_runs
    import src.endpoint_resolver as endpoint_resolver
    import src.llm_core as llm_core
    from core.models import ChatMessage

    sess.history = [ChatMessage(role="user" if i % 2 == 0 else "assistant", content=f"m{i}") for i in range(10)]
    sess.message_count = len(sess.history)

    def fake_resolve(kind, fallback_url=None, fallback_model=None, fallback_headers=None, owner=None):
        if utility:
            return UTILITY, "util-model", {}
        return fallback_url, fallback_model, fallback_headers

    monkeypatch.setattr(agent_runs, "is_active", lambda session_id: False)
    monkeypatch.setattr(endpoint_resolver, "resolve_endpoint", fake_resolve)
    monkeypatch.setattr(llm_core, "llm_call_async", llm)
    manager = _Manager(sess)
    manager.replace_messages = lambda sid, msgs: True
    if route == "session":
        monkeypatch.setattr(session_routes, "_verify_session_owner", lambda *a, **k: None)
        monkeypatch.setattr(session_routes, "effective_user", lambda request: OWNER)
        monkeypatch.setattr(session_routes, "router", APIRouter(prefix="/api"))
        router = session_routes.setup_session_routes(manager, {})
        endpoint = _endpoint(router, "/api/session/{session_id}/compact")
    else:
        monkeypatch.setattr(history_routes, "_verify_session_owner", lambda *a, **k: None)
        monkeypatch.setattr(history_routes, "SessionLocal", db)
        with db() as s:
            s.add(cdb.Session(id="s1", name="t", owner=OWNER, endpoint_url=sess.endpoint_url, model=KNOWN_MODEL))
            s.commit()
        router = history_routes.setup_history_routes(manager)
        endpoint = _endpoint(router, "/api/session/{session_id}/compact")
    return asyncio.run(endpoint(_request(), "s1"))


def _recorder(calls):
    async def llm(url, model, messages, **kwargs):
        calls.append(url)
        return "Summary"
    return llm


async def _forbidden_async(*args, **kwargs):
    raise AssertionError("outbound request made to an untrusted session URL")


@pytest.mark.parametrize("route", ["session", "history"])
def test_compact_refuses_untrusted_session_url(db, monkeypatch, route):
    monkeypatch.setattr(model_context, "get_context_length", _forbidden)
    monkeypatch.setattr(model_context.httpx, "get", _forbidden)
    with pytest.raises(HTTPException) as exc:
        _compact(monkeypatch, db, route, _session(UNTRUSTED), _forbidden_async)
    assert exc.value.status_code == 400
    assert exc.value.detail == trust.UNTRUSTED_ENDPOINT_MESSAGE
    assert "rebind" not in exc.value.detail


@pytest.mark.parametrize("route", ["session", "history"])
def test_compact_still_works_for_owner_visible_endpoint(db, monkeypatch, route):
    calls = []
    monkeypatch.setattr(model_context, "get_context_length", lambda u, m: 4242)
    _compact(monkeypatch, db, route, _session(CONFIGURED), _recorder(calls))
    assert calls == [CONFIGURED]


@pytest.mark.parametrize("route", ["session", "history"])
def test_compact_with_utility_endpoint_ignores_untrusted_session_url(db, monkeypatch, route):
    """The session URL is never used when a utility endpoint resolves, so it
    does not block compaction (and the history route does not probe it)."""
    calls = []
    monkeypatch.setattr(model_context, "get_context_length", _forbidden)
    monkeypatch.setattr(model_context.httpx, "get", _forbidden)
    _compact(monkeypatch, db, route, _session(UNTRUSTED), _recorder(calls), utility=True)
    assert calls == [UTILITY]


# ---------------------------------------------------------------- memory routes


def _memory(monkeypatch, path, sess, llm=None, audit=None, utility=False):
    """Call /api/memory/{extract,audit,import}. The task resolver returns the
    session fallback unless ``utility`` is set."""
    import routes.memory.memory_routes as memory_routes
    import src.auth_helpers as auth_helpers
    import src.utility_effort as utility_effort

    def fake_resolve(fallback_url=None, fallback_model=None, fallback_headers=None, owner=None):
        if utility:
            return UTILITY, "util-model", {}
        return fallback_url, fallback_model, fallback_headers

    async def fake_read(file, limit, label):
        return b"Alice likes green tea."

    monkeypatch.setattr(memory_routes, "get_current_user", lambda request: OWNER)
    monkeypatch.setattr(memory_routes, "require_user", lambda request: OWNER)
    monkeypatch.setattr(auth_helpers, "require_privilege", lambda *a, **k: None)
    monkeypatch.setattr(utility_effort, "effort_for_call", lambda *a, **k: None)
    monkeypatch.setattr(memory_routes, "resolve_task_endpoint", fake_resolve)
    monkeypatch.setattr(memory_routes, "read_upload_limited", fake_read)
    monkeypatch.setattr(memory_routes, "llm_call_async", llm or _forbidden_async)
    monkeypatch.setattr(memory_routes, "audit_memories", audit or _forbidden_async)
    router = memory_routes.setup_memory_routes(None, _Manager(sess))
    endpoint = _endpoint(router, "/api/memory/" + path)
    if path == "import":
        call = endpoint(_request(), session="s1", file=SimpleNamespace(filename="notes.txt"))
    else:
        call = endpoint(_request(), session="s1")
    return asyncio.run(call)


def _memory_llm(calls):
    async def llm(url, model, messages, **kwargs):
        calls.append(url)
        return "[]"
    return llm


def _memory_audit(calls):
    async def audit(manager, vector, url, model, headers, owner=None):
        calls.append(url)
        return {"before": 1, "after": 1}
    return audit


@pytest.mark.parametrize("path", ["extract", "audit", "import"])
def test_memory_routes_refuse_untrusted_session_url(db, monkeypatch, path):
    with pytest.raises(HTTPException) as exc:
        _memory(monkeypatch, path, _session(UNTRUSTED))
    assert exc.value.status_code == 400
    assert exc.value.detail == trust.UNTRUSTED_ENDPOINT_MESSAGE
    assert "rebind" not in exc.value.detail


@pytest.mark.parametrize("path", ["extract", "audit", "import"])
@pytest.mark.parametrize("url", [CONFIGURED, BUILTIN])
def test_memory_routes_still_work_for_trusted_urls(db, monkeypatch, path, url):
    calls = []
    _memory(monkeypatch, path, _session(url), llm=_memory_llm(calls), audit=_memory_audit(calls))
    assert calls == [url]


@pytest.mark.parametrize("path", ["extract", "audit", "import"])
def test_memory_routes_with_task_endpoint_ignore_untrusted_session_url(db, monkeypatch, path):
    calls = []
    _memory(monkeypatch, path, _session(UNTRUSTED), llm=_memory_llm(calls), audit=_memory_audit(calls),
            utility=True)
    assert calls == [UTILITY]


# ---------------------------------------------------------------- send_to_session agent tool


def _send_to_session(monkeypatch, sess, llm):
    import src.agent_tools.session_tools as session_tools
    import src.llm_core as llm_core

    sess.name = "target"
    sess.add_message = lambda msg: None
    monkeypatch.setattr(session_tools, "get_session_manager", lambda: _Manager(sess))
    monkeypatch.setattr(llm_core, "llm_call_async", llm)
    return asyncio.run(session_tools.send_to_session("s1\nhello", owner=OWNER))


def test_send_to_session_refuses_untrusted_session_url(db, monkeypatch):
    result = _send_to_session(monkeypatch, _session(UNTRUSTED), _forbidden_async)
    assert result == {"error": trust.UNTRUSTED_ENDPOINT_MESSAGE}


@pytest.mark.parametrize("url", [CONFIGURED, BUILTIN])
def test_send_to_session_still_works_for_trusted_urls(db, monkeypatch, url):
    calls = []
    result = _send_to_session(monkeypatch, _session(url), _recorder(calls))
    assert calls == [url]
    assert result["response"] == "Summary"


# ---------------------------------------------------------------- email ai-reply


def _ai_reply(monkeypatch, db, url, list_models):
    import routes.email.email_routes as email_routes
    import src.llm_core as llm_core

    monkeypatch.setattr(cdb, "SessionLocal", db)
    with db() as s:
        s.add(cdb.Session(id="s1", name="t", owner=OWNER, endpoint_url=url, model=KNOWN_MODEL))
        s.commit()
    monkeypatch.setattr(email_routes, "_load_settings", lambda: {})
    monkeypatch.setattr(email_routes, "_get_email_writing_style_for_account", lambda settings, account_id: "")

    def stop(*args, **kwargs):
        raise RuntimeError("stop after the model lookup")

    monkeypatch.setattr(email_routes, "_get_email_config", stop)
    monkeypatch.setattr(llm_core, "list_model_ids", list_models)
    monkeypatch.setattr(llm_core, "llm_call_async_with_fallback", _forbidden_async)
    monkeypatch.setattr(llm_core, "llm_call_async", _forbidden_async)
    router = email_routes.setup_email_routes()
    reply = _endpoint(router, "/api/email/ai-reply")
    return asyncio.run(reply({"original_body": "Hello there", "session_id": "s1", "fast": True}, owner=OWNER))


def test_ai_reply_refuses_untrusted_session_url(db, monkeypatch):
    result = _ai_reply(monkeypatch, db, UNTRUSTED, _forbidden)
    assert result == {"success": False, "error": trust.UNTRUSTED_ENDPOINT_MESSAGE}


@pytest.mark.parametrize("url", [CONFIGURED, BUILTIN])
def test_ai_reply_still_uses_trusted_session_url(db, monkeypatch, url):
    calls = []
    _ai_reply(monkeypatch, db, url, lambda u, headers=None: calls.append(u) or [])
    assert calls == [url]


# ---------------------------------------------------------------- background tool-job summary


def _background_summary(monkeypatch, db, url, calls):
    import src.llm_core as llm_core
    from src.background_tool_jobs import BackgroundToolJobs

    monkeypatch.setattr(cdb, "SessionLocal", db)
    with db() as s:
        s.add(cdb.Session(id="s1", name="t", owner=OWNER, endpoint_url=url, model=KNOWN_MODEL))
        s.commit()
    monkeypatch.setattr(llm_core, "llm_call_async", _recorder(calls))
    jobs = BackgroundToolJobs(is_busy=lambda sid: False)
    jobs.register("rp-trust", "s1", OWNER, "research", "query", 2)
    jobs.complete("rp-trust", "Report body.", [])
    asyncio.run(jobs.tick())
    row = jobs.list_for_chat("s1", OWNER)[0]
    assert row["status"] == "delivered"
    return row["message"]["content"]


def test_background_summary_refuses_untrusted_session_url(db, monkeypatch):
    calls = []
    content = _background_summary(monkeypatch, db, UNTRUSTED, calls)
    assert calls == []
    assert content.startswith("Research finished, but I could not generate its chat summary.")


@pytest.mark.parametrize("url", [CONFIGURED, BUILTIN])
def test_background_summary_still_uses_trusted_session_url(db, monkeypatch, url):
    calls = []
    content = _background_summary(monkeypatch, db, url, calls)
    assert calls == [url]
    assert content.startswith("Summary")
