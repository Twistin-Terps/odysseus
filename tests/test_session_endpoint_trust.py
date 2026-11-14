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
