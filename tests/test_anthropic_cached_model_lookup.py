"""A saved Anthropic endpoint's model cache must be found from its chat URL.

Session creation validates the requested model with list_model_ids(chat_url),
where chat_url is build_chat_url(base) = ".../v1/messages". When the cache
lookup misses, Anthropic falls back to the static ANTHROPIC_MODELS list, so
newer models such as claude-sonnet-4-6 are rejected as "Model not found".
"""

import pytest

import core.database as database
import src.database as compatibility_database
from src import llm_core
from src.endpoint_resolver import build_chat_url, normalize_base
from tests.helpers.database import disposable_database


CACHED = ["claude-sonnet-4-6", "claude-opus-4-6"]


@pytest.fixture
def anthropic_db(tmp_path, monkeypatch):
    with disposable_database(tmp_path) as factory:
        monkeypatch.setattr(database, "SessionLocal", factory)
        monkeypatch.setattr(compatibility_database, "SessionLocal", factory)
        yield factory


def _add_endpoint(factory, base_url, owner=None, endpoint_id="anthropic"):
    with factory() as db:
        db.add(database.ModelEndpoint(
            id=endpoint_id, name="Anthropic", owner=owner, base_url=base_url,
            is_enabled=True, api_key="server-secret",
            cached_models='["claude-sonnet-4-6", "claude-opus-4-6"]',
            pinned_models='["claude-sonnet-4-6"]',
        ))
        db.commit()


@pytest.mark.parametrize("base_url", [
    "https://api.anthropic.com/v1",
    "https://api.anthropic.com/v1/",
    "https://api.anthropic.com",
])
def test_anthropic_chat_url_finds_saved_model_cache(anthropic_db, base_url):
    _add_endpoint(anthropic_db, base_url)
    chat_url = build_chat_url(normalize_base(base_url))
    assert chat_url == "https://api.anthropic.com/v1/messages"

    assert llm_core._configured_cached_model_ids(
        chat_url, owner="cachetest", endpoint_id="anthropic") == CACHED
    ids = llm_core.list_model_ids(chat_url, owner="cachetest", endpoint_id="anthropic")
    assert "claude-sonnet-4-6" in ids


def test_model_list_base_matches_chat_and_registered_forms():
    base = llm_core._model_list_base
    assert base("https://api.anthropic.com/v1/messages") == base("https://api.anthropic.com/v1")
    assert base("http://localhost:1234/v1/chat/completions") == base("http://localhost:1234/v1")
    assert base("http://localhost:1234/v1/models") == base("http://localhost:1234")


def test_cache_lookup_still_respects_owner_and_host(anthropic_db):
    _add_endpoint(anthropic_db, "https://api.anthropic.com/v1", owner="bob")
    chat_url = "https://api.anthropic.com/v1/messages"
    assert llm_core._configured_cached_model_ids(chat_url, owner="alice", endpoint_id="anthropic") == []
    assert llm_core._configured_cached_model_ids(chat_url, owner="bob", endpoint_id="anthropic") == CACHED
    assert llm_core._configured_cached_model_ids(
        "https://other.example/v1/messages", owner="bob", endpoint_id="anthropic") == []
