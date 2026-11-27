"""May a session's stored endpoint URL be used for an outbound request?

A session created through ``POST /api/v1/chat`` with a token-supplied
``base_url`` keeps that URL in ``sessions.endpoint_url``. That route checks
and pins the URL on every turn; nothing else does. Routes other than
``sync_chat`` must therefore only call a stored URL the server itself chose:
a built-in provider URL, or an enabled ``ModelEndpoint`` the owner can see.
"""
from __future__ import annotations

import logging
from urllib.parse import unquote, urlsplit

from core.database import ModelEndpoint, SessionLocal

logger = logging.getLogger(__name__)

# Same base URLs as KNOWN_PROVIDERS in routes/webhook/webhook_routes.py, where
# the dict is local to the route setup function and cannot be imported.
# tests/test_session_endpoint_trust.py fails if the two lists drift apart.
BUILTIN_PROVIDER_BASES = frozenset({
    "https://api.deepseek.com/v1",
    "https://api.openai.com/v1",
    "https://api.mistral.ai/v1",
    "https://api.groq.com/openai/v1",
    "https://api.together.xyz/v1",
    "https://openrouter.ai/api/v1",
    "https://ollama.com/api",
    "https://opencode.ai/zen/v1",
    "https://opencode.ai/zen/go/v1",
    "https://api.fireworks.ai/inference/v1",
    "https://api.venice.ai/api/v1",
    "https://api.kimi.com/coding/v1",
})

UNTRUSTED_ENDPOINT_MESSAGE = (
    "This chat's model endpoint is not a configured endpoint. Pick a model in Settings."
)


def _origin(parsed):
    """(scheme, host, effective port) of an http(s) URL with a host, else None.

    Raises ValueError on an invalid port (urllib does)."""
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").rstrip(".").lower()
    if scheme not in {"http", "https"} or not host:
        return None
    return scheme, host, parsed.port or (443 if scheme == "https" else 80)


def _base_identity(url: str):
    """(origin, path) of an endpoint base URL, or None when it is not an
    http(s) URL with a host and no query or fragment."""
    parsed = urlsplit(url)
    if parsed.query or parsed.fragment or "?" in url or "#" in url:
        return None
    origin = _origin(parsed)
    if origin is None:
        return None
    return origin, parsed.path.rstrip("/")


def _session_identity(url: str):
    """(origin, path) of a session URL, or None when it is not an http(s) URL
    with a host, has userinfo, a non-ASCII host, port 0, a control character
    or whitespace, or its path holds a dot segment (also percent-encoded), a
    backslash, an encoded slash or an empty segment."""
    before_query = url.split("?", 1)[0].split("#", 1)[0]
    if "\\" in before_query:
        return None
    # urlsplit silently drops tabs and newlines, so judge the raw text.
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in url):
        return None
    parsed = urlsplit(url)
    # No userinfo; the host must be plain ASCII before it is case-folded
    # (the Kelvin sign lowercases to "k"); an explicit port 0 is not the
    # default port.
    if "@" in parsed.netloc or not parsed.netloc.isascii() or parsed.port == 0:
        return None
    origin = _origin(parsed)
    if origin is None:
        return None
    path = parsed.path
    if path.endswith("/"):
        path = path[:-1]
    if path:
        for segment in path[1:].split("/"):
            decoded = unquote(segment)
            if not segment or decoded in {".", ".."} or "/" in decoded or "\\" in decoded:
                return None
    return origin, path


def session_url_matches_endpoint(session_url: str, endpoint_base: str) -> bool:
    """Whether a stored session URL belongs to an endpoint's base URL.

    The base must be an http(s) URL with a host; scheme, host and effective
    port must be equal, and the session path must be the base path or below it
    on a segment boundary. A malformed base or session URL matches nothing and
    never raises, so one bad ModelEndpoint row cannot mark every session of
    its owner untrusted."""
    from src.endpoint_resolver import build_chat_url, normalize_base

    if not session_url or not endpoint_base:
        return False
    try:
        base = _base_identity(normalize_base(endpoint_base))
        if base is None:
            return False
        # The chat URL the server itself builds for this endpoint is trusted
        # as is: build_chat_url may swap the host for its Tailscale address,
        # so this exact comparison must run before the origin check.
        built = build_chat_url(normalize_base(endpoint_base)).rstrip("/")
        if session_url.strip().rstrip("/") == built:
            return True
        sess = _session_identity(session_url.strip())
        if sess is None:
            return False
        origin, base_path = base
        if sess[0] != origin:
            return False
        if sess[1] == base_path or sess[1].startswith(base_path + "/"):
            return True
        chat = _session_identity(build_chat_url(normalize_base(endpoint_base)))
        return chat is not None and sess == chat
    except Exception:
        return False


def is_builtin_provider_url(url: str) -> bool:
    """Whether ``url`` is the chat URL of a built-in provider (exact match,
    the rule ``sync_chat`` applies on resume)."""
    from src.endpoint_resolver import build_chat_url, normalize_base

    if not url:
        return False
    return url in {build_chat_url(normalize_base(base)) for base in BUILTIN_PROVIDER_BASES}


def session_matches_visible_endpoint(db, sess, owner: str | None) -> bool:
    """Whether the session URL matches an enabled ModelEndpoint the owner can
    see (only the bound endpoint counts when the session has ``endpoint_id``).

    Database errors propagate; callers must treat them as "not trusted".
    """
    url = getattr(sess, "endpoint_url", "") or ""
    query = db.query(ModelEndpoint).filter(ModelEndpoint.is_enabled == True)  # noqa: E712
    if owner:
        from src.auth_helpers import owner_filter
        query = owner_filter(query, ModelEndpoint, owner)
    else:
        # No owner: only shared endpoints, the rule sync_chat applies
        # (routes/webhook/webhook_routes.py). Never another user's private row.
        query = query.filter(ModelEndpoint.owner == None)  # noqa: E711
    bound_id = getattr(sess, "endpoint_id", None)
    for ep in query.all():
        if bound_id and ep.id != bound_id:
            continue
        if session_url_matches_endpoint(url, ep.base_url or ""):
            return True
    return False


def session_endpoint_is_trusted(sess, owner: str | None) -> bool:
    """True when the session's stored endpoint URL may be used for an outbound
    request outside ``sync_chat``: no stored URL, a built-in provider URL, or
    an enabled ModelEndpoint the owner can see. False on a database error."""
    url = getattr(sess, "endpoint_url", "") or ""
    if not url:
        return True
    if is_builtin_provider_url(url):
        return True
    db = None
    try:
        db = SessionLocal()
        return session_matches_visible_endpoint(db, sess, owner)
    except Exception as exc:
        logger.warning("Session endpoint check failed (%s); treating it as untrusted", type(exc).__name__)
        return False
    finally:
        if db is not None:
            db.close()


def uses_untrusted_session_url(url: str | None, sess, owner: str | None) -> bool:
    """True when ``url`` is the session's own stored URL and that URL is not
    trusted, i.e. the caller must refuse instead of contacting it."""
    stored = getattr(sess, "endpoint_url", "") or ""
    if not url or not stored or url != stored:
        return False
    return not session_endpoint_is_trusted(sess, owner)


def known_context_length(model: str) -> int:
    """Context window from the built-in table only, with no network probe."""
    from src.model_context import DEFAULT_CONTEXT, _lookup_known

    return int(_lookup_known(model or "") or DEFAULT_CONTEXT)
