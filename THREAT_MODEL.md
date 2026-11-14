# Threat Model

Odysseus is a **self-hosted AI workspace with privileged local access**. This document states the trust boundary so contributors can reason about security decisions without reading through the full auth and middleware stack.

## Trust Boundary

Odysseus is designed for **trusted users on a private network**, not public exposure. The README describes it as "treat it like an admin console" — that framing is accurate. A logged-in admin can execute shell commands, read and write files, send email, and control model serving. This is intentional. The threat model does not try to prevent admins from doing these things. It does try to prevent:

- Unauthenticated access
- Non-admins reaching admin-only capabilities
- The AI agent acting on instructions injected through untrusted content (web results, emails, fetched pages, memories)
- Internal services (ChromaDB, Ollama, SearXNG, etc.) being reachable from outside the host

## Roles and Capabilities

| Capability | Admin | Non-admin (default) |
|---|---|---|
| Chat with agent | ✓ | ✓ |
| Browser tool | ✓ | ✓ |
| Documents | ✓ | ✓ |
| Research mode | ✓ | ✓ |
| Image generation | ✓ | ✓ |
| Memory management | ✓ | ✓ |
| Shell / Python execution | ✓ | ✗ |
| File read / write | ✓ | ✗ |
| Email send / read | ✓ | ✗ |
| MCP tools | ✓ | ✗ |
| Calendar management | ✓ | ✗ |
| Token / webhook management | ✓ | ✗ |
| Model serving | ✓ | ✗ |
| Vault | ✓ | ✗ |
| Settings | ✓ | ✗ |

Non-admin defaults are in `core/auth.py:DEFAULT_PRIVILEGES`. Tool enforcement is in `src/tool_security.py:NON_ADMIN_BLOCKED_TOOLS`. Any tool whose name starts with `mcp__` is also blocked for non-admins. Admins always get full access regardless of stored privilege values.

## Authentication

- **Sessions:** bcrypt passwords, 7-day session tokens stored atomically in `data/sessions.json` via `core/atomic_io.py`.
- **2FA:** TOTP with 8 single-use backup codes. Verified after password check, before session issuance.
- **Reserved usernames:** request sentinels and the Default/Local storage owner cannot be registered or renamed into. Defined in `core/auth.py:RESERVED_USERNAMES`.
  - `internal-tool` is security-critical: `core/middleware.py:require_admin` treats any request where `request.state.current_user == "internal-tool"` as the in-process tool loopback and grants admin unconditionally. A real account with that name would silently pass every `require_admin` check.
- **Orphan sessions:** `validate_token` re-checks that the user record still exists on every call. A deleted user's cookie is dropped on next request rather than continuing to authenticate.

## Internal Tool Loopback

Agent tool calls reach admin-gated HTTP routes over an in-process HTTP loopback. The mechanism:

1. At app startup, `core/middleware.py` generates a random `INTERNAL_TOOL_TOKEN` via `secrets.token_hex(32)`. It is never persisted and never sent to clients.
2. Loopback requests carry `X-Odysseus-Internal-Token: <token>` or have `request.state.current_user` already set to `"internal-tool"` by the auth middleware.
3. `require_admin` recognises either signal and grants access without checking the session user.

The agent may be running in a non-admin user's session, but tool dispatch first calls `src/tool_security.py:owner_is_admin_or_single_user` to verify the session owner is an admin before issuing any loopback call. Non-admin users cannot invoke admin tools even via the agent.

## Prompt-Injection Hardening

External content that reaches the LLM is treated as untrusted via `src/prompt_security.py`:

- `untrusted_context_message(label, content)` wraps the content in a `user`-role message with a header block instructing the model not to follow instructions inside it. Content goes in as data, not as a system instruction.
- `UNTRUSTED_CONTEXT_POLICY` is a system-prompt preamble that states the same policy at the top of every session where untrusted data may appear.

**Untrusted surfaces that must go through this wrapper:** web search results, fetched URLs, emails (read), saved memories, skill text, notes, and any tool output sourced from outside the server. Injecting untrusted content directly into the system role is a security bug.

### Post-external-context tool approval gate — on by default

`src/tool_capabilities.py` carries a second layer: once untrusted content has entered a run, `ToolRunSecurityContext.decision_for()` blocks tools that execute code, mutate state, or cause external side effects until the user authorises the action separately.

It is on unless `ODYSSEUS_TOOL_APPROVAL_GATE` is set to a falsy value (`0`/`false`/`no`/`off`). The admin-only `tool_approval_mode` setting (Settings → Agent Tools, `off` = "Off (YOLO)") is the same knob exposed in the UI: with `off`, every run sets `approval_gate_bypassed` and this gate stops asking, exactly as if the env var were off. Request authority narrows which tool families a turn may use, but within an admitted family it does not bind the exact action: a request to read email admits `send_email` and `delete_email`, and agent processes inherit the host network. Until those are covered by their own boundaries, this gate is what stops an injected instruction from reaching them. Turning it off — by either knob — lets a successful injection reach `bash`, `host_shell`, `send_email` and `delete_email` without a separate confirmation.

Three exemptions apply even when the gate is on, all deliberate:

- Sources in `_CONTROL_PLANE_CONTEXT_SOURCES` (skills, runtime descriptors, the open editor document, the open email, uploaded files) are treated as control-plane metadata and still permit read-only tools.
- A TUI run that advertises a host shell bridge and declares `unattended_mode` exempts the local execution set in `TUI_CLIENT_TOOL_NAMES`. Personal, network and deployment-local tools are never exempted.
- Narrow continuation for local MCP tools declared via `ODYSSEUS_LOCAL_MCP_READ_TOOLS` and `ODYSSEUS_LOCAL_MCP_WRITE_TOOLS`: Only explicitly configured stdio MCP servers qualify; remote HTTP and SSE servers fail closed. Declarations never override built-in tool effects, so built-in email, browser, memory, image generation, and other built-in servers cannot receive continuation exceptions. Declared read tools remain untrusted (`EXTERNAL_UNTRUSTED`) to ensure that prompt injections in local data cannot reach shell, network, or unrelated tools without approval. Stdio transport does not guarantee network isolation, as local processes may still reach the host network. However, declared non-destructive write tools on the exact same stdio MCP server are permitted to continue without an approval prompt if the only untrusted context in the run was produced by declared local reads on that same server, without any explicit error or external taint. Genuinely external content (web search, web fetch, emails, external message context) blocks these writes. Authorization must still originate from the trusted request: request authority must permit the tool and retain the sealed backend resource grant. The residual same-store write risk (the agent writing to the same local store after reading a local prompt injection) remains subject to the user's initial request authority.

## Security Headers

`core/middleware.py:SecurityHeadersMiddleware` sets headers on every response:

- `X-Frame-Options: DENY` + `frame-ancestors 'none'` on all routes except tool-render iframes (which are sandboxed at the HTML level).
- `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer` everywhere.
- **CSP:** nonce-based `script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net`. `style-src 'unsafe-inline'` is intentionally kept — `static/index.html` ships inline `<style>` blocks and JS modules set `style=""` attributes at runtime. Inline styles do not execute script so the risk is visual-only. Removing this requires templating the HTML files and auditing all JS-set style attributes.

## Token-Supplied LLM Endpoints

`POST /api/v1/chat` (`routes/webhook/webhook_routes.py:sync_chat`) requires a `chat`-scoped API token. A token that starts a session with a direct `api_key` may also pass its own `base_url`; the server treats that URL as untrusted:

- **Validation:** `src/url_security.py:resolve_public_http_url` accepts only `http`/`https` URLs with a public host. The host is lowercased and trailing dots are ignored (`localhost.` is `localhost`; a host of only dots is refused). Refused names: `localhost`, `localhost.localdomain`, `ip6-localhost`, `ip6-loopback`, `metadata`, `metadata.google.internal`, any name ending in `.localhost`, `.localdomain`, `.local`, `.internal`, `.lan`, `.intranet`, `.home.arpa`, `.home`, `.corp`, `.private` or `.svc`, and every single-label name (no dot, not an IP literal). Any other name is resolved once and refused if any of its addresses is refused; an IP literal is judged directly. Refused addresses (`src/url_security.py:is_blocked_ip`): anything CPython's `ipaddress` flags as private, loopback, link-local, multicast, reserved or unspecified, plus an explicit table that does not depend on the CPython version: `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10` (RFC 6598 shared space, CGNAT), `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.0.2.0/24`, `192.88.99.0/24`, `192.168.0.0/16`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4`, `240.0.0.0/4`, `::`, `::1`, `64:ff9b:1::/48` (local-use NAT64), `100::/64`, `2001::/32` (Teredo), `2001:2::/48`, `2001:10::/28`, `2001:db8::/32`, `2002::/16` (6to4), `3fff::/20`, `5f00::/16`, `fc00::/7`, `fe80::/10`, `fec0::/10` (site-local) and `ff00::/8`. IPv4-mapped (`::ffff:a.b.c.d`) and well-known-prefix NAT64 (`64:ff9b::/96`) addresses are judged only by the IPv4 address they embed, and an ISATAP address (interface identifier `0000:5efe:a.b.c.d` or `0200:5efe:a.b.c.d`) under any otherwise accepted prefix is also refused if its embedded IPv4 is refused; 6to4 and Teredo are refused whole rather than decoded, and network-specific NAT64 prefixes cannot be recognised. A port that is not an integer from 1 to 65535 is refused, and so is a URL containing a query (`?`) or fragment (`#`). A refused URL returns 400, and the message does not repeat the URL.
- **Pinning:** the LLM request connects only to the first address that passed the check (`_pinned_llm_client` over `src/webhook_manager.py:_PinnedAsyncTransport`), so a second DNS lookup cannot rebind it to an internal host. Host and TLS SNI still come from the URL, so the certificate is verified against the hostname. Redirects and environment proxies are off, and the context window comes from the built-in table instead of probing the endpoint.
- **Resumed sessions:** a session keeps the URL it was created with, and `base_url`/`provider` are ignored on resume. Unless the session's URL is a built-in provider URL (`KNOWN_PROVIDERS`) or matches a `ModelEndpoint` the token owner can see, it is checked and pinned again on every resume, so a host whose DNS now points somewhere private returns 400.
- **Everywhere else:** no other feature calls the stored URL of such a session. Rewrite, compaction, memory extract/audit/import, the `send_to_session` tool, the email AI reply and background tool-job summaries refuse a session whose stored URL is neither a built-in provider URL nor an enabled `ModelEndpoint` its owner can see (`src/session_endpoint_trust.py`); the two context-size routes answer from the built-in table without probing; the chat routes return 400 and blank such a URL (`routes/chat_routes.py:_clear_orphaned_session_endpoint`). The rule fails closed when the endpoint lookup errors.
- **One address rule:** `src/url_security.py:is_blocked_ip` is also consulted by the webhook URL check and its pinned transport (`src/webhook_manager.py`), the web fetch and search guards (`src/outbound_fetch.py`), the strict mode of `src/url_safety.py`, and the CalDAV server check when `ODYSSEUS_ALLOW_PRIVATE_CALDAV` is off, so none of them accepts an address this rule refuses.

Built-in provider URLs and configured `ModelEndpoint`s are not checked, so configured local/LAN model servers keep working.

## Known Gaps

These are open, acknowledged, and contributor help is welcome:

1. **No shell/filesystem sandbox.** The agent `bash` and `read_file`/`write_file` tools run as the app process user with no network egress filtering or filesystem confinement. A successful prompt-injection reaching a shell-enabled admin session can make outbound requests to internal services. See #1058 for the sandbox proposal. The tool approval gate above is the compensating control and is on by default; turning it off leaves this gap unmitigated beyond the untrusted-context wrapper.

2. **`src/search/` partial consolidation.** `src.search.core` and `src.search.providers` correctly alias `services.search` via `sys.modules` replacement. `analytics`, `cache`, `content`, `query`, and `ranking` are still independent copies that can drift. The SSRF regression tests in `tests/test_webhook_ssrf_resilience.py` test `src.webhook_manager` directly (separate from search), so the safety net there is intact. See #1058.

3. **The `chat` token scope is broad.** API tokens are minted by admins only (`routes/api_token_routes.py`) and carry scopes from a fixed list: `chat` (the default), `todos:read`/`todos:write`, `documents:read`/`documents:write`, `email:read`/`email:draft`/`email:send`, `calendar:read`/`calendar:write`, `memory:read`/`memory:write`, `cookbook:read`/`cookbook:launch`. `_normalize_scopes` rejects any other scope, and `/tokens/profiles` lists preset bundles of them. There is no `admin` scope. The per-capability scopes are enforced on the Codex integration routes (`routes/codex_routes.py`), and the `documents:*` scopes also on uploads (`routes/upload_routes.py`). What is still coarse:
   - `chat`, the only scope a companion/mobile pairing token gets (`companion/pairing.py:COMPANION_SCOPE`), is one grant covering chat, sessions, history, the model list, and upload read/write (`src/auth_helpers.py:require_chat_api_token_scope`, `routes/webhook/webhook_routes.py`, `routes/model_routes.py`, `routes/upload_routes.py`).
   - An agent run started by any token gets one fixed tool policy, the non-admin block list (`src/tool_security.py:delegated_credential_blocked_tools`), and cannot answer tool approvals. A token cannot be given a narrower set of agent tools.
   - Scopes apply only to token requests. `src/auth_helpers.py:require_api_token_scope` returns the session user unchanged for browser requests, so a browser session cannot be limited to a subset of its user's privileges.
