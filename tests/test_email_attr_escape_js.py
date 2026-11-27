"""Attribute-injection regression for the email UI's `_esc` helpers.

`_esc` is defined twice (static/js/emailLibrary/utils.js and
static/js/emailInbox.js). Both used a textContent -> innerHTML round trip,
which escapes `& < >` but leaves `"` and `'` raw. The helpers are used inside
double-quoted attributes built from email data (sender names, image URLs,
recipient chips), so a value such as `x" style="...` closed the attribute and
added new ones to the element. These tests pin that both definitions now also
escape quotes, still escape `& < >`, and still map null/undefined to "".

The MCP server form in settings.js has a local `esc` lambda used in quoted
`title`/`data-*` attributes; it gets the same quote check.

The modules import DOM-dependent code, so each function is extracted from its
source by definition and evaluated in node with a minimal `document` stub that
behaves like a browser's textContent -> innerHTML serialization.
"""

import json
import re
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
_HAS_NODE = shutil.which("node") is not None

pytestmark = pytest.mark.skipif(not _HAS_NODE, reason="node binary not on PATH")

_ESC_SOURCES = {
    "emailLibrary/utils.js": (
        _REPO / "static" / "js" / "emailLibrary" / "utils.js",
        r"^export function _esc\(text\) \{\n.*?^\}",
    ),
    "emailInbox.js": (
        _REPO / "static" / "js" / "emailInbox.js",
        r"^function _esc\(text\) \{\n.*?^\}",
    ),
}

# Browser-like stand-in: textContent -> innerHTML escapes only & < > (and nbsp).
_DOM_STUB = r"""
globalThis.document = {
  createElement() {
    let text = '';
    return {
      set textContent(v) { text = v == null ? '' : String(v); },
      get textContent() { return text; },
      get innerHTML() {
        return text.replace(/&/g, '&amp;').replace(/ /g, '&nbsp;')
          .replace(/</g, '&lt;').replace(/>/g, '&gt;');
      },
    };
  },
};
"""


def _extract(path: Path, pattern: str) -> str:
    src = path.read_text(encoding="utf-8")
    m = re.search(pattern, src, re.S | re.M)
    assert m, f"_esc definition not found in {path}"
    return m.group(0).replace("export function", "function", 1)


def _run_esc(fn_src: str, inputs_js: str) -> list:
    js = _DOM_STUB + "\n" + fn_src + "\n" + textwrap.dedent(
        f"""
        const inputs = {inputs_js};
        console.log(JSON.stringify(inputs.map((v) => _esc(v))));
        """
    )
    proc = subprocess.run(
        ["node", "--input-type=module"],
        input=js, capture_output=True, text=True, cwd=str(_REPO), timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.strip())


@pytest.mark.parametrize("name", sorted(_ESC_SOURCES))
def test_esc_escapes_quotes_for_attribute_context(name):
    fn_src = _extract(*_ESC_SOURCES[name])
    out = _run_esc(fn_src, """['x" onmouseover="y', "x' style='z"]""")
    for value in out:
        assert '"' not in value and "'" not in value, (name, value)
    assert out[0] == "x&quot; onmouseover=&quot;y"
    assert out[1] == "x&#39; style=&#39;z"


@pytest.mark.parametrize("name", sorted(_ESC_SOURCES))
def test_esc_still_escapes_html_specials_and_empty_values(name):
    fn_src = _extract(*_ESC_SOURCES[name])
    out = _run_esc(fn_src, """['a & b <i>x</i>', null, undefined, '', 42]""")
    assert out[0] == "a &amp; b &lt;i&gt;x&lt;/i&gt;"
    assert out[1] == ""
    assert out[2] == ""
    assert out[3] == ""
    assert out[4] == "42"


def test_settings_mcp_form_esc_lambda_escapes_quotes():
    src = (_REPO / "static" / "js" / "settings.js").read_text(encoding="utf-8")
    # The lambda is defined just before the MCP server edit form that puts it
    # in title="..." and data-mcp-tool-name="..." attributes.
    anchor = src.index("const srv = servers.find(s => (s.id || s.name) === editId);")
    m = re.compile(r"const esc = (s => [^\n]*);").search(src, anchor)
    assert m and m.start() - anchor < 400, "MCP form esc lambda not found"
    js = f"""
    const esc = {m.group(1)};
    console.log(JSON.stringify([esc('x" onmouseover="y'), esc("x' style='z"), esc('a & <b>'), esc(null)]));
    """
    proc = subprocess.run(
        ["node", "--input-type=module"],
        input=js, capture_output=True, text=True, cwd=str(_REPO), timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout.strip())
    assert out[0] == "x&quot; onmouseover=&quot;y"
    assert out[1] == "x&#39; style=&#39;z"
    assert out[2].startswith("a &amp; &lt;b")
    assert out[3] == ""
