"""Attribute-injection regression for three more `_esc` helpers.

`_esc` in static/js/gallery.js, static/js/research/panel.js and
static/js/tasks.js used a textContent -> innerHTML round trip, which escapes
`& < >` but leaves `"` and `'` raw. Their output is placed inside quoted
attributes built from model output (AI vision tags, tool-argument prompts and
task names), fetched-page metadata (og:image thumbnails, source URLs) and
upload filenames, so a value such as `x" onmouseover="y` closed the attribute
and added new ones. These tests pin that each helper now also escapes quotes,
still escapes `& < >`, and keeps its previous handling of null, undefined and
other falsy values (which differs between the three helpers).

`_safeSourceHref` in research/panel.js returns `_esc(new URL(raw).href)` for
use in `href="..."`; the URL parser keeps a raw `"` in a host such as
`http://a"style=x.com/`, so it gets its own check.

The modules import DOM-dependent code, so each function is extracted from its
source by definition and evaluated in node with a minimal `document` stub that
behaves like a browser's textContent -> innerHTML serialization (the
textContent setter maps null and undefined to "").
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

_JS = _REPO / "static" / "js"

_ESC_SOURCES = {
    "gallery.js": (_JS / "gallery.js", r"^function _esc\(str\) \{\n.*?^\}"),
    "research/panel.js": (_JS / "research" / "panel.js", r"^function _esc\(s\) \{\n.*?^\}"),
    "tasks.js": (_JS / "tasks.js", r"^function _esc\(s\) \{\n.*?^\}"),
}

# Inputs: null, undefined, '', 0, false, 42.
_EMPTY_INPUTS_JS = "[null, undefined, '', 0, false, 42]"
_EMPTY_EXPECTED = {
    # `if (!str) return ''` -> every falsy value is ''.
    "gallery.js": ["", "", "", "", "", "42"],
    # `s || ''` -> every falsy value is ''.
    "research/panel.js": ["", "", "", "", "", "42"],
    # textContent = s -> null/undefined are '', 0 and false are stringified.
    "tasks.js": ["", "", "", "0", "false", "42"],
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
globalThis.window = { location: { origin: 'http://localhost:7000' } };
"""


def _extract(path: Path, pattern: str) -> str:
    src = path.read_text(encoding="utf-8")
    m = re.search(pattern, src, re.S | re.M)
    assert m, f"definition not found in {path}: {pattern}"
    return m.group(0)


def _run(fn_src: str, call: str, inputs_js: str) -> list:
    js = _DOM_STUB + "\n" + fn_src + "\n" + textwrap.dedent(
        f"""
        const inputs = {inputs_js};
        console.log(JSON.stringify(inputs.map((v) => {call}(v))));
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
    out = _run(fn_src, "_esc", """['x" onmouseover="y', "x' style='z"]""")
    for value in out:
        assert '"' not in value and "'" not in value, (name, value)
    assert out[0] == "x&quot; onmouseover=&quot;y"
    assert out[1] == "x&#39; style=&#39;z"


@pytest.mark.parametrize("name", sorted(_ESC_SOURCES))
def test_esc_still_escapes_html_specials(name):
    fn_src = _extract(*_ESC_SOURCES[name])
    out = _run(fn_src, "_esc", "['a & b <i>x</i>']")
    assert out == ["a &amp; b &lt;i&gt;x&lt;/i&gt;"]


@pytest.mark.parametrize("name", sorted(_ESC_SOURCES))
def test_esc_keeps_its_empty_and_falsy_value_handling(name):
    fn_src = _extract(*_ESC_SOURCES[name])
    out = _run(fn_src, "_esc", _EMPTY_INPUTS_JS)
    assert out == _EMPTY_EXPECTED[name], name


def test_research_safe_source_href_escapes_quote_in_host():
    path = _JS / "research" / "panel.js"
    esc_src = _extract(*_ESC_SOURCES["research/panel.js"])
    href_src = _extract(path, r"^function _safeSourceHref\(raw\) \{\n.*?^\}")
    out = _run(
        esc_src + "\n" + href_src,
        "_safeSourceHref",
        """['http://a"style=x.com/p', 'https://example.com/a?b=1&c=2', 'javascript:alert(1)']""",
    )
    assert out[0], "expected the http URL to be accepted"
    assert '"' not in out[0], out[0]
    assert "&quot;" in out[0], out[0]
    assert out[1] == "https://example.com/a?b=1&amp;c=2"
    assert out[2] == ""
