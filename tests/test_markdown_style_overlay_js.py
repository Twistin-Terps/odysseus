"""Model-written raw HTML must not keep a `style` that overlays the app.

`sanitizeAllowedHtml` keeps `style` on preserved <a>/<img>/<details> HTML.
A `position:fixed;inset:0;opacity:0` link would cover the whole window and
hijack the next click (prompt-injected phishing), so such styles are removed.

The renderer runs under node like tests/test_markdown_rendering_js.py, but
with a small template stub that really parses tags and attributes, so the
sanitiser's per-attribute loop sees the elements (the stub there returns no
elements and would let any style through untested).
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


@pytest.fixture(scope="module")
def node_available():
    if not _HAS_NODE:
        pytest.skip("node binary not on PATH")


_SCRIPT = textwrap.dedent(
    r"""
    import fs from 'node:fs';

    // Minimal parsing <template>: elements with attributes, removeAttribute,
    // remove, and serialisation back through innerHTML.
    const VOID = new Set(['img', 'br', 'hr', 'input', 'meta', 'link', 'source', 'wbr']);
    const decode = (v) => v
      .replace(/&quot;/g, '"').replace(/&#39;/g, "'")
      .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
    const encode = (v) => String(v).replace(/&/g, '&amp;').replace(/"/g, '&quot;');
    function parse(html) {
      const root = { children: [] };
      const stack = [root];
      const re = /<\/([a-zA-Z][\w-]*)\s*>|<([a-zA-Z][\w-]*)((?:\s+[^\s=\/>]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?)*)\s*\/?>|([^<]+|<)/g;
      let m;
      while ((m = re.exec(html)) !== null) {
        const top = stack[stack.length - 1];
        if (m[1]) {
          const tag = m[1].toLowerCase();
          for (let i = stack.length - 1; i > 0; i--) {
            if (stack[i].tag === tag) { stack.length = i; break; }
          }
        } else if (m[2]) {
          const tag = m[2].toLowerCase();
          const attributes = [];
          const are = /([^\s=\/>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
          let a;
          while ((a = are.exec(m[3] || '')) !== null) {
            const raw = a[2] ?? a[3] ?? a[4] ?? '';
            attributes.push({ name: a[1].toLowerCase(), value: decode(raw) });
          }
          const el = {
            tag, tagName: tag.toUpperCase(), attributes, children: [], parent: top,
            removeAttribute(n) {
              const i = this.attributes.findIndex(x => x.name === n.toLowerCase());
              if (i >= 0) this.attributes.splice(i, 1);
            },
            remove() {
              const i = this.parent.children.indexOf(this);
              if (i >= 0) this.parent.children.splice(i, 1);
            },
          };
          top.children.push(el);
          if (!VOID.has(tag)) stack.push(el);
        } else {
          top.children.push({ text: m[4] });
        }
      }
      return root;
    }
    function serialize(node) {
      return node.children.map(c => {
        if (c.text !== undefined) return c.text;
        const attrs = c.attributes.map(a => ` ${a.name}="${encode(a.value)}"`).join('');
        if (VOID.has(c.tag)) return `<${c.tag}${attrs}>`;
        return `<${c.tag}${attrs}>${serialize(c)}</${c.tag}>`;
      }).join('');
    }
    function all(node, out = []) {
      for (const c of node.children) if (c.tag) { out.push(c); all(c, out); }
      return out;
    }

    globalThis.window = { location: { origin: 'http://localhost' }, katex: null };
    globalThis.document = {
      readyState: 'loading',
      addEventListener() {},
      createElement(tag) {
        if (tag !== 'template') throw new Error(`unsupported element: ${tag}`);
        const tpl = { _root: { children: [] } };
        tpl.content = { querySelectorAll: () => all(tpl._root) };
        Object.defineProperty(tpl, 'innerHTML', {
          set(v) { tpl._root = parse(String(v)); },
          get() { return serialize(tpl._root); },
        });
        return tpl;
      },
    };
    globalThis.MutationObserver = class { observe() {} };

    let source = fs.readFileSync('./static/js/markdown.js', 'utf8');
    source = source.replace(/import uiModule from ['"]\.\/ui\.js(?:[?#][^'"]*)?['"];?/, '');
    source = source.replace(
      /import \{ splitTableRow \} from ['"]\.\/markdown\/tableRow\.js['"];/,
      `function splitTableRow(row) {
        return (row || '').replace(/^\\s*\\|/, '').replace(/\\|\\s*$/, '').split('|').map(c => c.trim());
      }`
    );
    const emojiSource = fs.readFileSync('./static/js/emojiShortcodes.js', 'utf8')
      .replace(/^export default .*$/m, '')
      .replace(/export const /g, 'const ')
      .replace(/export function /g, 'function ');
    source = source.replace(
      /import \{ replaceEmojiShortcodes, hasEmojiShortcode \} from ['"]\.\/emojiShortcodes\.js['"];/,
      () => emojiSource
    );
    source = source.replace(
      /var escapeHtml = uiModule\.esc;/,
      `var escapeHtml = (value) => String(value ?? '')
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');`
    );

    const mod = await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'));
    const inputs = JSON.parse(process.argv[1]);
    console.log(JSON.stringify(inputs.map(input => mod.mdToHtml(input))));
    """
)


def _render_all(markdowns):
    result = subprocess.run(
        ["node", "--input-type=module", "-e", _SCRIPT, json.dumps(markdowns)],
        cwd=_REPO, capture_output=True, text=True, timeout=15,
    )
    if result.returncode != 0:
        raise AssertionError(f"node failed:\nSTDERR:\n{result.stderr}\nSTDOUT:\n{result.stdout}")
    return json.loads(result.stdout.splitlines()[-1])


def _link(style):
    # Single quotes so the backslash/comment payloads need no escaping.
    return f"See <a href=\"https://evil.example\" style='{style}'>x</a> now"


_REFUSED = [
    "position:fixed;inset:0;opacity:0",
    "POSITION : absolute",
    "color:red; position:sticky",
    r"\70 osition:fixed",
    "pos/**/ition:fixed",
]

_KEPT = [
    "color:red",
    "text-align:center; font-weight:bold",
    "position:relative",
]


def _anchor(html):
    m = re.search(r"<a\b[^>]*>", html)
    assert m, f"link was not kept as an <a> element: {html!r}"
    return m.group(0)


def test_overlay_and_obfuscated_styles_are_removed(node_available):
    outputs = _render_all([_link(s) for s in _REFUSED])
    failures = []
    for style, html in zip(_REFUSED, outputs):
        anchor = _anchor(html)
        if "style=" in anchor or re.search(r"(?i)position", html):
            failures.append((style, html))
    assert not failures, f"overlay styles survived: {failures!r}"
    # The link text itself is still rendered.
    assert all(">x</a>" in html for html in outputs)


def test_harmless_styles_survive_unchanged(node_available):
    outputs = _render_all([_link(s) for s in _KEPT])
    for style, html in zip(_KEPT, outputs):
        anchor = _anchor(html)
        assert f'style="{style}"' in anchor, (style, html)
        assert 'href="https://evil.example"' in anchor, (style, html)
