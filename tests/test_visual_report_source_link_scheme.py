"""Security regression: Sources-list links must only use http/https.

The research report route is served with `script-src 'unsafe-inline'`, so a
stored source URL such as `javascript:alert(1)` rendered as an href would run
with the user's session when clicked. html.escape alone does not stop that.
"""
import re

from src.visual_report import generate_visual_report

_REFUSED = [
    ("javascript:alert(1)", "Refused plain js"),
    ("JaVaScRiPt:alert(1)", "Refused mixed case js"),
    (" javascript:alert(1)", "Refused leading space js"),
    ("java\tscript:alert(1)", "Refused embedded tab js"),
    ("data:text/html,<script>alert(1)</script>", "Refused data url"),
    ("vbscript:x", "Refused vbscript"),
]
_GOOD_URL = "https://example.org/a?b=1&c=2"
_IGNORED = "".join(chr(c) for c in range(0x21))


def _render():
    sources = [{"url": u, "title": t} for u, t in _REFUSED]
    sources.append({"url": _GOOD_URL, "title": "Good https source"})
    return generate_visual_report(
        question="Q",
        report_markdown="# Title\n\n## Section\n\nBody text.\n",
        sources=sources,
    )


def _hrefs(page):
    return [m.group(2) for m in re.finditer(r'href=(["\'])(.*?)\1', page, re.S)]


def test_only_http_https_hrefs_in_report():
    page = _render()
    for value in _hrefs(page):
        cleaned = re.sub(r"[\t\n\r]", "", value.strip(_IGNORED)).lower()
        cleaned = cleaned.replace("&amp;", "&")
        if cleaned.startswith("#"):
            continue  # in-page TOC anchors
        if cleaned.startswith("data:image/svg+xml"):
            continue  # static favicon <link>, not built from stored data
        assert cleaned.startswith(("http://", "https://")), value


def test_no_dangerous_scheme_anywhere_in_source_links():
    page = _render()
    assert 'href="javascript' not in page.lower()
    assert 'href=" javascript' not in page.lower()
    assert 'href="java\tscript' not in page.lower()
    assert 'href="data:text' not in page.lower()
    assert 'href="vbscript' not in page.lower()


def test_https_source_still_linked_with_escaped_ampersand():
    page = _render()
    assert '<a href="https://example.org/a?b=1&amp;c=2" target="_blank"' in page


def test_refused_source_titles_still_visible():
    page = _render()
    for _url, title in _REFUSED:
        assert f'<span class="source-title">{title}</span>' in page
    assert "Sources (7)" in page
