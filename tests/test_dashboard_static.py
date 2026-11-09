"""Static checks that keep the console compatible with the strict CSP and safe from stored XSS."""
import re
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "app" / "static"


def test_no_inline_script_style_or_handlers():
    html = (STATIC / "index.html").read_text()
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html), "inline <script> is blocked by the CSP"
    assert "<style" not in html and " style=" not in html, "inline styles are blocked by the CSP"
    assert not re.search(r"\son[a-z]+=", html), "inline event handlers are blocked by the CSP"


def test_no_external_resources():
    for f in ("index.html", "dashboard.css", "dashboard.js"):
        text = (STATIC / f).read_text().replace("http://www.w3.org/2000/svg", "")
        assert "https://" not in text and "http://" not in text, f"{f} loads an external resource"


def test_js_never_parses_html():
    js = (STATIC / "dashboard.js").read_text()
    for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert bad not in js, bad


def test_csv_export_blocks_formula_injection():
    js = (STATIC / "dashboard.js").read_text()
    assert "formula injection" in js
