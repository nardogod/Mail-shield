"""Simple vs Technical HTML + safe email preview (no clickable links)."""

from __future__ import annotations

from pathlib import Path

from mailshieldv1 import analyze, to_html

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "phishing" / "sample-1.eml"


def test_html_defaults_to_simple_with_tech_toggle() -> None:
    raw = SAMPLE.read_bytes()
    page = to_html(analyze(raw), raw=raw)
    assert 'id="view-simple" checked' in page or 'id="view-simple" checked/' in page
    assert 'id="view-tech"' in page
    assert "Simple report" in page
    assert "Technical report" in page
    assert "What you should do" in page
    assert "Safe preview" in page or "safe preview" in page.lower()
    assert "Reconstructed email" in page


def test_safe_preview_has_no_navigable_href() -> None:
    raw = SAMPLE.read_bytes()
    page = to_html(analyze(raw), raw=raw)
    # Defused links must not keep an active href destination.
    assert "link blocked" in page.lower()
    assert "image blocked" in page.lower() or "[image blocked" in page.lower()
    # Should not include live http(s) href attributes in the preview region.
    # (Analyst pivots in technical view still have https links by design.)
    simple_start = page.find('class="panel-simple"')
    tech_start = page.find('class="panel-tech"')
    simple = page[simple_start:tech_start]
    assert "href=\"http" not in simple
    assert "href='http" not in simple
