"""Static attachment analyzer tests."""

from __future__ import annotations

from pathlib import Path

from mailshieldv1 import analyze, to_html

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "phishing" / "attachments_lure.eml"


def test_attachments_inventory_and_flags() -> None:
    report = analyze(SAMPLE.read_bytes())
    assert len(report.attachments) >= 3
    names = {a["filename"] for a in report.attachments}
    assert "invoice.pdf.exe" in names
    assert "doc.pdf" in names
    assert "pay.lnk" in names
    rules = {f.rule_id for f in report.findings}
    assert "ATT-PRESENT" in rules
    assert "ATT-DOUBLE-EXT" in rules
    assert "ATT-DANGEROUS-EXT" in rules
    assert "ATT-PDF-ACTIVE" in rules
    assert "ATT-LNK" in rules
    assert report.verdict in {"medium", "high", "critical"}


def test_attachments_html_section() -> None:
    page = to_html(analyze(SAMPLE.read_bytes()))
    assert "Attachments" in page
    assert "invoice.pdf.exe" in page
    assert "dangerous_extension" in page or "double_extension" in page
