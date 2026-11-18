"""Headers analyzer and end-to-end engine tests."""

from __future__ import annotations

from pathlib import Path

from mailshieldv1 import analyze, to_html, to_json

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def test_benign_auth_pass() -> None:
    raw = (SAMPLES / "benign" / "simple_auth_pass.eml").read_bytes()
    report = analyze(raw)
    rule_ids = {f.rule_id for f in report.findings}
    assert "HDR-SPF-FAIL" not in rule_ids
    assert "HDR-DKIM-FAIL" not in rule_ids
    assert "HDR-DMARC-FAIL" not in rule_ids
    assert report.verdict in {"info", "low"}


def test_phishing_replyto_and_auth_fail() -> None:
    raw = (SAMPLES / "phishing" / "replyto_mismatch.eml").read_bytes()
    report = analyze(raw)
    rule_ids = {f.rule_id for f in report.findings}
    assert "HDR-FROM-REPLYTO-MISMATCH" in rule_ids
    assert "HDR-DMARC-FAIL" in rule_ids
    assert "HDR-DISPLAY-NAME-EMAIL-MISMATCH" in rule_ids
    assert report.verdict in {"medium", "high", "critical"}


def test_json_and_html_escape() -> None:
    raw = (
        b'From: "x<script>" <a@example.com>\r\n'
        b"Subject: <b>hi</b>\r\n"
        b"Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\r\n"
        b"\r\n"
        b"body\r\n"
    )
    report = analyze(raw)
    page = to_html(report)
    assert "<script>" not in page
    assert "&lt;b&gt;hi&lt;/b&gt;" in page or "&lt;b&gt;" in page
    assert "Severity legend" in page or "sev-info" in page
    data = to_json(report)
    assert '"verdict"' in data
