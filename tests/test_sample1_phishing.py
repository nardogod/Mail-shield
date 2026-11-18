"""sample-1 (Bradesco/Livelo lure) must score as phishing, with explainable why."""

from __future__ import annotations

from pathlib import Path

from mailshieldv1 import analyze, to_html

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "phishing" / "sample-1.eml"


def test_sample1_is_phishing_high() -> None:
    report = analyze(SAMPLE.read_bytes(), online=True, online_timeout=8.0)
    rules = {f.rule_id for f in report.findings}

    # Core "why this is phishing" signals for this sample:
    assert "HDR-BRAND-IMPERSONATION" in rules  # Bradesco/Livelo vs atendimento.com.br
    assert "HDR-DKIM-NONE" in rules or "HDR-COMPAUTH-FAIL" in rules
    assert "URL-SUSPICIOUS-HOST" in rules  # blog1seguimentmydomaine2bra.me
    assert report.auth.get("compauth") == "fail" or report.auth.get("dkim") == "none"
    assert report.verdict in {"high", "critical"}
    assert report.score >= 8

    page = to_html(report)
    assert "VirusTotal" in page
    assert "Why this verdict" in page


def test_sample1_offline_still_elevated() -> None:
    report = analyze(SAMPLE.read_bytes(), online=False)
    assert "HDR-BRAND-IMPERSONATION" in {f.rule_id for f in report.findings}
    assert report.verdict in {"medium", "high", "critical"}
    assert report.score >= 4
