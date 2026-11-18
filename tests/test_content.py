"""Content / BEC analyzer tests."""

from __future__ import annotations

from pathlib import Path

from mailshieldv1 import analyze

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "phishing" / "bec_wire_urgency.eml"


def test_bec_sample_hits_content_rules() -> None:
    report = analyze(SAMPLE.read_bytes())
    rules = {f.rule_id for f in report.findings}
    assert "BEC-URGENCY" in rules
    assert "BEC-PAYMENT" in rules
    assert "BEC-SECRECY" in rules
    assert report.verdict in {"medium", "high", "critical"}


def test_credential_rule_on_inline_message() -> None:
    raw = (
        b"From: a@evil.example\r\n"
        b"Subject: Verifique sua conta\r\n"
        b"\r\n"
        b"Por favor atualize seus dados e informe o CPF na pagina segura.\r\n"
    )
    report = analyze(raw)
    assert any(f.rule_id == "BEC-CREDENTIAL" for f in report.findings)
