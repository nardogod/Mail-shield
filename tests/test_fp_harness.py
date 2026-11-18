"""Benign / marketing samples must not score as phishing (FP harness)."""

from __future__ import annotations

from pathlib import Path

from mailshieldv1 import analyze

ROOT = Path(__file__).resolve().parents[1]
BENIGN = [
    ROOT / "samples" / "benign" / "simple_auth_pass.eml",
    ROOT / "samples" / "benign" / "newsletter_auth_pass.eml",
    ROOT / "samples" / "benign" / "internal_meeting.eml",
    ROOT / "samples" / "phishing" / "3.eml",  # auth-pass marketing with CPF language
]


def test_benign_corpus_stays_info_or_low() -> None:
    for path in BENIGN:
        report = analyze(path.read_bytes(), online=False)
        assert report.verdict in {"info", "low"}, (
            f"FP on {path.name}: verdict={report.verdict} score={report.score} "
            f"rules={[f.rule_id for f in report.findings]}"
        )


def test_structured_phishing_still_high() -> None:
    sample = ROOT / "samples" / "phishing" / "sample-1.eml"
    report = analyze(sample.read_bytes(), online=False)
    assert report.verdict in {"high", "critical"}
    assert report.score >= 8
