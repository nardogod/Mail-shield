"""Scoring v2 family scores + SIEM schema."""

from __future__ import annotations

from pathlib import Path

from mailshieldv1 import analyze
from mailshieldv1.report import to_siem_json

ROOT = Path(__file__).resolve().parents[1]


def test_score_families_present() -> None:
    report = analyze((ROOT / "samples" / "benign" / "simple_auth_pass.eml").read_bytes())
    assert isinstance(report.score_families, dict)


def test_siem_schema() -> None:
    report = analyze((ROOT / "samples" / "benign" / "simple_auth_pass.eml").read_bytes())
    data = report.to_siem_dict()
    assert data["schema"] == "mailshieldv1.siem.v1"
    assert "rule_ids" in data
    assert "score_families" in data
    text = to_siem_json(report)
    assert "mailshieldv1.siem.v1" in text
