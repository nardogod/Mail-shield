"""Offline hop geo hint tests."""

from __future__ import annotations

from pathlib import Path

from mailshieldv1 import analyze, to_html
from mailshieldv1.core.geo_hints import extract_ips, hint_for_hop

ROOT = Path(__file__).resolve().parents[1]
# Real-world style sample (renamed locally over time); fall back if missing.
_CPF_CANDIDATES = [
    ROOT / "samples" / "phishing" / "3.eml",
    ROOT / "samples" / "phishing" / "Notamos uma atualização recente no seu CPF.eml",
]
CPF = next((p for p in _CPF_CANDIDATES if p.is_file()), _CPF_CANDIDATES[0])
HOPS = ROOT / "samples" / "phishing" / "hops_chain.eml"


def test_extract_ips() -> None:
    text = "from x (23.251.225.94) by y [10.0.0.1] with ESMTP"
    ips = extract_ips(text)
    assert "23.251.225.94" in ips
    assert "10.0.0.1" in ips


def test_aws_region_hint() -> None:
    geo = hint_for_hop(
        from_host="e225-94.smtp-out.sa-east-1.amazonses.com",
        by_host="ty2pepf0000ab84.mail.protection.outlook.com",
        raw="from e225-94.smtp-out.sa-east-1.amazonses.com (23.251.225.94) by x",
    )
    assert geo.country == "Brazil"
    assert "São Paulo" in geo.city
    assert geo.source == "aws-region"
    assert geo.ip == "23.251.225.94"


def test_private_ip_hint() -> None:
    geo = hint_for_hop(
        from_host="internal.example",
        by_host="mx.example",
        raw="from internal.example (10.0.0.1) by mx.example",
    )
    assert geo.ip_scope == "private"
    assert geo.label.startswith("Private")


def test_hops_always_include_geo_fields() -> None:
    report = analyze(HOPS.read_bytes())
    assert report.hops
    for hop in report.hops:
        assert "geo_label" in hop
        assert "ip" in hop
        assert hop["geo_label"]


def test_cpf_sample_lists_brazil_in_html() -> None:
    import pytest

    if not CPF.is_file():
        pytest.skip(f"missing sample: {CPF}")
    page = to_html(analyze(CPF.read_bytes()))
    assert "Locations (offline hints)" in page
    assert "Brazil" in page
    assert "São Paulo" in page
