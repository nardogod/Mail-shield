"""Optional --online DNS enrichments — live network lookups (gated)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from mailshieldv1 import analyze, to_html
from mailshieldv1.cli import main
from mailshieldv1.online.lookups import enrich_online

ROOT = Path(__file__).resolve().parents[1]
BENIGN = ROOT / "samples" / "benign" / "simple_auth_pass.eml"
CPF = ROOT / "samples" / "phishing" / "3.eml"


def _require_live() -> None:
    if os.environ.get("MAILSHIELD_LIVE_TESTS") != "1":
        pytest.skip("set MAILSHIELD_LIVE_TESTS=1 to run live DNS tests")


@pytest.mark.network
def test_live_dns_enrich_online_example_com() -> None:
    _require_live()
    dns = pytest.importorskip("dns.resolver")
    _ = dns  # presence check
    result = enrich_online(
        from_domain="example.com",
        url_domains=["example.com"],
        timeout=8.0,
    )
    assert result["enabled"] is True
    assert result["from_domain"] == "example.com"
    assert isinstance(result["spf_txt"], list)
    assert isinstance(result["dmarc_txt"], list)
    assert result["resolutions"]
    assert any(
        (not str(x).startswith("error:")) and "v=spf1" in str(x).lower()
        for x in result["spf_txt"]
    ), result["spf_txt"]
    assert any(r.get("ok") and r.get("addresses") for r in result["resolutions"]), result[
        "resolutions"
    ]


@pytest.mark.network
def test_analyze_online_live_on_real_sample() -> None:
    _require_live()
    pytest.importorskip("dns.resolver")
    report = analyze(CPF.read_bytes(), online=True, online_timeout=8.0)
    assert report.online.get("enabled") is True
    assert report.online.get("from_domain")
    assert "spf_txt" in report.online
    assert "dmarc_txt" in report.online
    assert report.online.get("resolutions")
    assert any("Online mode" in n for n in report.analyzer_notes)
    page = to_html(report)
    assert "Online enrichments" in page
    assert "SPF TXT" in page


@pytest.mark.network
def test_cli_online_live(tmp_path: Path, monkeypatch) -> None:
    _require_live()
    pytest.importorskip("dns.resolver")
    monkeypatch.chdir(tmp_path)
    code = main([str(BENIGN), "--online", "-f", "json"])
    assert code == 0
    text = (tmp_path / "reports" / "simple_auth_pass.json").read_text(encoding="utf-8")
    assert '"enabled": true' in text or '"enabled": true' in text.replace(" ", "")
    assert "example.com" in text
    assert "spf_txt" in text
    assert "resolutions" in text


def test_geo_non_global_multicast() -> None:
    from mailshieldv1.core.geo_hints import hint_for_hop

    geo = hint_for_hop(
        from_host="x",
        by_host="y",
        raw="from x (224.0.0.1) by y",
    )
    assert geo.ip_scope == "non_global"
    assert "Non-global" in geo.label
