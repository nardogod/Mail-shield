"""sample5 (fake 6º Tabelião / protesto + boleto) must not score as benign."""

from __future__ import annotations

from pathlib import Path

from mailshieldv1 import analyze, to_html
from mailshieldv1.core.brands import display_brand_impersonation
from mailshieldv1.core.url_roles import classify_url

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "phishing" / "sample5.eml"


def test_tabeliao_display_not_supported_by_6protsp() -> None:
    hit = display_brand_impersonation(
        '"6º Tabelião de Protesto" <naoresponda@6protsp.com.br>',
        "Informativo - Tabelião de Protesto",
    )
    assert hit is not None
    assert "tabeliao" in hit["unsupported_brands"]


def test_sendgrid_click_href_is_cta() -> None:
    item = classify_url(
        "http://link.6protsp.com.br/ls/click?upn=abc",
        source="href",
    )
    assert item.role == "cta_action"


def test_sample5_is_phishing_not_looks_okay() -> None:
    raw = SAMPLE.read_bytes()
    report = analyze(raw)
    rules = {f.rule_id for f in report.findings}

    assert "HDR-BRAND-IMPERSONATION" in rules
    assert "CONTENT-PROTESTO-LURE" in rules
    assert "CONTENT-CONTACT-DOMAIN-MISMATCH" in rules  # sextoprotestosp vs 6protsp
    assert report.verdict in {"high", "critical"}
    assert report.score >= 8

    page = to_html(report, raw=raw)
    assert "Looks okay" not in page
    assert "Likely a scam" in page or "Dangerous" in page
    assert "cartório" in page.lower() or "protesto" in page.lower()
