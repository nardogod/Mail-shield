"""Auth panel, scoring calibration, and corpus FP regression."""

from __future__ import annotations

from pathlib import Path

from mailshieldv1 import analyze, to_html
from mailshieldv1.core.authresults import parse_auth_results
from mailshieldv1.core.domains import org_consistency, registrable_domain
from mailshieldv1.core.parser import parse_eml
from mailshieldv1.core.url_roles import classify_urls, group_url_variants

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def test_registrable_br_and_esp() -> None:
    assert registrable_domain("mkt.acordocerto.com.br") == "acordocerto.com.br"
    assert registrable_domain("www.example.com") == "example.com"


def test_auth_strong_pass_on_cpf_sample() -> None:
    msg = parse_eml((SAMPLES / "phishing" / "3.eml").read_bytes())
    auth = parse_auth_results(msg)
    assert auth.present
    assert auth.spf == "pass"
    assert auth.dkim == "pass"
    assert auth.dmarc == "pass"
    assert auth.strong_pass
    assert not auth.any_fail


def test_marketing_cpf_softened_verdict() -> None:
    """Real marketing mail with auth pass should not stay 'high' on CPF alone."""
    report = analyze((SAMPLES / "phishing" / "3.eml").read_bytes())
    assert report.auth.get("dmarc") == "pass"
    assert report.verdict in {"info", "low"}
    assert report.score < 8
    page = to_html(report)
    assert "Why this verdict" in page
    assert "Authentication" in page
    assert "spf" in page.lower()


def test_bec_still_elevated() -> None:
    report = analyze((SAMPLES / "phishing" / "bec_wire_urgency.eml").read_bytes())
    assert report.verdict in {"medium", "high", "critical"}
    ids = {c["rule_id"] for c in report.verdict_contributors}
    assert "BEC-PAYMENT" in ids or "BEC-URGENCY" in ids or "BEC-SECRECY" in ids


def test_url_variant_grouping() -> None:
    items = classify_urls(
        [
            "https://brand.example/pay?utm=1",
            "https://brand.example/pay?utm=2&x=y",
            "https://brand.example/other",
        ]
    )
    groups = group_url_variants(items)
    assert len(groups) == 2
    pay = next(g for g in groups if g["key"].endswith("/pay"))
    assert pay["count"] == 2


def test_org_consistency_helper() -> None:
    org = org_consistency(
        from_header="Brand <a@brand.example>",
        return_path="<bounce@mail.amazonses.com>",
        reply_to="help@brand.example",
        urls=["https://brand.example/cta", "https://track.amazonses.com/o"],
    )
    assert org["from_domain"] == "brand.example"
    assert org["esp_envelope"] is True
    assert org["consistent"] is True


def test_sibling_brand_nordea_not_foreign() -> None:
    org = org_consistency(
        from_header="Nordea <news@info.nordea.se>",
        return_path="<bounce@info.nordea.se>",
        reply_to="engagemang@nordea.se",
        urls=["https://www.nordea.com/en/promo", "https://www.w3.org/1999/xhtml"],
    )
    assert org["consistent"] is True
    assert "nordea.com" not in " ".join(org.get("reasons") or [])


def test_report_has_age_and_groups() -> None:
    report = analyze((SAMPLES / "benign" / "simple_auth_pass.eml").read_bytes())
    assert report.analyzed_at
    assert report.email_date
    assert report.email_age_days is not None
    assert report.online == {"enabled": False}
    assert isinstance(report.url_groups, list)


def test_html_title_includes_subject() -> None:
    report = analyze((SAMPLES / "benign" / "simple_auth_pass.eml").read_bytes())
    page = to_html(report)
    assert "Project update" in page
    assert f"score {report.score}" in page
