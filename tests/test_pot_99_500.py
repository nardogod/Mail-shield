"""Knowledge from phishing_pot sample-99..500 must catch prior FN clusters."""

from __future__ import annotations

from pathlib import Path

import pytest

from mailshieldv1 import analyze
from mailshieldv1.core.brands import claimed_brands

ROOT = Path(__file__).resolve().parents[1]
POT = ROOT / "samples" / "phishing" / "badsamples" / "phishing_pot" / "email"

pytestmark = pytest.mark.pot


def _need_pot(*files: str) -> None:
    if not POT.is_dir():
        pytest.skip("phishing_pot not cloned (see samples/README.md)")
    for name in files:
        if not (POT / name).is_file():
            pytest.skip(f"missing pot file {name}")


def test_bb_resgate_token() -> None:
    assert "banco_do_brasil" in claimed_brands("BB - Realize seu Resgate-123")


def test_sample414_bb_freemail_pdf() -> None:
    _need_pot("sample-414.eml")
    report = analyze((POT / "sample-414.eml").read_bytes())
    rules = {f.rule_id for f in report.findings}
    assert "HDR-FREEMAIL-BRAND" in rules or "HDR-BRAND-IMPERSONATION" in rules
    assert report.verdict in {"high", "critical"}


def test_sample223_paypal_freemail() -> None:
    _need_pot("sample-223.eml")
    report = analyze((POT / "sample-223.eml").read_bytes())
    rules = {f.rule_id for f in report.findings}
    assert "HDR-FREEMAIL-BRAND" in rules or "HDR-BRAND-IMPERSONATION" in rules
    assert report.verdict in {"medium", "high", "critical"}


def test_sample284_apple_body_brand() -> None:
    _need_pot("sample-284.eml")
    report = analyze((POT / "sample-284.eml").read_bytes())
    assert "HDR-BRAND-IMPERSONATION" in {f.rule_id for f in report.findings}
    assert report.verdict in {"medium", "high", "critical"}


def test_sample184_fr_aides() -> None:
    _need_pot("sample-184.eml")
    report = analyze((POT / "sample-184.eml").read_bytes())
    assert "CONTENT-FR-AIDES-LURE" in {f.rule_id for f in report.findings}
    assert report.verdict in {"medium", "high", "critical"}


def test_sample248_airdrop() -> None:
    _need_pot("sample-248.eml")
    report = analyze((POT / "sample-248.eml").read_bytes())
    rules = {f.rule_id for f in report.findings}
    assert "CONTENT-CRYPTO-AIRDROP" in rules or "HDR-BRAND-IMPERSONATION" in rules
    assert report.verdict in {"medium", "high", "critical"}


def test_pot_99_500_fn_rate() -> None:
    """Previously 42 info/low on pot 99..500; keep under-scored share low."""
    _need_pot("sample-99.eml", "sample-500.eml")
    weak = 0
    weak_ns: list[int] = []
    for n in range(99, 501):
        report = analyze((POT / f"sample-{n}.eml").read_bytes(), online=False)
        if report.verdict in {"info", "low"}:
            weak += 1
            weak_ns.append(n)
    assert weak <= 12, f"still under-scoring {weak} samples: {weak_ns}"
