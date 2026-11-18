"""Knowledge distilled from phishing_pot sample-1..99 must catch prior FN clusters."""

from __future__ import annotations

from pathlib import Path

import pytest

from mailshieldv1 import analyze
from mailshieldv1.core.brands import claimed_brands, display_brand_impersonation
from mailshieldv1.core.knowledge import (
    has_mixed_script_homoglyph,
    is_free_mail,
    normalize_for_match,
)

ROOT = Path(__file__).resolve().parents[1]
POT = ROOT / "samples" / "phishing" / "badsamples" / "phishing_pot" / "email"

pytestmark = pytest.mark.pot


def _need_pot(*files: str) -> None:
    if not POT.is_dir():
        pytest.skip("phishing_pot not cloned (see samples/README.md)")
    for name in files:
        if not (POT / name).is_file():
            pytest.skip(f"missing pot file {name}")


def test_knowledge_helpers() -> None:
    assert is_free_mail("gmail.com")
    assert not is_free_mail("bb.com.br")
    # Cyrillic 'о' (U+043E) → Latin 'o' via homoglyph map.
    assert "coinbase" in normalize_for_match("Cоinbase").lower()
    assert has_mixed_script_homoglyph("Krаkеn Security")  # Cyrillic a/e


def test_bb_and_crypto_brand_tokens() -> None:
    assert "banco_do_brasil" in claimed_brands("[BB] - Seu saldo foi liberado")
    assert "binance" in claimed_brands("Binance", "Withdraw Successful")
    assert "metamask" in claimed_brands("Meta Mask Institutional Notice")
    hit = display_brand_impersonation(
        "Binance <noreply@auswestbc.com.au>",
        "[Binance] Withdraw Successful",
    )
    assert hit and "binance" in hit["unsupported_brands"]


def test_sample4_irpf_freemail_not_benign() -> None:
    _need_pot("sample-4.eml")
    report = analyze((POT / "sample-4.eml").read_bytes())
    rules = {f.rule_id for f in report.findings}
    assert "HDR-FREEMAIL-BRAND" in rules or "HDR-BRAND-IMPERSONATION" in rules
    assert "CONTENT-IRPF-LURE" in rules
    assert report.verdict in {"high", "critical"}
    assert report.score >= 8


def test_sample81_binance_not_benign() -> None:
    _need_pot("sample-81.eml")
    report = analyze((POT / "sample-81.eml").read_bytes())
    rules = {f.rule_id for f in report.findings}
    assert "HDR-BRAND-IMPERSONATION" in rules
    assert report.verdict in {"high", "critical"}


def test_sample23_homoglyph_elevated() -> None:
    _need_pot("sample-23.eml")
    report = analyze((POT / "sample-23.eml").read_bytes())
    rules = {f.rule_id for f in report.findings}
    assert "HDR-HOMOGLYPH-DISPLAY" in rules or "HDR-INVISIBLE-UNICODE" in rules
    assert report.verdict in {"medium", "high", "critical"}


def test_pot_1_99_fn_rate_improved() -> None:
    """Previously 15 info/low on pot 1..99; keep under-scored share low."""
    _need_pot("sample-1.eml", "sample-99.eml")
    weak = 0
    for n in range(1, 100):
        p = POT / f"sample-{n}.eml"
        report = analyze(p.read_bytes(), online=False)
        if report.verdict in {"info", "low"}:
            weak += 1
    # Allow a couple of commodity leftovers; must be << prior 15.
    assert weak <= 3, f"still under-scoring {weak} pot samples"
