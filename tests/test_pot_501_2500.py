"""Knowledge from phishing_pot sample-501..2500 FN clusters."""

from __future__ import annotations

from pathlib import Path

import pytest

from mailshieldv1 import analyze
from mailshieldv1.core.brands import brand_supported_by_domain, claimed_brands

ROOT = Path(__file__).resolve().parents[1]
POT = ROOT / "samples" / "phishing" / "badsamples" / "phishing_pot" / "email"

pytestmark = pytest.mark.pot


def _need_pot(*files: str) -> None:
    if not POT.is_dir():
        pytest.skip("phishing_pot not cloned (see samples/README.md)")
    for name in files:
        if not (POT / name).is_file():
            pytest.skip(f"missing pot file {name}")


def test_bb_informe_and_ourocard_tokens() -> None:
    assert "banco_do_brasil" in claimed_brands("Informe BB: Conta bloqueada")
    assert "banco_do_brasil" in claimed_brands("Ourocard - Liberacao")


def test_electrum_lookalike_domain_not_supported() -> None:
    assert "electrum" in claimed_brands("Electrum", "UPDATE YOUR WALLET")
    assert not brand_supported_by_domain("electrum", "electrumteamnews.com")
    assert brand_supported_by_domain("electrum", "electrum.org")


def test_sample825_bb_freemail() -> None:
    _need_pot("sample-825.eml")
    report = analyze((POT / "sample-825.eml").read_bytes())
    rules = {f.rule_id for f in report.findings}
    assert "HDR-FREEMAIL-BRAND" in rules or "HDR-BRAND-IMPERSONATION" in rules
    assert report.verdict in {"high", "critical"}


def test_sample1352_electrum_wallet() -> None:
    _need_pot("sample-1352.eml")
    report = analyze((POT / "sample-1352.eml").read_bytes())
    rules = {f.rule_id for f in report.findings}
    assert "HDR-BRAND-IMPERSONATION" in rules or "CONTENT-CRYPTO-WALLET-UPDATE" in rules
    assert report.verdict in {"medium", "high", "critical"}


def test_sample611_antai() -> None:
    _need_pot("sample-611.eml")
    report = analyze((POT / "sample-611.eml").read_bytes())
    rules = {f.rule_id for f in report.findings}
    assert "CONTENT-FR-AMENDE-LURE" in rules or "HDR-BRAND-IMPERSONATION" in rules
    assert report.verdict in {"medium", "high", "critical"}


def test_sample680_imf_moneygram() -> None:
    _need_pot("sample-680.eml")
    report = analyze((POT / "sample-680.eml").read_bytes())
    rules = {f.rule_id for f in report.findings}
    assert "CONTENT-ADVANCE-FEE" in rules or "HDR-FREEMAIL-BRAND" in rules
    assert report.verdict in {"medium", "high", "critical"}


def test_pot_501_2500_fn_rate() -> None:
    """Previously 150 info/low; keep under-scored share much lower."""
    _need_pot("sample-501.eml", "sample-2500.eml")
    weak = 0
    weak_ns: list[int] = []
    # Stratified sample every 5th + all previously known FNs would be slow;
    # full sweep is the acceptance bar for this corpus slice.
    for n in range(501, 2501):
        report = analyze((POT / f"sample-{n}.eml").read_bytes(), online=False)
        if report.verdict in {"info", "low"}:
            weak += 1
            weak_ns.append(n)
    # Baseline before this batch was 150 info/low; allow commodity spam leftovers.
    assert weak <= 110, f"still under-scoring {weak} samples (first 30: {weak_ns[:30]})"
