"""brands.yml / lures.yml load and brand helpers."""

from __future__ import annotations

from mailshieldv1.core.brands import brand_supported_by_domain, claimed_brands
from mailshieldv1.core.knowledge_store import brands_catalog, lures_catalog


def test_brands_yml_loads() -> None:
    brands = brands_catalog()
    ids = {b["id"] for b in brands}
    assert "bradesco" in ids
    assert "electrum" in ids
    assert "banco_do_brasil" in ids


def test_lures_yml_loads() -> None:
    cat = lures_catalog()
    assert cat.get("simple")
    assert cat.get("composite")
    assert "CONTENT-CASINO-LURE" in (cat.get("commodity_lures") or [])


def test_claimed_from_yaml_tokens() -> None:
    assert "banco_do_brasil" in claimed_brands("Informe BB: Conta bloqueada")
    assert "electrum" in claimed_brands("Electrum Security")


def test_crypto_exact_label() -> None:
    assert brand_supported_by_domain("electrum", "electrum.org")
    assert not brand_supported_by_domain("electrum", "electrumteamnews.com")
