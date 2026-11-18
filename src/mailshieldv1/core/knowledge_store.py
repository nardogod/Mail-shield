"""Load brands.yml / lures.yml from package data."""

from __future__ import annotations

from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

from mailshieldv1.core.yaml_lite import load_path, loads


def _read_data(name: str) -> Any:
    # Prefer package resource; fall back to source-tree path for editable installs.
    try:
        root = resources.files("mailshieldv1") / "data" / name
        with resources.as_file(root) as path:
            return load_path(path)
    except (FileNotFoundError, ModuleNotFoundError, TypeError, AttributeError):
        here = Path(__file__).resolve().parents[1] / "data" / name
        return load_path(here)


@lru_cache(maxsize=1)
def brands_catalog() -> list[dict[str, Any]]:
    data = _read_data("brands.yml")
    brands = data.get("brands") if isinstance(data, dict) else data
    if not isinstance(brands, list):
        raise ValueError("brands.yml must contain a top-level 'brands' list")
    return brands


@lru_cache(maxsize=1)
def lures_catalog() -> dict[str, Any]:
    data = _read_data("lures.yml")
    if not isinstance(data, dict):
        raise ValueError("lures.yml must be a mapping")
    return data


def reload_knowledge() -> None:
    """Clear caches (tests / hot-reload)."""
    brands_catalog.cache_clear()
    lures_catalog.cache_clear()
