"""Brand impersonation checks — tokens/kinds loaded from data/brands.yml."""

from __future__ import annotations

import re
from email.utils import parseaddr
from typing import Any

from mailshieldv1.core.domains import email_domain
from mailshieldv1.core.knowledge import normalize_for_match
from mailshieldv1.core.knowledge_store import brands_catalog

_TOKEN_RE_CACHE: dict[str, re.Pattern[str]] = {}
_URL_IN_TEXT = re.compile(r"https?://\S+", re.IGNORECASE)


def _token_re(token: str) -> re.Pattern[str]:
    if token not in _TOKEN_RE_CACHE:
        _TOKEN_RE_CACHE[token] = re.compile(re.escape(token), re.IGNORECASE)
    return _TOKEN_RE_CACHE[token]


def _brands() -> list[dict[str, Any]]:
    return brands_catalog()


def claimed_brands(*texts: str) -> list[str]:
    """Return canonical brands mentioned in any of the texts (homoglyph-normalized)."""
    raw = "\n".join(t or "" for t in texts)
    if not raw:
        return []
    raw = _URL_IN_TEXT.sub(" ", raw)
    blob = normalize_for_match(raw)
    found: list[str] = []
    for entry in _brands():
        brand = str(entry["id"])
        tokens = entry.get("tokens") or []
        if any(_token_re(str(tok)).search(blob) for tok in tokens):
            found.append(brand)
    return found


def brand_supported_by_domain(brand: str, domain: str) -> bool:
    """True if the From domain plausibly belongs to the claimed brand."""
    d = (domain or "").lower()
    if not d:
        return False
    compact = d.replace("-", "").replace("_", "").replace(".", "")
    labels = [p.replace("-", "") for p in d.split(".") if p]

    entry = next((b for b in _brands() if b.get("id") == brand), None)
    if entry is None:
        return brand.replace("_", "") in compact

    kind = str(entry.get("kind") or "commercial")
    domain_cfg = entry.get("domain") or {}
    mode = str(domain_cfg.get("mode") or "")

    if mode == "contains":
        needles = [str(x).lower() for x in (domain_cfg.get("contains") or [])]
        return any(n in d for n in needles)

    if mode == "custom":
        equals = {str(x).lower() for x in (domain_cfg.get("equals") or [])}
        contains = [str(x).lower() for x in (domain_cfg.get("contains") or [])]
        suffix = [str(x).lower() for x in (domain_cfg.get("suffix") or [])]
        if d in equals:
            return True
        if any(c in d for c in contains):
            return True
        if any(d.endswith(s) for s in suffix):
            return True
        return False

    if mode == "exact_label" or kind == "crypto":
        extra = [str(x).lower().replace("-", "") for x in (domain_cfg.get("labels") or [])]
        label = brand.replace("_", "")
        wanted = {label, *extra}
        return any(p in wanted for p in labels)

    if mode == "institutional" or kind == "institutional":
        if d.endswith(".gov.br") or ".gov.br" in d or d.endswith(".gouv.fr"):
            if domain_cfg.get("require_gov") and brand == "antai":
                return "antai" in compact and ("gouv" in compact or "gov" in compact)
            if brand == "antai":
                return "antai" in compact and ("gouv" in compact or "gov" in compact)
            return True
        tokens = [str(x) for x in (domain_cfg.get("domain_tokens") or [])]
        if any(tok in compact for tok in tokens):
            return True
        # IMF-like institutional with custom equals already handled above.
        if brand == "imf":
            return False
        return False

    if kind == "support":
        needles = [str(x).lower() for x in (domain_cfg.get("contains") or [])]
        if needles:
            return any(n in compact or n in d for n in needles)

    # Default commercial: brand label appears in registrable domain.
    return brand.replace("_", "") in compact


def display_brand_impersonation(
    from_header: str,
    subject: str,
    body_excerpt: str = "",
) -> dict | None:
    """Detect brand claims that the From domain does not support."""
    name, _addr = parseaddr(from_header or "")
    from_d = email_domain(from_header)
    brands = claimed_brands(name, subject, body_excerpt or "")
    if not brands or not from_d:
        return None
    unsupported = [b for b in brands if not brand_supported_by_domain(b, from_d)]
    if not unsupported:
        return None
    return {
        "display_name": name,
        "from_domain": from_d,
        "claimed_brands": brands,
        "unsupported_brands": unsupported,
    }
