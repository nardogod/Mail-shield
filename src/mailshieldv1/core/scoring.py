"""Scoring v2: family weights, structured floor, commodity ceiling."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from mailshieldv1.core.knowledge_store import lures_catalog
from mailshieldv1.core.models import SEVERITY_RANK, Finding, Report

_BASE_WEIGHT = {
    "info": 0,
    "low": 1,
    "medium": 3,
    "high": 6,
    "critical": 10,
}

_SOFTENABLE = frozenset(
    {
        "HDR-FROM-REPLYTO-MISMATCH",
        "HDR-FROM-RETURNPATH-MISMATCH",
        "HDR-RETURNPATH-INFRA",
        "BEC-PAYMENT",
        "BEC-CREDENTIAL",
        "BEC-URGENCY",
        "ORG-MISMATCH",
    }
)

_ESCALATE_ON_WEAK_AUTH = frozenset(
    {
        "BEC-PAYMENT",
        "BEC-CREDENTIAL",
        "BEC-URGENCY",
        "ORG-MISMATCH",
        "URL-SUSPICIOUS-HOST",
        "HDR-RETURNPATH-INFRA",
    }
)

# Brand / identity structural phishing (floor toward high).
_STRUCTURED_BRAND = frozenset(
    {
        "HDR-BRAND-IMPERSONATION",
        "HDR-FREEMAIL-BRAND",
        "HDR-FREEMAIL-INVOICE",
        "HDR-HOMOGLYPH-DISPLAY",
        "HDR-LONG-DISPLAY-LURE",
    }
)

_FAMILY_BY_PREFIX = (
    ("HDR-BRAND", "brand"),
    ("HDR-FREEMAIL", "brand"),
    ("HDR-HOMOGLYPH", "brand"),
    ("HDR-INVISIBLE", "brand"),
    ("HDR-LONG-DISPLAY", "brand"),
    ("HDR-DISPLAY-NAME", "brand"),
    ("HDR-SPF", "auth"),
    ("HDR-DKIM", "auth"),
    ("HDR-DMARC", "auth"),
    ("HDR-COMPAUTH", "auth"),
    ("ONLINE-", "auth"),
    ("ATT-", "attachment"),
    ("URL-", "url"),
    ("ORG-", "org"),
    ("CONTENT-", "lure"),
    ("BEC-", "lure"),
    ("HDR-M365", "header"),
    ("HDR-FROM", "header"),
    ("HDR-RETURNPATH", "header"),
    ("HDR-MISSING", "header"),
    ("HOP-", "header"),
)


@dataclass
class Contributor:
    rule_id: str
    weight: float
    severity: str
    reason: str
    family: str = "other"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _threshold(score: float) -> str:
    if score >= 12:
        return "critical"
    if score >= 8:
        return "high"
    if score >= 4:
        return "medium"
    if score >= 1:
        return "low"
    return "info"


def _bump(sev: str) -> str:
    order = ["info", "low", "medium", "high", "critical"]
    try:
        i = order.index(sev)
    except ValueError:
        return sev
    return order[min(i + 1, len(order) - 1)]


def _family_for(rule_id: str) -> str:
    for prefix, fam in _FAMILY_BY_PREFIX:
        if rule_id.startswith(prefix):
            return fam
    if rule_id.startswith("MOD-AUTH"):
        return "auth"
    if rule_id.startswith("MOD-ORG"):
        return "org"
    return "other"


def _commodity_ids() -> frozenset[str]:
    cat = lures_catalog()
    ids = set(cat.get("commodity_lures") or [])
    for rule in cat.get("simple") or []:
        if rule.get("commodity"):
            ids.add(str(rule["id"]))
    return frozenset(ids)


def _structured_lure_ids() -> frozenset[str]:
    cat = lures_catalog()
    return frozenset(str(x) for x in (cat.get("structured_lures") or []))


def apply_calibration(
    report: Report,
    *,
    auth_strong_pass: bool,
    auth_any_fail: bool,
    auth_weak: bool,
    org_consistent: bool,
    esp_envelope: bool,
) -> list[Contributor]:
    """Mutate finding severities lightly, then compute family-aware score + verdict."""
    rule_ids = {f.rule_id for f in report.findings}
    structured_lures = _structured_lure_ids()
    commodity = _commodity_ids()

    institutional_phish = bool(
        rule_ids
        & (
            _STRUCTURED_BRAND
            | structured_lures
            | {
                "CONTENT-ROMANCE-LURE",  # still blocks full auth soften
                "CONTENT-CASINO-LURE",
                "CONTENT-FR-AIDES-LURE",
                "CONTENT-FR-CPF-LURE",
                "CONTENT-DOC-SHARE-LURE",
                "HDR-INVISIBLE-UNICODE",
            }
        )
    )
    structured_phish = bool(rule_ids & (_STRUCTURED_BRAND | structured_lures))

    soften = (
        auth_strong_pass
        and not auth_any_fail
        and not auth_weak
        and not institutional_phish
    )

    content_ids = [f.rule_id for f in report.findings if f.category == "content"]
    single_weak_content = (
        len(content_ids) == 1
        and not auth_weak
        and not auth_any_fail
        and not institutional_phish
    )

    calibrated: list[Finding] = []
    for f in report.findings:
        sev = f.severity
        conf = f.confidence
        if soften and f.rule_id in _SOFTENABLE:
            if f.rule_id.startswith("BEC-"):
                sev = "low"
                conf = min(conf, 0.45)
            elif f.rule_id.startswith("HDR-FROM-") or f.rule_id == "HDR-RETURNPATH-INFRA":
                sev = "info"
                conf = min(conf, 0.4)
            elif f.rule_id == "ORG-MISMATCH":
                sev = "low"
                conf = min(conf, 0.45)
        elif auth_weak and f.rule_id in _ESCALATE_ON_WEAK_AUTH:
            sev = _bump(sev) if sev in {"low", "medium"} else sev
            if f.rule_id.startswith("BEC-") and sev == "low":
                sev = "medium"
            conf = min(0.9, conf + 0.1)
        elif single_weak_content and f.rule_id in {
            "BEC-PAYMENT",
            "BEC-CREDENTIAL",
            "BEC-URGENCY",
        }:
            sev = "low"
            conf = min(conf, 0.5)

        if f.rule_id == "ATT-PDF-ACTIVE" and (
            rule_ids
            & {
                "CONTENT-IRPF-LURE",
                "HDR-FREEMAIL-BRAND",
                "HDR-FREEMAIL-INVOICE",
                "HDR-BRAND-IMPERSONATION",
            }
        ):
            sev = "high"
            conf = min(0.95, max(conf, 0.85))

        calibrated.append(
            Finding(
                rule_id=f.rule_id,
                category=f.category,
                severity=sev,
                confidence=conf,
                evidence=f.evidence,
                explanation=f.explanation,
                recommendation=f.recommendation,
            )
        )
    report.findings = calibrated

    contributors: list[Contributor] = []
    family_scores: dict[str, float] = {
        "auth": 0.0,
        "brand": 0.0,
        "lure": 0.0,
        "attachment": 0.0,
        "url": 0.0,
        "org": 0.0,
        "header": 0.0,
        "other": 0.0,
    }
    commodity_lure = 0.0
    structured_lure_w = 0.0

    for f in report.findings:
        w = _BASE_WEIGHT.get(f.severity, 0) * f.confidence
        if w <= 0:
            continue
        fam = _family_for(f.rule_id)
        family_scores[fam] = family_scores.get(fam, 0.0) + w
        if f.rule_id in commodity and fam == "lure":
            commodity_lure += w
        if f.rule_id in structured_lures:
            structured_lure_w += w
        contributors.append(
            Contributor(
                rule_id=f.rule_id,
                weight=round(w, 2),
                severity=f.severity,
                reason=f.explanation[:160],
                family=fam,
            )
        )

    # Modifiers
    if auth_strong_pass and not auth_weak and not institutional_phish:
        family_scores["auth"] -= 2.0
        contributors.append(
            Contributor(
                rule_id="MOD-AUTH-PASS",
                weight=-2.0,
                severity="info",
                reason="Authentication-Results indicate strong pass (MTA-asserted).",
                family="auth",
            )
        )
    elif auth_strong_pass and not auth_weak and institutional_phish:
        family_scores["auth"] -= 0.5
        contributors.append(
            Contributor(
                rule_id="MOD-AUTH-PASS",
                weight=-0.5,
                severity="info",
                reason=(
                    "Auth passes, but structural phishing signals keep risk elevated "
                    "(lookalike domains often authenticate)."
                ),
                family="auth",
            )
        )
    if auth_weak:
        family_scores["auth"] += 2.0
        contributors.append(
            Contributor(
                rule_id="MOD-AUTH-WEAK",
                weight=2.0,
                severity="medium",
                reason=(
                    "Authentication is weak/failed (temperror/none/fail/compauth) — "
                    "identity claims are not reliable."
                ),
                family="auth",
            )
        )
    if org_consistent and esp_envelope and not auth_weak and not institutional_phish:
        family_scores["org"] -= 1.5
        contributors.append(
            Contributor(
                rule_id="MOD-ORG-ESP",
                weight=-1.5,
                severity="info",
                reason="Brand domains look consistent with a known ESP envelope.",
                family="org",
            )
        )
    elif org_consistent and not auth_weak and not institutional_phish:
        family_scores["org"] -= 1.0
        contributors.append(
            Contributor(
                rule_id="MOD-ORG-CONSISTENT",
                weight=-1.0,
                severity="info",
                reason="From/URL registrable domains look organizationally consistent.",
                family="org",
            )
        )

    # Commodity ceiling: promo/romance/casino without structural brand/lure/auth fail.
    only_commodity = (
        commodity_lure > 0
        and not structured_phish
        and family_scores.get("brand", 0) <= 0
        and not auth_weak
        and not auth_any_fail
        and structured_lure_w <= 0
    )
    if only_commodity:
        # Cap lure family contribution so generic promo stays ≤ low/medium.
        capped = min(family_scores.get("lure", 0.0), 2.8)
        if capped < family_scores.get("lure", 0.0):
            contributors.append(
                Contributor(
                    rule_id="MOD-COMMODITY-CAP",
                    weight=round(capped - family_scores["lure"], 2),
                    severity="info",
                    reason=(
                        "Commodity spam lure without brand/auth structural signals — "
                        "score capped (promo/romance/casino)."
                    ),
                    family="lure",
                )
            )
            family_scores["lure"] = capped

    score = sum(family_scores.values())

    # Structured phishing floor: brand impersonation / IRPF / protesto / wallet etc.
    if structured_phish and score < 8.0:
        bump = 8.0 - score
        score = 8.0
        contributors.append(
            Contributor(
                rule_id="MOD-STRUCTURED-FLOOR",
                weight=round(bump, 2),
                severity="high",
                reason=(
                    "Structured phishing signals (brand/freemail/IRPF/protesto/crypto) "
                    "enforce at least verdict high."
                ),
                family="brand" if rule_ids & _STRUCTURED_BRAND else "lure",
            )
        )

    score = max(0.0, score)
    report.score = round(score, 2)
    report.verdict = _threshold(score)
    report.score_families = {k: round(v, 2) for k, v in family_scores.items() if abs(v) > 0.001}
    report.verdict_contributors = [
        c.to_dict() for c in sorted(contributors, key=lambda c: abs(c.weight), reverse=True)
    ]
    _ = SEVERITY_RANK
    return contributors
