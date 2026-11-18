"""Content / BEC phrasing analyzer. Rules loaded from data/lures.yml."""

from __future__ import annotations

import re
from email.message import EmailMessage
from email.utils import parseaddr
from functools import lru_cache
from typing import Any

from mailshieldv1.core.domains import email_domain, registrable_domain
from mailshieldv1.core.knowledge_store import lures_catalog
from mailshieldv1.core.models import Finding
from mailshieldv1.core.text import visible_body_text

_EMAIL_IN_BODY = re.compile(
    r"(?i)\b([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})\b"
)
_PROTESTO_INST = re.compile(
    r"(?i)\b(protesto|cart[oó]rio|tabeli[aã]o|tabelionato|cenprot|custas\s+cartor)"
)


@lru_cache(maxsize=1)
def _compiled() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    cat = lures_catalog()
    simple_out: list[dict[str, Any]] = []
    for rule in cat.get("simple") or []:
        pats = [re.compile(p, re.IGNORECASE) for p in (rule.get("patterns") or [])]
        simple_out.append({**rule, "_pats": pats})
    composite_out: list[dict[str, Any]] = []
    for rule in cat.get("composite") or []:
        groups = []
        for group in rule.get("require_all") or []:
            groups.append([re.compile(p, re.IGNORECASE) for p in group])
        composite_out.append({**rule, "_groups": groups})
    return simple_out, composite_out


def analyze(msg: EmailMessage) -> list[Finding]:
    text = visible_body_text(msg)
    subject = msg.get("Subject") or ""
    from_name, _ = parseaddr(msg.get("From") or "")
    haystack = f"{from_name}\n{subject}\n{text}"
    if not haystack.strip():
        return []

    findings: list[Finding] = []
    hit_ids: list[str] = []
    simple, composites = _compiled()

    for rule in simple:
        hits: list[str] = []
        for pat in rule["_pats"]:
            m = pat.search(haystack)
            if m:
                hits.append(m.group(0))
        if not hits:
            continue
        rid = str(rule["id"])
        hit_ids.append(rid)
        findings.append(
            Finding(
                rule_id=rid,
                category="content",
                severity=str(rule.get("severity") or "low"),
                confidence=float(rule.get("confidence") or 0.5),
                evidence="; ".join(dict.fromkeys(hits))[:300],
                explanation=str(rule.get("explanation") or ""),
                recommendation=str(rule.get("recommendation") or ""),
            )
        )

    # Corroboration among BEC content rules.
    ids = set(hit_ids)
    if {"BEC-URGENCY", "BEC-PAYMENT"}.issubset(ids) or {"BEC-SECRECY", "BEC-PAYMENT"}.issubset(
        ids
    ):
        raised: list[Finding] = []
        for f in findings:
            if f.rule_id in {"BEC-PAYMENT", "BEC-URGENCY", "BEC-SECRECY"}:
                raised.append(
                    Finding(
                        rule_id=f.rule_id,
                        category=f.category,
                        severity="medium" if f.severity == "low" else f.severity,
                        confidence=min(0.85, f.confidence + 0.15),
                        evidence=f.evidence + "; corroborated_content=true",
                        explanation=f.explanation + " Multiple content signals co-occurred.",
                        recommendation=f.recommendation,
                    )
                )
            else:
                raised.append(f)
        findings = raised

    if {"BEC-CREDENTIAL", "BEC-URGENCY"}.issubset(ids):
        raised2: list[Finding] = []
        for f in findings:
            if f.rule_id == "BEC-CREDENTIAL":
                raised2.append(
                    Finding(
                        rule_id=f.rule_id,
                        category=f.category,
                        severity="medium",
                        confidence=min(0.85, f.confidence + 0.15),
                        evidence=f.evidence + "; corroborated_urgency=true",
                        explanation=f.explanation + " Co-occurred with urgency language.",
                        recommendation=f.recommendation,
                    )
                )
            else:
                raised2.append(f)
        findings = raised2

    for rule in composites:
        if not all(any(p.search(haystack) for p in group) for group in rule["_groups"]):
            continue
        findings.append(
            Finding(
                rule_id=str(rule["id"]),
                category="content",
                severity=str(rule.get("severity") or "high"),
                confidence=float(rule.get("confidence") or 0.85),
                evidence=str(rule.get("evidence") or rule["id"]),
                explanation=str(rule.get("explanation") or ""),
                recommendation=str(rule.get("recommendation") or ""),
            )
        )

    # Body contact mailbox on a different org domain (cartório lookalikes).
    from_d = email_domain(msg.get("From") or "")
    from_reg = registrable_domain(from_d) if from_d else ""
    if from_reg and _PROTESTO_INST.search(haystack):
        mismatches: list[str] = []
        for m in _EMAIL_IN_BODY.finditer(haystack):
            addr = m.group(1).lower()
            if addr.endswith(("@example.com", "@domain.com")):
                continue
            contact_reg = registrable_domain(addr.split("@", 1)[-1])
            if contact_reg and contact_reg != from_reg and contact_reg not in {
                "w3.org",
                "schema.org",
            }:
                mismatches.append(f"{addr} ({contact_reg})")
        mismatches = list(dict.fromkeys(mismatches))[:5]
        if mismatches:
            findings.append(
                Finding(
                    rule_id="CONTENT-CONTACT-DOMAIN-MISMATCH",
                    category="content",
                    severity="medium",
                    confidence=0.75,
                    evidence=f"from_domain={from_reg}; body_contacts=" + ", ".join(mismatches),
                    explanation=(
                        "Body lists a contact email on a different organization domain "
                        "than the From address while claiming an official notary/cartório "
                        "role — typical of lookalike-domain phishing."
                    ),
                    recommendation=(
                        "Treat the From domain and the body contact domain as untrusted "
                        "until verified out-of-band."
                    ),
                )
            )

    return findings
