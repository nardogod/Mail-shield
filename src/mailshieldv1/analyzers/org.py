"""Organizational domain consistency findings."""

from __future__ import annotations

from email.message import EmailMessage

from mailshieldv1.core.domains import org_consistency
from mailshieldv1.core.models import Finding
from mailshieldv1.core.urls import extract_urls


def analyze(msg: EmailMessage) -> list[Finding]:
    urls = extract_urls(msg)
    org = org_consistency(
        from_header=msg.get("From") or "",
        return_path=msg.get("Return-Path") or "",
        reply_to=msg.get("Reply-To") or "",
        urls=urls,
    )
    if not org.get("from_domain"):
        return []
    if org.get("consistent"):
        esp = " ESP envelope noted." if org.get("esp_envelope") else ""
        return [
            Finding(
                rule_id="ORG-CONSISTENT",
                category="org",
                severity="info",
                confidence=0.7,
                evidence=f"from={org['from_domain']}; urls={org['url_domains'][:6]}",
                explanation=(
                    "From and URL registrable domains look organizationally consistent."
                    + esp
                ),
                recommendation="Use as a down-weight signal when Authentication-Results also pass.",
            )
        ]
    return [
        Finding(
            rule_id="ORG-MISMATCH",
            category="org",
            severity="medium",
            confidence=0.7,
            evidence="; ".join(org.get("reasons") or [])[:300]
            or f"from={org['from_domain']}",
            explanation=(
                "Brand domains across From / URLs do not look consistent "
                "(possible impersonation or mixed infrastructure)."
            ),
            recommendation="Compare display brand vs URL hosts carefully before acting.",
        )
    ]
