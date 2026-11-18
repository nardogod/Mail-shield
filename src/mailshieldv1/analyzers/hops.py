"""Received-path analyzer. Treat early hops as forgeable."""

from __future__ import annotations

from email.message import EmailMessage

from mailshieldv1.core.hops import parse_hops
from mailshieldv1.core.models import Finding

_HIGH_HOP_COUNT = 12


def analyze(msg: EmailMessage) -> list[Finding]:
    hops = parse_hops(msg)
    findings: list[Finding] = []

    if not hops:
        findings.append(
            Finding(
                rule_id="HOP-NONE",
                category="hops",
                severity="low",
                confidence=0.6,
                evidence="No Received headers",
                explanation=(
                    "No Received headers found. The file may be incomplete, "
                    "hand-crafted, or not captured after MTA transit."
                ),
                recommendation="Prefer .eml exports that include the full header block.",
            )
        )
        return findings

    newest = hops[0]
    oldest = hops[-1]
    last_by = newest.by_host or newest.from_host or "n/a"
    # Prefer oldest from= (sending host), not by= (already the next MTA).
    origin = oldest.from_host or oldest.by_host or "n/a"
    findings.append(
        Finding(
            rule_id="HOP-MAP",
            category="hops",
            severity="info",
            confidence=1.0,
            evidence=f"hops={len(hops)}; last_by={last_by}; claimed_origin={origin}",
            explanation=(
                f"Last hop (start here): by={last_by}. "
                f"Claimed origin (forgeable): {origin}. "
                "Only hops on your side of the trust boundary are reliable."
            ),
            recommendation=(
                "Confirm last_by is your mail infrastructure; "
                "ignore claimed origin for attribution."
            ),
        )
    )

    if len(hops) >= _HIGH_HOP_COUNT:
        findings.append(
            Finding(
                rule_id="HOP-COUNT-HIGH",
                category="hops",
                severity="low",
                confidence=0.5,
                evidence=f"count={len(hops)}",
                explanation=(
                    "Unusually long Received chain; sometimes used to obscure origin."
                ),
                recommendation=(
                    "Review the newest trusted hops first; "
                    "ignore unverifiable early hops."
                ),
            )
        )

    if newest.from_host and newest.by_host and newest.from_host == newest.by_host:
        findings.append(
            Finding(
                rule_id="HOP-NEWEST-FROM-BY-SAME",
                category="hops",
                severity="info",
                confidence=0.4,
                evidence=f"from={newest.from_host}; by={newest.by_host}",
                explanation=(
                    "Newest Received line has identical from/by tokens "
                    "(parser-level signal)."
                ),
                recommendation=(
                    "Inspect the raw Received line; may be benign rewriting "
                    "or odd MTA config."
                ),
            )
        )

    return findings
