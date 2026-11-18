"""Public report contract: Finding and Report."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # noqa: D105
        return self.name.lower()


SEVERITY_RANK = {s.name.lower(): int(s) for s in Severity}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    severity: str
    confidence: float
    evidence: str
    explanation: str
    recommendation: str

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_RANK:
            raise ValueError(f"invalid severity: {self.severity}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")


@dataclass
class Report:
    subject: str
    from_addr: str
    to_addrs: list[str]
    message_id: str
    findings: list[Finding] = field(default_factory=list)
    verdict: str = "info"
    score: float = 0.0
    verdict_contributors: list[dict[str, Any]] = field(default_factory=list)
    analyzer_notes: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    urls_defanged: list[str] = field(default_factory=list)
    url_items: list[dict[str, Any]] = field(default_factory=list)
    url_groups: list[dict[str, Any]] = field(default_factory=list)
    hops: list[dict[str, Any]] = field(default_factory=list)
    attachments: list[dict[str, Any]] = field(default_factory=list)
    auth: dict[str, Any] = field(default_factory=dict)
    org: dict[str, Any] = field(default_factory=dict)
    email_date: str = ""
    analyzed_at: str = ""
    email_age_days: int | None = None
    online: dict[str, Any] = field(default_factory=dict)
    score_families: dict[str, float] = field(default_factory=dict)
    schema: str = "mailshieldv1.report.v1"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "subject": self.subject,
            "from": self.from_addr,
            "to": self.to_addrs,
            "message_id": self.message_id,
            "verdict": self.verdict,
            "score": self.score,
            "score_families": dict(self.score_families),
            "verdict_contributors": list(self.verdict_contributors),
            "auth": dict(self.auth),
            "org": dict(self.org),
            "email_date": self.email_date,
            "analyzed_at": self.analyzed_at,
            "email_age_days": self.email_age_days,
            "findings": [asdict(f) for f in self.findings],
            "urls": list(self.urls),
            "urls_defanged": list(self.urls_defanged),
            "url_items": list(self.url_items),
            "url_groups": list(self.url_groups),
            "hops": list(self.hops),
            "attachments": list(self.attachments),
            "online": dict(self.online),
            "analyzer_notes": list(self.analyzer_notes),
        }

    def to_siem_dict(self) -> dict[str, Any]:
        """Stable, compact JSON contract for SIEM / ticketing ingestion."""
        ranked = sorted(
            self.findings,
            key=lambda f: (SEVERITY_RANK.get(f.severity, 0), f.confidence),
            reverse=True,
        )
        return {
            "schema": "mailshieldv1.siem.v1",
            "verdict": self.verdict,
            "score": self.score,
            "score_families": dict(self.score_families),
            "subject": self.subject,
            "from": self.from_addr,
            "to": list(self.to_addrs),
            "message_id": self.message_id,
            "email_date": self.email_date,
            "analyzed_at": self.analyzed_at,
            "email_age_days": self.email_age_days,
            "auth": {
                "spf": self.auth.get("spf"),
                "dkim": self.auth.get("dkim"),
                "dmarc": self.auth.get("dmarc"),
                "compauth": self.auth.get("compauth"),
                "authserv_id": self.auth.get("authserv_id"),
                "trusted": self.auth.get("trusted"),
                "strong_pass": self.auth.get("strong_pass"),
                "weak": self.auth.get("weak"),
                "any_fail": self.auth.get("any_fail"),
            },
            "org_consistent": bool((self.org or {}).get("consistent")),
            "rule_ids": [f.rule_id for f in self.findings],
            "top_findings": [
                {
                    "rule_id": f.rule_id,
                    "category": f.category,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "explanation": f.explanation[:200],
                }
                for f in ranked[:10]
                if f.severity not in {"info"}
            ],
            "urls_defanged": list(self.urls_defanged)[:50],
            "attachment_count": len(self.attachments),
            "online_enabled": bool((self.online or {}).get("enabled")),
        }
