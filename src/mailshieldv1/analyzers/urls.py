"""Static URL analyzer: extract signals only. Never fetches destinations."""

from __future__ import annotations

import re
from email.message import EmailMessage
from urllib.parse import urlparse

from mailshieldv1.core.brands import display_brand_impersonation
from mailshieldv1.core.domains import IGNORE_URL_DOMAINS, registrable_domain
from mailshieldv1.core.knowledge import is_url_shortener
from mailshieldv1.core.models import Finding
from mailshieldv1.core.text import visible_body_text
from mailshieldv1.core.urls import extract_urls

_IP_HOST = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$|"
    r"^\[?[0-9a-fA-F:]+\]?$"
)
_SUSPICIOUS_TLDS = frozenset(
    {"me", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "icu", "cn", "ru", "click", "link"}
)


def _looks_random_label(label: str) -> bool:
    """Heuristic: long consonant-heavy or mixed token labels used as phish hosts."""
    lab = re.sub(r"[^a-z0-9]", "", (label or "").lower())
    if len(lab) < 12:
        return False
    vowels = sum(1 for c in lab if c in "aeiou")
    if vowels / max(len(lab), 1) < 0.25 and len(lab) >= 16:
        return True
    # digit + long alpha mash
    return bool(re.search(r"[a-z]{8,}\d+[a-z]{3,}|\d+[a-z]{10,}", lab))


def analyze(msg: EmailMessage) -> list[Finding]:
    urls = extract_urls(msg)
    findings: list[Finding] = []

    if not urls:
        return findings

    findings.append(
        Finding(
            rule_id="URL-EXTRACTED",
            category="urls",
            severity="info",
            confidence=1.0,
            evidence=f"count={len(urls)}",
            explanation="URLs were extracted from the message body (static parse only).",
            recommendation="Review defanged URL list in the report before visiting any link.",
        )
    )

    brand_hit = display_brand_impersonation(
        msg.get("From") or "",
        msg.get("Subject") or "",
        visible_body_text(msg)[:2500],
    )
    claimed = set(brand_hit["unsupported_brands"]) if brand_hit else set()

    for url in urls:
        try:
            parsed = urlparse(url if "://" in url else f"http://{url}")
            host = (parsed.hostname or "").lower()
        except ValueError:
            continue
        reg = registrable_domain(host)
        if host and _IP_HOST.match(host):
            findings.append(
                Finding(
                    rule_id="URL-IP-LITERAL",
                    category="urls",
                    severity="medium",
                    confidence=0.75,
                    evidence=url[:300],
                    explanation="URL uses a raw IP host instead of a domain name.",
                    recommendation="Treat as suspicious; confirm the expected destination offline.",
                )
            )
        if "@" in (parsed.netloc or ""):
            findings.append(
                Finding(
                    rule_id="URL-USERINFO",
                    category="urls",
                    severity="medium",
                    confidence=0.8,
                    evidence=url[:300],
                    explanation=(
                        "URL contains userinfo (user:pass@host), "
                        "often used to spoof brands."
                    ),
                    recommendation="Ignore the display name before @; verify the real host.",
                )
            )
        if host and is_url_shortener(host):
            findings.append(
                Finding(
                    rule_id="URL-SHORTENER",
                    category="urls",
                    severity="medium",
                    confidence=0.7,
                    evidence=url[:300],
                    explanation=(
                        "URL uses a public shortener that hides the final destination — "
                        "common in phishing CTAs."
                    ),
                    recommendation=(
                        "Do not click; expand/unshorten in a safe tool before any visit."
                    ),
                )
            )
        if not reg or reg in IGNORE_URL_DOMAINS:
            continue
        label = reg.split(".")[0]
        tld = reg.rsplit(".", 1)[-1]
        suspicious = _looks_random_label(label) or (
            tld in _SUSPICIOUS_TLDS and len(label) >= 10
        )
        if suspicious:
            sev = "high" if claimed else "medium"
            findings.append(
                Finding(
                    rule_id="URL-SUSPICIOUS-HOST",
                    category="urls",
                    severity=sev,
                    confidence=0.8 if claimed else 0.65,
                    evidence=url[:300],
                    explanation=(
                        "URL host looks like a disposable / randomly labeled phishing domain"
                        + (
                            f" while the message claims brand(s): {', '.join(sorted(claimed))}."
                            if claimed
                            else "."
                        )
                    ),
                    recommendation=(
                        "Do not visit; pivot the domain (VT/urlscan) and compare to the real brand."
                    ),
                )
            )

    return findings
