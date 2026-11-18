"""Orchestrates parse + analyzers into a Report. Pure library by default."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from email.message import EmailMessage
from email.utils import getaddresses, parsedate_to_datetime

from mailshieldv1.analyzers import DEFAULT_ANALYZERS
from mailshieldv1.core.attachments import list_attachments
from mailshieldv1.core.authresults import (
    parse_auth_results,
    reset_authserv_id,
    resolve_authserv_id,
    set_authserv_id,
)
from mailshieldv1.core.domains import org_consistency, url_domain
from mailshieldv1.core.hops import parse_hops
from mailshieldv1.core.limits import DEFAULT_LIMITS, Limits
from mailshieldv1.core.models import Finding, Report
from mailshieldv1.core.parser import parse_eml
from mailshieldv1.core.scoring import apply_calibration
from mailshieldv1.core.url_roles import classify_urls, group_url_variants
from mailshieldv1.core.urls import defang_url, extract_urls_with_sources

Analyzer = Callable[[EmailMessage], list[Finding]]


def _meta(msg: EmailMessage) -> tuple[str, str, list[str], str]:
    subject = msg.get("Subject") or ""
    from_addr = msg.get("From") or ""
    to_addrs = [addr for _, addr in getaddresses(msg.get_all("To", []) or []) if addr]
    message_id = msg.get("Message-ID") or msg.get("Message-Id") or ""
    return subject, from_addr, to_addrs, message_id


def _email_age(msg: EmailMessage, now: datetime) -> tuple[str, int | None]:
    raw = msg.get("Date") or ""
    if not raw:
        return "", None
    try:
        dt = parsedate_to_datetime(raw)
    except (TypeError, ValueError, IndexError, OverflowError):
        return raw[:120], None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    age = max(0, int((now - dt).total_seconds() // 86400))
    return dt.isoformat(), age


def analyze(
    raw: bytes,
    *,
    analyzers: Sequence[Analyzer] | None = None,
    limits: Limits = DEFAULT_LIMITS,
    online: bool = False,
    online_timeout: float = 8.0,
    authserv_id: str | None = None,
) -> Report:
    """Analyze raw .eml bytes and return a structured Report.

    Offline by default (no network). Pass online=True for optional DNS lookups.

    ``authserv_id`` (or env ``MAILSHIELD_AUTHSERV_ID``) names the receiving MTA's
    Authentication-Results authserv-id. Score softening (``strong_pass``) only
    applies when that id matches — forged attacker pass headers cannot zero risk.
    """
    expected = resolve_authserv_id(authserv_id)
    token = set_authserv_id(expected)
    try:
        return _analyze_inner(
            raw,
            analyzers=analyzers,
            limits=limits,
            online=online,
            online_timeout=online_timeout,
            authserv_id=expected,
        )
    finally:
        reset_authserv_id(token)


def _analyze_inner(
    raw: bytes,
    *,
    analyzers: Sequence[Analyzer] | None,
    limits: Limits,
    online: bool,
    online_timeout: float,
    authserv_id: str | None,
) -> Report:
    msg = parse_eml(raw, limits=limits)
    subject, from_addr, to_addrs, message_id = _meta(msg)
    urls, url_sources = extract_urls_with_sources(msg)
    url_items = classify_urls(urls, sources=url_sources)
    url_groups = group_url_variants(url_items)
    hops = parse_hops(msg)
    attachments = list_attachments(msg)
    auth = parse_auth_results(msg, authserv_id=authserv_id)
    org = org_consistency(
        from_header=from_addr,
        return_path=msg.get("Return-Path") or "",
        reply_to=msg.get("Reply-To") or "",
        urls=urls,
    )
    now = datetime.now(UTC)
    email_date, email_age_days = _email_age(msg, now)

    report = Report(
        subject=subject,
        from_addr=from_addr,
        to_addrs=to_addrs,
        message_id=message_id,
        urls=urls,
        urls_defanged=[defang_url(u) for u in urls],
        url_items=[u.to_dict() for u in url_items],
        url_groups=url_groups,
        hops=[h.to_dict() for h in hops],
        attachments=[a.to_dict() for a in attachments],
        auth=auth.to_dict(),
        org=dict(org),
        email_date=email_date,
        analyzed_at=now.isoformat(),
        email_age_days=email_age_days,
    )
    chosen = analyzers if analyzers is not None else DEFAULT_ANALYZERS
    for run in chosen:
        report.findings.extend(run(msg))

    if online:
        from mailshieldv1.online import enrich_online

        domains = [str(d) for d in (org.get("url_domains") or [])]
        # Prefer non-ignored / CTA-like hosts for resolution budget.
        cta_hosts = [
            url_domain(str(u.get("url") or ""))
            for u in report.url_items
            if u.get("role") in {"cta_action", "other"}
        ]
        prefer = [d for d in cta_hosts if d] + domains
        seen: set[str] = set()
        url_domains: list[str] = []
        for d in prefer:
            if d and d not in seen:
                seen.add(d)
                url_domains.append(d)
        report.online = enrich_online(
            from_domain=str(org.get("from_domain") or ""),
            url_domains=url_domains,
            timeout=online_timeout,
        )
        for row in report.online.get("resolutions") or []:
            host = str(row.get("host") or "")
            if not host or host == org.get("from_domain"):
                # From-domain resolution failure is weaker than CTA sinkhole.
                if not row.get("ok") and host:
                    report.findings.append(
                        Finding(
                            rule_id="ONLINE-FROM-DNS-FAIL",
                            category="online",
                            severity="low",
                            confidence=0.55,
                            evidence=f"host={host}; error={row.get('error')}",
                            explanation="From domain did not resolve during online DNS check.",
                            recommendation=(
                                "Confirm domain age/ownership via pivots before trusting."
                            ),
                        )
                    )
                continue
            if row.get("ok"):
                continue
            report.findings.append(
                Finding(
                    rule_id="ONLINE-URL-DNS-FAIL",
                    category="online",
                    severity="high",
                    confidence=0.85,
                    evidence=f"host={host}; error={row.get('error')}",
                    explanation=(
                        "A linked host in the message does not resolve in live DNS — "
                        "common for disposable phishing landing domains."
                    ),
                    recommendation="Treat the URL as hostile; do not visit; pivot in VT/urlscan.",
                )
            )
        report.analyzer_notes.append(
            "Online mode: DNS TXT/A lookups only; destinations were not HTTP-fetched."
        )
    else:
        report.online = {"enabled": False}

    apply_calibration(
        report,
        auth_strong_pass=auth.strong_pass,
        auth_any_fail=auth.any_fail,
        auth_weak=auth.weak,
        org_consistent=bool(org.get("consistent")),
        esp_envelope=bool(org.get("esp_envelope")),
    )

    if auth.trusted:
        report.analyzer_notes.append(
            f"Authentication-Results trusted for authserv-id={auth.authserv_id!r}; "
            "strong pass may soften marketing false positives."
        )
    else:
        report.analyzer_notes.append(
            "Authentication-Results are not trusted for score softening "
            "(pass --authserv-id / MAILSHIELD_AUTHSERV_ID for your receiving MTA). "
            "Forged attacker pass headers cannot zero the verdict."
        )
    report.analyzer_notes.append(
        "Authentication checks use the topmost Authentication-Results header only "
        "(ARC is fallback when AR is absent) unless --online DNS hints are enabled."
    )
    report.analyzer_notes.append(
        "URLs are extracted and defanged locally; destinations are never fetched. "
        "Tracking pixels are kept and grouped by likely sender purpose; "
        "query-string clones are collapsed into variant groups."
    )
    report.analyzer_notes.append(
        "Analyst pivots are optional outbound links to Unshorten.it, DomainTools, "
        "PhishTank, dnstwist.it, and MXToolbox — opened only if you click them."
    )
    report.analyzer_notes.append(
        "Received hops: index 0 is newest. Hops before your trust boundary can be forged."
    )
    report.analyzer_notes.append(
        "Hop locations are offline hints (private IP class, AWS region tokens, "
        "Microsoft 365 footprints, IPv6 special-use) — not a live GeoIP city database."
    )
    report.analyzer_notes.append(
        "Attachments are inventoried with static byte/extension checks only; "
        "nothing is executed or written to disk."
    )
    report.analyzer_notes.append(
        "Verdict score v2 is family-weighted (auth/brand/lure/attachment/url/org) "
        "with a commodity-spam ceiling and a structured-phishing floor; "
        "strong auth + org consistency softens marketing false positives."
    )
    report.analyzer_notes.append(
        "Brand tokens and content lures load from package data "
        "(mailshieldv1/data/brands.yml, lures.yml)."
    )
    return report
