"""Non-technical copy for the default Simple report view."""

from __future__ import annotations

from mailshieldv1.core.models import Finding, Report

_VERDICT_PLAIN = {
    "info": (
        "Looks okay",
        "We did not find strong signs of a scam. Still, only open links you expected.",
        "You can usually treat this as normal mail. If something feels off, ask IT/security.",
    ),
    "low": (
        "Be careful",
        "There are weak warning signs. It may be marketing or a mild risk.",
        "Do not click unexpected links or open attachments until you are sure who sent it.",
    ),
    "medium": (
        "Suspicious — investigate",
        "Several warning signs suggest this may not be trustworthy.",
        "Do not click links, open files, or reply with personal data. Forward to IT/security.",
    ),
    "high": (
        "Likely a scam",
        "Strong signs of phishing or impersonation were found.",
        "Do not interact with this email. Report it to IT/security and delete it from your inbox.",
    ),
    "critical": (
        "Dangerous — treat as phishing",
        "This message shows clear phishing patterns (fake brand, broken authentication, "
        "and/or hostile links).",
        "Do not click anything. Report it now and remove it from your mailbox.",
    ),
}

_RULE_PLAIN: dict[str, str] = {
    "HDR-BRAND-IMPERSONATION": (
        "The name at the top pretends to be a known brand, but the real email address "
        "does not belong to that brand."
    ),
    "HDR-FREEMAIL-BRAND": (
        "This was sent from a free mailbox (like Gmail) while pretending to be a bank, "
        "crypto exchange, or company."
    ),
    "HDR-FREEMAIL-INVOICE": (
        "An invoice/payment message came from a free mailbox — often used to deliver malware."
    ),
    "HDR-HOMOGLYPH-DISPLAY": (
        "The sender name uses lookalike foreign letters to fake a brand name."
    ),
    "HDR-INVISIBLE-UNICODE": (
        "The sender name hides invisible characters used to dodge spam filters."
    ),
    "HDR-LONG-DISPLAY-LURE": (
        "The sender name is abnormally long and already contains scam instructions."
    ),
    "HDR-COMPAUTH-FAIL": (
        "Your mail system could not verify the sender’s identity (Microsoft authentication failed)."
    ),
    "HDR-DKIM-NONE": "This message was not cryptographically signed by the sender domain.",
    "HDR-SPF-TEMPERROR": "Sender authentication (SPF) could not be completed successfully.",
    "HDR-DMARC-TEMPERROR": "Sender authentication (DMARC) could not be completed successfully.",
    "HDR-DMARC-FAIL": (
        "Sender authentication (DMARC) failed — the domain policy rejected this path."
    ),
    "HDR-SPF-FAIL": "Sender authentication (SPF) failed.",
    "HDR-DKIM-FAIL": "Sender signature (DKIM) failed.",
    "HDR-RETURNPATH-INFRA": (
        "The technical return address looks like a raw server/VPS, not a normal company mailbox."
    ),
    "HDR-FROM-REPLYTO-MISMATCH": (
        "Replies would go to a different address than the one shown as the sender."
    ),
    "HDR-FROM-RETURNPATH-MISMATCH": (
        "The bounce/return address differs from the visible From address."
    ),
    "HDR-MISSING-FROM": "The From address is missing or unusable.",
    "HDR-M365-SCL": "Microsoft already scored this message as elevated spam/phish risk.",
    "HDR-M365-BCL": "Microsoft marked this sender as high bulk/complaint traffic.",
    "URL-SUSPICIOUS-HOST": (
        "A link points to a strange or disposable-looking website — not the brand’s real site."
    ),
    "URL-IP-LITERAL": "A link uses a raw IP address instead of a normal website name.",
    "URL-USERINFO": "A link tries to look like a brand before the real destination (@ trick).",
    "ONLINE-URL-DNS-FAIL": (
        "A linked website does not exist / does not resolve on the internet right now."
    ),
    "ONLINE-FROM-DNS-FAIL": "The sender domain did not resolve in a live DNS check.",
    "ORG-MISMATCH": (
        "The sender domain and the websites in the message do not match the same organization."
    ),
    "BEC-URGENCY": "The text pushes you to act immediately (a common scam pressure tactic).",
    "BEC-PAYMENT": "The text talks about payments or money movement.",
    "BEC-CREDENTIAL": "The text asks for passwords, account details, or national ID data.",
    "BEC-SECRECY": "The text asks you to keep the request secret from colleagues.",
    "CONTENT-PROTESTO-LURE": (
        "This looks like a fake cartório/protesto notice asking for payment or CPF — "
        "a common Brazilian scam (even when the email authenticates)."
    ),
    "CONTENT-CONTACT-DOMAIN-MISMATCH": (
        "The message claims to be an official office but lists a contact email on a "
        "different website than the sender address."
    ),
    "CONTENT-IRPF-LURE": (
        "This looks like a fake IRPF / tax-refund notice with an attachment — "
        "a common Brazilian phishing pattern."
    ),
    "CONTENT-CRYPTO-WITHDRAW": (
        "This pretends a crypto wallet/exchange withdraw or security alert to make you "
        "click cancel/verify."
    ),
    "CONTENT-TECHSUPPORT-LURE": (
        "Unsolicited tech-support / monitoring language — often a pretext for malware."
    ),
    "CONTENT-ROMANCE-LURE": (
        "Unsolicited romance/dating message with pressure to click — often a scam funnel."
    ),
    "CONTENT-FR-AIDES-LURE": (
        "Unsolicited French energy-aid or credit-consolidation offer — common bulk scam."
    ),
    "CONTENT-CASINO-LURE": (
        "Unsolicited casino/bonus offer — often a scam or malware funnel."
    ),
    "CONTENT-CRYPTO-AIRDROP": (
        "Crypto airdrop / claim-rewards lure — often used to drain wallets."
    ),
    "CONTENT-ADVANCE-FEE": (
        "Looks like an advance-fee / fake lawyer inheritance letter."
    ),
    "CONTENT-FR-AMENDE-LURE": (
        "Fake French traffic-fine / ANTAI notice — do not pay via email links."
    ),
    "CONTENT-FR-CPF-LURE": (
        "Unsolicited French CPF / training-rights offer — common phishing funnel."
    ),
    "CONTENT-CRYPTO-WALLET-UPDATE": (
        "Fake crypto wallet update/verify notice — often steals recovery phrases."
    ),
    "CONTENT-DOC-SHARE-LURE": (
        "Unsolicited 'document shared / sign here' message — common phishing lure."
    ),
    "URL-SHORTENER": (
        "A link uses a short URL that hides where you would actually go."
    ),
    "ATT-DANGEROUS-EXT": "An attachment looks like a program/script and should not be opened.",
    "ATT-PDF-ACTIVE": (
        "A PDF attachment has active content (scripts/actions) and should not be opened."
    ),
    "ATT-DOUBLE-EXT": "An attachment filename hides a dangerous extension (e.g. .pdf.exe).",
    "ATT-MACRO": "An Office attachment may contain macros.",
    "ATT-LNK": "A Windows shortcut (.lnk) attachment was found.",
}


def plain_verdict(report: Report) -> tuple[str, str, str]:
    """Return (title, meaning, action) for the Simple view."""
    return _VERDICT_PLAIN.get(report.verdict, _VERDICT_PLAIN["medium"])


def plain_reason(finding: Finding) -> str:
    return _RULE_PLAIN.get(finding.rule_id, finding.explanation)


def top_plain_reasons(report: Report, *, limit: int = 5) -> list[tuple[str, str, str]]:
    """Return (rule_id, severity, plain_text) for the most important findings."""
    ranked = sorted(
        [f for f in report.findings if f.severity in {"low", "medium", "high", "critical"}],
        key=lambda f: (
            {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(f.severity, 0),
            f.confidence,
        ),
        reverse=True,
    )
    out: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for f in ranked:
        if f.rule_id in seen:
            continue
        seen.add(f.rule_id)
        out.append((f.rule_id, f.severity, plain_reason(f)))
        if len(out) >= limit:
            break
    return out
