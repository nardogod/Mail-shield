"""Header / authentication analyzer. Reads local headers only — no DNS or crypto."""

from __future__ import annotations

import re
from email.message import EmailMessage
from email.utils import parseaddr

from mailshieldv1.core.authresults import parse_auth_results
from mailshieldv1.core.brands import claimed_brands, display_brand_impersonation
from mailshieldv1.core.domains import email_domain
from mailshieldv1.core.knowledge import (
    has_invisible_unicode,
    has_mixed_script_homoglyph,
    has_zwsp_letter_spacing,
    is_free_mail,
)
from mailshieldv1.core.models import Finding
from mailshieldv1.core.text import visible_body_text

_AUTH_RESULT_RE = re.compile(
    r"\b(spf|dkim|dmarc)=(pass|fail|softfail|neutral|none|temperror|permerror)\b",
    re.IGNORECASE,
)
_INFRA_HOST = re.compile(
    r"(?i)(ubuntu|droplet|vps|compute\.amazonaws|digitalocean|"
    r"contabo|ovh|linode|vultr|dedicated|smtp-out)"
)


def _addr(value: str | None) -> tuple[str, str]:
    name, addr = parseaddr(value or "")
    return name.strip(), addr.strip().lower()


def analyze(msg: EmailMessage) -> list[Finding]:
    findings: list[Finding] = []
    auth = parse_auth_results(msg)

    from_name, from_addr = _addr(msg.get("From"))
    _reply_name, reply_addr = _addr(msg.get("Reply-To"))
    return_path_raw = msg.get("Return-Path")
    _, return_path = _addr(return_path_raw) if return_path_raw else ("", "")
    subject = msg.get("Subject") or ""

    if not from_addr:
        findings.append(
            Finding(
                rule_id="HDR-MISSING-FROM",
                category="headers",
                severity="high",
                confidence=0.95,
                evidence="From header missing or empty",
                explanation="A message without a usable From address is abnormal.",
                recommendation="Treat as suspicious; do not trust display identity.",
            )
        )

    body_excerpt = visible_body_text(msg)[:2500]

    # Brand claimed in display/subject/body but From domain does not support it.
    brand_hit = display_brand_impersonation(
        msg.get("From") or "", subject, body_excerpt
    )
    if brand_hit:
        brands = ", ".join(brand_hit["unsupported_brands"])
        findings.append(
            Finding(
                rule_id="HDR-BRAND-IMPERSONATION",
                category="headers",
                severity="high",
                confidence=0.9,
                evidence=(
                    f"display={brand_hit['display_name']!r}; "
                    f"from_domain={brand_hit['from_domain']}; "
                    f"unsupported_brands={brands}"
                ),
                explanation=(
                    "Display name / subject / body claims a known brand that the From "
                    "domain does not belong to — classic phishing impersonation."
                ),
                recommendation=(
                    "Do not trust the brand in the display name; verify the real From "
                    "domain and Authentication-Results before acting."
                ),
            )
        )

    # Free-mail From + brand tokens (gmail PayPal/BB/crypto) — pot FN pattern.
    from_dom = email_domain(msg.get("From") or "") or (
        from_addr.split("@", 1)[-1] if from_addr and "@" in from_addr else ""
    )
    if is_free_mail(from_dom):
        free_brands = claimed_brands(from_name, subject, body_excerpt)
        if free_brands:
            findings.append(
                Finding(
                    rule_id="HDR-FREEMAIL-BRAND",
                    category="headers",
                    severity="high",
                    confidence=0.88,
                    evidence=(
                        f"from_domain={from_dom}; display={from_name!r}; "
                        f"brands={', '.join(free_brands)}"
                    ),
                    explanation=(
                        "Sender uses a consumer free-mail domain while the message "
                        "claims a bank, crypto, or corporate brand — common phishing path."
                    ),
                    recommendation=(
                        "Ignore the brand claim; free-mail never speaks for "
                        "banks/exchanges. Verify out-of-band."
                    ),
                )
            )
        # Freemail + invoice/payment subject with attachment is classic BEC/phish.
        elif re.search(
            r"(?i)\b(invoice|payment\s+details|purchase\s+confirmation|fatura|nota\s+fiscal)\b",
            f"{subject}\n{from_name}",
        ):
            findings.append(
                Finding(
                    rule_id="HDR-FREEMAIL-INVOICE",
                    category="headers",
                    severity="high",
                    confidence=0.82,
                    evidence=f"from_domain={from_dom}; subject={subject[:160]!r}",
                    explanation=(
                        "Invoice/payment mail from a free-mail address is a common "
                        "malware-delivery and BEC pattern."
                    ),
                    recommendation=(
                        "Do not open attachments or pay; confirm any invoice via a known channel."
                    ),
                )
            )

    # Homoglyph / invisible Unicode evasion in display or subject (pot samples 23/88).
    identity_blob = f"{from_name}\n{subject}"
    if has_mixed_script_homoglyph(identity_blob):
        findings.append(
            Finding(
                rule_id="HDR-HOMOGLYPH-DISPLAY",
                category="headers",
                severity="high",
                confidence=0.9,
                evidence=f"display={from_name!r}; subject={subject[:120]!r}",
                explanation=(
                    "Display name or subject mixes Latin with Cyrillic/Greek lookalike "
                    "characters to spoof a brand while bypassing simple keyword filters."
                ),
                recommendation=(
                    "Treat the visible brand as forged; do not click links or open attachments."
                ),
            )
        )
    if has_invisible_unicode(identity_blob) or has_zwsp_letter_spacing(body_excerpt[:1500]):
        findings.append(
            Finding(
                rule_id="HDR-INVISIBLE-UNICODE",
                category="headers",
                severity="medium",
                confidence=0.8,
                evidence=f"display={from_name!r}; subject={subject[:120]!r}",
                explanation=(
                    "Message embeds invisible Unicode (zero-width / variation selectors) "
                    "in identity or body text — often used to evade phishing filters."
                ),
                recommendation="Treat obfuscated identity/body as hostile until proven otherwise.",
            )
        )

    # Entire lure packed into an absurdly long From display name (pot sample 79).
    if len(from_name) >= 90 and re.search(
        r"(?i)(http|https|verify|transfer|funds|click|account|password|login)",
        from_name,
    ):
        findings.append(
            Finding(
                rule_id="HDR-LONG-DISPLAY-LURE",
                category="headers",
                severity="high",
                confidence=0.85,
                evidence=f"display_len={len(from_name)}; display={from_name[:180]!r}",
                explanation=(
                    "From display name is unusually long and contains call-to-action / "
                    "payment language — the lure is smuggled into the sender name."
                ),
                recommendation="Do not follow instructions in the display name; report the message.",
            )
        )

    if from_addr and reply_addr and from_addr != reply_addr:
        sev = "low" if auth.strong_pass else "medium"
        findings.append(
            Finding(
                rule_id="HDR-FROM-REPLYTO-MISMATCH",
                category="headers",
                severity=sev,
                confidence=0.55 if auth.strong_pass else 0.8,
                evidence=(
                    f"From={from_addr}; Reply-To={reply_addr}; "
                    f"auth_strong_pass={auth.strong_pass}"
                ),
                explanation=(
                    "Reply-To differs from From. Common in marketing; risky when auth fails."
                ),
                recommendation=(
                    "If Authentication-Results show pass, this is often benign ESP routing; "
                    "otherwise verify before replying."
                ),
            )
        )

    if from_addr and return_path and return_path != from_addr:
        sev = "info" if auth.strong_pass else "low"
        # Bare infra / VPS envelope is a stronger phishing tell.
        if _INFRA_HOST.search(return_path) or (
            "@" in return_path and "." not in return_path.rsplit("@", 1)[-1]
        ):
            sev = "medium" if not auth.strong_pass else "low"
            findings.append(
                Finding(
                    rule_id="HDR-RETURNPATH-INFRA",
                    category="headers",
                    severity=sev,
                    confidence=0.8,
                    evidence=f"Return-Path={return_path}; From={from_addr}",
                    explanation=(
                        "Return-Path looks like raw infrastructure / VPS hostname "
                        "rather than a brand mail domain — common on phishing drops."
                    ),
                    recommendation=(
                        "Correlate with SPF/DKIM/DMARC and the first public hop IP."
                    ),
                )
            )
        findings.append(
            Finding(
                rule_id="HDR-FROM-RETURNPATH-MISMATCH",
                category="headers",
                severity="info" if auth.strong_pass else sev if sev != "medium" else "low",
                confidence=0.4 if auth.strong_pass else 0.55,
                evidence=(
                    f"From={from_addr}; Return-Path={return_path}; "
                    f"spf={auth.spf}; dkim={auth.dkim}; dmarc={auth.dmarc}"
                ),
                explanation=(
                    "Return-Path differs from From. Typical for lists/ESP when auth passes; "
                    "more concerning when SPF/DKIM/DMARC fail or are missing."
                ),
                recommendation=(
                    "Weight this using the Authentication panel "
                    "(MTA-asserted SPF/DKIM/DMARC)."
                ),
            )
        )

    auth_headers = msg.get_all("Authentication-Results", []) or []
    auth_headers += msg.get_all("ARC-Authentication-Results", []) or []
    auth_blob = " ".join(str(h) for h in auth_headers)
    results = {
        m.group(1).lower(): m.group(2).lower() for m in _AUTH_RESULT_RE.finditer(auth_blob)
    }

    if not auth.present:
        findings.append(
            Finding(
                rule_id="HDR-NO-AUTH-RESULTS",
                category="authentication",
                severity="low",
                confidence=0.5,
                evidence="Authentication-Results header absent",
                explanation=(
                    "No Authentication-Results found. Offline mode cannot prove SPF/DKIM/DMARC; "
                    "use --online for optional DNS checks, or prefer MTA-exported samples."
                ),
                recommendation="Prefer .eml files that include Authentication-Results.",
            )
        )
    else:
        for mech in ("spf", "dkim", "dmarc"):
            status = results.get(mech)
            if status is None:
                findings.append(
                    Finding(
                        rule_id=f"HDR-{mech.upper()}-MISSING",
                        category="authentication",
                        severity="info",
                        confidence=0.6,
                        evidence=auth_blob[:500],
                        explanation=(
                            f"No {mech.upper()} result token found in Authentication-Results."
                        ),
                        recommendation=(
                            f"Confirm whether the receiving path evaluates {mech.upper()}."
                        ),
                    )
                )
            elif status in {"fail", "permerror"}:
                findings.append(
                    Finding(
                        rule_id=f"HDR-{mech.upper()}-FAIL",
                        category="authentication",
                        severity="high" if mech == "dmarc" else "medium",
                        confidence=0.85,
                        evidence=f"{mech}={status}",
                        explanation=(
                            f"Authentication-Results reports {mech.upper()}={status} "
                            "(MTA-asserted, not re-validated here unless --online)."
                        ),
                        recommendation="Treat identity claims with high caution.",
                    )
                )
            elif status == "temperror":
                findings.append(
                    Finding(
                        rule_id=f"HDR-{mech.upper()}-TEMPERROR",
                        category="authentication",
                        severity="medium",
                        confidence=0.7,
                        evidence=f"{mech}={status}",
                        explanation=(
                            f"{mech.upper()} temperror usually means the MTA could not "
                            "complete the check (often a broken/non-domain mailfrom). "
                            "Combined with brand claims this is a phishing tell."
                        ),
                        recommendation="Do not treat the sender identity as authenticated.",
                    )
                )
            elif status == "none" and mech == "dkim":
                findings.append(
                    Finding(
                        rule_id="HDR-DKIM-NONE",
                        category="authentication",
                        severity="medium",
                        confidence=0.75,
                        evidence="dkim=none",
                        explanation=(
                            "Message is not DKIM-signed. Legitimate brand mail is usually signed; "
                            "unsigned brand impersonation is a strong phishing signal."
                        ),
                        recommendation="Require DKIM/DMARC pass before trusting brand content.",
                    )
                )
            elif status == "softfail" and mech == "spf":
                findings.append(
                    Finding(
                        rule_id="HDR-SPF-SOFTFAIL",
                        category="authentication",
                        severity="low",
                        confidence=0.7,
                        evidence="spf=softfail",
                        explanation="SPF softfail: sending host is not authorized, policy is soft.",
                        recommendation="Combine with DMARC and content signals.",
                    )
                )

        if auth.compauth == "fail":
            findings.append(
                Finding(
                    rule_id="HDR-COMPAUTH-FAIL",
                    category="authentication",
                    severity="high",
                    confidence=0.85,
                    evidence="compauth=fail",
                    explanation=(
                        "Microsoft composite authentication failed (compauth=fail). "
                        "The receiving MTA did not accept the asserted identity."
                    ),
                    recommendation="Treat as unauthenticated; escalate with brand/URL signals.",
                )
            )

    # Microsoft filtering hints when present on the sample.
    scl = (msg.get("X-MS-Exchange-Organization-SCL") or "").strip()
    bcl_header = msg.get("X-Microsoft-Antispam") or ""
    bcl_m = re.search(r"BCL:(\d+)", bcl_header)
    if scl.isdigit() and int(scl) >= 5:
        findings.append(
            Finding(
                rule_id="HDR-M365-SCL",
                category="headers",
                severity="medium" if int(scl) < 7 else "high",
                confidence=0.7,
                evidence=f"SCL={scl}",
                explanation=(
                    f"Microsoft SCL={scl} indicates elevated spam/phish suspicion "
                    "on the receiving path."
                ),
                recommendation="Use as corroboration with auth and brand/URL findings.",
            )
        )
    if bcl_m and int(bcl_m.group(1)) >= 7:
        findings.append(
            Finding(
                rule_id="HDR-M365-BCL",
                category="headers",
                severity="medium",
                confidence=0.65,
                evidence=f"BCL={bcl_m.group(1)}",
                explanation=(
                    f"Microsoft BCL={bcl_m.group(1)} is a high bulk-complaint signal "
                    "often seen on unsolicited/phishing campaigns."
                ),
                recommendation="Combine with Authentication-Results and CTA domain review.",
            )
        )

    if from_name and from_addr:
        angle = re.search(r"[\w.+-]+@[\w.-]+", from_name)
        if angle and angle.group(0).lower() != from_addr:
            findings.append(
                Finding(
                    rule_id="HDR-DISPLAY-NAME-EMAIL-MISMATCH",
                    category="headers",
                    severity="medium",
                    confidence=0.75,
                    evidence=f"display={from_name!r}; address={from_addr}",
                    explanation=(
                        "Display name contains an email that does not match "
                        "the From address."
                    ),
                    recommendation="Do not trust the display name; verify the actual address.",
                )
            )

    return findings
