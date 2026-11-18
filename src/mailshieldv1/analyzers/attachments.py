"""Static attachment analyzer. Never opens/executes files outside capped scans."""

from __future__ import annotations

from email.message import EmailMessage

from mailshieldv1.core.attachments import list_attachments
from mailshieldv1.core.models import Finding

_FLAG_RULES: dict[str, tuple[str, str, float, str, str]] = {
    "dangerous_extension": (
        "ATT-DANGEROUS-EXT",
        "high",
        0.85,
        "Attachment uses an executable or script-like extension.",
        "Do not open; detonate only in an isolated sandbox if required.",
    ),
    "double_extension": (
        "ATT-DOUBLE-EXT",
        "high",
        0.9,
        "Filename uses a double extension (e.g. .pdf.exe) to spoof document type.",
        "Treat as malicious until proven otherwise.",
    ),
    "macro_indicator": (
        "ATT-MACRO",
        "high",
        0.8,
        "Static markers suggest Office VBA / macro content.",
        "Disable macros; analyze in a lab — do not enable content on a workstation.",
    ),
    "macro_enabled_office": (
        "ATT-MACRO-OFFICE",
        "high",
        0.75,
        "Office macro-enabled extension (e.g. .docm / .xlsm).",
        "Prefer macro-free formats; open only in a controlled environment.",
    ),
    "pdf_active_content": (
        "ATT-PDF-ACTIVE",
        "medium",
        0.7,
        "PDF contains JavaScript / OpenAction / Launch style keywords.",
        "Do not open locally; use a PDF sandbox or strip active content.",
    ),
    "lnk": (
        "ATT-LNK",
        "high",
        0.85,
        "Windows shortcut (.lnk) attachment detected.",
        "LNK files can launch payloads — inspect with a dedicated parser in a lab.",
    ),
}


def analyze(msg: EmailMessage) -> list[Finding]:
    attachments = list_attachments(msg)
    if not attachments:
        return []

    findings: list[Finding] = [
        Finding(
            rule_id="ATT-PRESENT",
            category="attachments",
            severity="info",
            confidence=1.0,
            evidence=f"count={len(attachments)}",
            explanation="One or more attachments were inventoried (static metadata only).",
            recommendation="Review filenames and flags before opening anything.",
        )
    ]

    # Emit at most one finding per flag type (aggregate filenames).
    by_flag: dict[str, list[str]] = {}
    for att in attachments:
        for flag in att.flags:
            by_flag.setdefault(flag, []).append(att.filename)

    for flag, names in by_flag.items():
        rule = _FLAG_RULES.get(flag)
        if not rule:
            continue
        rule_id, severity, confidence, explanation, recommendation = rule
        evidence = ", ".join(names[:5])
        if len(names) > 5:
            evidence += f" (+{len(names) - 5} more)"
        findings.append(
            Finding(
                rule_id=rule_id,
                category="attachments",
                severity=severity,
                confidence=confidence,
                evidence=evidence[:300],
                explanation=explanation,
                recommendation=recommendation,
            )
        )
    return findings
