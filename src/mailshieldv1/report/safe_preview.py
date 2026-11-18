"""Safe email reconstruction: no clickable links, no remote images, with callouts."""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from email.message import EmailMessage
from html.parser import HTMLParser

from mailshieldv1.core.models import Finding, Report
from mailshieldv1.core.text import visible_body_text
from mailshieldv1.core.urls import defang_url, walk_body_text
from mailshieldv1.report.plain_language import plain_reason

_SKIP_TAGS = frozenset(
    {"script", "style", "iframe", "object", "embed", "form", "svg", "link", "meta"}
)
# Void / empty elements must not bump skip_depth (no matching end tag).
_VOID_SKIP = frozenset({"link", "meta", "br", "hr", "input", "source", "base", "area"})
_FROM_RULES = frozenset(
    {
        "HDR-BRAND-IMPERSONATION",
        "HDR-FREEMAIL-BRAND",
        "HDR-FREEMAIL-INVOICE",
        "HDR-HOMOGLYPH-DISPLAY",
        "HDR-INVISIBLE-UNICODE",
        "HDR-LONG-DISPLAY-LURE",
        "HDR-DISPLAY-NAME-EMAIL-MISMATCH",
        "HDR-MISSING-FROM",
        "HDR-FROM-REPLYTO-MISMATCH",
        "HDR-FROM-RETURNPATH-MISMATCH",
        "HDR-RETURNPATH-INFRA",
        "HDR-COMPAUTH-FAIL",
        "HDR-DKIM-NONE",
        "HDR-SPF-FAIL",
        "HDR-DKIM-FAIL",
        "HDR-DMARC-FAIL",
        "HDR-SPF-TEMPERROR",
        "HDR-DMARC-TEMPERROR",
        "HDR-M365-SCL",
        "HDR-M365-BCL",
        "ORG-MISMATCH",
        "CONTENT-PROTESTO-LURE",
        "CONTENT-CONTACT-DOMAIN-MISMATCH",
        "CONTENT-IRPF-LURE",
        "CONTENT-CRYPTO-WITHDRAW",
        "CONTENT-TECHSUPPORT-LURE",
        "CONTENT-ROMANCE-LURE",
        "CONTENT-FR-AIDES-LURE",
        "CONTENT-FR-AMENDE-LURE",
        "CONTENT-FR-CPF-LURE",
        "CONTENT-CASINO-LURE",
        "CONTENT-CRYPTO-AIRDROP",
        "CONTENT-CRYPTO-WALLET-UPDATE",
        "CONTENT-ADVANCE-FEE",
        "CONTENT-DOC-SHARE-LURE",
    }
)
_URL_RULES = frozenset(
    {
        "URL-SUSPICIOUS-HOST",
        "URL-IP-LITERAL",
        "URL-USERINFO",
        "URL-SHORTENER",
        "ONLINE-URL-DNS-FAIL",
    }
)
_BODY_RULES = frozenset(
    {
        "BEC-URGENCY",
        "BEC-PAYMENT",
        "BEC-CREDENTIAL",
        "BEC-SECRECY",
        "CONTENT-PROTESTO-LURE",
        "CONTENT-CONTACT-DOMAIN-MISMATCH",
        "CONTENT-IRPF-LURE",
        "CONTENT-CRYPTO-WITHDRAW",
        "CONTENT-TECHSUPPORT-LURE",
        "CONTENT-ROMANCE-LURE",
        "CONTENT-FR-AIDES-LURE",
        "CONTENT-FR-AMENDE-LURE",
        "CONTENT-FR-CPF-LURE",
        "CONTENT-CASINO-LURE",
        "CONTENT-CRYPTO-AIRDROP",
        "CONTENT-CRYPTO-WALLET-UPDATE",
        "CONTENT-ADVANCE-FEE",
        "CONTENT-DOC-SHARE-LURE",
    }
)
_ATT_RULES = frozenset(
    {
        "ATT-PRESENT",
        "ATT-DANGEROUS-EXT",
        "ATT-DOUBLE-EXT",
        "ATT-MACRO",
        "ATT-MACRO-OFFICE",
        "ATT-PDF-ACTIVE",
        "ATT-LNK",
    }
)
_NEG_SEV = frozenset({"medium", "high", "critical"})


@dataclass
class Callout:
    number: int
    area: str  # from | subject | body | attachment | link
    severity: str
    title: str
    plain: str
    rule_id: str


class _SafeHtml(HTMLParser):
    """Rewrite HTML into a defused fragment (no href navigation, no remote images)."""

    def __init__(self, hot_hosts: set[str]) -> None:
        super().__init__(convert_charrefs=True)
        self.hot_hosts = hot_hosts
        self.parts: list[str] = []
        self._skip_depth = 0
        self.link_marks = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_l = tag.lower()
        if tag_l in _SKIP_TAGS:
            if tag_l not in _VOID_SKIP:
                self._skip_depth += 1
            return
        if self._skip_depth:
            return
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        if tag_l == "a":
            href = attr_map.get("href", "").strip()
            fang = html.escape(defang_url(href)) if href else ""
            host = ""
            m = re.search(r"(?i)https?://([^/\s]+)", href)
            if m:
                host = m.group(1).lower().rstrip(".")
            mark = ""
            if host and any(host == h or host.endswith("." + h) for h in self.hot_hosts):
                self.link_marks += 1
                mark = ' data-hot="1" class="hot-link"'
            self.parts.append(
                f'<span{mark} title="Link disabled for safety">'
                f'<span class="safe-link-label">[link blocked]</span> '
                f'<code class="safe-url">{fang}</code></span><span class="safe-link-text">'
            )
            return
        if tag_l in {"img", "image"}:
            src = attr_map.get("src", "").strip()
            alt = html.escape(attr_map.get("alt", "") or "image")
            if src.startswith("http"):
                fang = html.escape(defang_url(src))
            else:
                fang = html.escape(src[:120])
            extra = f" — {fang}" if fang else ""
            self.parts.append(
                f'<span class="safe-img" title="Image blocked">'
                f"[image blocked: {alt}{extra}]</span>"
            )
            return
        if tag_l in {"br"}:
            self.parts.append("<br/>")
            return
        if tag_l in {"p", "div", "tr", "li", "h1", "h2", "h3", "h4", "table", "tbody", "thead"}:
            self.parts.append(f"<{tag_l}>")
            return
        if tag_l in {"td", "th", "span", "strong", "em", "b", "i", "u"}:
            self.parts.append(f"<{tag_l}>")
            return

    def handle_endtag(self, tag: str) -> None:
        tag_l = tag.lower()
        if tag_l in _SKIP_TAGS:
            if self._skip_depth:
                self._skip_depth -= 1
            return
        if self._skip_depth:
            return
        if tag_l == "a":
            self.parts.append("</span>")
            return
        if tag_l in {"p", "div", "tr", "li", "h1", "h2", "h3", "h4", "table", "tbody", "thead",
                     "td", "th", "span", "strong", "em", "b", "i", "u"}:
            self.parts.append(f"</{tag_l}>")

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        self.parts.append(html.escape(data))


def _html_body(msg: EmailMessage) -> str:
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            try:
                text = part.get_content()
            except (KeyError, TypeError, ValueError, LookupError, UnicodeError):
                continue
            if isinstance(text, str) and text.strip():
                return text[:500_000]
    return walk_body_text(msg)[:500_000]


def _hot_hosts(report: Report) -> set[str]:
    hosts: set[str] = set()
    for f in report.findings:
        if f.rule_id not in _URL_RULES:
            continue
        host_re = r"(?i)(?:https?://|hxxps?\[://\])?([a-z0-9.-]+\.[a-z]{2,})"
        for m in re.finditer(host_re, f.evidence):
            hosts.add(m.group(1).lower().replace("[.]", "."))
    for item in report.url_items:
        if item.get("role") == "cta_action":
            url = str(item.get("url") or "")
            m = re.search(r"(?i)https?://([^/\s]+)", url)
            if m:
                hosts.add(m.group(1).lower())
    # Prefer suspicious hosts from findings evidence domains already collected.
    return {h for h in hosts if h and "w3.org" not in h and "google" not in h}


def build_callouts(report: Report) -> list[Callout]:
    callouts: list[Callout] = []
    n = 0
    used: set[str] = set()

    def add(area: str, f: Finding, title: str) -> None:
        nonlocal n
        if f.rule_id in used:
            return
        if f.severity not in {"low", "medium", "high", "critical"}:
            return
        used.add(f.rule_id)
        n += 1
        callouts.append(
            Callout(
                number=n,
                area=area,
                severity=f.severity,
                title=title,
                plain=plain_reason(f),
                rule_id=f.rule_id,
            )
        )

    for f in report.findings:
        if f.rule_id in _FROM_RULES:
            add("from", f, "Sender / identity")
        elif f.rule_id.startswith("HDR-") and "SUBJECT" not in f.rule_id:
            if f.severity in _NEG_SEV:
                add("from", f, "Sender / identity")
    for f in report.findings:
        if f.rule_id in _URL_RULES:
            add("link", f, "Suspicious link")
        elif f.rule_id in _BODY_RULES:
            add("body", f, "Message wording")
        elif f.rule_id in _ATT_RULES and f.rule_id != "ATT-PRESENT":
            add("attachment", f, "Attachment")
    return callouts


def render_safe_preview(msg: EmailMessage, report: Report) -> tuple[str, list[Callout]]:
    """Return (safe_html_fragment, callouts). Never emits navigable links or remote images."""
    callouts = build_callouts(report)
    hot = _hot_hosts(report)
    raw = _html_body(msg)
    if "<" in raw and ">" in raw:
        parser = _SafeHtml(hot)
        try:
            parser.feed(raw)
            parser.close()
            body = "".join(parser.parts)
        except (AssertionError, ValueError, TypeError):
            body = html.escape(visible_body_text(msg))
    else:
        body = html.escape(visible_body_text(msg))
        # Defang bare URLs in plain text so they cannot be auto-linked by viewers.
        body = re.sub(
            r"(?i)(https?://[^\s<]+)",
            lambda m: f'<code class="safe-url">{html.escape(defang_url(m.group(1)))}</code>',
            body,
        )

    from_marks = [c for c in callouts if c.area == "from"]
    link_marks = [c for c in callouts if c.area == "link"]
    body_marks = [c for c in callouts if c.area == "body"]
    att_marks = [c for c in callouts if c.area == "attachment"]

    def pills(items: list[Callout]) -> str:
        return "".join(
            f'<span class="callout-pill sev-{html.escape(c.severity)}" '
            f'title="{html.escape(c.plain)}">#{c.number}</span>'
            for c in items
        )

    att_block = ""
    if report.attachments:
        rows = []
        for a in report.attachments:
            flag = " flagged" if a.get("flags") else ""
            fname = html.escape(str(a.get("filename") or ""))
            rows.append(
                f'<li class="att-item{flag}"><code>{fname}</code> {pills(att_marks)}</li>'
            )
        att_block = (
            '<div class="preview-att"><strong>Attachments (not opened):</strong>'
            f"<ul>{''.join(rows)}</ul></div>"
        )

    legend = "".join(
        f'<li><span class="callout-pill sev-{html.escape(c.severity)}">#{c.number}</span> '
        f"<strong>{html.escape(c.title)}</strong> — {html.escape(c.plain)}</li>"
        for c in callouts
    ) or "<li>No strong visual callouts for this message.</li>"

    banner = (
        "Safe preview — links and images are blocked so you cannot open them by accident."
    )
    chrome = f"""
<div class="preview-wrap">
  <p class="preview-banner">{banner}</p>
  <div class="preview-chrome">
    <div class="preview-row{' hot' if from_marks else ''}">
      <span class="preview-label">From</span>
      <span class="preview-value">{html.escape(report.from_addr)}</span>
      {pills(from_marks)}
      {'<span class="arrow-hint">← look here</span>' if from_marks else ''}
    </div>
    <div class="preview-row">
      <span class="preview-label">Subject</span>
      <span class="preview-value">{html.escape(report.subject)}</span>
      {pills(body_marks) if not from_marks else ''}
    </div>
  </div>
  <div class="preview-body{' hot-body' if link_marks or body_marks else ''}">
    {body}
  </div>
  {att_block}
  <div class="preview-legend">
    <h3>What the markers mean</h3>
    <ol class="callout-list">{legend}</ol>
  </div>
</div>
"""
    return chrome, callouts
