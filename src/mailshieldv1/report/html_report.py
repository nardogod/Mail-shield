"""Minimal HTML renderer. All dynamic values are escaped."""

from __future__ import annotations

import html
import re
from typing import Any

from mailshieldv1.core.models import Finding, Report
from mailshieldv1.core.url_roles import UrlItem, group_by_role
from mailshieldv1.core.urls import defang_url
from mailshieldv1.report.pivots import PivotGroup, PivotLink, build_pivots

_NEG = frozenset({"medium", "high", "critical"})
_KV_EVIDENCE = re.compile(
    r"(?P<k>[A-Za-z0-9_-]+)=(?P<v>[^;]+)(?:;\s*)?"
)


def _badge(severity: str) -> str:
    s = html.escape(severity)
    return f'<span class="badge sev-{s}">{s}</span>'


def _tone(severity: str) -> str:
    return "neg" if severity in _NEG else "pos"


def _format_evidence(evidence: str, severity: str) -> str:
    """Color address pairs in evidence (e.g. From=…; Reply-To=…)."""
    matches = list(_KV_EVIDENCE.finditer(evidence))
    if len(matches) < 2:
        cls = "ev-neg" if severity in _NEG else "ev-pos"
        return f'<code class="{cls}">{html.escape(evidence)}</code>'

    parts: list[str] = []
    for i, m in enumerate(matches):
        key = html.escape(m.group("k"))
        val = html.escape(m.group("v").strip())
        val_cls = "addr-a" if i == 0 else "addr-b"
        if severity not in _NEG:
            val_cls = "addr-ok"
        parts.append(
            f'<span class="kv"><span class="k">{key}=</span>'
            f'<span class="{val_cls}">{val}</span></span>'
        )
    return "<code>" + "; ".join(parts) + "</code>"


def _finding_row(f: Finding) -> str:
    tone = _tone(f.severity)
    return (
        f'<tr class="row-{tone}">'
        f"<td>{html.escape(f.rule_id)}</td>"
        f"<td>{_badge(f.severity)}</td>"
        f"<td>{html.escape(f.category)}</td>"
        f"<td>{html.escape(f.explanation)}</td>"
        f"<td>{_format_evidence(f.evidence, f.severity)}</td>"
        f"<td>{html.escape(f.recommendation)}</td>"
        "</tr>"
    )


def _pivot_anchors(links: list[PivotLink], *, primary: bool = False) -> str:
    esc = html.escape
    bits = []
    for link in links:
        cls = "pivot primary" if primary or link.label.startswith("Unshorten") else "pivot"
        bits.append(
            f'<a class="{cls}" href="{esc(link.url)}" target="_blank" '
            f'rel="noopener noreferrer" title="{esc(link.hint)}">'
            f"{esc(link.label)}</a>"
        )
    return "".join(bits)


def _pivot_group_html(group: PivotGroup) -> str:
    esc = html.escape
    target_show = esc(defang_url(group.target) if "://" in group.target else group.target)
    flag = (
        ' <span class="badge sev-high">shortener</span>'
        if group.emphasize_unshorten
        else ""
    )
    note = f'<p class="key-hint">{esc(group.note)}</p>' if group.note else ""
    items_html = ""
    if group.items:
        rows = []
        for i, item in enumerate(group.items):
            extra = ""
            if i < len(group.item_links) and group.item_links[i]:
                extra = (
                    f'<div class="pivot-links">'
                    f"{_pivot_anchors(group.item_links[i], primary=True)}"
                    f"</div>"
                )
            rows.append(
                f"<li><code class=\"ev-neg\">{esc(item)}</code>{extra}</li>"
            )
        items_html = f'<ul class="pivot-items">{"".join(rows)}</ul>'
    return (
        f'<div class="pivot-card">'
        f"<h3>{esc(group.title)}{flag}</h3>"
        f"<p><code class=\"ev-neg\">{target_show}</code></p>"
        f"{note}"
        f'<div class="pivot-links">{_pivot_anchors(group.links)}</div>'
        f"{items_html}"
        f"</div>"
    )


def _section(title: str, body: str, *, open_: bool = False, meta: str = "") -> str:
    """Collapsible report block (native HTML details — no JavaScript)."""
    esc = html.escape
    opened = " open" if open_ else ""
    meta_html = f' <span class="sec-meta">{esc(meta)}</span>' if meta else ""
    return (
        f"<details class=\"section\"{opened}>"
        f"<summary><span class=\"sec-title\">{esc(title)}</span>{meta_html}</summary>"
        f'<div class="section-body">{body}</div>'
        f"</details>"
    )


def _path_nodes(hops: list[dict[str, Any]]) -> list[str]:
    """Build origin → mailbox path using both from and by (deduped)."""
    nodes: list[str] = []
    for h in reversed(hops):  # oldest first
        for key in ("from_host", "by_host"):
            part = str(h.get(key) or "").strip()
            if part and (not nodes or nodes[-1] != part):
                nodes.append(part)
    return nodes


def _hops_section_body(hops: list[dict[str, Any]]) -> str:
    esc = html.escape
    if not hops:
        return (
            "<p><strong>No Received headers.</strong> "
            "Export the full message (not just the body) before blaming the path.</p>"
        )

    newest = hops[0]
    oldest = hops[-1]
    last_by = str(newest.get("by_host") or "-")
    last_from = str(newest.get("from_host") or "-")
    # External sender HELO/name lives in the oldest from=, not by=.
    origin = str(oldest.get("from_host") or oldest.get("by_host") or "-")
    nodes = _path_nodes(hops)
    path = " → ".join(nodes) if nodes else "-"

    # Practical unique location list (always shown).
    loc_items: list[str] = []
    seen_loc: set[str] = set()
    for h in hops:
        label = str(h.get("geo_label") or "Location unknown")
        ip = str(h.get("ip") or "")
        key = f"{label}|{ip}"
        if key in seen_loc:
            continue
        seen_loc.add(key)
        country = str(h.get("country") or "")
        city = str(h.get("city") or "")
        detail = label
        if country or city:
            detail = ", ".join(x for x in (city, country) if x) or label
        ip_bit = f" — <code>{esc(ip)}</code>" if ip else ""
        src = str(h.get("geo_source") or "")
        loc_items.append(
            f"<li><strong>{esc(detail)}</strong>{ip_bit}"
            f' <span class="sec-meta">[{esc(src)}]</span></li>'
        )
    locations = (
        "<p><strong>Locations (offline hints):</strong></p>"
        f"<ul class=\"geo-list\">{''.join(loc_items)}</ul>"
        "<p class=\"key-hint\">Derived from hop IPs + known AWS/M365 region tokens. "
        "Not a live GeoIP lookup — forgeable hops can lie.</p>"
    )

    takeaways = (
        "<ol class=\"takeaways\">"
        "<li><strong>Check first:</strong> is the last hop "
        f"(<code>{esc(last_by)}</code>) one of <em>your</em> mail servers?</li>"
        "<li><strong>First public handoff:</strong> "
        f"<code class=\"addr-b\">{esc(origin)}</code> "
        "(oldest <em>from</em> — forgeable; not proof of location).</li>"
        "<li>If auth failed but the bottom looks &quot;internal&quot;, "
        "treat early hops as attacker-controlled storytelling.</li>"
        "</ol>"
    )

    summary = (
        f'<div class="hop-summary">'
        f"<p><strong>Hops:</strong> {len(hops)} &nbsp;|&nbsp; "
        f"<strong>Last hop (trust this first):</strong> "
        f"<code class=\"addr-ok\">{esc(last_by)}</code> received from "
        f"<code>{esc(last_from)}</code></p>"
        f"<p><strong>Path (oldest → newest):</strong> "
        f"<code class=\"hop-path\">{esc(path)}</code></p>"
        f"<p><strong>First seen sending host (untrusted):</strong> "
        f"<code class=\"addr-b\">{esc(origin)}</code></p>"
        f"{locations}"
        f"{takeaways}"
        f"</div>"
    )

    rows = []
    for h in hops:
        idx = int(h.get("index") or 0)
        if idx == 0:
            role = "LAST HOP — start here"
            row_cls = "row-pos"
        elif idx == len(hops) - 1:
            role = "FIRST SEEN — forgeable"
            row_cls = "row-neg"
        else:
            role = "intermediate"
            row_cls = ""
        geo = str(h.get("geo_label") or "-")
        rows.append(
            f'<tr class="{row_cls}">'
            f"<td>{idx}</td>"
            f"<td>{esc(role)}</td>"
            f"<td><code>{esc(str(h.get('from_host') or '-'))}</code></td>"
            f"<td><code>{esc(str(h.get('by_host') or '-'))}</code></td>"
            f"<td><code>{esc(str(h.get('ip') or '-'))}</code></td>"
            f"<td>{esc(geo)}</td>"
            f"<td>{esc(str(h.get('with_protocol') or '-'))}</td>"
            "</tr>"
        )

    table = (
        "<p class=\"key-hint\">Table is newest-first (#0 = mailbox side).</p>"
        "<table><thead><tr>"
        "<th>#</th><th>role</th><th>from</th><th>by</th>"
        "<th>ip</th><th>location</th><th>with</th>"
        "</tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )

    raw_rows = "".join(
        f"<li><code>{esc(str(h.get('raw') or ''))}</code></li>" for h in hops
    )
    raw = (
        "<details class=\"nested\" open>"
        "<summary>Raw Received lines</summary>"
        f"<ol>{raw_rows}</ol>"
        "</details>"
    )
    return summary + table + raw


def _auth_section_body(auth: dict[str, Any]) -> str:
    esc = html.escape
    if not auth:
        return "<p>No authentication summary.</p>"
    present = bool(auth.get("present"))
    rows = []
    for mech in ("spf", "dkim", "dmarc", "compauth"):
        status = str(auth.get(mech) or "missing")
        if status == "pass":
            cls = "addr-ok"
        elif status in {"fail", "permerror", "softfail", "temperror", "none"}:
            cls = "addr-b"
        else:
            cls = "sec-meta"
        rows.append(
            f"<tr><td>{esc(mech.upper())}</td>"
            f'<td><code class="{cls}">{esc(status)}</code></td></tr>'
        )
    note = (
        "<p class=\"key-hint\">Values are MTA-asserted from Authentication-Results / "
        "ARC-Authentication-Results. Offline mode does not re-validate DNS or DKIM crypto.</p>"
    )
    raw = str(auth.get("raw") or "")
    raw_block = (
        f'<details class="nested"><summary>Raw Authentication-Results</summary>'
        f"<p><code>{esc(raw)}</code></p></details>"
        if raw
        else ""
    )
    status_line = (
        '<p><strong>Header present:</strong> '
        f'<span class="{"addr-ok" if present else "addr-b"}">'
        f'{"yes" if present else "no"}</span></p>'
    )
    return (
        status_line
        + note
        + "<table><thead><tr><th>Mechanism</th><th>Result</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
        + raw_block
    )


def _why_section_body(report: Report) -> str:
    esc = html.escape
    contribs = report.verdict_contributors or []
    if not contribs:
        return (
            f"<p>Score <strong>{esc(str(report.score))}</strong> — "
            "no weighted contributors (informational only).</p>"
        )
    rows = []
    for c in contribs:
        w = float(c.get("weight") or 0)
        w_cls = "addr-b" if w > 0 else "addr-ok"
        rows.append(
            f"<tr>"
            f"<td><code>{esc(str(c.get('rule_id') or ''))}</code></td>"
            f"<td>{_badge(str(c.get('severity') or 'info'))}</td>"
            f'<td><code class="{w_cls}">{w:+.2f}</code></td>'
            f"<td>{esc(str(c.get('reason') or ''))}</td>"
            f"</tr>"
        )
    return (
        f"<p><strong>Score:</strong> {esc(str(report.score))} → "
        f"verdict <span class=\"badge sev-{esc(report.verdict)}\">{esc(report.verdict)}</span></p>"
        "<p class=\"key-hint\">Positive weights raise risk; negative modifiers "
        "(auth pass / org consistency) reduce marketing false positives.</p>"
        "<table><thead><tr>"
        "<th>Contributor</th><th>Severity</th><th>Weight</th><th>Reason</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _org_section_body(org: dict[str, Any]) -> str:
    esc = html.escape
    if not org:
        return "<p>No org summary.</p>"
    consistent = bool(org.get("consistent"))
    esp = bool(org.get("esp_envelope"))
    urls = ", ".join(esc(str(d)) for d in (org.get("url_domains") or [])[:12]) or "-"
    reasons = org.get("reasons") or []
    reason_html = (
        "<ul>" + "".join(f"<li><code>{esc(str(r))}</code></li>" for r in reasons) + "</ul>"
        if reasons
        else "<p class=\"key-hint\">No mismatch reasons recorded.</p>"
    )
    from_d = esc(str(org.get("from_domain") or "-"))
    rp_d = esc(str(org.get("return_path_domain") or "-"))
    rt_d = esc(str(org.get("reply_to_domain") or "-"))
    return (
        f"<p><strong>From domain:</strong> <code>{from_d}</code><br/>"
        f"<strong>Return-Path:</strong> <code>{rp_d}</code><br/>"
        f"<strong>Reply-To:</strong> <code>{rt_d}</code><br/>"
        f"<strong>URL domains:</strong> <code>{urls}</code><br/>"
        f"<strong>Consistent:</strong> "
        f'<span class="{"addr-ok" if consistent else "addr-b"}">'
        f'{"yes" if consistent else "no"}</span> &nbsp;|&nbsp; '
        f"<strong>ESP envelope:</strong> "
        f'<span class="{"addr-ok" if esp else "sec-meta"}">'
        f'{"yes" if esp else "no"}</span></p>'
        f"{reason_html}"
    )


def _online_section_body(online: dict[str, Any]) -> str:
    esc = html.escape
    if not online or not online.get("enabled"):
        return (
            "<p>Online mode was <strong>off</strong>. "
            "Re-run with <code>--online</code> for optional DNS TXT/A hints "
            "(requires <code>mailshieldv1[online]</code>).</p>"
        )
    notes = "".join(f"<li>{esc(str(n))}</li>" for n in (online.get("notes") or []))
    spf = "<br/>".join(esc(str(x)) for x in (online.get("spf_txt") or [])[:5]) or "-"
    dmarc = "<br/>".join(esc(str(x)) for x in (online.get("dmarc_txt") or [])[:5]) or "-"
    res_rows = []
    for r in online.get("resolutions") or []:
        if r.get("ok"):
            addrs = ", ".join(esc(str(a)) for a in (r.get("addresses") or [])[:6])
            res_rows.append(
                f"<tr class=\"row-pos\"><td><code>{esc(str(r.get('host')))}</code></td>"
                f"<td><code>{addrs}</code></td></tr>"
            )
        else:
            res_rows.append(
                f"<tr class=\"row-neg\"><td><code>{esc(str(r.get('host')))}</code></td>"
                f"<td>{esc(str(r.get('error') or 'failed'))}</td></tr>"
            )
    return (
        f"<p><strong>From domain:</strong> "
        f"<code>{esc(str(online.get('from_domain') or '-'))}</code></p>"
        f"<p><strong>SPF TXT:</strong><br/><code>{spf}</code></p>"
        f"<p><strong>DMARC TXT:</strong><br/><code>{dmarc}</code></p>"
        "<table><thead><tr><th>Host</th><th>Resolution</th></tr></thead><tbody>"
        + ("".join(res_rows) or "<tr><td colspan=\"2\">No resolutions.</td></tr>")
        + "</tbody></table>"
        + (f"<ul>{notes}</ul>" if notes else "")
    )


def _urls_section_body(
    url_items: list[dict[str, Any]],
    url_groups: list[dict[str, Any]] | None = None,
) -> str:
    esc = html.escape
    if not url_items:
        return "<p>No URLs extracted.</p>"
    items = [
        UrlItem(
            url=str(u.get("url") or ""),
            defanged=str(u.get("defanged") or ""),
            role=str(u.get("role") or "other"),
            role_title=str(u.get("role_title") or ""),
            sender_purpose=str(u.get("sender_purpose") or ""),
            source=str(u.get("source") or "body_text"),
        )
        for u in url_items
    ]
    blocks: list[str] = [
        "<p class=\"key-hint\">All URLs are kept (including tracking pixels). "
        "Grouped by the likely reason the <em>sender</em> included them. "
        "Query-string clones are collapsed below. Destinations were not fetched.</p>"
    ]
    if url_groups:
        variant_lis = []
        for g in url_groups:
            count = int(g.get("count") or 1)
            sample = esc(str(g.get("sample_defanged") or g.get("key") or ""))
            role = esc(str(g.get("role_title") or g.get("role") or ""))
            extra = (
                f' <span class="badge sev-info">{count} variants</span>'
                if count > 1
                else ""
            )
            variant_lis.append(
                f"<li><code class=\"ev-neg\">{sample}</code> "
                f'<span class="sec-meta">[{role}]</span>{extra}</li>'
            )
        blocks.append(
            '<div class="url-role-card">'
            "<h3>Variant groups "
            f'<span class="sec-meta">({len(url_groups)} unique path(s))</span></h3>'
            "<p class=\"role-purpose\">Same host+path with different query strings "
            "count as one group (members retained in JSON).</p>"
            f"<ul>{''.join(variant_lis)}</ul>"
            "</div>"
        )
    for role, title, purpose, group in group_by_role(items):
        lis = "".join(
            f"<li><code class=\"ev-neg\">{esc(i.defanged)}</code> "
            f'<span class="sec-meta">[{esc(i.source)}]</span></li>'
            for i in group
        )
        blocks.append(
            f'<div class="url-role-card" data-role="{esc(role)}">'
            f"<h3>{esc(title)} "
            f'<span class="sec-meta">({len(group)})</span></h3>'
            f'<p class="role-purpose">{esc(purpose)}</p>'
            f"<ul>{lis}</ul>"
            f"</div>"
        )
    return "\n".join(blocks)


def _attachments_section_body(attachments: list[dict[str, Any]]) -> str:
    esc = html.escape
    if not attachments:
        return "<p>No attachments inventoried.</p>"
    rows = []
    for a in attachments:
        flags = a.get("flags") or []
        flag_html = (
            ", ".join(f'<span class="badge sev-high">{esc(str(f))}</span>' for f in flags)
            if flags
            else '<span class="sec-meta">none</span>'
        )
        row_cls = "row-neg" if flags else "row-pos"
        rows.append(
            f'<tr class="{row_cls}">'
            f"<td><code>{esc(str(a.get('filename') or ''))}</code></td>"
            f"<td>{esc(str(a.get('content_type') or ''))}</td>"
            f"<td>{esc(str(a.get('size') or 0))}</td>"
            f"<td>{flag_html}</td>"
            "</tr>"
        )
    return (
        "<p class=\"key-hint\">Static checks only — files are not executed or saved.</p>"
        "<table><thead><tr>"
        "<th>filename</th><th>type</th><th>size</th><th>flags</th>"
        "</tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


def _simple_view(report: Report, preview_html: str) -> str:
    from mailshieldv1.report.plain_language import plain_verdict, top_plain_reasons

    esc = html.escape
    title, meaning, action = plain_verdict(report)
    reasons = top_plain_reasons(report)
    reason_lis = "".join(
        f"<li><span class=\"badge sev-{esc(sev)}\">{esc(sev)}</span> {esc(text)}</li>"
        for _rid, sev, text in reasons
    ) or "<li>No major warnings were listed.</li>"
    v_tone = _tone(report.verdict)
    return f"""
<section class="simple-panel">
  <p class="verdict {v_tone}">{esc(title)}</p>
  <p class="plain-lead"><strong>What this means:</strong> {esc(meaning)}</p>
  <p class="plain-action"><strong>What you should do:</strong> {esc(action)}</p>
  <h2>Why we think that</h2>
  <ol class="plain-reasons">{reason_lis}</ol>
  <h2>Reconstructed email (safe)</h2>
  <p class="key-hint">This is a rebuilt copy of the message. Links and images cannot be opened.</p>
  {preview_html}
</section>
"""


def to_html(report: Report, *, raw: bytes | None = None) -> str:
    """Render dual Simple (default) + Technical report in one HTML file.

    Market pattern (PhishSpot / Check Point / Graphus): non-technical first,
    safe email preview with links/images disabled, technical details on demand.
    """
    esc = html.escape
    rows = [_finding_row(f) for f in report.findings]
    body_rows = "\n".join(rows) or '<tr><td colspan="6">No findings.</td></tr>'
    findings_table = (
        "<table><thead><tr>"
        "<th>Rule</th><th>Severity</th><th>Category</th>"
        "<th>Explanation</th><th>Evidence</th><th>Recommendation</th>"
        "</tr></thead><tbody>"
        f"{body_rows}</tbody></table>"
    )
    notes = "".join(f"<li>{esc(n)}</li>" for n in report.analyzer_notes)
    urls_block = _urls_section_body(report.url_items, report.url_groups)

    pivots = build_pivots(report.from_addr, report.urls)
    pivots_block = "\n".join(_pivot_group_html(g) for g in pivots)
    hops_body = _hops_section_body(report.hops)
    attachments_body = _attachments_section_body(report.attachments)
    auth_body = _auth_section_body(report.auth)
    why_body = _why_section_body(report)
    org_body = _org_section_body(report.org)
    online_body = _online_section_body(report.online)

    preview_html = (
        "<p class=\"key-hint\">Pass the original .eml bytes to include a reconstructed preview.</p>"
    )
    if raw:
        from mailshieldv1.core.parser import parse_eml
        from mailshieldv1.report.safe_preview import render_safe_preview

        msg = parse_eml(raw)
        preview_html, _callouts = render_safe_preview(msg, report)

    neg_n = sum(1 for f in report.findings if f.severity in _NEG)
    risky_att = sum(1 for a in report.attachments if a.get("flags"))
    track_n = sum(1 for u in report.url_items if u.get("role") == "tracking_pixel")
    group_n = len(report.url_groups or [])
    v = esc(report.verdict)
    v_tone = _tone(report.verdict)
    page_title = esc((report.subject or "report")[:80])
    age = (
        f"{report.email_age_days} day(s)"
        if report.email_age_days is not None
        else "unknown"
    )
    auth_present = bool((report.auth or {}).get("present"))

    tech_sections = [
        _section(
            "Why this verdict",
            why_body,
            open_=True,
            meta=f"score {report.score}",
        ),
        _section(
            "Authentication",
            auth_body,
            open_=True,
            meta="present" if auth_present else "missing",
        ),
        _section(
            "Org / ESP consistency",
            org_body,
            open_=False,
            meta="ok" if (report.org or {}).get("consistent") else "check",
        ),
        _section(
            "Findings",
            findings_table,
            open_=True,
            meta=f"{len(report.findings)} total, {neg_n} medium+",
        ),
        _section(
            "Received path",
            hops_body,
            open_=True,
            meta=f"{len(report.hops)} hop(s)",
        ),
        _section(
            "Attachments",
            attachments_body,
            open_=bool(report.attachments),
            meta=f"{len(report.attachments)} file(s), {risky_att} flagged",
        ),
        _section(
            "URLs by sender purpose",
            urls_block,
            open_=bool(report.url_items),
            meta=f"{len(report.url_items)} total, {group_n} groups, {track_n} tracking",
        ),
        _section(
            "Online enrichments",
            online_body,
            open_=bool((report.online or {}).get("enabled")),
            meta="on" if (report.online or {}).get("enabled") else "off",
        ),
        _section(
            "Analyst pivots",
            "<p class=\"key-hint\">Optional third-party tools (new tab). "
            "Engine stays offline until you click. Prefer Unshorten.it for short links.</p>"
            + pivots_block,
            open_=False,
            meta=str(len(pivots)),
        ),
        _section("Notes", f"<ul>{notes}</ul>", open_=False),
    ]
    simple = _simple_view(report, preview_html)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>mailshieldv1 — {page_title}</title>
  <style>
    :root {{
      --pos: #0a7a32;
      --pos-bg: #e8f7ee;
      --neg: #b00020;
      --neg-bg: #fde8ec;
      --info: #455a64;
      --low: #2e7d32;
      --medium: #ef6c00;
      --high: #c62828;
      --critical: #7b1fa2;
    }}
    body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; max-width: 1100px; }}
    .view-ctrl {{ position: absolute; opacity: 0; pointer-events: none; }}
    .view-toggle {{
      display: flex; gap: 0.5rem; margin: 1rem 0 1.25rem; flex-wrap: wrap;
      align-items: center;
    }}
    .view-toggle label {{
      border: 1px solid #888; padding: 0.45rem 0.9rem; cursor: pointer; background: #fff;
      font-weight: 600;
    }}
    #view-simple:checked ~ .view-toggle label[for="view-simple"],
    #view-tech:checked ~ .view-toggle label[for="view-tech"] {{
      background: #111; color: #fff; border-color: #111;
    }}
    .panel-tech {{ display: none; }}
    #view-simple:checked ~ .panel-simple {{ display: block; }}
    #view-simple:checked ~ .panel-tech {{ display: none; }}
    #view-tech:checked ~ .panel-simple {{ display: none; }}
    #view-tech:checked ~ .panel-tech {{ display: block; }}
    .plain-lead, .plain-action {{ font-size: 1.05rem; line-height: 1.45; }}
    .plain-reasons {{ padding-left: 1.2rem; }}
    .plain-reasons li {{ margin: 0.45rem 0; }}
    .preview-wrap {{
      border: 1px solid #ccc; background: #fafafa; padding: 0.75rem; margin-top: 0.5rem;
    }}
    .preview-banner {{
      background: #fff3cd; border: 1px solid #e0c36a; padding: 0.5rem 0.75rem;
      margin: 0 0 0.75rem; font-weight: 600;
    }}
    .preview-chrome {{ border: 1px solid #ddd; background: #fff; margin-bottom: 0.75rem; }}
    .preview-row {{
      display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: baseline;
      padding: 0.55rem 0.75rem; border-bottom: 1px solid #eee;
    }}
    .preview-row.hot {{ background: var(--neg-bg); }}
    .preview-label {{ min-width: 4.5rem; font-weight: 700; color: #555; }}
    .preview-value {{ flex: 1; word-break: break-word; }}
    .preview-body {{
      border: 1px solid #ddd; background: #fff; padding: 1rem; max-height: 28rem;
      overflow: auto; line-height: 1.45;
    }}
    .preview-body.hot-body {{ box-shadow: inset 3px 0 0 var(--neg); }}
    .safe-link-label, .safe-img {{
      color: var(--neg); font-weight: 700; text-decoration: line-through;
    }}
    .safe-url {{ color: var(--neg); }}
    .hot-link {{
      display: inline-block; background: var(--neg-bg); padding: 0.1rem 0.25rem;
      border-bottom: 2px solid var(--neg);
    }}
    .callout-pill {{
      display: inline-block; min-width: 1.4rem; text-align: center;
      border-radius: 999px; color: #fff; font-weight: 700; font-size: 0.8rem;
      padding: 0.1rem 0.35rem;
    }}
    .arrow-hint {{ color: var(--neg); font-weight: 700; }}
    .preview-legend {{ margin-top: 0.75rem; }}
    .callout-list {{ padding-left: 1.1rem; }}
    .callout-list li {{ margin: 0.35rem 0; }}
    .preview-att ul {{ margin: 0.35rem 0 0; padding-left: 1.2rem; }}
    .att-item.flagged {{ background: var(--neg-bg); }}
    .legend {{
      display: flex; flex-wrap: wrap; gap: 0.75rem 1.25rem;
      padding: 0.75rem 1rem; border: 1px solid #ddd; background: #fafafa;
      margin: 1rem 0 1.5rem;
    }}
    .legend span {{ display: inline-flex; align-items: center; gap: 0.4rem; }}
    .badge {{
      display: inline-block; padding: 0.15rem 0.5rem; border-radius: 0.25rem;
      font-size: 0.85rem; font-weight: 700; text-transform: uppercase; color: #fff;
    }}
    .sev-info {{ background: var(--info); }}
    .sev-low {{ background: var(--low); }}
    .sev-medium {{ background: var(--medium); }}
    .sev-high {{ background: var(--high); }}
    .sev-critical {{ background: var(--critical); }}
    .verdict {{ font-size: 1.35rem; font-weight: 700; }}
    .verdict.pos {{ color: var(--pos); }}
    .verdict.neg {{ color: var(--neg); }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 0.5rem; }}
    th, td {{
      border: 1px solid #ccc; padding: 0.4rem 0.6rem;
      text-align: left; vertical-align: top;
    }}
    th {{ background: #f4f4f4; }}
    tr.row-neg {{ background: var(--neg-bg); }}
    tr.row-pos {{ background: var(--pos-bg); }}
    code {{ word-break: break-all; font-size: 0.9rem; }}
    .addr-a {{ color: var(--pos); font-weight: 700; }}
    .addr-b {{ color: var(--neg); font-weight: 700; }}
    .addr-ok {{ color: var(--pos); font-weight: 700; }}
    .ev-neg {{ color: var(--neg); }}
    .ev-pos {{ color: var(--pos); }}
    .key-hint {{ font-size: 0.9rem; color: #555; margin-top: 0.25rem; }}
    .pivot-card {{
      border: 1px solid #ddd; padding: 0.75rem 1rem; margin: 0.75rem 0;
      background: #fcfcfc;
    }}
    .pivot-card h3 {{ margin: 0 0 0.4rem; font-size: 1rem; }}
    .pivot-links {{ display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.5rem; }}
    a.pivot {{
      display: inline-block; padding: 0.25rem 0.6rem; border: 1px solid #888;
      text-decoration: none; color: #111; background: #fff; font-size: 0.9rem;
    }}
    a.pivot:hover {{ background: #eee; }}
    a.pivot.primary {{
      border-color: var(--high); background: var(--neg-bg); font-weight: 700;
    }}
    ul.pivot-items {{ margin: 0.75rem 0 0; padding-left: 1.2rem; }}
    ul.pivot-items li {{ margin: 0.35rem 0; }}
    details.section {{
      border: 1px solid #ccc; margin: 0.75rem 0; background: #fff;
    }}
    details.section > summary {{
      cursor: pointer; padding: 0.65rem 0.9rem; background: #f3f3f3;
      font-weight: 700; list-style: none;
    }}
    details.section > summary::-webkit-details-marker {{ display: none; }}
    details.section > summary::before {{ content: "▸ "; }}
    details.section[open] > summary::before {{ content: "▾ "; }}
    .sec-meta {{ font-weight: 500; color: #666; font-size: 0.9rem; }}
    .section-body {{ padding: 0.75rem 1rem 1rem; }}
    details.nested {{ margin-top: 0.75rem; }}
    details.nested > summary {{ cursor: pointer; color: #444; }}
    .hop-summary {{
      background: #f8faf8; border: 1px solid #d5e0d5; padding: 0.75rem 1rem;
      margin-bottom: 0.75rem;
    }}
    .hop-path {{ font-weight: 600; }}
    ol.takeaways {{ margin: 0.5rem 0 0; padding-left: 1.2rem; }}
    ol.takeaways li {{ margin: 0.25rem 0; }}
    ul.geo-list {{ margin: 0.35rem 0 0.5rem; padding-left: 1.2rem; }}
    ul.geo-list li {{ margin: 0.2rem 0; }}
    .url-role-card {{
      border: 1px solid #ddd; padding: 0.75rem 1rem; margin: 0.75rem 0;
      background: #fafafa;
    }}
    .url-role-card h3 {{ margin: 0 0 0.35rem; font-size: 1rem; }}
    .role-purpose {{ margin: 0 0 0.5rem; color: #333; font-size: 0.95rem; }}
    .url-role-card ul {{ margin: 0; padding-left: 1.2rem; }}
  </style>
</head>
<body>
  <h1>mailshieldv1</h1>
  <p class="key-hint">Default view is for everyone. Analysts can switch to Technical.</p>
  <input class="view-ctrl" type="radio" name="viewmode" id="view-simple" checked/>
  <input class="view-ctrl" type="radio" name="viewmode" id="view-tech"/>
  <div class="view-toggle">
    <label for="view-simple">Simple report</label>
    <label for="view-tech">Technical report</label>
  </div>

  <div class="panel-simple">
    {simple}
  </div>

  <div class="panel-tech">
  <details class="section">
    <summary><span class="sec-title">Legend</span></summary>
    <div class="section-body">
      <div class="legend" aria-label="Severity legend">
        <span><span class="badge sev-info">info</span> informational</span>
        <span><span class="badge sev-low">low</span> weak signal</span>
        <span><span class="badge sev-medium">medium</span> investigate</span>
        <span><span class="badge sev-high">high</span> strong risk</span>
        <span><span class="badge sev-critical">critical</span> urgent risk</span>
        <span><strong style="color:var(--pos)">Green</strong> = pass / trust-first</span>
        <span><strong style="color:var(--neg)">Red</strong> = fail / untrusted</span>
      </div>
      <p class="key-hint">Click a section title to expand or collapse.</p>
    </div>
  </details>
  <p class="verdict {v_tone}">Verdict: {v}
     <span class="sec-meta">(score {esc(str(report.score))})</span></p>
  <p><strong>From:</strong> {esc(report.from_addr)}<br/>
     <strong>Subject:</strong> {esc(report.subject)}<br/>
     <strong>Message-ID:</strong> {esc(report.message_id)}<br/>
     <strong>Date:</strong> {esc(report.email_date or "-")}
     <span class="sec-meta">(age {esc(age)}; analyzed {esc(report.analyzed_at or "-")})</span></p>
  <h2>Safe email reconstruction</h2>
  {preview_html}
  {"".join(tech_sections)}
  </div>
</body>
</html>
"""
