"""Analyst pivot links to third-party tools. No network I/O from mailshieldv1."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from email.utils import parseaddr
from urllib.parse import quote, urlparse

from mailshieldv1.core.domains import IGNORE_URL_DOMAINS, registrable_domain
from mailshieldv1.core.urls import defang_url

_SKIP_PIVOT_HOSTS = frozenset(IGNORE_URL_DOMAINS) | frozenset(
    {
        "www.w3.org",
        "www.schema.org",
    }
)

# Common public shortener hosts — Unshorten pivot is emphasized for these.
_SHORTENERS = frozenset(
    {
        "bit.ly",
        "bitly.com",
        "t.co",
        "tinyurl.com",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "rebrand.ly",
        "cutt.ly",
        "shorturl.at",
        "rb.gy",
        "lnkd.in",
        "s.id",
        "t.ly",
    }
)

_MAX_URLS_PER_HOST = 12


@dataclass(frozen=True)
class PivotLink:
    label: str
    url: str
    hint: str = ""


@dataclass
class PivotGroup:
    title: str
    target: str
    links: list[PivotLink]
    emphasize_unshorten: bool = False
    items: list[str] = field(default_factory=list)
    item_links: list[list[PivotLink]] = field(default_factory=list)
    note: str = ""


def host_of(url: str) -> str:
    raw = url if "://" in url else f"http://{url}"
    try:
        host = (urlparse(raw).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""
    if host.startswith("www."):
        host = host[4:]
    return host


def email_domain(from_header: str) -> str:
    _, addr = parseaddr(from_header or "")
    if "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[-1].lower().rstrip(".")


def _is_shortener(host: str) -> bool:
    return host in _SHORTENERS or any(host.endswith(f".{s}") for s in _SHORTENERS)


def _dedupe_links(links: list[PivotLink]) -> list[PivotLink]:
    seen: set[str] = set()
    out: list[PivotLink] = []
    for link in links:
        if link.label in seen:
            continue
        seen.add(link.label)
        out.append(link)
    return out


def _whois(domain: str) -> PivotLink:
    return PivotLink(
        "DomainTools WHOIS",
        f"https://whois.domaintools.com/{quote(domain)}",
        "Registration / history for the domain",
    )


def _dnstwist(domain: str) -> PivotLink:
    return PivotLink(
        "dnstwist.it",
        f"https://dnstwist.it/?domain={quote(domain)}",
        "Lookalike / typosquat domain permutations",
    )


def _phishtank(value: str) -> PivotLink:
    return PivotLink(
        "PhishTank",
        f"https://phishtank.org/search.php?exact=1&search_term={quote(value, safe='')}",
        "Search known phishing reports",
    )


def _virustotal_domain(domain: str) -> PivotLink:
    return PivotLink(
        "VirusTotal domain",
        f"https://www.virustotal.com/gui/domain/{quote(domain)}",
        "Multi-engine reputation for the domain (open in browser)",
    )


def _virustotal_url(url: str) -> PivotLink:
    # VT GUI accepts URL search; analysts can paste if hash lookup needed.
    return PivotLink(
        "VirusTotal URL",
        f"https://www.virustotal.com/gui/search/{quote(url, safe='')}",
        "Search the URL on VirusTotal (no API key; browser only)",
    )


def _urlscan(domain: str) -> PivotLink:
    return PivotLink(
        "urlscan.io",
        f"https://urlscan.io/search/#domain:{quote(domain)}",
        "Historical scans / screenshots for the domain",
    )


def _mx_domain(domain: str) -> PivotLink:
    return PivotLink(
        "MXToolbox SuperTool",
        f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{quote(domain)}&run=toolpage",
        "MX / related DNS checks for the domain",
    )


def _mx_headers() -> PivotLink:
    return PivotLink(
        "MXToolbox Email Headers",
        "https://mxtoolbox.com/EmailHeaders.aspx",
        "Paste full headers for hop / auth analysis",
    )


def _unshorten(url: str) -> PivotLink:
    return PivotLink(
        "Unshorten.it",
        f"https://unshorten.it/?shortURL={quote(url, safe='')}",
        "Expand short links before visiting (preferred first step)",
    )


def _domain_links(domain: str) -> list[PivotLink]:
    if not domain:
        return []
    return _dedupe_links(
        [
            _whois(domain),
            _virustotal_domain(domain),
            _urlscan(domain),
            _dnstwist(domain),
            _phishtank(domain),
            _mx_domain(domain),
        ]
    )


def build_pivots(from_addr: str, urls: list[str]) -> list[PivotGroup]:
    """Build de-duplicated analyst shortcuts: sender once, each host once."""
    groups: list[PivotGroup] = []

    sender_dom = email_domain(from_addr)
    groups.append(
        PivotGroup(
            title="Message / sender domain",
            target=sender_dom or "(no From domain)",
            links=_dedupe_links([*_domain_links(sender_dom), _mx_headers()]),
            note="Domain tools once for the From address; Email Headers is paste-based.",
        )
    )

    by_host: dict[str, list[str]] = {}
    for url in urls:
        host = host_of(url) or "(unknown host)"
        by_host.setdefault(host, []).append(url)

    for host, host_urls in by_host.items():
        reg = registrable_domain(host) if host != "(unknown host)" else ""
        if host in _SKIP_PIVOT_HOSTS or reg in _SKIP_PIVOT_HOSTS:
            continue
        shortener = host != "(unknown host)" and _is_shortener(host)
        links = _domain_links(host) if host != "(unknown host)" else []
        shown = host_urls[:_MAX_URLS_PER_HOST]
        extra = len(host_urls) - len(shown)

        item_links: list[list[PivotLink]] = []
        for u in shown:
            row_links = [_virustotal_url(u)]
            if shortener:
                row_links.insert(0, _unshorten(u))
            item_links.append(row_links)

        note = f"{len(host_urls)} URL(s) on this host — domain tools listed once."
        if shortener:
            note += " Shortener detected: Unshorten.it is offered per URL below."
        if extra > 0:
            note += f" Showing {len(shown)}, {extra} more omitted."

        groups.append(
            PivotGroup(
                title="Host",
                target=host,
                links=links,
                emphasize_unshorten=shortener,
                items=[defang_url(u) for u in shown],
                item_links=item_links,
                note=note,
            )
        )
    return groups


def pivots_as_dicts(from_addr: str, urls: list[str]) -> list[dict]:
    return [
        {
            "title": g.title,
            "target": g.target,
            "emphasize_unshorten": g.emphasize_unshorten,
            "note": g.note,
            "items": list(g.items),
            "item_links": [[asdict(x) for x in row] for row in g.item_links],
            "links": [asdict(x) for x in g.links],
        }
        for g in build_pivots(from_addr, urls)
    ]
