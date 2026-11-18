"""Registrable-domain helpers and ESP / org-consistency checks (offline)."""

from __future__ import annotations

from email.utils import parseaddr
from urllib.parse import urlparse

# Multi-part public suffixes we care about for BR/EU marketing samples.
_MULTI_SUFFIX = frozenset(
    {
        "com.br",
        "org.br",
        "net.br",
        "co.uk",
        "org.uk",
        "ac.uk",
        "com.au",
        "co.jp",
        "com.mx",
    }
)

# Expected bulk-send / ESP domains (not the brand, but legitimate transit/envelope).
_ESP_DOMAINS = frozenset(
    {
        "amazonses.com",
        "amazonaws.com",
        "sendgrid.net",
        "mailgun.org",
        "mandrillapp.com",
        "exacttarget.com",
        "salesforce.com",
        "mailchimp.com",
        "google.com",
        "gmail.com",
        "outlook.com",
        "office365.com",
        "protection.outlook.com",
        "microsoft.com",
        "user-subscription.com",
        "list-manage.com",
        "mailchimpapp.net",
        "constantcontact.com",
        "ct.sendgrid.net",
    }
)

# Markup / CDN / cloud hosts are not brand-impersonation signals.
IGNORE_URL_DOMAINS = frozenset(
    {
        "w3.org",
        "schema.org",
        "xmlns.com",
        "microsoft.com",
        "office.com",
        "google.com",
        "gstatic.com",
        "googleapis.com",
        "windows.net",
        "azureedge.net",
        "azurewebsites.net",
        "cloudfront.net",
        "amazonaws.com",
        "akamaihd.net",
        "akamaized.net",
        "cloudflare.com",
        "googleusercontent.com",
    }
)
_IGNORE_URL_DOMAINS = IGNORE_URL_DOMAINS


def registrable_domain(host: str) -> str:
    host = (host or "").lower().strip().strip(".")
    if not host or host.startswith("[") or ":" in host:
        return ""
    # Strip trailing port if somehow present
    host = host.split(":")[0]
    parts = [p for p in host.split(".") if p]
    if len(parts) < 2:
        return host
    last2 = ".".join(parts[-2:])
    if last2 in _MULTI_SUFFIX and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last2


def email_domain(value: str) -> str:
    _, addr = parseaddr(value or "")
    if "@" not in addr:
        return ""
    return registrable_domain(addr.rsplit("@", 1)[-1])


def url_domain(url: str) -> str:
    raw = url if "://" in url else f"http://{url}"
    try:
        host = urlparse(raw).hostname or ""
    except ValueError:
        return ""
    return registrable_domain(host)


def is_esp(domain: str) -> bool:
    d = (domain or "").lower()
    if not d:
        return False
    if d in _ESP_DOMAINS:
        return True
    return any(d.endswith(f".{e}") for e in _ESP_DOMAINS)


def brand_label(domain: str) -> str:
    """nordea.se / nordea.com → nordea; foo.com.br → foo."""
    d = (domain or "").lower()
    if not d:
        return ""
    parts = [p for p in d.split(".") if p]
    if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI_SUFFIX:
        return parts[-3]
    return parts[0] if parts else ""


def same_brand(a: str, b: str) -> bool:
    if not a or not b:
        return False
    if a == b:
        return True
    la, lb = brand_label(a), brand_label(b)
    return bool(la and la == lb)


def org_consistency(
    *,
    from_header: str,
    return_path: str,
    reply_to: str,
    urls: list[str],
) -> dict:
    """Return consistency summary for scoring / findings."""
    from_d = email_domain(from_header)
    rp_d = email_domain(return_path)
    rt_d = email_domain(reply_to)
    url_domains = sorted({url_domain(u) for u in urls if url_domain(u)})
    brand_urls = [
        d
        for d in url_domains
        if not is_esp(d) and d not in _IGNORE_URL_DOMAINS
    ]

    related = True
    reasons: list[str] = []
    if from_d and rp_d and rp_d != from_d and not is_esp(rp_d) and not same_brand(from_d, rp_d):
        related = False
        reasons.append(f"return_path_domain={rp_d} != from_domain={from_d}")
    if from_d and rt_d and rt_d != from_d and not is_esp(rt_d):
        # Soft: marketing often uses sibling Reply-To; not a hard fail here.
        pass
    foreign = [
        d for d in brand_urls if from_d and d != from_d and not same_brand(from_d, d)
    ]
    if foreign:
        related = False
        reasons.append(f"url_domains_foreign={foreign[:5]}")

    esp_envelope = bool(rp_d and is_esp(rp_d))
    return {
        "from_domain": from_d,
        "return_path_domain": rp_d,
        "reply_to_domain": rt_d,
        "url_domains": url_domains,
        "esp_envelope": esp_envelope,
        "consistent": related and bool(from_d),
        "reasons": reasons,
    }
