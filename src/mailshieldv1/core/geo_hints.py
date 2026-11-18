"""Offline hop location hints from IPs + known provider host/region tokens.

No network lookups. City/country for arbitrary public IPs requires a local
GeoIP database (not bundled); without it we still always emit structured
fields and classify private vs public.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass

# AWS region tokens frequently appear in SES / SMTP hostnames.
_AWS_REGIONS: dict[str, tuple[str, str]] = {
    "sa-east-1": ("Brazil", "São Paulo"),
    "us-east-1": ("United States", "Ashburn / N. Virginia"),
    "us-east-2": ("United States", "Ohio"),
    "us-west-1": ("United States", "N. California"),
    "us-west-2": ("United States", "Oregon"),
    "eu-west-1": ("Ireland", "Dublin"),
    "eu-west-2": ("United Kingdom", "London"),
    "eu-west-3": ("France", "Paris"),
    "eu-central-1": ("Germany", "Frankfurt"),
    "eu-north-1": ("Sweden", "Stockholm"),
    "ap-southeast-1": ("Singapore", "Singapore"),
    "ap-southeast-2": ("Australia", "Sydney"),
    "ap-northeast-1": ("Japan", "Tokyo"),
    "ap-northeast-2": ("South Korea", "Seoul"),
    "ap-south-1": ("India", "Mumbai"),
    "ca-central-1": ("Canada", "Montreal"),
}

# Microsoft 365 / Exchange Online footprint tokens in hostnames.
_M365_FOOTPRINTS: dict[str, tuple[str, str]] = {
    "namprd": ("United States", "Microsoft 365 North America"),
    "eurprd": ("Europe", "Microsoft 365 Europe"),
    "apcprd": ("Asia-Pacific", "Microsoft 365 Asia-Pacific"),
    "lamprd": ("Latin America", "Microsoft 365 Latin America"),
    "auprd": ("Australia", "Microsoft 365 Australia"),
    "canprd": ("Canada", "Microsoft 365 Canada"),
    "indprd": ("India", "Microsoft 365 India"),
    "jpnprd": ("Japan", "Microsoft 365 Japan"),
}

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b")
_AWS_TOKEN = re.compile(
    r"\b([a-z]{2}(?:-[a-z]+)+-\d)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class GeoHint:
    ip: str
    ip_scope: str  # none | private | loopback | linklocal | public
    country: str
    city: str
    label: str
    source: str  # none | rfc1918 | aws-region | m365-region | unknown-public

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def extract_ips(text: str) -> list[str]:
    """Return validated IPs found in a Received line (order preserved, unique)."""
    found: list[str] = []
    seen: set[str] = set()
    for match in list(_IPV4.finditer(text)) + list(_IPV6.finditer(text)):
        token = match.group(0)
        try:
            ip = str(ipaddress.ip_address(token))
        except ValueError:
            continue
        if ip not in seen:
            seen.add(ip)
            found.append(ip)
    return found


def _scope(ip: str) -> str:
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return "none"
    if obj.is_loopback:
        return "loopback"
    if obj.is_link_local:
        return "linklocal"
    if obj.is_multicast:
        return "non_global"
    if obj.is_private:
        # Includes RFC1918 and (on some Python builds) documentation ranges.
        return "private"
    # Reserved / benchmark / other non-global — not a public geo signal.
    if obj.is_reserved or not obj.is_global:
        return "non_global"
    return "public"


def _pick_ip(ips: list[str]) -> str:
    """Prefer a public IP when present (typical 'from' client address)."""
    for ip in ips:
        if _scope(ip) == "public":
            return ip
    return ips[0] if ips else ""


def _from_aws(haystack: str) -> tuple[str, str] | None:
    for match in _AWS_TOKEN.finditer(haystack):
        key = match.group(1).lower()
        if key in _AWS_REGIONS:
            return _AWS_REGIONS[key]
    return None


def _from_m365(haystack: str) -> tuple[str, str] | None:
    lower = haystack.lower()
    for token, pair in _M365_FOOTPRINTS.items():
        if token in lower:
            return pair
    if "protection.outlook.com" in lower or "mail.protection.outlook.com" in lower:
        return ("Unknown", "Microsoft 365 Edge / Protection")
    if "outlook.com" in lower or "office365.com" in lower:
        return ("Unknown", "Microsoft 365 / Outlook")
    return None


def hint_for_hop(*, from_host: str, by_host: str, raw: str) -> GeoHint:
    """Always returns a GeoHint (possibly unknown) — offline only."""
    ips = extract_ips(raw)
    ip = _pick_ip(ips)
    scope = _scope(ip) if ip else "none"
    haystack = f"{from_host} {by_host} {raw}".lower()

    if scope in {"private", "loopback", "linklocal"}:
        return GeoHint(
            ip=ip,
            ip_scope=scope,
            country="",
            city="",
            label="Private / internal network",
            source="rfc1918",
        )
    if scope == "non_global":
        return GeoHint(
            ip=ip,
            ip_scope=scope,
            country="",
            city="",
            label="Non-global / special-use IP (not a public geo signal)",
            source="special-use",
        )

    aws = _from_aws(haystack)
    if aws:
        country, city = aws
        return GeoHint(
            ip=ip,
            ip_scope=scope or "none",
            country=country,
            city=city,
            label=f"{city}, {country}",
            source="aws-region",
        )

    m365 = _from_m365(haystack)
    if m365:
        country, city = m365
        label = f"{city}, {country}" if country != "Unknown" else city
        return GeoHint(
            ip=ip,
            ip_scope=scope or "none",
            country="" if country == "Unknown" else country,
            city=city,
            label=label,
            source="m365-region",
        )

    if ip and scope == "public":
        return GeoHint(
            ip=ip,
            ip_scope=scope,
            country="",
            city="",
            label="Public IP — country/city unknown (offline; no GeoIP DB)",
            source="unknown-public",
        )

    return GeoHint(
        ip=ip,
        ip_scope=scope,
        country="",
        city="",
        label="Location unknown",
        source="none",
    )
