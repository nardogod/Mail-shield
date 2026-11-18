"""Parse Received headers into a hop path. No network. Forgery-aware."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from email.message import EmailMessage
from typing import Any

from mailshieldv1.core.geo_hints import GeoHint, hint_for_hop

# Cap to bound work on header bombs.
MAX_HOPS = 50
MAX_RAW_CHARS = 500

_FROM = re.compile(r"\bfrom\s+(\S+)", re.IGNORECASE)
_BY = re.compile(r"\bby\s+(\S+)", re.IGNORECASE)
_WITH = re.compile(r"\bwith\s+(\S+)", re.IGNORECASE)


@dataclass(frozen=True)
class Hop:
    """One Received line. index 0 = newest (top header, closest to mailbox)."""

    index: int
    from_host: str
    by_host: str
    with_protocol: str
    raw: str
    ip: str = ""
    ip_scope: str = "none"
    country: str = ""
    city: str = ""
    geo_label: str = ""
    geo_source: str = "none"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _clean_token(token: str) -> str:
    return token.strip().strip("();,").lower()


def _apply_geo(index: int, from_host: str, by_host: str, with_protocol: str, raw: str) -> Hop:
    geo: GeoHint = hint_for_hop(from_host=from_host, by_host=by_host, raw=raw)
    return Hop(
        index=index,
        from_host=from_host,
        by_host=by_host,
        with_protocol=with_protocol,
        raw=raw,
        ip=geo.ip,
        ip_scope=geo.ip_scope,
        country=geo.country,
        city=geo.city,
        geo_label=geo.label,
        geo_source=geo.source,
    )


def parse_hops(msg: EmailMessage) -> list[Hop]:
    """Return hops newest-first (email Received prepending order)."""
    headers = msg.get_all("Received", []) or []
    hops: list[Hop] = []
    for i, raw in enumerate(headers[:MAX_HOPS]):
        text = " ".join(str(raw).split())
        from_m = _FROM.search(text)
        by_m = _BY.search(text)
        with_m = _WITH.search(text)
        hops.append(
            _apply_geo(
                i,
                _clean_token(from_m.group(1)) if from_m else "",
                _clean_token(by_m.group(1)) if by_m else "",
                _clean_token(with_m.group(1)) if with_m else "",
                text[:MAX_RAW_CHARS],
            )
        )
    return hops
