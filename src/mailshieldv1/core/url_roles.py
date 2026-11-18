"""Classify extracted URLs by likely sender purpose. Nothing is dropped."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from urllib.parse import urlparse

from mailshieldv1.core.urls import defang_url

_TRACKING_PATH = re.compile(
    r"(?i)("
    r"/track(?:ing)?/|/pixel|/open(?:ed)?|/click|/beacon|"
    r"/email/customer/tracking|/wf/open|/rhx|/ga\.js|"
    r"open\.gif|pixel\.(?:gif|png)|1x1|spacer\.(?:gif|png)"
    r")"
)
# ESP click wrappers in <a href> are CTAs (tracked redirects), not open-pixels.
_CLICK_REDIRECT = re.compile(
    r"(?i)(/ls/click|/wf/click|/click(?:ed)?(?:/|\?)|/c/|/ss/c/)"
)
_OPEN_BEACON = re.compile(
    r"(?i)(/wf/open|/open(?:ed)?(?:/|\?)|/pixel|/beacon|/track(?:ing)?/|"
    r"/email/customer/tracking|open\.gif|pixel\.(?:gif|png)|1x1|spacer\.(?:gif|png))"
)
_UNSUB = re.compile(
    r"(?i)(unsubscribe|opt[-_]?out|preference|list-remove|descadastr)"
)
_CTA = re.compile(
    r"(?i)("
    r"/login|/signin|/account|/verify|/confirm|/secure|"
    r"/pay(?:ment)?|/wire|/portal|/checkout|/invoice|"
    r"/subscription|/atualizar|/negoci|acordo|boleto|cpf"
    r")"
)
_MEDIA_EXT = re.compile(r"(?i)\.(png|jpe?g|gif|webp|svg|css|woff2?)(?:\?|$)")
_MARKUP_HOSTS = frozenset({"w3.org", "www.w3.org", "schema.org", "www.schema.org"})


@dataclass(frozen=True)
class UrlItem:
    url: str
    defanged: str
    role: str
    role_title: str
    sender_purpose: str
    source: str  # href | img | body_text

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


_ROLE_META: dict[str, tuple[str, str]] = {
    "tracking_pixel": (
        "Tracking / telemetry",
        "Likely used by the sender to see if the message was opened or a link was hit "
        "(campaign analytics). Usually not meant as a human click target.",
    ),
    "unsubscribe": (
        "Unsubscribe / preferences",
        "Lets the recipient leave the list or change preferences. Also helps the sender "
        "stay compliant and keep the mailing list clean.",
    ),
    "cta_action": (
        "Call to action",
        "Pushes the recipient to do something valuable to the sender "
        "(login, pay, verify identity, open a portal, negotiate debt, etc.).",
    ),
    "media_asset": (
        "Image / layout asset",
        "Loads branding or layout (logo, banner, icon). Supports how the message looks; "
        "may also double as a tracking beacon if hosted on a tracking domain.",
    ),
    "markup_namespace": (
        "HTML / markup namespace",
        "Not a user-facing link. Comes from HTML boilerplate (e.g. xmlns). "
        "The sender did not intend this as a destination for the reader.",
    ),
    "other": (
        "Other / unclassified",
        "No strong offline pattern matched. Still keep it — review context in the message.",
    ),
}


def classify_url(url: str, *, source: str = "body_text") -> UrlItem:
    raw = url if "://" in url else f"http://{url}"
    try:
        parsed = urlparse(raw)
        host = (parsed.hostname or "").lower()
        path_q = f"{parsed.path}?{parsed.query}"
    except ValueError:
        # Malformed bracketed hosts / junk URLs in phishing corpora.
        title, purpose = _ROLE_META["other"]
        return UrlItem(
            url=url,
            defanged=defang_url(url),
            role="other",
            role_title=title,
            sender_purpose=purpose,
            source=source,
        )
    hay = f"{host}{path_q}"

    if host in _MARKUP_HOSTS or hay.startswith("www.w3.org/") or "/1999/xhtml" in hay:
        role = "markup_namespace"
    elif source == "img":
        if _OPEN_BEACON.search(hay) or _TRACKING_PATH.search(hay) or "tracking" in hay:
            role = "tracking_pixel"
        else:
            role = "media_asset"
    elif _UNSUB.search(hay):
        role = "unsubscribe"
    elif source in {"href", "body_text"} and _CLICK_REDIRECT.search(hay):
        # SendGrid/Zenvia-style click wrappers are the real call-to-action target.
        role = "cta_action"
    elif _OPEN_BEACON.search(hay) or (
        _TRACKING_PATH.search(hay) and not _CLICK_REDIRECT.search(hay)
    ):
        role = "tracking_pixel"
    elif _CTA.search(hay):
        role = "cta_action"
    elif _MEDIA_EXT.search(parsed.path or ""):
        role = "media_asset"
    else:
        role = "other"

    # Open beacons always win; click redirects in href stay CTA.
    if _OPEN_BEACON.search(hay) or "/tracking/" in hay.lower():
        if not (source in {"href", "body_text"} and _CLICK_REDIRECT.search(hay)):
            role = "tracking_pixel"

    title, purpose = _ROLE_META[role]
    return UrlItem(
        url=url,
        defanged=defang_url(url),
        role=role,
        role_title=title,
        sender_purpose=purpose,
        source=source,
    )


def classify_urls(
    urls: list[str],
    *,
    sources: dict[str, str] | None = None,
) -> list[UrlItem]:
    """Classify every URL; never drops entries."""
    srcmap = sources or {}
    return [classify_url(u, source=srcmap.get(u, "body_text")) for u in urls]


def group_by_role(items: list[UrlItem]) -> list[tuple[str, str, str, list[UrlItem]]]:
    """Return ordered groups: (role, title, purpose, items)."""
    order = [
        "cta_action",
        "tracking_pixel",
        "unsubscribe",
        "media_asset",
        "markup_namespace",
        "other",
    ]
    buckets: dict[str, list[UrlItem]] = {k: [] for k in order}
    for item in items:
        buckets.setdefault(item.role, []).append(item)
    out: list[tuple[str, str, str, list[UrlItem]]] = []
    for role in order:
        group = buckets.get(role) or []
        if not group:
            continue
        title, purpose = _ROLE_META[role]
        out.append((role, title, purpose, group))
    return out


def variant_key(url: str) -> str:
    """Group key: scheme + host + path (query/fragment ignored)."""
    raw = url if "://" in url else f"http://{url}"
    try:
        parsed = urlparse(raw)
        scheme = (parsed.scheme or "http").lower()
        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"
    except ValueError:
        return raw.lower()[:200]
    return f"{scheme}://{host}{path}"


def group_url_variants(items: list[UrlItem]) -> list[dict]:
    """Collapse query-string clones; keep members (not dropped)."""
    order: list[str] = []
    buckets: dict[str, list[UrlItem]] = {}
    for item in items:
        key = variant_key(item.url)
        if key not in buckets:
            order.append(key)
            buckets[key] = []
        buckets[key].append(item)
    groups: list[dict] = []
    for key in order:
        members = buckets[key]
        sample = members[0]
        groups.append(
            {
                "key": key,
                "count": len(members),
                "role": sample.role,
                "role_title": sample.role_title,
                "sender_purpose": sample.sender_purpose,
                "sample_defanged": sample.defanged,
                "members_defanged": [m.defanged for m in members],
            }
        )
    return groups
