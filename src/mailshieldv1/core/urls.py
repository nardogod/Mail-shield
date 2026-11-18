"""Extract and defang URLs from email content. No network fetches."""

from __future__ import annotations

import re
from email.message import EmailMessage
from html.parser import HTMLParser

# Cap extraction to bound CPU/memory on hostile messages.
MAX_URLS = 200
MAX_TEXT_CHARS = 1_000_000

_URL_RE = re.compile(
    r"(?i)\b(?:https?://|www\.)[^\s<>\"'\)\]]+"
)


class _LinkCollector(HTMLParser):
    """Collect href and img/src without dropping any http(s) references."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.refs: list[tuple[str, str]] = []  # (url, source)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_l = tag.lower()
        attr_map = {k.lower(): (v or "").strip() for k, v in attrs}
        if tag_l == "a" and attr_map.get("href"):
            self.refs.append((attr_map["href"], "href"))
        if tag_l in {"img", "image"} and attr_map.get("src"):
            self.refs.append((attr_map["src"], "img"))


def defang_url(url: str) -> str:
    """SOC-style defang so links are not clickable in chats/tickets."""
    u = url.strip()
    u = re.sub(r"(?i)https://", "hxxps[://]", u)
    u = re.sub(r"(?i)http://", "hxxp[://]", u)
    if re.match(r"(?i)^www\.", u):
        u = "hxxp[://]" + u
    return u.replace(".", "[.]").replace("@", "[@]")


def _trim_url(url: str) -> str:
    return url.rstrip(".,;:!?)]}>\"'")


def walk_body_text(msg: EmailMessage) -> str:
    chunks: list[str] = []
    total = 0
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        ctype = part.get_content_type()
        if ctype not in {"text/plain", "text/html"}:
            continue
        try:
            text = part.get_content()
        except (KeyError, TypeError, ValueError, LookupError, UnicodeError):
            continue
        if not isinstance(text, str):
            continue
        if total >= MAX_TEXT_CHARS:
            break
        remain = MAX_TEXT_CHARS - total
        piece = text[:remain]
        chunks.append(piece)
        total += len(piece)
    return "\n".join(chunks)


def extract_urls_with_sources(msg: EmailMessage) -> tuple[list[str], dict[str, str]]:
    """Return unique URLs (order preserved) and best-effort source map.

    Sources: href | img | body_text. Nothing is filtered out for being a pixel.
    """
    text = walk_body_text(msg)
    found: list[str] = []
    seen: set[str] = set()
    sources: dict[str, str] = {}

    def add(raw: str, source: str) -> None:
        if len(found) >= MAX_URLS:
            return
        url = _trim_url(raw)
        if not url or url in seen:
            # Prefer img/href over body_text if seen again.
            if url in sources and sources[url] == "body_text" and source != "body_text":
                sources[url] = source
            return
        low = url.lower()
        if low.startswith(("mailto:", "cid:", "javascript:", "data:")):
            return
        if not (low.startswith(("http://", "https://", "www."))):
            return
        seen.add(url)
        found.append(url)
        sources[url] = source

    parser = _LinkCollector()
    try:
        parser.feed(text)
        parser.close()
    except (AssertionError, ValueError, TypeError):
        parser.refs = []
    for href, source in parser.refs:
        add(href, source)

    for match in _URL_RE.finditer(text):
        add(match.group(0), "body_text")
        if len(found) >= MAX_URLS:
            break

    return found, sources


def extract_urls(msg: EmailMessage) -> list[str]:
    """Return unique URLs found in text/html bodies (order preserved). No fetching."""
    urls, _sources = extract_urls_with_sources(msg)
    return urls


def extract_defanged_urls(msg: EmailMessage) -> list[str]:
    return [defang_url(u) for u in extract_urls(msg)]
