"""Safe extraction of visible email body text for rule matching."""

from __future__ import annotations

import re
from email.message import EmailMessage
from html.parser import HTMLParser

from mailshieldv1.core.urls import MAX_TEXT_CHARS, walk_body_text

_TAG_RE = re.compile(r"<[^>]+>")


class _VisibleText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in {"script", "style"}:
            self._skip = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style"}:
            self._skip = False

    def handle_data(self, data: str) -> None:
        if not self._skip and data.strip():
            self.parts.append(data)


def visible_body_text(msg: EmailMessage) -> str:
    """Return plain-ish body text (HTML tags stripped). Bounded length."""
    raw = walk_body_text(msg)
    if "<" in raw and ">" in raw:
        parser = _VisibleText()
        try:
            parser.feed(raw)
            parser.close()
            text = " ".join(parser.parts)
        except (AssertionError, ValueError, TypeError):
            text = _TAG_RE.sub(" ", raw)
    else:
        text = raw
    text = re.sub(r"\s+", " ", text).strip()
    return text[:MAX_TEXT_CHARS]
