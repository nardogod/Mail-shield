"""Built-in analyzers. Each exposes analyze(msg) -> list[Finding]."""

from mailshieldv1.analyzers import attachments, content, headers, hops, org, urls

DEFAULT_ANALYZERS = (
    headers.analyze,
    hops.analyze,
    urls.analyze,
    content.analyze,
    attachments.analyze,
    org.analyze,
)

__all__ = [
    "DEFAULT_ANALYZERS",
    "attachments",
    "content",
    "headers",
    "hops",
    "org",
    "urls",
]
