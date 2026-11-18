"""Safe .eml parsing with size and structure limits. No network."""

from __future__ import annotations

import email
import email.policy
from email.message import EmailMessage, Message

from mailshieldv1.core.limits import DEFAULT_LIMITS, LimitExceeded, Limits


def _count_parts(msg: Message, limit: int, *, depth: int = 0, max_depth: int = 50) -> int:
    if depth > max_depth:
        raise LimitExceeded(f"message exceeds max_mime_depth={max_depth}")
    count = 1
    if msg.is_multipart():
        for part in msg.iter_parts():
            count += _count_parts(part, limit, depth=depth + 1, max_depth=max_depth)
            if count > limit:
                raise LimitExceeded(f"message exceeds max_parts={limit}")
    return count


def parse_eml(raw: bytes, limits: Limits = DEFAULT_LIMITS) -> EmailMessage:
    """Parse raw RFC822 bytes into an EmailMessage under hard limits."""
    if not isinstance(raw, bytes | bytearray):
        raise TypeError("raw email must be bytes")
    if len(raw) == 0:
        raise ValueError("empty email input")
    if len(raw) > limits.max_bytes:
        raise LimitExceeded(f"email exceeds max_bytes={limits.max_bytes}")

    header_end = raw.find(b"\r\n\r\n")
    if header_end < 0:
        header_end = raw.find(b"\n\n")
    header_size = len(raw) if header_end < 0 else header_end
    if header_size > limits.max_header_bytes:
        raise LimitExceeded(f"headers exceed max_header_bytes={limits.max_header_bytes}")

    # policy.default: modern UTF-8-friendly parsing; does not execute content.
    try:
        msg = email.message_from_bytes(bytes(raw), policy=email.policy.default)
    except RecursionError as exc:
        raise LimitExceeded(
            f"message exceeds safe MIME nesting (max_mime_depth={limits.max_mime_depth})"
        ) from exc
    if not isinstance(msg, EmailMessage):
        raise TypeError("parser did not return EmailMessage")
    try:
        _count_parts(msg, limits.max_parts, max_depth=limits.max_mime_depth)
    except RecursionError as exc:
        raise LimitExceeded(
            f"message exceeds safe MIME nesting (max_mime_depth={limits.max_mime_depth})"
        ) from exc
    return msg
