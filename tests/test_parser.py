"""Parser and limit tests."""

from __future__ import annotations

import pytest

from mailshieldv1.core.limits import LimitExceeded, Limits
from mailshieldv1.core.parser import parse_eml


def test_parse_simple_message() -> None:
    raw = (
        b"From: a@example.com\r\n"
        b"To: b@example.com\r\n"
        b"Subject: hi\r\n"
        b"\r\n"
        b"body\r\n"
    )
    msg = parse_eml(raw)
    assert msg["Subject"] == "hi"
    assert msg.get_content().strip() == "body"


def test_reject_empty() -> None:
    with pytest.raises(ValueError):
        parse_eml(b"")


def test_reject_oversized_body() -> None:
    limits = Limits(max_bytes=64)
    with pytest.raises(LimitExceeded):
        parse_eml(b"From: a@example.com\r\n\r\n" + b"x" * 100, limits=limits)


def test_reject_oversized_headers() -> None:
    limits = Limits(max_header_bytes=32)
    raw = b"From: a@example.com\r\nX-Pad: " + b"A" * 64 + b"\r\n\r\nbody\r\n"
    with pytest.raises(LimitExceeded):
        parse_eml(raw, limits=limits)


def test_reject_non_bytes() -> None:
    with pytest.raises(TypeError):
        parse_eml("not-bytes")  # type: ignore[arg-type]
