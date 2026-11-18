"""Hard limits for untrusted email input (AppSec)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Limits:
    max_bytes: int = 5 * 1024 * 1024  # 5 MiB
    max_header_bytes: int = 256 * 1024
    max_parts: int = 200
    max_mime_depth: int = 50


DEFAULT_LIMITS = Limits()


class LimitExceeded(ValueError):
    """Raised when an input violates configured safety limits."""
