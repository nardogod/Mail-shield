"""Core models, limits, and parser."""

from mailshieldv1.core.limits import DEFAULT_LIMITS, LimitExceeded, Limits
from mailshieldv1.core.models import Finding, Report, Severity
from mailshieldv1.core.parser import parse_eml

__all__ = [
    "DEFAULT_LIMITS",
    "Finding",
    "LimitExceeded",
    "Limits",
    "Report",
    "Severity",
    "parse_eml",
]
