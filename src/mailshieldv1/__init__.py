"""mailshieldv1 — local deterministic email analysis engine."""

from mailshieldv1.core.models import Finding, Report, Severity
from mailshieldv1.core.urls import defang_url
from mailshieldv1.engine import analyze
from mailshieldv1.report import to_html, to_json, to_siem_json

__all__ = [
    "Finding",
    "Report",
    "Severity",
    "analyze",
    "defang_url",
    "to_html",
    "to_json",
    "to_siem_json",
]
__version__ = "0.1.0"
