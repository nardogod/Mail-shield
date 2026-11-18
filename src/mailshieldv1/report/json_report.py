"""JSON renderers (full report + SIEM-stable)."""

from __future__ import annotations

import json

from mailshieldv1.core.models import Report
from mailshieldv1.report.pivots import pivots_as_dicts


def to_json(report: Report, *, indent: int = 2) -> str:
    data = report.to_dict()
    data["analyst_pivots"] = pivots_as_dicts(report.from_addr, report.urls)
    return json.dumps(data, indent=indent, ensure_ascii=False) + "\n"


def to_siem_json(report: Report, *, indent: int | None = None) -> str:
    """Compact stable schema for SIEM pipelines (mailshieldv1.siem.v1)."""
    return json.dumps(report.to_siem_dict(), indent=indent, ensure_ascii=False) + "\n"
