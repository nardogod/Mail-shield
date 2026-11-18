"""Shared ingest pipeline: .eml bytes/path → Report → report file + SIEM row."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

from mailshieldv1.core.limits import LimitExceeded
from mailshieldv1.engine import analyze
from mailshieldv1.report import to_html, to_json, to_siem_json
from mailshieldv1.report.plain_language import plain_verdict, top_plain_reasons

_SAFE_STEM = re.compile(r"[^A-Za-z0-9._-]+")
DEFAULT_REPORTS_DIR = Path("reports")


def safe_name(stem: str) -> str:
    cleaned = _SAFE_STEM.sub("_", stem).strip("._") or "report"
    return cleaned[:80]


def ext_for(fmt: str) -> str:
    if fmt == "siem":
        return "siem.json"
    return "txt" if fmt == "urls" else fmt


def default_report_path(eml: Path, fmt: str, *, reports_dir: Path = DEFAULT_REPORTS_DIR) -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    return (reports_dir / f"{safe_name(eml.stem)}.{ext_for(fmt)}").resolve()


def resolve_output(path: Path, eml: Path, fmt: str) -> Path:
    raw = path.expanduser()
    looks_dir = (
        str(path).endswith(("/", "\\"))
        or raw.is_dir()
        or (not raw.exists() and raw.suffix == "")
    )
    if looks_dir:
        raw.mkdir(parents=True, exist_ok=True)
        return (raw / f"{safe_name(eml.stem)}.{ext_for(fmt)}").resolve()
    raw.parent.mkdir(parents=True, exist_ok=True)
    return raw.resolve()


def render_report(report: Any, *, fmt: str, raw: bytes) -> str:
    if fmt == "html":
        return to_html(report, raw=raw)
    if fmt == "urls":
        return "\n".join(report.urls_defanged) + ("\n" if report.urls_defanged else "")
    if fmt == "siem":
        return to_siem_json(report, indent=None)
    return to_json(report)


def print_summary(report: Any, *, path: Path | None = None) -> None:
    title, why, action = plain_verdict(report)
    prefix = f"{path.name}: " if path else ""
    auth = report.auth or {}
    print(
        f"{prefix}{title}  (verdict={report.verdict} score={report.score})",
        file=sys.stderr,
    )
    print(f"  {why}", file=sys.stderr)
    top = top_plain_reasons(report, limit=2)
    if top:
        bits = "; ".join(reason for _rid, _sev, reason in top)
        print(f"  Why: {bits}", file=sys.stderr)
    else:
        print(f"  Next: {action}", file=sys.stderr)
    print(
        f"  auth=spf:{auth.get('spf')}/dkim:{auth.get('dkim')}/dmarc:{auth.get('dmarc')}",
        file=sys.stderr,
    )


def analyze_and_write(
    eml_path: Path,
    *,
    fmt: str = "siem",
    output: Path | None = None,
    reports_dir: Path = DEFAULT_REPORTS_DIR,
    online: bool = False,
    online_timeout: float = 8.0,
    authserv_id: str | None = None,
    quiet: bool = False,
    raw: bytes | None = None,
) -> dict[str, Any]:
    """Analyze one .eml and write a report. Returns a SIEM-ish summary row."""
    path = eml_path.expanduser().resolve()
    data = raw if raw is not None else path.read_bytes()
    try:
        report = analyze(
            data,
            online=online,
            online_timeout=online_timeout,
            authserv_id=authserv_id,
        )
    except (LimitExceeded, ValueError, TypeError, RuntimeError) as exc:
        raise RuntimeError(f"{path.name}: {exc}") from exc

    if not quiet:
        print_summary(report, path=path)

    text = render_report(report, fmt=fmt, raw=data)
    if output is not None and str(output) == "-":
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
        out_s = "-"
    elif output is None:
        out = default_report_path(path, fmt, reports_dir=reports_dir)
        out.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {out}", file=sys.stderr)
        out_s = str(out)
    else:
        out = resolve_output(output, path, fmt)
        out.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {out}", file=sys.stderr)
        out_s = str(out)

    return {
        "file": str(path),
        "report": out_s,
        "verdict": report.verdict,
        "score": report.score,
        "subject": report.subject,
        "from": report.from_addr,
        "message_id": report.message_id,
    }


def output_is_directory(output: Path) -> bool:
    """True when -o should be treated as a directory (batch-safe)."""
    op = output.expanduser()
    raw = str(output)
    if raw.endswith(("/", "\\")) or op.is_dir():
        return True
    if not op.exists() and op.suffix == "":
        return True
    return False


def batch_index_dir(
    output: Path | None,
    reports_dir: Path = DEFAULT_REPORTS_DIR,
) -> Path:
    """
    Directory for batch_index.siem.json.

    Treat as a directory when:
    - the path already exists as a directory, or
    - the original string ends with / or \\ (CLI ``-o reports/``), or
    - the path does not exist yet and has no suffix (``-o reports`` before mkdir).

    Otherwise use the parent (file output like ``-o out.siem.json``).
    """
    if output is None or str(output) == "-":
        return reports_dir
    op = output.expanduser()
    if output_is_directory(output):
        return op
    return op.parent

def require_batch_directory(output: Path | None) -> str | None:
    """
    Return an error message if batch/watch -o is a single file path.

    ``None`` means OK (default reports dir, stdout rejected elsewhere, or a directory).
    """
    if output is None:
        return None
    if str(output) == "-":
        return "batch/watch mode cannot write all reports to stdout (-)"
    if output_is_directory(output):
        return None
    return (
        f"batch/watch mode requires -o to be a directory "
        f"(got file path {output}); use a dir, trailing slash, or omit -o"
    )


def write_batch_index(rows: list[dict[str, Any]], index_dir: Path) -> Path:
    index_dir.mkdir(parents=True, exist_ok=True)
    index_path = (index_dir / "batch_index.siem.json").resolve()
    index_path.write_text(
        json.dumps({"schema": "mailshieldv1.batch.v1", "results": rows}, ensure_ascii=False)
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"wrote {index_path}", file=sys.stderr)
    return index_path
