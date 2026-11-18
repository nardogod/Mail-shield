"""Level 1: watch a folder for new .eml files and analyze them."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

from mailshieldv1.ingest.pipeline import (
    DEFAULT_REPORTS_DIR,
    analyze_and_write,
    write_batch_index,
)


def _state_path(watch_dir: Path) -> Path:
    return watch_dir / ".mailshield_watch_state.json"


def _load_state(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"processed": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"processed": {}}
    if not isinstance(data, dict):
        return {"processed": {}}
    data.setdefault("processed", {})
    return data


def _save_state(path: Path, state: dict[str, Any]) -> None:
    path.write_text(json.dumps(state, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _fingerprint(path: Path) -> str:
    st = path.stat()
    return f"{st.st_mtime_ns}:{st.st_size}"


def scan_once(
    watch_dir: Path,
    *,
    fmt: str = "siem",
    output: Path | None = None,
    reports_dir: Path = DEFAULT_REPORTS_DIR,
    online: bool = False,
    online_timeout: float = 8.0,
    quiet: bool = False,
    process_existing: bool = False,
) -> list[dict[str, Any]]:
    """Process new (or all) .eml files under watch_dir once."""
    watch_dir = watch_dir.expanduser().resolve()
    if not watch_dir.is_dir():
        raise FileNotFoundError(f"not a directory: {watch_dir}")

    state_file = _state_path(watch_dir)
    state = _load_state(state_file)
    processed: dict[str, str] = dict(state.get("processed") or {})
    rows: list[dict[str, Any]] = []

    for path in sorted(watch_dir.rglob("*.eml")):
        if path.name.startswith("."):
            continue
        key = str(path.resolve())
        fp = _fingerprint(path)
        if not process_existing and processed.get(key) == fp:
            continue
        try:
            row = analyze_and_write(
                path,
                fmt=fmt,
                output=output,
                reports_dir=reports_dir,
                online=online,
                online_timeout=online_timeout,
                quiet=quiet,
            )
        except (OSError, RuntimeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            continue
        processed[key] = fp
        rows.append(row)

    state["processed"] = processed
    _save_state(state_file, state)
    if rows:
        write_batch_index(rows, output if output and output.is_dir() else reports_dir)
    return rows


def watch_loop(
    watch_dir: Path,
    *,
    interval: float = 5.0,
    once: bool = False,
    fmt: str = "siem",
    output: Path | None = None,
    reports_dir: Path = DEFAULT_REPORTS_DIR,
    online: bool = False,
    online_timeout: float = 8.0,
    quiet: bool = False,
    process_existing: bool = False,
) -> int:
    """Poll watch_dir for new .eml files. Ctrl+C to stop."""
    watch_dir = watch_dir.expanduser().resolve()
    print(
        f"watching {watch_dir} every {interval:.1f}s → reports as {fmt}",
        file=sys.stderr,
    )
    first = True
    try:
        while True:
            rows = scan_once(
                watch_dir,
                fmt=fmt,
                output=output,
                reports_dir=reports_dir,
                online=online,
                online_timeout=online_timeout,
                quiet=quiet,
                process_existing=process_existing and first,
            )
            if rows:
                print(f"processed {len(rows)} new message(s)", file=sys.stderr)
            first = False
            if once:
                return 0
            time.sleep(max(1.0, interval))
    except KeyboardInterrupt:
        print("stopped", file=sys.stderr)
        return 0
