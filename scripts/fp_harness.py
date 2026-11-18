#!/usr/bin/env python3
"""False-positive harness for benign / marketing mail.

Exit 0 if every labeled benign sample stays at verdict info|low.
Exit 1 if any sample scores medium+ (potential FP).

Usage:
  python scripts/fp_harness.py
  python scripts/fp_harness.py samples/benign samples/phishing/3.eml
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mailshieldv1 import analyze  # noqa: E402

DEFAULT_PATHS = [
    ROOT / "samples" / "benign",
    ROOT / "samples" / "phishing" / "3.eml",  # authenticated marketing (CPF) — must stay soft
]
MAX_OK = {"info", "low"}


def _emls(paths: list[Path]) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        p = p.resolve()
        if p.is_file() and p.suffix.lower() == ".eml":
            out.append(p)
        elif p.is_dir():
            out.extend(sorted(p.rglob("*.eml")))
    return out


def main(argv: list[str] | None = None) -> int:
    args = [Path(a) for a in (argv or sys.argv[1:])] or DEFAULT_PATHS
    files = _emls(args)
    if not files:
        print("error: no .eml inputs", file=sys.stderr)
        return 2

    rows = []
    fps = []
    for path in files:
        report = analyze(path.read_bytes(), online=False)
        row = {
            "file": str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path),
            "verdict": report.verdict,
            "score": report.score,
            "families": report.score_families,
            "rules": [f.rule_id for f in report.findings if f.severity != "info"],
        }
        rows.append(row)
        ok = report.verdict in MAX_OK
        mark = "OK " if ok else "FP!"
        print(f"{mark}  {row['verdict']:8} {row['score']:5.1f}  {row['file']}")
        if not ok:
            fps.append(row)

    summary = {
        "schema": "mailshieldv1.fp_harness.v1",
        "total": len(rows),
        "false_positives": len(fps),
        "fp_rate": round(len(fps) / max(len(rows), 1), 4),
        "results": rows,
    }
    out = ROOT / "reports" / "fp_harness.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {out}")
    print(f"FP {len(fps)}/{len(rows)} ({summary['fp_rate']:.1%})")
    return 1 if fps else 0


if __name__ == "__main__":
    raise SystemExit(main())
