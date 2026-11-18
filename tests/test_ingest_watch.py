"""Watched-folder ingest (level 1)."""

from __future__ import annotations

from pathlib import Path

from mailshieldv1.cli import main
from mailshieldv1.ingest.watch import scan_once

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "benign" / "simple_auth_pass.eml"


def test_scan_once_processes_new_eml(tmp_path: Path) -> None:
    watch = tmp_path / "drop"
    watch.mkdir()
    target = watch / "msg.eml"
    target.write_bytes(SAMPLE.read_bytes())
    reports = tmp_path / "reports"

    rows = scan_once(
        watch,
        fmt="siem",
        reports_dir=reports,
        quiet=True,
        process_existing=True,
    )
    assert len(rows) == 1
    assert rows[0]["verdict"] in {"info", "low"}
    assert list(reports.glob("*.siem.json"))

    # Second scan should skip unchanged file
    rows2 = scan_once(watch, fmt="siem", reports_dir=reports, quiet=True)
    assert rows2 == []


def test_cli_watch_once(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    watch = tmp_path / "inbox"
    watch.mkdir()
    (watch / "a.eml").write_bytes(SAMPLE.read_bytes())
    code = main(["watch", str(watch), "--once", "--process-existing", "--quiet"])
    assert code == 0
    assert list((tmp_path / "reports").glob("*.siem.json"))
