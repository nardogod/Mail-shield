"""Watched-folder ingest (level 1)."""

from __future__ import annotations

from pathlib import Path

from mailshieldv1.cli import main
from mailshieldv1.ingest.pipeline import batch_index_dir
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
        settle=0,
    )
    assert len(rows) == 1
    assert rows[0]["verdict"] in {"info", "low"}
    assert list(reports.glob("*.siem.json"))

    # Second scan should skip unchanged file
    rows2 = scan_once(watch, fmt="siem", reports_dir=reports, quiet=True, settle=0)
    assert rows2 == []


def test_scan_once_defers_unstable_file(tmp_path: Path, monkeypatch) -> None:
    watch = tmp_path / "drop"
    watch.mkdir()
    (watch / "growing.eml").write_bytes(b"partial")
    reports = tmp_path / "reports"
    calls = {"n": 0}

    def _flip(path: Path) -> str:
        calls["n"] += 1
        # Initial fp + first stable sample share a value; second sample differs.
        if calls["n"] <= 2:
            return "1:7"
        return "2:14"

    monkeypatch.setattr("mailshieldv1.ingest.watch._fingerprint", _flip)
    rows = scan_once(
        watch,
        fmt="siem",
        reports_dir=reports,
        quiet=True,
        process_existing=True,
        settle=0.01,
    )
    assert rows == []
    assert not list(reports.glob("*.siem.json"))


def test_batch_index_dir_outdir_semantics(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    out = tmp_path / "dest"
    assert batch_index_dir(out, reports) == out  # not created yet, no suffix
    file_out = tmp_path / "one.siem.json"
    assert batch_index_dir(file_out, reports) == tmp_path
    existing = tmp_path / "exists"
    existing.mkdir()
    assert batch_index_dir(existing, reports) == existing


def test_watch_batch_index_missing_outdir(tmp_path: Path) -> None:
    watch = tmp_path / "drop"
    watch.mkdir()
    (watch / "msg.eml").write_bytes(SAMPLE.read_bytes())
    out = tmp_path / "outdir"
    rows = scan_once(
        watch,
        fmt="siem",
        output=out,
        reports_dir=tmp_path / "reports",
        quiet=True,
        process_existing=True,
        settle=0,
    )
    assert len(rows) == 1
    assert (out / "batch_index.siem.json").is_file()


def test_cli_watch_once(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    watch = tmp_path / "inbox"
    watch.mkdir()
    (watch / "a.eml").write_bytes(SAMPLE.read_bytes())
    code = main(["watch", str(watch), "--once", "--process-existing", "--quiet"])
    assert code == 0
    assert list((tmp_path / "reports").glob("*.siem.json"))
