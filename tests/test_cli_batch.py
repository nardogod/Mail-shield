"""CLI batch directory + siem format."""

from __future__ import annotations

from pathlib import Path

from mailshieldv1.cli import main

ROOT = Path(__file__).resolve().parents[1]
BENIGN_DIR = ROOT / "samples" / "benign"


def test_cli_batch_directory(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    code = main([str(BENIGN_DIR), "-f", "siem"])
    assert code == 0
    err = capsys.readouterr().err
    assert "batch:" in err
    reports = list((tmp_path / "reports").glob("*.siem.json"))
    assert len(reports) >= 3
    assert (tmp_path / "reports" / "batch_index.siem.json").is_file()


def test_cli_summary_three_lines(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    sample = BENIGN_DIR / "simple_auth_pass.eml"
    code = main([str(sample), "-f", "json"])
    assert code == 0
    err = capsys.readouterr().err
    assert "verdict=" in err
    assert "auth=spf:" in err
