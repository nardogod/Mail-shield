"""CLI smoke tests."""

from __future__ import annotations

from pathlib import Path

from mailshieldv1.cli import main

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "benign" / "simple_auth_pass.eml"


def test_cli_default_writes_reports(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    code = main([str(SAMPLE)])
    assert code == 0
    out = tmp_path / "reports" / "simple_auth_pass.html"
    assert out.is_file()
    assert "mailshieldv1" in out.read_text(encoding="utf-8")
    assert "wrote" in capsys.readouterr().err


def test_cli_json_override(tmp_path: Path, capsys) -> None:
    out = tmp_path / "report.json"
    code = main([str(SAMPLE), "-f", "json", "-o", str(out)])
    assert code == 0
    assert "verdict" in out.read_text(encoding="utf-8")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "wrote" in captured.err


def test_cli_stdout_dash(tmp_path: Path, capsys) -> None:
    code = main([str(SAMPLE), "-f", "json", "-o", "-"])
    assert code == 0
    assert "verdict" in capsys.readouterr().out


def test_cli_missing_file() -> None:
    code = main(["C:/definitely/missing/mailshieldv1.eml"])
    assert code == 2
