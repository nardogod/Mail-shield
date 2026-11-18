"""URL extract / defang tests."""

from __future__ import annotations

from pathlib import Path

from mailshieldv1 import analyze
from mailshieldv1.cli import main
from mailshieldv1.core.urls import defang_url

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "phishing" / "replyto_mismatch.eml"


def test_defang() -> None:
    assert defang_url("https://evil.example/a") == "hxxps[://]evil[.]example/a"
    assert defang_url("http://evil.example") == "hxxp[://]evil[.]example"
    nested = defang_url("https://a.example/?next=https://b.example")
    assert "https://" not in nested
    assert "hxxps[://]b[.]example" in nested


def test_extract_from_sample() -> None:
    report = analyze(SAMPLE.read_bytes())
    assert report.urls
    assert any("192.0.2.10" in u for u in report.urls)
    assert all("[.]" in u for u in report.urls_defanged)
    assert any(f.rule_id == "URL-IP-LITERAL" for f in report.findings)


def test_cli_urls_format(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    code = main([str(SAMPLE), "-f", "urls"])
    assert code == 0
    out = tmp_path / "reports" / "replyto_mismatch.txt"
    text = out.read_text(encoding="utf-8")
    assert "hxxp" in text
    assert "https://" not in text
    assert "wrote" in capsys.readouterr().err
