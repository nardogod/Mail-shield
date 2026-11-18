"""IMAP pull ingest (level 2) — mocked, no network."""

from __future__ import annotations

from pathlib import Path

import pytest

from mailshieldv1.ingest import imap_pull

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "benign" / "simple_auth_pass.eml"


class _FakeIMAP:
    def __init__(self, raw: bytes) -> None:
        self._raw = raw
        self.logged_out = False
        self.flags: list[tuple[bytes, str]] = []

    def login(self, user: str, password: str) -> tuple[str, list]:
        assert user and password
        return ("OK", [b"Logged in"])

    def select(self, mailbox: str, readonly: bool = False) -> tuple[str, list]:
        return ("OK", [b"1"])

    def search(self, charset, criteria: str) -> tuple[str, list]:
        return ("OK", [b"1"])

    def fetch(self, num, what: str):
        return ("OK", [(b"1 (RFC822 {n})", self._raw)])

    def store(self, num, op: str, flags: str) -> tuple[str, list]:
        self.flags.append((num, flags))
        return ("OK", [])

    def logout(self) -> tuple[str, list]:
        self.logged_out = True
        return ("OK", [])


def test_pull_and_analyze_mocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    raw = SAMPLE.read_bytes()
    fake = _FakeIMAP(raw)

    def _connect(**kwargs):  # noqa: ANN003
        return fake

    monkeypatch.setattr(imap_pull, "_connect", _connect)

    save = tmp_path / "eml"
    reports = tmp_path / "reports"
    rows = imap_pull.pull_and_analyze(
        host="imap.example.com",
        user="u@example.com",
        password="secret",
        save_dir=save,
        reports_dir=reports,
        fmt="siem",
        quiet=True,
        mark_seen=True,
    )
    assert len(rows) == 1
    assert list(save.glob("*.eml"))
    assert list(reports.glob("*.siem.json"))
    assert fake.logged_out
    assert fake.flags


def test_password_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MAILSHIELD_IMAP_PASSWORD", "x")
    assert imap_pull.password_from_env("MAILSHIELD_IMAP_PASSWORD") == "x"
    monkeypatch.delenv("MAILSHIELD_IMAP_PASSWORD", raising=False)
    with pytest.raises(RuntimeError):
        imap_pull.password_from_env("MAILSHIELD_IMAP_PASSWORD")
