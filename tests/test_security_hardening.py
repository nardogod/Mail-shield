"""Hardening: IMAP TLS, Auth-Results top header, DNS timeout, MIME depth, batch -o."""

from __future__ import annotations

import email
import email.policy
import ssl
import time
from email.message import EmailMessage
from pathlib import Path

import pytest

from mailshieldv1.cli import main
from mailshieldv1.core.authresults import parse_auth_results
from mailshieldv1.core.limits import LimitExceeded, Limits
from mailshieldv1.core.parser import parse_eml
from mailshieldv1.ingest import imap_pull
from mailshieldv1.online import lookups


def test_imap_ssl_context_verifies_hostname() -> None:
    ctx = imap_pull.imap_ssl_context()
    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_imap_no_ssl_warns_cleartext(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    class _Fake:
        def login(self, *a):
            return ("OK", [])

        def select(self, *a, **k):
            return ("OK", [b"1"])

        def search(self, *a):
            return ("OK", [b""])

        def logout(self):
            return ("OK", [])

    monkeypatch.setattr(imap_pull, "_connect", lambda **k: _Fake())
    imap_pull.pull_and_analyze(
        host="imap.example.com",
        user="u@example.com",
        password="secret",
        ssl=False,
        save_dir=tmp_path / "eml",
        reports_dir=tmp_path / "reports",
        quiet=True,
    )
    err = capsys.readouterr().err
    assert "cleartext" in err.lower() or "no-ssl" in err.lower()


def test_auth_results_top_fail_beats_lower_pass() -> None:
    # First header in the file = topmost receiving-MTA header.
    raw = (
        b"Authentication-Results: mx.google.com; dkim=fail header.d=evil.test; "
        b"spf=fail smtp.mailfrom=evil.test\r\n"
        b"Authentication-Results: attacker.example; dkim=pass; spf=pass\r\n"
        b"From: a@evil.test\r\n\r\nbody\r\n"
    )
    parsed = email.message_from_bytes(raw, policy=email.policy.default)
    assert isinstance(parsed, EmailMessage)
    auth = parse_auth_results(parsed)
    assert auth.present
    assert auth.spf == "fail"
    assert auth.dkim == "fail"
    assert "attacker" not in auth.raw


def test_auth_results_authserv_id_filter() -> None:
    raw = (
        b"Authentication-Results: mx.google.com; spf=fail\r\n"
        b"Authentication-Results: other.example; spf=pass; dkim=pass\r\n"
        b"From: a@x.test\r\n\r\nbody\r\n"
    )
    parsed = email.message_from_bytes(raw, policy=email.policy.default)
    assert isinstance(parsed, EmailMessage)
    auth = parse_auth_results(parsed, authserv_id="mx.google.com")
    assert auth.spf == "fail"
    ignored = parse_auth_results(parsed, authserv_id="not-present.example")
    assert ignored.present is False


def test_auth_results_arc_fallback_only_without_ar() -> None:
    raw = (
        b"ARC-Authentication-Results: i=1; mx.google.com; spf=pass\r\n"
        b"From: a@x.test\r\n\r\nbody\r\n"
    )
    parsed = email.message_from_bytes(raw, policy=email.policy.default)
    assert isinstance(parsed, EmailMessage)
    auth = parse_auth_results(parsed)
    assert auth.present
    assert auth.spf == "pass"


def test_resolve_host_timeout_returns_quickly(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    def _slow(*_a, **_k):
        time.sleep(4.0)
        return []

    monkeypatch.setattr(socket, "getaddrinfo", _slow)
    t0 = time.perf_counter()
    result = lookups._resolve_host("slow.example", timeout=0.5)
    elapsed = time.perf_counter() - t0
    assert result["ok"] is False
    assert result["error"] == "timeout"
    assert elapsed < 1.5, f"timeout took {elapsed:.2f}s (expected ~0.5s)"


def test_deep_mime_raises_limit_exceeded() -> None:
    # Build nested multipart/mixed ~2000 deep (bytes).
    inner = b"Content-Type: text/plain\r\n\r\nhi\r\n"
    raw = inner
    for _ in range(2000):
        raw = (
            b"Content-Type: multipart/mixed; boundary=b\r\n\r\n"
            b"--b\r\n" + raw + b"\r\n--b--\r\n"
        )
    with pytest.raises(LimitExceeded):
        parse_eml(raw, limits=Limits(max_bytes=50 * 1024 * 1024, max_mime_depth=50))


def test_batch_rejects_file_output(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    root = Path(__file__).resolve().parents[1]
    benign = root / "samples" / "benign"
    out = tmp_path / "one.siem.json"
    code = main([str(benign), "-f", "siem", "-o", str(out)])
    assert code == 2
    assert "directory" in capsys.readouterr().err.lower()


def test_batch_quiet_still_writes_index(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    root = Path(__file__).resolve().parents[1]
    benign = root / "samples" / "benign"
    code = main([str(benign), "-f", "siem", "--quiet"])
    assert code == 0
    assert (tmp_path / "reports" / "batch_index.siem.json").is_file()


def test_watch_rejects_file_output(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    watch = tmp_path / "inbox"
    watch.mkdir()
    code = main(["watch", str(watch), "--once", "-o", str(tmp_path / "x.siem.json")])
    assert code == 2
    assert "directory" in capsys.readouterr().err.lower()
