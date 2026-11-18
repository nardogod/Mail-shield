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


def test_worst_result_wins_inside_same_header() -> None:
    raw = (
        b"Authentication-Results: mx.google.com; "
        b"dkim=fail header.d=a; dkim=pass header.d=b; "
        b"spf=pass; spf=fail; dmarc=pass; dmarc=fail\r\n"
        b"From: a@evil.test\r\n\r\nbody\r\n"
    )
    parsed = email.message_from_bytes(raw, policy=email.policy.default)
    assert isinstance(parsed, EmailMessage)
    auth = parse_auth_results(parsed, authserv_id="mx.google.com")
    assert auth.dkim == "fail"
    assert auth.spf == "fail"
    assert auth.dmarc == "fail"


def test_forged_single_attacker_pass_cannot_zero_bec() -> None:
    from mailshieldv1 import analyze

    raw = (
        b"Authentication-Results: attacker.example; "
        b"spf=pass; dkim=pass; dmarc=pass\r\n"
        b"From: CEO <ceo@victim.example>\r\n"
        b"To: finance@victim.example\r\n"
        b"Subject: Urgent wire transfer - keep confidential\r\n"
        b"\r\n"
        b"Please process the payment today and do not tell anyone.\r\n"
        b"Send the wire to the new account immediately.\r\n"
    )
    without = analyze(
        raw.replace(
            b"Authentication-Results: attacker.example; "
            b"spf=pass; dkim=pass; dmarc=pass\r\n",
            b"",
        )
    )
    forged = analyze(raw)
    assert forged.auth.get("trusted") is False
    assert forged.auth.get("strong_pass") is False
    assert forged.auth.get("weak") is True
    assert forged.verdict in {"high", "critical"}
    assert forged.score >= 8
    # Forged pass must not score better (lower) than no auth header.
    assert forged.score >= without.score - 0.5


def test_authserv_id_e2e_cli_and_analyze(tmp_path: Path, monkeypatch, capsys) -> None:
    from mailshieldv1 import analyze

    raw = (
        b"Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass\r\n"
        b"Authentication-Results: attacker.example; spf=fail; dkim=fail\r\n"
        b"From: a@example.com\r\nSubject: hi\r\n\r\nbody\r\n"
    )
    trusted = analyze(raw, authserv_id="mx.google.com")
    assert trusted.auth.get("trusted") is True
    assert trusted.auth.get("strong_pass") is True
    assert trusted.auth.get("spf") == "pass"

    ignored = analyze(raw, authserv_id="not-our-mx.example")
    assert ignored.auth.get("present") is False
    assert ignored.auth.get("strong_pass") is False

    monkeypatch.setenv("MAILSHIELD_AUTHSERV_ID", "mx.google.com")
    via_env = analyze(raw)
    assert via_env.auth.get("trusted") is True

    root = Path(__file__).resolve().parents[1]
    sample = root / "samples" / "benign" / "simple_auth_pass.eml"
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MAILSHIELD_AUTHSERV_ID", raising=False)
    code = main([str(sample), "-f", "json", "--authserv-id", "mx.example.com", "--quiet"])
    assert code == 0
    text = (tmp_path / "reports" / "simple_auth_pass.json").read_text(encoding="utf-8")
    assert '"trusted": true' in text.replace(" ", "") or '"trusted":true' in text.replace(" ", "")


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
