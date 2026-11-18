"""Level 2: IMAP pull → save .eml → analyze → SIEM/report."""

from __future__ import annotations

import email
import email.header
import imaplib
import os
import re
import ssl
import sys
from pathlib import Path
from typing import Any

from mailshieldv1.ingest.pipeline import (
    DEFAULT_REPORTS_DIR,
    analyze_and_write,
    batch_index_dir,
    safe_name,
    write_batch_index,
)

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _decode_header(value: str | None) -> str:
    if not value:
        return ""
    parts = email.header.decode_header(value)
    out: list[str] = []
    for chunk, charset in parts:
        if isinstance(chunk, bytes):
            out.append(chunk.decode(charset or "utf-8", errors="replace"))
        else:
            out.append(chunk)
    return "".join(out)


def _message_filename(raw: bytes, uid: str) -> str:
    try:
        msg = email.message_from_bytes(raw)
        subj = _decode_header(msg.get("Subject"))[:40] or "message"
        mid = (msg.get("Message-ID") or uid).strip("<>")
    except Exception:  # noqa: BLE001 — best-effort naming only
        subj, mid = "message", uid
    stem = safe_name(f"{uid}_{subj}_{mid}")[:80]
    return f"{stem}.eml"


def imap_ssl_context() -> ssl.SSLContext:
    """TLS context with hostname check + CERT_REQUIRED (default trust store)."""
    return ssl.create_default_context()


def _connect(
    *,
    host: str,
    port: int,
    user: str,
    password: str,
    ssl_enabled: bool = True,
) -> imaplib.IMAP4:
    if ssl_enabled:
        ctx = imap_ssl_context()
        client: imaplib.IMAP4 = imaplib.IMAP4_SSL(host, port, ssl_context=ctx)
    else:
        client = imaplib.IMAP4(host, port)
    client.login(user, password)
    return client


def pull_and_analyze(
    *,
    host: str,
    user: str,
    password: str,
    port: int = 993,
    ssl: bool = True,
    mailbox: str = "INBOX",
    criteria: str = "UNSEEN",
    limit: int = 50,
    save_dir: Path,
    mark_seen: bool = True,
    fmt: str = "siem",
    output: Path | None = None,
    reports_dir: Path = DEFAULT_REPORTS_DIR,
    online: bool = False,
    online_timeout: float = 8.0,
    authserv_id: str | None = None,
    quiet: bool = False,
) -> list[dict[str, Any]]:
    """
    Fetch messages via IMAP, write .eml under save_dir, analyze each.

    Password should come from an environment variable (see CLI --password-env).
    """
    save_dir = save_dir.expanduser().resolve()
    save_dir.mkdir(parents=True, exist_ok=True)

    if not ssl:
        print(
            "warning: IMAP --no-ssl: login credentials (password) are sent in cleartext",
            file=sys.stderr,
        )

    print(f"imap: connecting {host}:{port} as {user} mailbox={mailbox!r}", file=sys.stderr)
    client = _connect(
        host=host, port=port, user=user, password=password, ssl_enabled=ssl
    )
    rows: list[dict[str, Any]] = []
    try:
        typ, _ = client.select(mailbox, readonly=not mark_seen)
        if typ != "OK":
            raise RuntimeError(f"cannot select mailbox {mailbox!r}")

        typ, data = client.search(None, criteria)
        if typ != "OK" or not data or not data[0]:
            print("imap: no messages matched", file=sys.stderr)
            return []

        ids = data[0].split()
        if limit > 0:
            ids = ids[-limit:]  # newest among matches when server orders ascending
        print(f"imap: fetching {len(ids)} message(s) ({criteria})", file=sys.stderr)

        for num in ids:
            uid = num.decode("ascii", errors="replace")
            typ, fetched = client.fetch(num, "(RFC822)")
            if typ != "OK" or not fetched or not fetched[0]:
                print(f"imap: skip uid={uid} fetch failed", file=sys.stderr)
                continue
            # fetched[0] is (meta, raw_bytes)
            part = fetched[0]
            if not isinstance(part, tuple) or len(part) < 2:
                continue
            raw = part[1]
            if not isinstance(raw, bytes | bytearray):
                continue
            raw_b = bytes(raw)
            fname = _message_filename(raw_b, uid)
            eml_path = save_dir / fname
            # avoid overwrite collisions
            if eml_path.exists():
                eml_path = save_dir / f"{safe_name(uid)}_{fname}"
            eml_path.write_bytes(raw_b)
            print(f"imap: saved {eml_path.name}", file=sys.stderr)

            try:
                row = analyze_and_write(
                    eml_path,
                    fmt=fmt,
                    output=output,
                    reports_dir=reports_dir,
                    online=online,
                    online_timeout=online_timeout,
                    authserv_id=authserv_id,
                    quiet=quiet,
                    raw=raw_b,
                )
                row["imap_uid"] = uid
                rows.append(row)
            except RuntimeError as exc:
                print(f"error: {exc}", file=sys.stderr)
                # Leave UNSEEN so a later run can retry after a failed analyze.
                continue

            if mark_seen:
                client.store(num, "+FLAGS", "\\Seen")
    finally:
        try:
            client.logout()
        except Exception as exc:  # noqa: BLE001 — logout best-effort
            print(f"imap: logout warning: {exc}", file=sys.stderr)

    if rows:
        write_batch_index(rows, batch_index_dir(output, reports_dir))
    return rows


def password_from_env(env_name: str) -> str:
    value = os.environ.get(env_name, "")
    if not value:
        raise RuntimeError(
            f"environment variable {env_name} is empty; "
            "set your IMAP app password there (do not pass passwords on the CLI)."
        )
    return value
