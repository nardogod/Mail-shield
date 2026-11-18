"""Command-line entry point: analyze | watch | imap."""

from __future__ import annotations

import argparse
import imaplib
import sys
from collections import Counter
from pathlib import Path

from mailshieldv1.core.limits import LimitExceeded
from mailshieldv1.ingest.imap_pull import password_from_env, pull_and_analyze
from mailshieldv1.ingest.pipeline import (
    DEFAULT_REPORTS_DIR,
    analyze_and_write,
    batch_index_dir,
    require_batch_directory,
    write_batch_index,
)
from mailshieldv1.ingest.watch import watch_loop


def _collect_inputs(path: Path) -> list[Path]:
    resolved = path.expanduser().resolve()
    if resolved.is_file():
        return [resolved]
    if resolved.is_dir():
        files = sorted(resolved.rglob("*.eml"))
        if not files:
            raise FileNotFoundError(f"no .eml files under directory: {resolved}")
        return files
    raise FileNotFoundError(f"not a file or directory: {resolved}")


def _add_common_analyze_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "-f",
        "--format",
        choices=("json", "html", "urls", "siem"),
        default="html",
        help="Output format (default: html). 'siem' = stable compact JSON.",
    )
    p.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Override output file/directory. Use - for stdout.",
    )
    p.add_argument(
        "--online",
        action="store_true",
        help="Optional DNS lookups (requires dnspython / mailshieldv1[online]).",
    )
    p.add_argument(
        "--online-timeout",
        type=float,
        default=8.0,
        help="Per-query DNS timeout seconds for --online (default: 8).",
    )
    p.add_argument("--quiet", action="store_true", help="Suppress terminal summary.")


def _cmd_analyze(args: argparse.Namespace) -> int:
    try:
        inputs = _collect_inputs(args.eml)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    batch = len(inputs) > 1
    if batch:
        bad = require_batch_directory(args.output)
        if bad:
            print(f"error: {bad}", file=sys.stderr)
            return 2

    rows = []
    exit_code = 0
    for path in inputs:
        try:
            row = analyze_and_write(
                path,
                fmt=args.format,
                output=args.output,
                online=args.online,
                online_timeout=args.online_timeout,
                quiet=args.quiet,
            )
            rows.append(row)
        except FileNotFoundError as exc:
            print(f"error: {exc}", file=sys.stderr)
            exit_code = 2
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            exit_code = 1
        except (LimitExceeded, ValueError, TypeError) as exc:
            print(f"error: {path.name}: {exc}", file=sys.stderr)
            exit_code = 1

    if batch and rows:
        if not args.quiet:
            c = Counter(r["verdict"] for r in rows)
            print(
                f"batch: {len(rows)} files  "
                + " ".join(f"{k}={v}" for k, v in sorted(c.items())),
                file=sys.stderr,
            )
        write_batch_index(rows, batch_index_dir(args.output, DEFAULT_REPORTS_DIR))
    return exit_code


def _cmd_watch(args: argparse.Namespace) -> int:
    bad = require_batch_directory(args.output)
    if bad:
        print(f"error: {bad}", file=sys.stderr)
        return 2
    return watch_loop(
        args.dir,
        interval=args.interval,
        once=args.once,
        fmt=args.format,
        output=args.output,
        online=args.online,
        online_timeout=args.online_timeout,
        quiet=args.quiet,
        process_existing=args.process_existing,
    )


def _cmd_imap(args: argparse.Namespace) -> int:
    try:
        password = password_from_env(args.password_env)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    fmt = args.format
    # Prefer SIEM for IMAP automation unless user asked otherwise via default override
    if fmt == "html":
        fmt = "siem"

    try:
        rows = pull_and_analyze(
            host=args.host,
            port=args.port,
            user=args.user,
            password=password,
            ssl=not args.no_ssl,
            mailbox=args.mailbox,
            criteria=args.criteria,
            limit=args.limit,
            save_dir=args.save_dir,
            mark_seen=not args.leave_unseen,
            fmt=fmt,
            output=args.output,
            online=args.online,
            online_timeout=args.online_timeout,
            quiet=args.quiet,
        )
    except (OSError, RuntimeError, imaplib.IMAP4.error) as exc:
        print(f"error: imap: {exc}", file=sys.stderr)
        return 1

    if not args.quiet:
        print(f"imap: done ({len(rows)} analyzed)", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    parser = argparse.ArgumentParser(
        prog="mailshieldv1",
        description=(
            "Local deterministic email threat analysis. "
            "Subcommands: analyze (default), watch, imap."
        ),
    )
    sub = parser.add_subparsers(dest="command")

    # analyze (also default when first arg looks like a path)
    p_an = sub.add_parser("analyze", help="Analyze .eml file or directory")
    p_an.add_argument("eml", type=Path, help="Path to .eml file or directory")
    _add_common_analyze_flags(p_an)
    p_an.set_defaults(func=_cmd_analyze, format="html")

    p_watch = sub.add_parser(
        "watch",
        help="Level 1: watch a folder for new .eml files and analyze them",
    )
    p_watch.add_argument("dir", type=Path, help="Directory to watch for .eml drops")
    _add_common_analyze_flags(p_watch)
    p_watch.set_defaults(format="siem")
    p_watch.add_argument(
        "--interval",
        type=float,
        default=5.0,
        help="Poll interval seconds (default: 5)",
    )
    p_watch.add_argument(
        "--once",
        action="store_true",
        help="Scan once and exit (no loop)",
    )
    p_watch.add_argument(
        "--process-existing",
        action="store_true",
        help="On first scan, also process .eml files already in the folder",
    )
    p_watch.set_defaults(func=_cmd_watch)

    p_imap = sub.add_parser(
        "imap",
        help="Level 2: pull mail via IMAP → save .eml → analyze",
    )
    p_imap.add_argument("--host", required=True, help="IMAP host (e.g. imap.gmail.com)")
    p_imap.add_argument("--port", type=int, default=993, help="IMAP port (default: 993)")
    p_imap.add_argument("--user", required=True, help="IMAP username / email")
    p_imap.add_argument(
        "--password-env",
        default="MAILSHIELD_IMAP_PASSWORD",
        help="Env var holding the app password (default: MAILSHIELD_IMAP_PASSWORD)",
    )
    p_imap.add_argument("--mailbox", default="INBOX", help="Mailbox name (default: INBOX)")
    p_imap.add_argument(
        "--criteria",
        default="UNSEEN",
        help='IMAP search criteria (default: UNSEEN). Example: ALL, UNSEEN, \'FROM "x"\'',
    )
    p_imap.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Max messages to fetch this run (default: 50)",
    )
    p_imap.add_argument(
        "--save-dir",
        type=Path,
        default=Path("inbox_eml"),
        help="Where to store downloaded .eml files (default: inbox_eml/)",
    )
    p_imap.add_argument(
        "--leave-unseen",
        action="store_true",
        help="Do not set \\Seen after download",
    )
    p_imap.add_argument(
        "--no-ssl",
        action="store_true",
        help="Disable SSL (not recommended)",
    )
    _add_common_analyze_flags(p_imap)
    p_imap.set_defaults(format="siem", func=_cmd_imap)

    # Backward compatible: `mailshieldv1 file.eml` (no subcommand)
    if not argv or argv[0] not in {"analyze", "watch", "imap", "-h", "--help"}:
        if argv and not argv[0].startswith("-"):
            argv = ["analyze", *argv]
        elif not argv:
            argv = ["--help"]

    args = parser.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 2
    return int(func(args))


if __name__ == "__main__":
    raise SystemExit(main())
