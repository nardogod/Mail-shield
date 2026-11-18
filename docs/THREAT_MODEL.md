# Threat model (v0)

## Assets

- Analyst workstation integrity
- Correctness of findings (avoid false trust)
- Confidentiality of email content written to reports
- IMAP credentials (app passwords) when using ingest

## Trust boundaries

| Input | Trust |
|-------|-------|
| Local `.eml` file | **Untrusted** |
| `Authentication-Results` header | Claim from the **topmost** receiving-MTA header only — useful, not re-proven here |
| Drop folder (`watch`) | Untrusted files appearing on disk |
| IMAP server | Semi-trusted transport; TLS verified by default |
| Analyzer code in this repo | Trusted when reviewed |
| Third-party analyzers | Untrusted unless you audit them |

## What we mitigate now

- Oversized / header-bomb style inputs via hard limits (`max_bytes`, `max_header_bytes`,
  `max_parts`, `max_mime_depth`)
- Deeply nested MIME (`RecursionError` / depth cap → `LimitExceeded`)
- Accidental network use in the **default** engine path (offline)
- XSS in HTML reports via escaping
- Path surprises in CLI via resolve + batch `-o` directory checks
- IMAP TLS: `ssl.create_default_context()` with hostname check + `CERT_REQUIRED`
- Forged lower `Authentication-Results`: only the top header is scored; ARC is fallback-only

## What we do not mitigate yet

- Full process sandbox (no root / no net) — document only; Docker later
- Malicious archive/PDF exploit chains beyond static checks
- Supply-chain attacks on future dependencies (keep deps minimal; audit in CI)
- Cleartext IMAP when the operator passes `--no-ssl` (explicit warning only)

## Watch mode (level 1)

- Reads `.eml` files from a local directory; treats them as hostile input.
- Writes analysis artifacts under `reports/` (or `-o` directory).
- State file `.mailshield_watch_state.json` tracks processed fingerprints and **failed**
  fingerprints (so a permanently bad file is not retried every poll until it changes).
- A short settle window avoids analyzing a file still being copied.

## IMAP mode (level 2)

- Credentials come from an environment variable only (never CLI argv).
- Default path uses TLS with certificate verification. `--no-ssl` sends the password in
  cleartext and prints a warning.
- Downloaded messages are written as `.eml` on disk under `--save-dir` (protect that folder).
- Successful analyze may set `\Seen` (`mark_seen`); failures leave the message UNSEEN for retry.
- Treat the IMAP host as part of your trust boundary (phishing of the analyst mailbox is in-scope
  for analysis, not a substitute for mailbox account security).

## Optional online mode

`--online` / `analyze(..., online=True)` performs DNS TXT/A lookups only (no URL HTTP fetch).
Treat that as an explicit analyst opt-in that leaves the workstation network boundary.
Host resolve uses a timed worker thread without changing process-wide socket defaults.

## Explicit non-goals for authentication

`mailshieldv1` does **not** cryptographically prove SPF/DKIM/DMARC offline. It surfaces
the receiving MTA’s topmost `Authentication-Results` (optional `authserv_id` filter) and may
optionally show published SPF/DMARC TXT records online. Absence of auth headers is
informational, not a definitive fail.
