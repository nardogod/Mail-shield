# Threat model (v0)

## Assets

- Analyst workstation integrity
- Correctness of findings (avoid false trust)
- Confidentiality of email content written to reports

## Trust boundaries

| Input | Trust |
|-------|-------|
| Local `.eml` file | **Untrusted** |
| `Authentication-Results` header | Claim from a receiving MTA — useful, not re-proven here |
| Analyzer code in this repo | Trusted when reviewed |
| Third-party analyzers | Untrusted unless you audit them |

## What we mitigate now

- Oversized / header-bomb style inputs via hard limits
- Accidental network use in the **default** engine path (offline)
- XSS in HTML reports via escaping
- Path surprises in CLI via resolve + regular-file check

## What we do not mitigate yet

- Full process sandbox (no root / no net) — document only; Docker later
- Malicious archive/PDF exploit chains beyond static checks (attachments analyzer later)
- Supply-chain attacks on future dependencies (keep deps minimal; audit in CI)

## Optional online mode

`--online` / `analyze(..., online=True)` performs DNS TXT/A lookups only (no URL HTTP fetch).
Treat that as an explicit analyst opt-in that leaves the workstation network boundary.

## Explicit non-goals for authentication

`mailshieldv1` does **not** cryptographically prove SPF/DKIM/DMARC offline. It surfaces
MTA `Authentication-Results` and may optionally show published SPF/DMARC TXT records
online. Absence of auth headers is informational, not a definitive fail.
