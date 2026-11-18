# mailshieldv1

Local, deterministic email threat analysis for `.eml` files.

**No AI. Offline by default.** Feed bytes in, get a structured report out.

```text
analyze(raw_bytes) -> Report
```

## What it does

- Safely parses local `.eml` input under size/structure limits
- Runs deterministic analyzers (headers/auth, hops + offline geo hints, static URLs,
  content/BEC, attachments, org/ESP consistency)
- Weighted, explainable verdict (HTML **Why this verdict** + Authentication panel)
- Dual HTML report: **Simple** (default, non-technical) + **Technical** toggle for analysts
- Safe reconstructed email preview (links/images blocked; callouts on suspicious spots)
- Extracts URLs (including tracking pixels) and SOC-defangs them — never fetches;
  groups by **sender purpose** and collapses query-string **variants**
- Optional `--online` DNS hints (SPF/DMARC TXT + host resolve; no URL fetch)
- HTML/JSON **analyst pivots**: optional click-out to Unshorten.it, DomainTools WHOIS,
  PhishTank, dnstwist.it, MXToolbox

## What it does not do

- LLM / ML classification
- Full cryptographic DKIM verification (offline reads `Authentication-Results` only)
- URL fetching
- Hosted multi-user triage UI

## Layout

| Path | Role |
|------|------|
| `src/mailshieldv1/` | Engine, analyzers, CLI |
| `samples/` | Curated `.eml` for demos + CI |
| `inbox_eml/` | Drop folder for watch / IMAP (gitignored contents) |
| `reports/` | CLI output (gitignored; regenerate anytime) |
| `docs/` | Architecture, threat model, extending |
| `scripts/` | FP harness |

## Install

```bash
python -m pip install -e ".[dev]"
# optional online extras (also pulled by [dev]):
python -m pip install -e ".[online]"
```

## CLI

```bash
# Always writes reports/<eml-stem>.html by default
mailshieldv1 path/to/message.eml

mailshieldv1 samples/phishing/replyto_mismatch.eml
# -> reports/replyto_mismatch.html

mailshieldv1 samples/phishing/replyto_mismatch.eml -f json
# -> reports/replyto_mismatch.json

mailshieldv1 samples/phishing/replyto_mismatch.eml -f urls
# -> reports/replyto_mismatch.txt  (defanged URLs)

# Optional DNS enrichments (requires dnspython)
mailshieldv1 samples/benign/simple_auth_pass.eml --online

# Override path, or use -o - for stdout
mailshieldv1 samples/phishing/replyto_mismatch.eml -f json -o -

# Day-to-day: watch a drop folder (Outlook/rule → .eml → analyze)
mailshieldv1 watch ./inbox_eml --once --process-existing

# IMAP pull (optional / WIP — needs MAILSHIELD_IMAP_PASSWORD)
# mailshieldv1 imap --host imap.gmail.com --user you@gmail.com
```

## Library

```python
from mailshieldv1 import analyze, to_json

report = analyze(open("message.eml", "rb").read())
# report = analyze(raw, online=True)  # optional DNS only
print(to_json(report))
```

## Security notes

Treat every `.eml` as hostile input. The engine applies hard limits and does not open
network connections unless you pass `--online` / `online=True` (DNS only). HTML output
escapes all dynamic values. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## License

MIT — see [LICENSE](LICENSE).
