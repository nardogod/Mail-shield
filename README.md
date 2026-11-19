# mailshieldv1

Built to practice email threat analysis the way a SOC analyst does it.  
**Not a replacement for commercial or established tools.**

Local, deterministic email threat analysis for `.eml` files.

**No AI. Offline by default.** Feed bytes in, get a structured report out.

```text
analyze(raw_bytes) -> Report
```

## Why this exists

Entry-level SOC roles do not need a new product category. They need evidence that you know which signals matter, where tools lie, and how you would investigate without automation.

This repo is that practice surface:

| What a reviewer can check | Where it shows up |
|---------------------------|-------------------|
| Analyst signals (auth, Reply-To mismatch, URLs, attachments, BEC) | analyzers + weighted verdict |
| Hostile-input posture | parse limits, no URL fetch, [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) |
| Explainability | HTML **Why this verdict** + Authentication panel |
| Engineering hygiene | tests, CI (ruff / pytest / bandit / pip-audit), scoped docs |

If you open one file first, open the threat model. The code is meant to match what that document promises.

## Related tools

Day-to-day professional SOC email triage is already covered better by established products
(Proofpoint, Mimecast, Microsoft Defender for Office 365, Abnormal Security, Sublime Security)
and by header helpers / pivots ([Microsoft MHA](https://github.com/microsoft/MHA), MXToolbox, PhishTank).
This repo is practice, not a substitute.

What differs on purpose here:

- **Offline / deterministic** — same bytes → same findings; no LLM
- **Explainable scoring** — every severity bump is a named finding
- **AppSec-first ingest** — hard MIME/size limits; preview strips script/iframe/form and blocks links/images
- **Auth trust boundary** — forged `Authentication-Results` do not soften the verdict unless `--authserv-id` matches your receiving MTA

## What it does

- Safely parses local `.eml` input under hard limits (default: 5 MiB body, 256 KiB
  headers, 200 MIME parts, MIME depth 50)
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

## Known limitations (worth saying out loud)

- **BEC keyword negation** — phrases like “no payment changes” can still hit payment/urgency rules. Example: `samples/benign/internal_meeting.eml` scores high without a matching `--authserv-id`. Documented trade-off; negation handling is future work.
- **Auth without authserv-id** — safe default, noisy for demos; pass your MTA id.
- **Attachments** — static checks, not full PDF/OLE exploit analysis.
- **IMAP / watch** — useful for a personal loop; not a production mail gateway.

Honesty about FPs and trust boundaries is part of the skill this project is meant to show.

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

# Trust Authentication-Results only from your receiving MTA (required to soften FPs)
mailshieldv1 samples/benign/simple_auth_pass.eml --authserv-id mx.example.com

# IMAP pull (optional / WIP — needs MAILSHIELD_IMAP_PASSWORD)
# mailshieldv1 imap --host imap.gmail.com --user you@gmail.com
```

Without `--authserv-id` (or `MAILSHIELD_AUTHSERV_ID`), auth claims are treated as untrusted. Legitimate mail can look worse than expected — that default is intentional and defensive. Set the id to your receiving MTA when you have it.

## Library

```python
from mailshieldv1 import analyze, to_json

report = analyze(open("message.eml", "rb").read())
# report = analyze(raw, online=True)  # optional DNS only
print(to_json(report))
```

## Layout

| Path | Role |
|------|------|
| `src/mailshieldv1/` | Engine, analyzers, CLI |
| `samples/` | Curated `.eml` for demos + CI |
| `inbox_eml/` | Drop folder for watch / IMAP (gitignored contents) |
| `reports/` | CLI output (gitignored; regenerate anytime) |
| `docs/` | Architecture, threat model, extending, references |
| `scripts/` | FP harness |

## Security notes

Treat every `.eml` as hostile input. The engine applies the limits above (there is no
separate parse wall-clock timeout). It does not open network connections unless you pass
`--online` / `online=True` (DNS only). HTML output escapes all dynamic values.
IMAP uses verified TLS by default; `--no-ssl` sends credentials in cleartext.
See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## License

MIT — see [LICENSE](LICENSE).
