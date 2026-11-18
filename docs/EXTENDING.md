# Extending

## Custom analyzer

```python
from email.message import EmailMessage
from mailshieldv1 import Finding, analyze
from mailshieldv1.analyzers import DEFAULT_ANALYZERS

def my_rules(msg: EmailMessage) -> list[Finding]:
    subject = msg.get("Subject") or ""
    if "urgent" in subject.lower():
        return [
            Finding(
                rule_id="CUSTOM-URGENT-SUBJECT",
                category="content",
                severity="low",
                confidence=0.4,
                evidence=subject,
                explanation="Subject contains urgency language.",
                recommendation="Corroborate with other signals.",
            )
        ]
    return []

report = analyze(raw_bytes, analyzers=[*DEFAULT_ANALYZERS, my_rules])
```

Keep analyzers free of network I/O.

## Knowledge data (brands / lures / scoring)

Edit package YAML instead of hardcoding Python:

- `src/mailshieldv1/data/brands.yml` — brand tokens + domain support rules
- `src/mailshieldv1/data/lures.yml` — simple/composite content regex lures + commodity vs structured lists
- `src/mailshieldv1/data/scoring.yml` — severity weights, verdict thresholds (4/8/12), rule-id → family prefixes

Requires runtime dependency `PyYAML`. After edits, call `reload_knowledge()` or restart the process (catalogs are cached).

## FP harness

```bash
python scripts/fp_harness.py
```

Benign/marketing samples must stay at `info|low`. Results land in `reports/fp_harness.json`.

## CLI batch + SIEM JSON

```bash
mailshieldv1 path/to/dir -f siem
mailshieldv1 message.eml -f siem -o -
```

SIEM schema: `mailshieldv1.siem.v1` (`Report.to_siem_dict()` / `to_siem_json`).

## Automation: watched folder (level 1)

Drop `.eml` files into a folder (Outlook/Gmail rule, manual save, or sync):

```bash
# process existing + exit
mailshieldv1 watch ./inbox_eml --once --process-existing

# keep polling every 5s
mailshieldv1 watch ./inbox_eml --interval 5
```

State is stored in `./inbox_eml/.mailshield_watch_state.json`. Reports default to `siem` under `reports/`.

## Automation: IMAP pull (level 2)

Uses stdlib `imaplib` (no extra deps). Password via env var only:

```bash
# Gmail: create an App Password, then:
export MAILSHIELD_IMAP_PASSWORD='your-app-password'

mailshieldv1 imap \
  --host imap.gmail.com \
  --user you@gmail.com \
  --save-dir ./inbox_eml \
  --criteria UNSEEN \
  --limit 20
```

Outlook / Microsoft 365 (IMAP enabled):

```bash
mailshieldv1 imap \
  --host outlook.office365.com \
  --user you@company.com \
  --save-dir ./inbox_eml
```

Flow: fetch RFC822 → write `.eml` → `analyze` → `*.siem.json` + `batch_index.siem.json`.
