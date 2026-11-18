# inbox_eml

Drop folder for day-to-day automation (watch / IMAP). Contents are gitignored.

```bash
# Outlook/rule saves .eml here, then:
mailshieldv1 watch ./inbox_eml --once --process-existing
mailshieldv1 watch ./inbox_eml --interval 5
```

IMAP (optional / WIP) writes downloaded messages here too.
