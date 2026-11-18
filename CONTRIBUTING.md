# Contributing

## Principles

1. Prefer the smallest change that meets the goal.
2. Treat `.eml` input as hostile (AppSec).
3. No network I/O inside analyzers or the engine.
4. English-only for code, docs, and user-facing strings.
5. Add tests for new rules and failure modes.

## Setup

```bash
python -m pip install -e ".[dev]"
pytest
ruff check src tests
```

## Pull requests

- One focused change per PR when possible
- Update docs if the public API or threat model changes
- Do not add real malware samples
