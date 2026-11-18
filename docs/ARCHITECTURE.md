# Architecture

## Core rule

`mailshieldv1` is a pure Python library. The engine accepts raw email bytes and returns a `Report`. CLI and HTML are consumers. Future connectors and UIs must not reshape the engine.

```text
.eml bytes -> SafeParser -> Analyzers -> Report -> JSON | HTML | SIEM
                ^
   watch/IMAP ingest (optional) writes .eml then calls the same engine
```

## Components

| Piece | Role |
|-------|------|
| `core/limits.py` | Hard caps (bytes, headers, MIME parts, MIME depth) |
| `core/parser.py` | Stdlib `email` parse under limits |
| `core/models.py` | `Finding`, `Report`, severity |
| `core/authresults.py` | Topmost `Authentication-Results` (+ ARC fallback) |
| `core/knowledge_store.py` | Load `brands.yml` / `lures.yml` / `scoring.yml` |
| `core/scoring.py` | Family weights, commodity cap, structured floor |
| `analyzers/*` | `analyze(msg) -> list[Finding]` |
| `online/*` | Optional DNS enrichments (off by default) |
| `engine.py` | Orchestration |
| `report/*` | HTML/JSON/SIEM renderers |
| `report/pivots.py` | Optional analyst click-out URLs (no fetch) |
| `ingest/pipeline.py` | Shared analyze → write report / batch index |
| `ingest/watch.py` | Level 1: folder watch → analyze |
| `ingest/imap_pull.py` | Level 2: IMAP pull → `.eml` → analyze |
| `cli.py` | `analyze` \| `watch` \| `imap` |

## Knowledge data

| File | Purpose |
|------|---------|
| `data/brands.yml` | Brand tokens + supported domains |
| `data/lures.yml` | Content/BEC lure patterns; commodity vs structured lists |
| `data/scoring.yml` | Severity weights, verdict thresholds (4/8/12), rule→family prefixes |

`reload_knowledge()` clears YAML caches and compiled lure regexes.

## Analyzer contract

Each analyzer receives a parsed `EmailMessage` and returns zero or more `Finding` objects. Custom analyzers can be passed to `analyze(..., analyzers=[...])`.

## Isolation intent

Analyzers must not perform network I/O. Optional DNS lives in `online/` and runs only when
explicitly requested. Process sandboxing (containers) is optional and out of band for v0.1.
