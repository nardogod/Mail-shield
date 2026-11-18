# Architecture

## Core rule

`mailshieldv1` is a pure Python library. The engine accepts raw email bytes and returns a `Report`. CLI and HTML are consumers. Future connectors and UIs must not reshape the engine.

```text
.eml bytes -> SafeParser -> Analyzers -> Report -> JSON | HTML | (your UI)
```

## Components

| Piece | Role |
|-------|------|
| `core/limits.py` | Hard caps (bytes, headers, MIME parts) |
| `core/parser.py` | Stdlib `email` parse under limits |
| `core/models.py` | `Finding`, `Report`, severity |
| `analyzers/*` | `analyze(msg) -> list[Finding]` |
| `core/scoring.py` | Weighted verdict + calibration |
| `online/*` | Optional DNS enrichments (off by default) |
| `engine.py` | Orchestration |
| `report/*` | Renderers |
| `cli.py` | Local file entry point |

## Analyzer contract

Each analyzer receives a parsed `EmailMessage` and returns zero or more `Finding` objects. Custom analyzers can be passed to `analyze(..., analyzers=[...])`.

## Isolation intent

Analyzers must not perform network I/O. Optional DNS lives in `online/` and runs only when
explicitly requested. Process sandboxing (containers) is optional and out of band for v0.1.
