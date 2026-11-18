"""Load YAML knowledge files. Prefers PyYAML; falls back to JSON twin files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def loads(text: str) -> Any:
    try:
        import yaml  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "PyYAML is required to load brands.yml / lures.yml. "
            "Install with: pip install 'mailshieldv1' (or PyYAML)."
        ) from exc
    return yaml.safe_load(text)


def load_path(path: Path) -> Any:
    path = Path(path)
    if path.suffix.lower() in {".json"}:
        return json.loads(path.read_text(encoding="utf-8"))
    return loads(path.read_text(encoding="utf-8"))
