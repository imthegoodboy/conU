"""Small JSON parsing helpers for release and packaging checks."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for key, value in pairs:
        if key in values:
            raise ValueError(f"duplicate JSON key: {key}")
        values[key] = value
    return values


def loads_json(text: str) -> Any:
    return json.loads(text, object_pairs_hook=reject_duplicate_json_keys)


def load_json(path: Path, *, encoding: str = "utf-8") -> Any:
    return loads_json(path.read_text(encoding=encoding))


def load_json_object(path: Path, *, encoding: str = "utf-8") -> dict[str, Any]:
    value = load_json(path, encoding=encoding)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value
