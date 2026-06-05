#!/usr/bin/env python3
"""Compile every repository Python helper used by release and smoke checks."""

from __future__ import annotations

import sys
import tokenize
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHON_SOURCE_ROOTS = (
    ROOT / "scripts",
    ROOT / "sdk" / "python",
    ROOT / "examples" / "python",
)


def main() -> int:
    try:
        targets = discover_python_sources()
        if not targets:
            raise ValueError("no Python sources found")
        for target in targets:
            compile_source(target)
    except (OSError, SyntaxError, ValueError) as exc:
        print(f"Python script compile check failed: {exc}", file=sys.stderr)
        return 1

    print(f"Python script compile check passed: {len(targets)} file(s)")
    return 0


def compile_source(path: Path) -> None:
    with tokenize.open(path) as source_file:
        source = source_file.read()
    compile(source, str(path), "exec", dont_inherit=True)


def discover_python_sources() -> tuple[Path, ...]:
    targets: set[Path] = set()
    for source_root in PYTHON_SOURCE_ROOTS:
        if not source_root.exists():
            continue
        for path in source_root.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            if path.is_file():
                targets.add(path.resolve())
    return tuple(sorted(targets))


if __name__ == "__main__":
    raise SystemExit(main())
