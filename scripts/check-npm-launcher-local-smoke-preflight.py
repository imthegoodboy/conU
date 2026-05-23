#!/usr/bin/env python3
"""Regression checks for npm launcher local smoke binary preflight."""

from __future__ import annotations

import importlib.util
import tempfile
from pathlib import Path


def main() -> int:
    smoke = load_smoke_helpers()

    with fixture_dir() as root:
        bin_dir = root / "bin"
        write_binaries(bin_dir, smoke)
        smoke.verify_archive_binaries(Path("fixture.zip"), bin_dir)

    with fixture_dir() as root:
        expect_failure(
            smoke,
            root / "missing-bin",
            "missing binary directory",
            "missing binary directory",
        )

    with fixture_dir() as root:
        bin_dir = root / "bin"
        write_binaries(bin_dir, smoke, skip="conud")
        expect_failure(smoke, bin_dir, "missing executable(s): conud", "missing binary")

    with fixture_dir() as root:
        bin_dir = root / "bin"
        write_binaries(bin_dir, smoke, skip="conu-relay")
        bin_dir.joinpath(f"conu-relay{smoke.binary_suffix()}").mkdir()
        expect_failure(
            smoke,
            bin_dir,
            "not a regular file: conu-relay",
            "directory named as binary",
        )

    print("npm launcher local smoke preflight check passed")
    return 0


def load_smoke_helpers():
    helper_path = Path(__file__).with_name("smoke-npm-launcher-local.py")
    spec = importlib.util.spec_from_file_location("conu_npm_launcher_local_smoke", helper_path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"could not load helper script {helper_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class fixture_dir:
    def __enter__(self) -> Path:
        self.temp = tempfile.TemporaryDirectory(prefix="conu-npm-local-smoke-preflight-")
        return Path(self.temp.name)

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.temp.cleanup()


def write_binaries(bin_dir: Path, smoke, skip: str | None = None) -> None:
    bin_dir.mkdir(parents=True, exist_ok=True)
    suffix = smoke.binary_suffix()
    for name in smoke.REQUIRED_BINARIES:
        if name == skip:
            continue
        bin_dir.joinpath(f"{name}{suffix}").write_text(name, encoding="utf-8")


def expect_failure(smoke, bin_dir: Path, expected: str, label: str) -> None:
    try:
        smoke.verify_archive_binaries(Path("fixture.zip"), bin_dir)
    except SystemExit as exc:
        message = str(exc)
        if expected in message:
            return
        raise SystemExit(f"{label}: expected {expected}, got: {message}") from exc
    raise SystemExit(f"{label}: expected smoke preflight failure")


if __name__ == "__main__":
    raise SystemExit(main())
