#!/usr/bin/env python3
"""Regression checks for release version validation."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


SCRIPT = Path(__file__).with_name("verify-release-versions.py")


def load_module():
    spec = importlib.util.spec_from_file_location("verify_release_versions", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load release version verifier module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    module = load_module()
    for version in ("0.1.0", "1.2.3-rc.1", "1.2.3+build.5", "1.2.3-rc.1+build.5"):
        if not module.is_semver_like(version):
            raise AssertionError(f"valid release version was rejected: {version!r}")
    for version in ("0.1.0\n", "0.1.0 extra", "v0.1.0", "latest"):
        if module.is_semver_like(version):
            raise AssertionError(f"invalid release version was accepted: {version!r}")
    print("release version regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
