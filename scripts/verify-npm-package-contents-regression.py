#!/usr/bin/env python3
"""Regression checks for npm package content and public metadata validation."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path


SCRIPT = Path(__file__).with_name("verify-npm-package-contents.py")


def load_module():
    spec = importlib.util.spec_from_file_location("verify_npm_package_contents", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load npm package content verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def assert_raises(func, pattern: str) -> None:
    try:
        func()
    except ValueError as exc:
        if pattern not in str(exc):
            raise AssertionError(f"expected {pattern!r} in {exc!r}") from exc
        return
    raise AssertionError(f"expected ValueError containing {pattern!r}")


def manifest_for(rule) -> dict[str, object]:
    repo = Path(__file__).resolve().parents[1]
    return json.loads((repo / rule.directory / "package.json").read_text(encoding="utf-8"))


def rule_by_name(module, name: str):
    for rule in module.PACKAGES:
        if rule.name == name:
            return rule
    raise AssertionError(f"missing package rule {name}")


def run_public_metadata_tests(module) -> None:
    cli_rule = rule_by_name(module, "@conu/cli")
    cli_manifest = manifest_for(cli_rule)
    module.validate_manifest_public_surface(cli_rule, cli_manifest)

    broken_bin = copy.deepcopy(cli_manifest)
    broken_bin["bin"]["conu"] = "bin/missing.js"
    assert_raises(
        lambda: module.validate_manifest_public_surface(cli_rule, broken_bin),
        "bin must match",
    )

    broken_files = copy.deepcopy(cli_manifest)
    broken_files["files"].append("dist/")
    assert_raises(
        lambda: module.validate_manifest_public_surface(cli_rule, broken_files),
        "files changed",
    )

    duplicate_files = copy.deepcopy(cli_manifest)
    duplicate_files["files"].append("bin/")
    assert_raises(
        lambda: module.validate_manifest_public_surface(cli_rule, duplicate_files),
        "duplicate entries",
    )

    broken_postinstall = copy.deepcopy(cli_manifest)
    broken_postinstall["scripts"]["postinstall"] = "node scripts/other.js"
    assert_raises(
        lambda: module.validate_manifest_public_surface(cli_rule, broken_postinstall),
        "scripts.postinstall",
    )

    sdk_rule = rule_by_name(module, "@conu/sdk")
    sdk_manifest = manifest_for(sdk_rule)
    module.validate_manifest_public_surface(sdk_rule, sdk_manifest)

    broken_exports = copy.deepcopy(sdk_manifest)
    broken_exports["exports"]["."]["default"] = "./src/missing.js"
    assert_raises(
        lambda: module.validate_manifest_public_surface(sdk_rule, broken_exports),
        "exports must match",
    )

    broken_engine = copy.deepcopy(sdk_manifest)
    broken_engine["engines"]["node"] = ">=18"
    assert_raises(
        lambda: module.validate_manifest_public_surface(sdk_rule, broken_engine),
        "engines.node",
    )


def main() -> int:
    module = load_module()
    run_public_metadata_tests(module)
    print("npm package content regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
