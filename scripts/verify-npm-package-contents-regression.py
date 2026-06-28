#!/usr/bin/env python3
"""Regression checks for npm package content and public metadata validation."""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace


SCRIPT = Path(__file__).with_name("verify-npm-package-contents.py")
SENSITIVE_SENTINEL = "do-not-print-this-npm-token"


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
        if SENSITIVE_SENTINEL in str(exc):
            raise AssertionError("npm package verifier error leaked a sensitive path value") from exc
        if pattern not in str(exc):
            raise AssertionError(f"expected {pattern!r} in {exc!r}") from exc
        return
    raise AssertionError(f"expected ValueError containing {pattern!r}")


def manifest_for(module, rule) -> dict[str, object]:
    repo = Path(__file__).resolve().parents[1]
    return module.load_json(repo / rule.directory / "package.json")


def rule_by_name(module, name: str):
    for rule in module.PACKAGES:
        if rule.name == name:
            return rule
    raise AssertionError(f"missing package rule {name}")


def run_public_metadata_tests(module) -> None:
    cli_rule = rule_by_name(module, "@imthegoodboy/conu")
    cli_manifest = manifest_for(module, cli_rule)
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

    sensitive_files = copy.deepcopy(cli_manifest)
    sensitive_files["files"].append(f"lib/{SENSITIVE_SENTINEL}.js")
    assert_raises(
        lambda: module.validate_manifest_public_surface(cli_rule, sensitive_files),
        "pathDisplayed=false",
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
    sdk_manifest = manifest_for(module, sdk_rule)
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


def run_json_duplicate_key_tests(module) -> None:
    with tempfile.TemporaryDirectory(prefix="conu-npm-json-") as temp_text:
        temp = Path(temp_text)
        duplicate = temp / "package.json"
        duplicate.write_text(
            '{"name":"@imthegoodboy/conu","version":"0.1.0","version":"'
            + SENSITIVE_SENTINEL
            + '"}\n',
            encoding="utf-8",
            newline="\n",
        )
        try:
            module.load_json(duplicate)
        except ValueError as exc:
            rendered = str(exc)
            if "duplicate JSON key: version" not in rendered:
                raise AssertionError(f"unexpected duplicate-key error: {rendered!r}") from exc
            if SENSITIVE_SENTINEL in rendered:
                raise AssertionError("duplicate-key error leaked the shadow value") from exc
        else:
            raise AssertionError("duplicate top-level package JSON key unexpectedly passed")

        nested = temp / "nested-package.json"
        nested.write_text(
            '{"name":"@imthegoodboy/conu","scripts":{"postinstall":"node scripts/install.js",'
            + '"postinstall":"'
            + SENSITIVE_SENTINEL
            + '"}}\n',
            encoding="utf-8",
            newline="\n",
        )
        assert_raises(lambda: module.load_json(nested), "duplicate JSON key: postinstall")


def run_npm_pack_privacy_tests(module) -> None:
    original_run = module.subprocess.run

    def failed_pack(*_args, **_kwargs):
        return SimpleNamespace(
            returncode=1,
            stdout="",
            stderr=f"npm ERR! auth token {SENSITIVE_SENTINEL}\n",
        )

    module.subprocess.run = failed_pack
    stderr = io.StringIO()
    try:
        with contextlib.redirect_stderr(stderr):
            try:
                module.run_npm_pack("npm", Path("packaging/npm/conu-cli"))
            except ValueError as exc:
                rendered = str(exc)
                if "npm stderr suppressed" not in rendered:
                    raise AssertionError(f"expected suppressed-stderr error: {rendered}") from exc
                if SENSITIVE_SENTINEL in rendered:
                    raise AssertionError("npm pack failure leaked the npm stderr value") from exc
            else:
                raise AssertionError("failed npm pack unexpectedly passed")
    finally:
        module.subprocess.run = original_run

    if SENSITIVE_SENTINEL in stderr.getvalue():
        raise AssertionError("npm pack failure printed raw npm stderr")


def run_pack_path_display_guard_tests(module) -> None:
    assert_raises(
        lambda: module.normalize_pack_path(f"lib\\{SENSITIVE_SENTINEL}.js"),
        "pathDisplayed=false",
    )
    assert_raises(
        lambda: module.normalize_pack_path(f"/{SENSITIVE_SENTINEL}/index.js"),
        "pathDisplayed=false",
    )
    assert_raises(
        lambda: module.reject_forbidden_path(f"lib/{SENSITIVE_SENTINEL}.token"),
        "pathDisplayed=false",
    )

    cli_rule = rule_by_name(module, "@imthegoodboy/conu")
    cli_manifest = manifest_for(module, cli_rule)
    version = cli_manifest["version"]
    base_files = [
        {"path": path, "size": 10}
        for path in sorted(cli_rule.allowed_files)
    ]

    original_run_npm_pack = module.run_npm_pack
    try:
        module.run_npm_pack = lambda _npm, _package_dir: {
            "name": cli_rule.name,
            "version": version,
            "id": f"{cli_rule.name}@{version}",
            "filename": "conu-cli-0.1.0.tgz",
            "size": 100,
            "unpackedSize": 100,
            "bundled": [],
            "files": [
                *base_files,
                {"path": f"lib/{SENSITIVE_SENTINEL}.js", "size": 10},
            ],
            "entryCount": len(base_files) + 1,
        }
        assert_raises(
            lambda: module.validate_package(Path(__file__).resolve().parents[1], "npm", cli_rule),
            "pathDisplayed=false",
        )

        module.run_npm_pack = lambda _npm, _package_dir: {
            "name": cli_rule.name,
            "version": version,
            "id": f"{cli_rule.name}@{version}",
            "filename": "conu-cli-0.1.0.tgz",
            "size": 100,
            "unpackedSize": 100,
            "bundled": [],
            "files": [
                *base_files,
                {"path": f"lib/{SENSITIVE_SENTINEL}.js", "size": module.MAX_ENTRY_BYTES + 1},
            ],
            "entryCount": len(base_files) + 1,
        }
        assert_raises(
            lambda: module.validate_package(Path(__file__).resolve().parents[1], "npm", cli_rule),
            "pathDisplayed=false",
        )
    finally:
        module.run_npm_pack = original_run_npm_pack


def main() -> int:
    module = load_module()
    run_public_metadata_tests(module)
    run_json_duplicate_key_tests(module)
    run_npm_pack_privacy_tests(module)
    run_pack_path_display_guard_tests(module)
    print("npm package content regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
