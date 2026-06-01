#!/usr/bin/env python3
"""Validate npm publish preconditions before tagged publication."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")


@dataclass(frozen=True)
class PackageRule:
    name: str
    directory: Path


@dataclass(frozen=True)
class PackageInfo:
    name: str
    version: str
    directory: Path


PACKAGES = (
    PackageRule(name="@conu/cli", directory=Path("packaging/npm/conu-cli")),
    PackageRule(name="@conu/sdk", directory=Path("sdk/typescript")),
)


def find_npm() -> str:
    candidates = ("npm.cmd", "npm") if sys.platform == "win32" else ("npm",)
    for candidate in candidates:
        path = shutil.which(candidate)
        if path:
            return path
    raise ValueError("npm executable was not found on PATH")


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def require_string(manifest: dict[str, Any], field: str, context: Path) -> str:
    value = manifest.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{context} must contain a non-empty {field} string")
    return value


def validate_manifest(repo: Path, rule: PackageRule) -> PackageInfo:
    manifest_path = repo / rule.directory / "package.json"
    manifest = load_json(manifest_path)

    name = require_string(manifest, "name", manifest_path)
    if name != rule.name:
        raise ValueError(f"{manifest_path} name must be {rule.name}")

    version = require_string(manifest, "version", manifest_path)
    if not SEMVER_RE.match(version):
        raise ValueError(f"{manifest_path} version is not semver-like: {version}")

    if manifest.get("private") is True:
        raise ValueError(f"{manifest_path} must not set private=true for publication")

    require_string(manifest, "description", manifest_path)
    require_string(manifest, "license", manifest_path)

    publish_config = manifest.get("publishConfig")
    if not isinstance(publish_config, dict):
        raise ValueError(f"{manifest_path} must contain publishConfig")
    if publish_config.get("access") != "public":
        raise ValueError(f"{manifest_path} publishConfig.access must be public")

    repository = manifest.get("repository")
    if not isinstance(repository, dict) or repository.get("type") != "git":
        raise ValueError(f"{manifest_path} repository.type must be git")
    require_string(repository, "url", manifest_path)

    bugs = manifest.get("bugs")
    if not isinstance(bugs, dict):
        raise ValueError(f"{manifest_path} must contain bugs.url")
    require_string(bugs, "url", manifest_path)

    require_string(manifest, "homepage", manifest_path)

    return PackageInfo(name=name, version=version, directory=rule.directory)


def validate_required_token(env_name: str | None) -> None:
    if not env_name:
        return
    value = os.environ.get(env_name, "")
    if not value.strip():
        raise ValueError(f"{env_name} is required for tagged npm publication")
    if not is_single_line_token_value(value):
        raise ValueError(
            f"{env_name} must be a single-line token value without whitespace or control characters"
        )


def is_single_line_token_value(value: str) -> bool:
    return all(character > " " and character != "\x7f" for character in value)


def npm_version_exists(npm: str, package: PackageInfo) -> bool:
    result = subprocess.run(
        [npm, "view", f"{package.name}@{package.version}", "version", "--json"],
        check=False,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode == 0:
        try:
            reported = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"npm registry returned invalid JSON for {package.name}@{package.version}: {exc}"
            ) from exc
        if reported == package.version:
            return True
        raise ValueError(
            f"npm registry returned unexpected version for {package.name}@{package.version}"
        )

    combined = f"{result.stdout}\n{result.stderr}".lower()
    if "e404" in combined or "404 not found" in combined:
        return False
    raise ValueError(f"npm registry availability check failed for {package.name}@{package.version}")


def check_registry_availability(npm: str, packages: tuple[PackageInfo, ...]) -> None:
    existing: list[str] = []
    for package in packages:
        if npm_version_exists(npm, package):
            existing.append(f"{package.name}@{package.version}")
    if existing:
        raise ValueError(
            "npm package version already exists; refusing to start a partial publish: "
            + ", ".join(existing)
        )


def validate_package_version_consistency(packages: tuple[PackageInfo, ...]) -> None:
    versions = sorted({package.version for package in packages})
    if len(versions) > 1:
        details = ", ".join(f"{package.name}@{package.version}" for package in packages)
        raise ValueError(
            "npm package versions must match before publication: "
            + details
        )


def selected_packages(names: list[str]) -> tuple[PackageRule, ...]:
    if not names:
        return PACKAGES
    by_name = {package.name: package for package in PACKAGES}
    missing = sorted(name for name in names if name not in by_name)
    if missing:
        raise ValueError(f"unknown package selector(s): {', '.join(missing)}")
    return tuple(by_name[name] for name in names)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--package",
        action="append",
        choices=[package.name for package in PACKAGES],
        default=[],
        help="limit verification to one package; may be repeated",
    )
    parser.add_argument(
        "--registry-check",
        action="store_true",
        help="query npm and fail before publishing if any target version already exists",
    )
    parser.add_argument(
        "--require-token-env",
        default="",
        help="require this environment variable to be non-empty without printing its value",
    )
    parser.add_argument(
        "--npm",
        default="",
        help=argparse.SUPPRESS,
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        repo = Path(__file__).resolve().parents[1]
        os.chdir(repo)

        packages = tuple(validate_manifest(repo, rule) for rule in selected_packages(args.package))
        validate_package_version_consistency(packages)
        validate_required_token(args.require_token_env or None)

        if args.registry_check:
            npm = args.npm or find_npm()
            check_registry_availability(npm, packages)

    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"npm publish preflight failed: {exc}", file=sys.stderr)
        return 1

    checked = ", ".join(f"{package.name}@{package.version}" for package in packages)
    registry_note = " with registry availability" if args.registry_check else ""
    print(f"npm publish preflight passed{registry_note}: {checked}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
