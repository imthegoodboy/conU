#!/usr/bin/env python3
"""Validate npm package dry-run contents before publication."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


MAX_ENTRY_BYTES = 1_000_000
MAX_PACKAGE_BYTES = 1_000_000
FORBIDDEN_PARTS = frozenset(
    {
        ".conu",
        ".git",
        ".github",
        "coverage",
        "dist",
        "logs",
        "messages",
        "node_modules",
        "routes",
        "runtime",
        "security",
        "sessions",
        "streams",
        "target",
        "vendor",
    }
)
FORBIDDEN_NAMES = frozenset(
    {
        ".env",
        ".env.local",
        ".npmrc",
        "node.toml",
        "runtime.toml",
        "trust.toml",
    }
)
FORBIDDEN_SUFFIXES = (".key", ".pem", ".p12", ".pfx", ".token", ".tgz", ".zip")


@dataclass(frozen=True)
class PackageRule:
    name: str
    directory: Path
    allowed_files: frozenset[str]


PACKAGES = (
    PackageRule(
        name="@conu/cli",
        directory=Path("packaging/npm/conu-cli"),
        allowed_files=frozenset(
            {
                "README.md",
                "bin/conu-mcp.js",
                "bin/conu-relay.js",
                "bin/conu.js",
                "bin/conud.js",
                "lib/archive-preflight.js",
                "lib/download-limits.js",
                "lib/download-policy.js",
                "lib/platform.js",
                "lib/run.js",
                "package.json",
                "scripts/check-archive-preflight.js",
                "scripts/check-download-limits.js",
                "scripts/check-download-policy.js",
                "scripts/install.js",
            }
        ),
    ),
    PackageRule(
        name="@conu/sdk",
        directory=Path("sdk/typescript"),
        allowed_files=frozenset(
            {
                "README.md",
                "package.json",
                "src/browser.d.ts",
                "src/browser.js",
                "src/index.d.ts",
                "src/index.js",
            }
        ),
    ),
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


def normalize_pack_path(raw_path: Any) -> str:
    if not isinstance(raw_path, str) or not raw_path:
        raise ValueError("npm pack reported an empty or non-string file path")
    if "\\" in raw_path:
        raise ValueError(f"npm pack path uses backslash separators: {raw_path}")
    path = PurePosixPath(raw_path)
    if path.is_absolute():
        raise ValueError(f"npm pack path is absolute: {raw_path}")
    if any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(f"npm pack path is not normalized: {raw_path}")
    return "/".join(path.parts)


def reject_forbidden_path(path: str) -> None:
    parts = PurePosixPath(path).parts
    lower_parts = {part.lower() for part in parts}
    forbidden_parts = sorted(lower_parts & FORBIDDEN_PARTS)
    if forbidden_parts:
        raise ValueError(f"{path} contains forbidden package path component {forbidden_parts[0]}")

    name = parts[-1].lower()
    if name in FORBIDDEN_NAMES or name.startswith(".env."):
        raise ValueError(f"{path} contains forbidden package file name")
    if name.endswith(FORBIDDEN_SUFFIXES):
        raise ValueError(f"{path} contains forbidden package file suffix")


def run_npm_pack(npm: str, package_dir: Path) -> dict[str, Any]:
    result = subprocess.run(
        [npm, "pack", "--dry-run", "--json"],
        cwd=package_dir,
        check=False,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="")
        raise ValueError(f"npm pack dry-run failed in {package_dir}")

    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"npm pack dry-run did not return JSON for {package_dir}: {exc}") from exc

    if not isinstance(report, list) or len(report) != 1 or not isinstance(report[0], dict):
        raise ValueError(f"npm pack dry-run returned an unexpected report shape for {package_dir}")
    return report[0]


def validate_size(field: str, value: Any, limit: int, context: str) -> None:
    if not isinstance(value, int) or value < 0:
        raise ValueError(f"{context} reported invalid {field}")
    if value > limit:
        raise ValueError(f"{context} reported {field} above {limit} bytes")


def validate_package(repo: Path, npm: str, rule: PackageRule) -> int:
    package_dir = repo / rule.directory
    manifest = load_json(package_dir / "package.json")
    if manifest.get("name") != rule.name:
        raise ValueError(f"{rule.directory}/package.json name must be {rule.name}")
    version = manifest.get("version")
    if not isinstance(version, str) or not version:
        raise ValueError(f"{rule.directory}/package.json must contain a non-empty version")

    report = run_npm_pack(npm, package_dir)
    if report.get("name") != rule.name:
        raise ValueError(f"{rule.name} npm pack reported unexpected package name")
    if report.get("version") != version:
        raise ValueError(f"{rule.name} npm pack version does not match package.json")
    if report.get("id") != f"{rule.name}@{version}":
        raise ValueError(f"{rule.name} npm pack reported unexpected package id")

    filename = report.get("filename")
    if not isinstance(filename, str) or "/" in filename or "\\" in filename or not filename.endswith(".tgz"):
        raise ValueError(f"{rule.name} npm pack reported an unsafe tarball filename")

    validate_size("package size", report.get("size"), MAX_PACKAGE_BYTES, rule.name)
    validate_size("unpacked size", report.get("unpackedSize"), MAX_PACKAGE_BYTES, rule.name)

    bundled = report.get("bundled")
    if bundled not in ([], None):
        raise ValueError(f"{rule.name} npm package must not include bundled dependencies")

    files = report.get("files")
    if not isinstance(files, list):
        raise ValueError(f"{rule.name} npm pack report is missing files")

    actual_files: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict):
            raise ValueError(f"{rule.name} npm pack reported a non-object file entry")
        path = normalize_pack_path(entry.get("path"))
        reject_forbidden_path(path)
        validate_size("file size", entry.get("size"), MAX_ENTRY_BYTES, f"{rule.name}:{path}")
        actual_files.add(path)

    if len(actual_files) != len(files):
        raise ValueError(f"{rule.name} npm pack reported duplicate file paths")

    if report.get("entryCount") != len(actual_files):
        raise ValueError(f"{rule.name} npm pack entryCount does not match files")

    missing = sorted(rule.allowed_files - actual_files)
    extra = sorted(actual_files - rule.allowed_files)
    if missing or extra:
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("unexpected " + ", ".join(extra))
        raise ValueError(f"{rule.name} npm package contents changed: {'; '.join(details)}")

    print(f"{rule.name} package contents verified: {len(actual_files)} files")
    return len(actual_files)


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
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        repo = Path(__file__).resolve().parents[1]
        npm = find_npm()
        total = 0
        for package in selected_packages(args.package):
            total += validate_package(repo, npm, package)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"npm package content check failed: {exc}", file=sys.stderr)
        return 1

    print(f"npm package content check passed: {total} files verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
