#!/usr/bin/env python3
"""Validate conU release versions before packaging or publishing."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - CI uses Python 3.11+.
    print("Python 3.11+ is required for TOML parsing", file=sys.stderr)
    raise SystemExit(2)


SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
CRATE_MANIFESTS = (
    Path("crates/conu-cli/Cargo.toml"),
    Path("crates/conud/Cargo.toml"),
    Path("crates/conu-core/Cargo.toml"),
    Path("crates/conu-protocol/Cargo.toml"),
    Path("crates/conu-relay/Cargo.toml"),
    Path("crates/conu-sdk/Cargo.toml"),
    Path("crates/conu-mcp/Cargo.toml"),
)
NPM_MANIFESTS = (
    Path("packaging/npm/conu-cli/package.json"),
    Path("sdk/typescript/package.json"),
)


def read_toml(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def package_version(manifest: Path) -> str:
    data = read_toml(manifest)
    try:
        return str(data["package"]["version"])
    except KeyError as exc:
        raise ValueError(f"{manifest} does not contain package.version") from exc


def npm_version(manifest: Path) -> str:
    data = read_json(manifest)
    try:
        return str(data["version"])
    except KeyError as exc:
        raise ValueError(f"{manifest} does not contain version") from exc


def expected_tag_version() -> str | None:
    explicit = os.environ.get("CONU_RELEASE_TAG", "").strip()
    ref_type = os.environ.get("GITHUB_REF_TYPE", "").strip()
    ref_name = os.environ.get("GITHUB_REF_NAME", "").strip()

    tag = explicit
    if not tag and ref_type == "tag":
        tag = ref_name
    if not tag:
        return None
    if not tag.startswith("v"):
        raise ValueError(f"release tag must start with 'v': {tag}")
    version = tag[1:]
    if not version:
        raise ValueError("release tag is missing a version after 'v'")
    return version


def is_semver_like(version: str) -> bool:
    return SEMVER_RE.fullmatch(version) is not None


def main() -> int:
    try:
        repo = Path(__file__).resolve().parents[1]
        os.chdir(repo)

        versions: dict[str, str] = {}
        for manifest in CRATE_MANIFESTS:
            versions[str(manifest)] = package_version(manifest)
        for manifest in NPM_MANIFESTS:
            versions[str(manifest)] = npm_version(manifest)

        unique_versions = sorted(set(versions.values()))
        if len(unique_versions) != 1:
            print("release versions are inconsistent:", file=sys.stderr)
            for path, version in sorted(versions.items()):
                print(f"  {path}: {version}", file=sys.stderr)
            return 1

        release_version = unique_versions[0]
        if not is_semver_like(release_version):
            print(f"release version is not semver-like: {release_version}", file=sys.stderr)
            return 1

        tag_version = expected_tag_version()
        if tag_version is not None and tag_version != release_version:
            print(
                f"release tag v{tag_version} does not match package version {release_version}",
                file=sys.stderr,
            )
            return 1
    except (OSError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        print(f"release version check failed: {exc}", file=sys.stderr)
        return 1

    tag_note = f", tag v{tag_version}" if tag_version else ""
    print(f"release version check passed: {release_version}{tag_note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
