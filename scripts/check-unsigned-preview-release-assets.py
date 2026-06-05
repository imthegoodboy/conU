#!/usr/bin/env python3
"""Verify unsigned preview release assets before manual test publication."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from github_release_secrets import find_gh, infer_repo, normalize_repo, run_gh_json
from json_safety import load_json_object


SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
PREVIEW_TAG_RE = re.compile(r"^preview-[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")
PREVIEW_ARCHIVE_RE = re.compile(
    r"^conu-(?P<version>\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)-"
    r"(?P<target>windows-x64|macos-x64|macos-arm64|linux-x64|linux-arm64)"
    r"(?P<extension>\.zip|\.tar\.gz)(?P<sidecar>\.sha256)?$"
)
SHA256_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PREVIEW_TARGETS = (
    ("windows-x64", ".zip"),
    ("macos-x64", ".zip"),
    ("macos-arm64", ".zip"),
    ("linux-x64", ".tar.gz"),
    ("linux-arm64", ".tar.gz"),
)
FORBIDDEN_ASSET_MARKERS = (
    ".asc",
    ".mailbox",
    ".npmrc",
    ".session",
    "apt-repository",
    "ciphertext",
    "conu_home",
    "gpg",
    "hosted-linux-repository",
    "inbox",
    "key",
    "logs",
    "messages",
    "node.toml",
    "nupkg",
    "package-manager",
    "payload",
    "private",
    "repository-metadata",
    "routes",
    "runtime",
    "secret",
    "security",
    "sessions",
    "token",
    "trust.toml",
    "update-policy",
)
FORBIDDEN_ASSET_FAILURE_GUARDS = "assetNameDisplayed=false markerDisplayed=false contentsDisplayed=false"


@dataclass(frozen=True)
class UnsignedPreviewAssetReadiness:
    repo: str
    tag: str
    version: str
    ready: bool
    draft: bool
    prerelease: bool
    required_assets: tuple[str, ...]
    present_assets: tuple[str, ...]
    missing_assets: tuple[str, ...]
    duplicate_assets: tuple[str, ...]
    invalid_assets: tuple[str, ...]
    forbidden_assets: tuple[str, ...]
    unexpected_assets: tuple[str, ...]
    issues: tuple[str, ...]

    def as_json(self) -> dict[str, Any]:
        return {
            "schema": "conu.unsignedPreviewReleaseAssets.v1",
            "repo": self.repo,
            "tag": self.tag,
            "version": self.version,
            "ready": self.ready,
            "release": {
                "draft": self.draft,
                "prerelease": self.prerelease,
            },
            "requiredAssetCount": len(self.required_assets),
            "presentAssetCount": len(self.present_assets),
            "actualAssetCount": len(self.present_assets) + len(self.unexpected_assets),
            "missingAssets": list(self.missing_assets),
            "duplicateAssets": list(self.duplicate_assets),
            "invalidAssets": list(self.invalid_assets),
            "forbiddenAssets": list(self.forbidden_assets),
            "unexpectedAssets": list(self.unexpected_assets),
            "issues": list(self.issues),
            "payloadDisplayed": False,
            "tokenDisplayed": False,
            "tokenHashDisplayed": False,
            "keyMaterialDisplayed": False,
            "contentsDisplayed": False,
            "secretValuesDisplayed": False,
            "forbiddenAssetNameDisplayed": False,
            "forbiddenAssetMarkerDisplayed": False,
        }


def validate_preview_tag(tag: str) -> str:
    value = tag.strip()
    if not PREVIEW_TAG_RE.fullmatch(value):
        raise ValueError(f"unsigned preview release tag is invalid: {tag}")
    return value


def expected_preview_asset_names(version: str) -> tuple[str, ...]:
    if not SEMVER_RE.fullmatch(version):
        raise ValueError(f"release version is not semver-like: {version}")
    names: list[str] = []
    for target, extension in PREVIEW_TARGETS:
        archive = f"conu-{version}-{target}{extension}"
        names.extend([archive, f"{archive}.sha256"])
    return tuple(names)


def release_tag_name(payload: dict[str, Any]) -> str:
    value = payload.get("tag_name", payload.get("tagName"))
    if not isinstance(value, str) or not value.strip():
        raise ValueError("GitHub Release metadata did not include a tag name")
    return value.strip()


def release_bool(payload: dict[str, Any], api_field: str, view_field: str) -> bool:
    value = payload.get(api_field, payload.get(view_field, False))
    if not isinstance(value, bool):
        raise ValueError(f"GitHub Release metadata field {api_field} must be boolean")
    return value


def asset_name(asset: dict[str, Any]) -> str:
    value = asset.get("name")
    if not isinstance(value, str) or not value:
        raise ValueError("GitHub Release asset entry did not include a non-empty name")
    has_control = any(ord(character) <= 32 or ord(character) == 127 for character in value)
    if value != value.strip() or has_control:
        raise ValueError("GitHub Release asset names must not contain whitespace or control characters")
    return value


def asset_size_issue(asset: dict[str, Any], name: str) -> str | None:
    if "size" not in asset:
        return None
    value = asset["size"]
    if not isinstance(value, int) or isinstance(value, bool):
        return f"{name}: size is not an integer"
    if value <= 0:
        return f"{name}: size must be greater than zero"
    return None


def asset_state_issue(asset: dict[str, Any], name: str) -> str | None:
    if "state" not in asset:
        return None
    value = asset["state"]
    if not isinstance(value, str) or value != "uploaded":
        return f"{name}: state must be uploaded"
    return None


def asset_local_issue(asset: dict[str, Any], name: str, *, include_detail: bool = True) -> str | None:
    value = asset.get("localInvalidReason")
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        return f"{name}: local invalid reason must be a non-empty string"
    if not include_detail:
        return f"{name}: local invalid reason was provided"
    return f"{name}: {value.strip()}"


def asset_digest_issue(repo: str, asset: dict[str, Any], name: str) -> str | None:
    if repo == "local/dist" and asset.get("localAsset") is True:
        return None
    value = asset.get("digest")
    if not isinstance(value, str) or not SHA256_DIGEST_RE.fullmatch(value):
        return f"{name}: digest must be sha256 metadata"
    return None


def forbidden_asset_marker(name: str) -> str | None:
    lower = name.lower()
    if "/" in name or "\\" in name or name in {".", ".."} or ".." in name.split("."):
        return "path separator or traversal marker"
    for marker in FORBIDDEN_ASSET_MARKERS:
        if marker in lower:
            return marker
    return None


def forbidden_asset_issue() -> str:
    return f"release asset name contains forbidden marker; {FORBIDDEN_ASSET_FAILURE_GUARDS}"


def report_asset_name(name: str) -> str:
    if forbidden_asset_marker(name) is not None:
        return f"release asset; {FORBIDDEN_ASSET_FAILURE_GUARDS}"
    return name


def infer_preview_version(names: tuple[str, ...]) -> tuple[str, tuple[str, ...]]:
    versions: set[str] = set()
    invalid_names: list[str] = []
    for name in names:
        marker = forbidden_asset_marker(name)
        if marker is not None:
            continue
        match = PREVIEW_ARCHIVE_RE.fullmatch(name)
        if match is None:
            invalid_names.append(f"{name}: not an unsigned preview platform archive or checksum")
            continue
        target = match.group("target")
        extension = match.group("extension")
        if (target, extension) not in PREVIEW_TARGETS:
            invalid_names.append(f"{name}: target/extension pair is not allowed")
            continue
        versions.add(match.group("version"))
    if len(versions) != 1:
        invalid_names.append("unsigned preview assets must contain exactly one release version")
        return "", tuple(invalid_names)
    return next(iter(versions)), tuple(invalid_names)


def audit_preview_assets(
    repo: str,
    tag: str,
    payload: dict[str, Any],
) -> UnsignedPreviewAssetReadiness:
    if not isinstance(payload, dict):
        raise ValueError("GitHub Release metadata must be a JSON object")

    expected_tag = validate_preview_tag(tag)
    actual_tag = release_tag_name(payload)
    if actual_tag != expected_tag:
        raise ValueError(f"GitHub Release tag mismatch: expected {expected_tag}, found {actual_tag}")

    assets_payload = payload.get("assets")
    if not isinstance(assets_payload, list):
        raise ValueError("GitHub Release metadata did not include an assets list")

    names: list[str] = []
    invalid: list[str] = []
    forbidden: list[str] = []
    for asset in assets_payload:
        if not isinstance(asset, dict):
            raise ValueError("GitHub Release assets must be JSON objects")
        name = asset_name(asset)
        marker = forbidden_asset_marker(name)
        display_name = report_asset_name(name)
        names.append(name)

        size_issue = asset_size_issue(asset, display_name)
        if size_issue:
            invalid.append(size_issue)
        state_issue = asset_state_issue(asset, display_name)
        if state_issue:
            invalid.append(state_issue)
        local_issue = asset_local_issue(asset, display_name, include_detail=marker is None)
        if local_issue:
            invalid.append(local_issue)
        digest_issue = asset_digest_issue(repo, asset, display_name)
        if digest_issue:
            invalid.append(digest_issue)

        if marker is not None:
            forbidden.append(forbidden_asset_issue())

    name_tuple = tuple(names)
    version, version_issues = infer_preview_version(name_tuple)
    invalid.extend(version_issues)
    required = expected_preview_asset_names(version) if version else ()
    required_set = set(required)
    present_set = set(names)
    missing = tuple(name for name in required if name not in present_set)
    present = tuple(name for name in required if name in present_set)
    duplicates = tuple(sorted(report_asset_name(name) for name, count in Counter(names).items() if count > 1))
    unexpected = tuple(report_asset_name(name) for name in names if name not in required_set)

    draft = release_bool(payload, "draft", "isDraft")
    prerelease = release_bool(payload, "prerelease", "isPrerelease")

    issues: list[str] = []
    if draft:
        issues.append("unsigned preview release must not be a draft")
    if not prerelease:
        issues.append("unsigned preview release must be marked prerelease")
    if missing:
        issues.append("unsigned preview release is missing required platform assets")
    if duplicates:
        issues.append("unsigned preview release contains duplicate asset names")
    if invalid:
        issues.append("unsigned preview release contains invalid asset metadata")
    if forbidden:
        issues.append("unsigned preview release contains forbidden asset names")
    if unexpected:
        issues.append("unsigned preview release contains unexpected assets")

    return UnsignedPreviewAssetReadiness(
        repo=repo,
        tag=expected_tag,
        version=version,
        ready=not (issues or missing or duplicates or invalid or forbidden or unexpected),
        draft=draft,
        prerelease=prerelease,
        required_assets=required,
        present_assets=present,
        missing_assets=missing,
        duplicate_assets=duplicates,
        invalid_assets=tuple(invalid),
        forbidden_assets=tuple(forbidden),
        unexpected_assets=unexpected,
        issues=tuple(issues),
    )


def load_release_assets(repo: str, release_id: int, gh: str) -> list[dict[str, Any]]:
    payload = run_gh_json(
        gh,
        [
            "api",
            "--paginate",
            "--slurp",
            f"repos/{repo}/releases/{release_id}/assets?per_page=100",
        ],
        "gh api unsigned preview release assets",
    )
    if not isinstance(payload, list):
        raise ValueError("gh api unsigned preview release assets returned an unexpected payload")
    pages: list[Any]
    if all(isinstance(page, list) for page in payload):
        pages = payload
    else:
        pages = [payload]

    assets: list[dict[str, Any]] = []
    for page in pages:
        if not isinstance(page, list):
            raise ValueError("gh api unsigned preview release assets returned a non-list page")
        for asset in page:
            if not isinstance(asset, dict):
                raise ValueError("gh api unsigned preview release assets returned a non-object asset")
            assets.append(asset)
    return assets


def load_release_metadata(repo: str, tag: str, gh: str) -> dict[str, Any]:
    payload = run_gh_json(
        gh,
        ["api", f"repos/{repo}/releases/tags/{tag}"],
        "gh api unsigned preview release metadata",
    )
    if not isinstance(payload, dict):
        raise ValueError("gh api unsigned preview release metadata returned an unexpected payload")
    release_id = payload.get("id")
    if not isinstance(release_id, int) or isinstance(release_id, bool):
        raise ValueError("gh api unsigned preview release metadata did not include a numeric release id")
    payload = dict(payload)
    payload["assets"] = load_release_assets(repo, release_id, gh)
    return payload


def load_release_json(path: Path) -> dict[str, Any]:
    try:
        payload = load_json_object(path, encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"failed to read release fixture JSON: {exc}") from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"release fixture JSON was invalid: {exc}") from exc
    return payload


def load_dist_metadata(tag: str, dist_dir: Path) -> dict[str, Any]:
    dist = dist_dir.expanduser()
    if dist.is_symlink():
        raise ValueError(f"unsigned preview dist directory must not be a symlink: {dist}")
    if not dist.exists() or not dist.is_dir():
        raise ValueError(f"unsigned preview dist directory does not exist: {dist}")

    assets: list[dict[str, Any]] = []
    for path in sorted(dist.iterdir(), key=lambda item: item.name):
        asset: dict[str, Any] = {"name": path.name, "state": "uploaded", "localAsset": True}
        try:
            stat_result = path.lstat()
        except OSError as exc:
            asset["size"] = 0
            asset["localInvalidReason"] = f"local asset could not be statted: {exc}"
            assets.append(asset)
            continue

        asset["size"] = stat_result.st_size
        if path.is_symlink():
            asset["localInvalidReason"] = "local asset must not be a symlink"
        elif not path.is_file():
            asset["localInvalidReason"] = "local asset must be a regular file"
        assets.append(asset)

    return {
        "tag_name": tag,
        "draft": False,
        "prerelease": True,
        "assets": assets,
    }


def print_text_report(report: UnsignedPreviewAssetReadiness) -> None:
    if report.ready:
        print(
            "Unsigned preview release asset readiness passed: "
            f"{report.repo}@{report.tag} has {len(report.required_assets)} required asset(s)"
        )
        return

    print(
        f"Unsigned preview release asset readiness failed for {report.repo}@{report.tag}",
        file=sys.stderr,
    )
    for issue in report.issues:
        print(f"issue: {issue}", file=sys.stderr)
    for name in report.missing_assets:
        print(f"missing: {name}", file=sys.stderr)
    for name in report.duplicate_assets:
        print(f"duplicate: {name}", file=sys.stderr)
    for issue in report.invalid_assets:
        print(f"invalid: {issue}", file=sys.stderr)
    for issue in report.forbidden_assets:
        print(f"forbidden: {issue}", file=sys.stderr)
    for name in report.unexpected_assets:
        print(f"unexpected: {name}", file=sys.stderr)


def default_tag() -> str:
    for name in ("CONU_PREVIEW_TAG", "PREVIEW_TAG"):
        value = os.environ.get(name, "").strip()
        if value:
            return value
    run_id = os.environ.get("GITHUB_RUN_ID", "").strip()
    if run_id:
        return f"preview-{run_id}"
    return "preview-local"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo",
        default="",
        help="GitHub repository in owner/name form; defaults to GH_REPO or gh repo view",
    )
    parser.add_argument(
        "--tag",
        default=default_tag(),
        help="preview tag to verify; defaults to CONU_PREVIEW_TAG, PREVIEW_TAG, or preview-$GITHUB_RUN_ID",
    )
    parser.add_argument(
        "--release-json",
        type=Path,
        default=None,
        help="read GitHub Release metadata from a JSON fixture instead of gh api",
    )
    parser.add_argument(
        "--dist-dir",
        type=Path,
        default=None,
        help="read local preview release asset files from a dist directory instead of gh api",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print a machine-readable readiness report",
    )
    parser.add_argument(
        "--gh",
        default="",
        help=argparse.SUPPRESS,
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        repo_root = Path(__file__).resolve().parents[1]
        os.chdir(repo_root)

        tag = validate_preview_tag(args.tag)
        gh = args.gh.strip()
        repo = args.repo.strip()
        if args.release_json is not None and args.dist_dir is not None:
            raise ValueError("--release-json and --dist-dir cannot be used together")

        if args.dist_dir is not None:
            repo = normalize_repo(repo or "local/dist")
            payload = load_dist_metadata(tag, args.dist_dir)
        else:
            if not repo:
                gh = gh or find_gh()
                repo = infer_repo(gh)
            repo = normalize_repo(repo)

            if args.release_json:
                payload = load_release_json(args.release_json)
            else:
                gh = gh or find_gh()
                payload = load_release_metadata(repo, tag, gh)

        if not repo:
            gh = gh or find_gh()
            repo = infer_repo(gh)
        repo = normalize_repo(repo)

        report = audit_preview_assets(repo, tag, payload)
    except (OSError, ValueError) as exc:
        print(f"Unsigned preview release asset readiness failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report.as_json(), indent=2, sort_keys=True))
    else:
        print_text_report(report)
    return 0 if report.ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
