#!/usr/bin/env python3
"""Verify tagged GitHub Release assets are public before npm publication."""

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
SHA256_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
FORBIDDEN_ASSET_MARKERS = (
    ".mailbox",
    ".session",
    "ciphertext",
    "conu_home",
    "inbox",
    "logs",
    "messages",
    "node.toml",
    "payload",
    "private",
    "routes",
    "runtime",
    "secret",
    "security",
    "sessions",
    "token",
    "trust.toml",
)
DEBIAN_ARCHES = {
    "linux-x64": "amd64",
    "linux-arm64": "arm64",
}
RPM_ARCHES = {
    "linux-x64": "x86_64",
    "linux-arm64": "aarch64",
}
STATIC_PACKAGE_MANAGER_ASSETS = (
    "conu.rb",
    "conu.json",
    "imthegoodboy.conU.yaml",
    "conu.spec",
)


@dataclass(frozen=True)
class ReleaseAssetReadiness:
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
        }


def debian_version(version: str) -> str:
    return version.replace("-", "~")


def rpm_version(version: str) -> str:
    return version.replace("-", "~").replace("+", "_")


def validate_tag(tag: str) -> tuple[str, str]:
    raw = tag.strip()
    if not raw.startswith("v"):
        raise ValueError(f"release tag must start with 'v': {tag}")
    version = raw[1:]
    if not SEMVER_RE.fullmatch(version):
        raise ValueError(f"release tag version is not semver-like: {tag}")
    return raw, version


def expected_release_asset_names(version: str) -> tuple[str, ...]:
    platform_archives = (
        f"conu-{version}-windows-x64.zip",
        f"conu-{version}-macos-x64.zip",
        f"conu-{version}-macos-arm64.zip",
        f"conu-{version}-linux-x64.tar.gz",
        f"conu-{version}-linux-arm64.tar.gz",
    )

    names: list[str] = []
    for archive in platform_archives:
        names.extend([archive, f"{archive}.sha256"])
        if "-linux-" in archive:
            names.append(f"{archive}.asc")

    names.extend(STATIC_PACKAGE_MANAGER_ASSETS)
    names.append(f"conu.{version}.nupkg")

    deb_version = debian_version(version)
    for target in DEBIAN_ARCHES:
        package = f"conu_{deb_version}_{DEBIAN_ARCHES[target]}.deb"
        names.extend([package, f"{package}.sha256", f"{package}.asc"])

    rpm_ver = rpm_version(version)
    for target in RPM_ARCHES:
        package = f"conu-{rpm_ver}-1.{RPM_ARCHES[target]}.rpm"
        names.extend([package, f"{package}.sha256", f"{package}.asc"])

    apt_metadata = f"conu-{deb_version}-apt-repository-metadata.zip"
    rpm_metadata = f"conu-{rpm_ver}-rpm-repository-metadata.zip"
    for metadata in (apt_metadata, rpm_metadata):
        names.extend([metadata, f"{metadata}.sha256", f"{metadata}.asc"])

    names.extend(["conu-linux-gpg-key.asc", "conu-linux-gpg-key.asc.sha256"])

    hosted_bundle = f"conu-{version}-hosted-linux-repositories.zip"
    hosted_site = f"conu-{version}-hosted-linux-repository-site.zip"
    for hosted in (hosted_bundle, hosted_site):
        names.extend([hosted, f"{hosted}.sha256", f"{hosted}.asc"])

    update_policy = f"conu-{version}-update-policy.json"
    names.extend([update_policy, f"{update_policy}.sha256", f"{update_policy}.asc"])

    submissions = f"conu-{version}-package-manager-submissions.zip"
    names.extend([submissions, f"{submissions}.sha256", f"{submissions}.asc"])

    duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
    if duplicates:
        raise ValueError(f"internal expected asset list contains duplicate(s): {', '.join(duplicates)}")
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


def asset_local_issue(asset: dict[str, Any], name: str) -> str | None:
    value = asset.get("localInvalidReason")
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        return f"{name}: local invalid reason must be a non-empty string"
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


def audit_release_assets(
    repo: str,
    tag: str,
    payload: dict[str, Any],
) -> ReleaseAssetReadiness:
    if not isinstance(payload, dict):
        raise ValueError("GitHub Release metadata must be a JSON object")

    expected_tag, version = validate_tag(tag)
    actual_tag = release_tag_name(payload)
    required_assets = expected_release_asset_names(version)
    required_set = set(required_assets)
    expected_prerelease = "-" in version

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
        names.append(name)

        size_issue = asset_size_issue(asset, name)
        if size_issue:
            invalid.append(size_issue)
        state_issue = asset_state_issue(asset, name)
        if state_issue:
            invalid.append(state_issue)
        local_issue = asset_local_issue(asset, name)
        if local_issue:
            invalid.append(local_issue)
        digest_issue = asset_digest_issue(repo, asset, name)
        if digest_issue:
            invalid.append(digest_issue)

        marker = forbidden_asset_marker(name)
        if marker:
            forbidden.append(f"{name}: matched forbidden marker {marker}")

    counts = Counter(names)
    present_set = set(names)
    missing = tuple(name for name in required_assets if name not in present_set)
    duplicates = tuple(sorted(name for name, count in counts.items() if count > 1))
    present = tuple(name for name in required_assets if name in present_set)
    unexpected = tuple(sorted(name for name in present_set - required_set))
    draft = release_bool(payload, "draft", "isDraft")
    prerelease = release_bool(payload, "prerelease", "isPrerelease")

    issues: list[str] = []
    if actual_tag != expected_tag:
        issues.append(f"release tag is {actual_tag}, expected {expected_tag}")
    if draft:
        issues.append("release is still a draft")
    if prerelease != expected_prerelease:
        if expected_prerelease:
            issues.append("release prerelease flag must be true for semver prerelease tags")
        else:
            issues.append("release prerelease flag must be false for stable tags")
    if missing:
        issues.append(f"missing {len(missing)} required release asset(s)")
    if duplicates:
        issues.append(f"found {len(duplicates)} duplicate release asset name(s)")
    if invalid:
        issues.append(f"found {len(invalid)} invalid release asset metadata issue(s)")
    if forbidden:
        issues.append(f"found {len(forbidden)} forbidden release asset name(s)")
    if unexpected:
        issues.append(f"found {len(unexpected)} unexpected release asset name(s)")

    return ReleaseAssetReadiness(
        repo=repo,
        tag=expected_tag,
        version=version,
        ready=not issues,
        draft=draft,
        prerelease=prerelease,
        required_assets=required_assets,
        present_assets=present,
        missing_assets=missing,
        duplicate_assets=duplicates,
        invalid_assets=tuple(invalid),
        forbidden_assets=tuple(forbidden),
        unexpected_assets=unexpected,
        issues=tuple(issues),
    )


def load_release_metadata(repo: str, tag: str, gh: str) -> dict[str, Any]:
    payload = run_gh_json(
        gh,
        ["api", f"repos/{repo}/releases/tags/{tag}"],
        "gh api GitHub Release metadata",
    )
    if not isinstance(payload, dict):
        raise ValueError("gh api GitHub Release metadata returned an unexpected payload")
    release_id = payload.get("id")
    if not isinstance(release_id, int) or isinstance(release_id, bool):
        raise ValueError("gh api GitHub Release metadata did not include a numeric release id")
    payload = dict(payload)
    payload["assets"] = load_release_assets(repo, release_id, gh)
    return payload


def load_release_assets(repo: str, release_id: int, gh: str) -> list[dict[str, Any]]:
    payload = run_gh_json(
        gh,
        [
            "api",
            "--paginate",
            "--slurp",
            f"repos/{repo}/releases/{release_id}/assets?per_page=100",
        ],
        "gh api GitHub Release assets",
    )
    if not isinstance(payload, list):
        raise ValueError("gh api GitHub Release assets returned an unexpected payload")
    pages: list[Any]
    if all(isinstance(page, list) for page in payload):
        pages = payload
    else:
        pages = [payload]

    assets: list[dict[str, Any]] = []
    for page in pages:
        if not isinstance(page, list):
            raise ValueError("gh api GitHub Release assets returned a non-list page")
        for asset in page:
            if not isinstance(asset, dict):
                raise ValueError("gh api GitHub Release assets returned a non-object asset")
            assets.append(asset)
    return assets


def load_release_json(path: Path) -> dict[str, Any]:
    try:
        payload = load_json_object(path, encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"failed to read release fixture JSON: {exc}") from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"release fixture JSON was invalid: {exc}") from exc
    return payload


def load_dist_metadata(tag: str, dist_dir: Path) -> dict[str, Any]:
    tag, version = validate_tag(tag)
    dist = dist_dir.expanduser()
    if dist.is_symlink():
        raise ValueError(f"release dist directory must not be a symlink: {dist}")
    if not dist.exists() or not dist.is_dir():
        raise ValueError(f"release dist directory does not exist: {dist}")

    assets: list[dict[str, Any]] = []
    for path in sorted(dist.iterdir(), key=lambda item: item.name):
        name = path.name
        asset: dict[str, Any] = {"name": name, "state": "uploaded", "localAsset": True}
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
        "prerelease": "-" in version,
        "assets": assets,
    }


def print_text_report(report: ReleaseAssetReadiness) -> None:
    if report.ready:
        print(
            "GitHub Release asset publication preflight passed: "
            f"{report.repo}@{report.tag} has {len(report.required_assets)} required asset(s)"
        )
        return

    print(
        f"GitHub Release asset publication preflight failed for {report.repo}@{report.tag}",
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
    for name in ("CONU_RELEASE_TAG", "GITHUB_REF_NAME", "TAG_NAME"):
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return ""


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
        help="release tag to verify; defaults to CONU_RELEASE_TAG, GITHUB_REF_NAME, or TAG_NAME",
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
        help="read local release asset files from a dist directory instead of gh api",
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

        tag, _version = validate_tag(args.tag)
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

        report = audit_release_assets(repo, tag, payload)
    except (OSError, ValueError) as exc:
        print(f"GitHub Release asset publication preflight failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report.as_json(), indent=2, sort_keys=True))
    else:
        print_text_report(report)
    return 0 if report.ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
