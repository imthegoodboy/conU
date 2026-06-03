#!/usr/bin/env python3
"""Fail tagged releases before overwriting an existing GitHub Release."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from github_release_secrets import find_gh, infer_repo, normalize_repo


SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")


@dataclass(frozen=True)
class ReleaseClobberReadiness:
    repo: str
    tag: str
    ready: bool
    existing_release: bool
    allowed_existing_release: bool
    draft: bool
    prerelease: bool
    asset_count: int
    issues: tuple[str, ...]

    def as_json(self) -> dict[str, Any]:
        return {
            "repo": self.repo,
            "tag": self.tag,
            "ready": self.ready,
            "existingRelease": self.existing_release,
            "allowedExistingRelease": self.allowed_existing_release,
            "release": {
                "draft": self.draft,
                "prerelease": self.prerelease,
                "assetCount": self.asset_count,
            },
            "issues": list(self.issues),
        }


def validate_tag(tag: str) -> str:
    raw = tag.strip()
    if not raw.startswith("v"):
        raise ValueError(f"release tag must start with 'v': {tag}")
    version = raw[1:]
    if not SEMVER_RE.fullmatch(version):
        raise ValueError(f"release tag version is not semver-like: {tag}")
    return raw


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


def release_asset_count(payload: dict[str, Any]) -> int:
    assets = payload.get("assets", [])
    if not isinstance(assets, list):
        raise ValueError("GitHub Release metadata assets field must be a list")
    return len(assets)


def audit_release_clobber(
    repo: str,
    tag: str,
    payload: dict[str, Any] | None,
    *,
    allow_existing_release: bool = False,
) -> ReleaseClobberReadiness:
    expected_tag = validate_tag(tag)
    if payload is None:
        return ReleaseClobberReadiness(
            repo=repo,
            tag=expected_tag,
            ready=True,
            existing_release=False,
            allowed_existing_release=allow_existing_release,
            draft=False,
            prerelease=False,
            asset_count=0,
            issues=(),
        )
    if not isinstance(payload, dict):
        raise ValueError("GitHub Release metadata must be a JSON object or null")

    actual_tag = release_tag_name(payload)
    draft = release_bool(payload, "draft", "isDraft")
    prerelease = release_bool(payload, "prerelease", "isPrerelease")
    asset_count = release_asset_count(payload)

    issues: list[str] = []
    if actual_tag != expected_tag:
        issues.append(f"release tag is {actual_tag}, expected {expected_tag}")
    if not allow_existing_release:
        issues.append(
            "GitHub Release already exists for this tag; refusing to overwrite release assets"
        )

    return ReleaseClobberReadiness(
        repo=repo,
        tag=expected_tag,
        ready=not issues,
        existing_release=True,
        allowed_existing_release=allow_existing_release,
        draft=draft,
        prerelease=prerelease,
        asset_count=asset_count,
        issues=tuple(issues),
    )


def is_not_found_error(result: subprocess.CompletedProcess[str]) -> bool:
    combined = f"{result.stdout}\n{result.stderr}".lower()
    return "not found" in combined or "http 404" in combined or "status code: 404" in combined


def verify_repo_access(repo: str, gh: str) -> None:
    result = subprocess.run(
        [gh, "api", f"repos/{repo}"],
        check=False,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise ValueError(
            "gh api repository lookup failed with "
            f"exit code {result.returncode}; run gh auth status or check repository access"
        )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"gh api repository lookup returned invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("gh api repository lookup returned an unexpected payload")


def load_release_metadata(repo: str, tag: str, gh: str) -> dict[str, Any] | None:
    result = subprocess.run(
        [gh, "api", f"repos/{repo}/releases/tags/{tag}"],
        check=False,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        if is_not_found_error(result):
            verify_repo_access(repo, gh)
            return None
        raise ValueError(
            "gh api GitHub Release lookup failed with "
            f"exit code {result.returncode}; run gh auth status or check repository access"
        )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"gh api GitHub Release lookup returned invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("gh api GitHub Release lookup returned an unexpected payload")
    return payload


def load_release_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"failed to read release fixture JSON: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"release fixture JSON was invalid: {exc}") from exc
    if payload is None:
        return None
    if not isinstance(payload, dict):
        raise ValueError("release fixture JSON must contain an object or null")
    return payload


def print_text_report(report: ReleaseClobberReadiness) -> None:
    if report.ready:
        if report.existing_release:
            print(
                "GitHub Release clobber preflight passed with explicit allow: "
                f"{report.repo}@{report.tag} already exists with "
                f"{report.asset_count} asset record(s)"
            )
        else:
            print(
                "GitHub Release clobber preflight passed: "
                f"{report.repo}@{report.tag} has no existing release"
            )
        return

    print(
        f"GitHub Release clobber preflight failed for {report.repo}@{report.tag}",
        file=sys.stderr,
    )
    for issue in report.issues:
        print(f"issue: {issue}", file=sys.stderr)
    if report.existing_release:
        print(f"existingRelease: true; assetCount: {report.asset_count}", file=sys.stderr)


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
        help="read GitHub Release metadata from a JSON fixture instead of gh api; JSON null means absent",
    )
    parser.add_argument(
        "--allow-existing-release",
        action="store_true",
        help="report an existing release as ready; intended only for explicit maintainer recovery checks",
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

        tag = validate_tag(args.tag)
        gh = args.gh.strip()
        repo = args.repo.strip()
        if not repo:
            gh = gh or find_gh()
            repo = infer_repo(gh)
        repo = normalize_repo(repo)

        if args.release_json:
            payload = load_release_json(args.release_json)
        else:
            gh = gh or find_gh()
            payload = load_release_metadata(repo, tag, gh)

        report = audit_release_clobber(
            repo,
            tag,
            payload,
            allow_existing_release=args.allow_existing_release,
        )
    except (OSError, ValueError) as exc:
        print(f"GitHub Release clobber preflight failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report.as_json(), indent=2, sort_keys=True))
    else:
        print_text_report(report)
    return 0 if report.ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
