#!/usr/bin/env python3
"""Audit GitHub Actions release secret names before creating a release tag."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REQUIRED_RELEASE_SECRETS: tuple[str, ...] = (
    "CONU_WINDOWS_SIGN_CERT_PFX_BASE64",
    "CONU_WINDOWS_SIGN_CERT_PASSWORD",
    "CONU_MACOS_DEVELOPER_ID_APPLICATION_P12_BASE64",
    "CONU_MACOS_DEVELOPER_ID_APPLICATION_PASSWORD",
    "CONU_MACOS_CODESIGN_IDENTITY",
    "CONU_MACOS_NOTARY_APPLE_ID",
    "CONU_MACOS_NOTARY_TEAM_ID",
    "CONU_MACOS_NOTARY_PASSWORD",
    "CONU_LINUX_GPG_PRIVATE_KEY_BASE64",
    "CONU_LINUX_GPG_PASSPHRASE",
    "CONU_LINUX_GPG_KEY_ID",
    "CONU_LINUX_GPG_KEY_FINGERPRINT",
    "NPM_TOKEN",
)


@dataclass(frozen=True)
class SecretReadiness:
    repo: str
    required: tuple[str, ...]
    present: tuple[str, ...]
    missing: tuple[str, ...]

    @property
    def ready(self) -> bool:
        return not self.missing

    def as_json(self) -> dict[str, Any]:
        return {
            "repo": self.repo,
            "ready": self.ready,
            "required": list(self.required),
            "present": list(self.present),
            "missing": list(self.missing),
        }


def find_gh() -> str:
    candidates = ("gh.exe", "gh") if sys.platform == "win32" else ("gh",)
    for candidate in candidates:
        path = shutil.which(candidate)
        if path:
            return path
    raise ValueError("GitHub CLI executable was not found on PATH")


def run_gh_json(gh: str, args: list[str], description: str) -> Any:
    result = subprocess.run(
        [gh, *args],
        check=False,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise ValueError(
            f"{description} failed with exit code {result.returncode}; run gh auth status"
        )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{description} returned invalid JSON: {exc}") from exc


def infer_repo(gh: str) -> str:
    env_repo = os.environ.get("GH_REPO", "").strip()
    if env_repo:
        return env_repo

    payload = run_gh_json(
        gh,
        ["repo", "view", "--json", "nameWithOwner"],
        "gh repo view",
    )
    if not isinstance(payload, dict):
        raise ValueError("gh repo view returned an unexpected payload")
    repo = payload.get("nameWithOwner")
    if not isinstance(repo, str) or not repo.strip():
        raise ValueError("gh repo view did not return nameWithOwner")
    return repo.strip()


def load_secret_names(repo: str, gh: str) -> set[str]:
    payload = run_gh_json(
        gh,
        ["secret", "list", "--repo", repo, "--json", "name"],
        "gh secret list",
    )
    if not isinstance(payload, list):
        raise ValueError("gh secret list returned an unexpected payload")

    names: set[str] = set()
    for item in payload:
        if not isinstance(item, dict):
            raise ValueError("gh secret list returned a non-object secret entry")
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("gh secret list returned a secret entry without a name")
        names.add(name.strip())
    return names


def audit_secret_names(repo: str, configured_names: set[str]) -> SecretReadiness:
    present = tuple(name for name in REQUIRED_RELEASE_SECRETS if name in configured_names)
    missing = tuple(name for name in REQUIRED_RELEASE_SECRETS if name not in configured_names)
    return SecretReadiness(
        repo=repo,
        required=REQUIRED_RELEASE_SECRETS,
        present=present,
        missing=missing,
    )


def print_text_report(report: SecretReadiness) -> None:
    if report.ready:
        print(
            "GitHub release secret readiness passed: "
            f"{len(report.present)}/{len(report.required)} required secret names configured "
            f"for {report.repo}"
        )
        return

    print(
        "GitHub release secret readiness failed: "
        f"{len(report.missing)}/{len(report.required)} required secret names missing "
        f"for {report.repo}",
        file=sys.stderr,
    )
    for name in report.missing:
        print(f"missing: {name}", file=sys.stderr)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo",
        default="",
        help="GitHub repository in owner/name form; defaults to GH_REPO or gh repo view",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print a machine-readable report containing secret names only",
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

        gh = args.gh or find_gh()
        repo = args.repo.strip() or infer_repo(gh)
        report = audit_secret_names(repo, load_secret_names(repo, gh))
    except (OSError, ValueError) as exc:
        print(f"GitHub release secret readiness failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report.as_json(), indent=2, sort_keys=True))
    else:
        print_text_report(report)
    return 0 if report.ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
