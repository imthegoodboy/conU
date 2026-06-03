"""Shared GitHub release-secret metadata and GitHub CLI helpers."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Any


NPM_TOKEN_SECRET_NAME = "NPM_TOKEN"
NPM_TOKEN_ROTATION_MARKER_VAR = "CONU_NPM_TOKEN_ROTATED_AFTER"
NPM_TOKEN_ROTATION_REQUIRED_AFTER = "2026-06-03T00:00:00Z"
REPO_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,98}[A-Za-z0-9])?$")
REPO_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")


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
    NPM_TOKEN_SECRET_NAME,
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


@dataclass(frozen=True)
class SecretMetadata:
    name: str
    updated_at: str


def find_gh() -> str:
    candidates = ("gh.exe", "gh") if sys.platform == "win32" else ("gh",)
    for candidate in candidates:
        path = shutil.which(candidate)
        if path:
            return path
    raise ValueError("GitHub CLI executable was not found on PATH")


def normalize_repo(repo: str) -> str:
    value = repo.strip()
    parts = value.split("/")
    if len(parts) != 2:
        raise ValueError("GitHub repository must be in owner/name form")
    owner, name = (part.strip() for part in parts)
    if not owner or not name:
        raise ValueError("GitHub repository must be in owner/name form")
    if name in {".", ".."}:
        raise ValueError("GitHub repository name is invalid")
    if not REPO_OWNER_RE.fullmatch(owner):
        raise ValueError("GitHub repository owner contains unsupported characters")
    if not REPO_NAME_RE.fullmatch(name):
        raise ValueError("GitHub repository name contains unsupported characters")
    return f"{owner}/{name}"


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
        return normalize_repo(env_repo)

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
    return normalize_repo(repo)


def load_secret_metadata(repo: str, gh: str) -> dict[str, SecretMetadata]:
    repo = normalize_repo(repo)
    payload = run_gh_json(
        gh,
        ["secret", "list", "--repo", repo, "--json", "name,updatedAt"],
        "gh secret list",
    )
    if not isinstance(payload, list):
        raise ValueError("gh secret list returned an unexpected payload")

    records: dict[str, SecretMetadata] = {}
    for item in payload:
        if not isinstance(item, dict):
            raise ValueError("gh secret list returned a non-object secret entry")
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("gh secret list returned a secret entry without a name")
        updated_at = item.get("updatedAt", "")
        if updated_at is not None and not isinstance(updated_at, str):
            raise ValueError("gh secret list returned a non-string updatedAt field")
        normalized_name = name.strip()
        records[normalized_name] = SecretMetadata(
            name=normalized_name,
            updated_at=(updated_at or "").strip(),
        )
    return records


def load_secret_names(repo: str, gh: str) -> set[str]:
    return set(load_secret_metadata(repo, gh))


def audit_secret_names(repo: str, configured_names: set[str]) -> SecretReadiness:
    repo = normalize_repo(repo)
    present = tuple(name for name in REQUIRED_RELEASE_SECRETS if name in configured_names)
    missing = tuple(name for name in REQUIRED_RELEASE_SECRETS if name not in configured_names)
    return SecretReadiness(
        repo=repo,
        required=REQUIRED_RELEASE_SECRETS,
        present=present,
        missing=missing,
    )
