#!/usr/bin/env python3
"""Audit GitHub Actions release secrets before creating a release tag."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from github_release_secrets import (
    NPM_TOKEN_ROTATION_MARKER_VAR,
    NPM_TOKEN_ROTATION_REQUIRED_AFTER,
    NPM_TOKEN_SECRET_NAME,
    REQUIRED_RELEASE_SECRETS,
    SecretReadiness,
    audit_secret_names,
    find_gh,
    infer_repo,
    load_secret_metadata,
    load_secret_names,
    load_variable_values,
    normalize_repo,
)


REQUIRED_VARIABLE_VALUES = (NPM_TOKEN_ROTATION_MARKER_VAR,)
FULL_RELEASE_PROFILE = "tagged-release"
SIMPLE_LAUNCH_PROFILE = "simple-launch"
SIMPLE_LAUNCH_REQUIRED_SECRETS = (NPM_TOKEN_SECRET_NAME,)


@dataclass(frozen=True)
class SecretUpdatedAtReadiness:
    secret_name: str
    required_after: str
    updated_at: str
    ready: bool
    issues: tuple[str, ...]

    def as_json(self) -> dict[str, Any]:
        return {
            "checked": True,
            "ready": self.ready,
            "secretName": self.secret_name,
            "requiredAfter": self.required_after,
            "updatedAt": self.updated_at,
            "issues": list(self.issues),
            "payloadDisplayed": False,
            "tokenDisplayed": False,
            "tokenHashDisplayed": False,
            "keyMaterialDisplayed": False,
            "contentsDisplayed": False,
            "secretValuesDisplayed": False,
        }


@dataclass(frozen=True)
class ReleaseSecretReadiness:
    repo: str
    profile: str
    secrets: SecretReadiness
    npm_token_secret_updated_at: SecretUpdatedAtReadiness
    npm_rotation_marker: Any

    @property
    def ready(self) -> bool:
        return (
            self.secrets.ready
            and self.npm_token_secret_updated_at.ready
            and self.npm_rotation_marker.ready
        )

    def as_json(self) -> dict[str, Any]:
        return {
            "schema": "conu.githubReleaseSecretReadiness.v1",
            "repo": self.repo,
            "profile": self.profile,
            "ready": self.ready,
            "releaseSecrets": self.secrets.as_json(),
            "npmTokenSecretUpdatedAt": self.npm_token_secret_updated_at.as_json(),
            "npmTokenRotationMarker": self.npm_rotation_marker.as_json(),
            "payloadDisplayed": False,
            "tokenDisplayed": False,
            "tokenHashDisplayed": False,
            "keyMaterialDisplayed": False,
            "contentsDisplayed": False,
            "secretValuesDisplayed": False,
        }


def load_script_module(filename: str, module_name: str):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"could not load {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def parse_utc_timestamp(value: str, label: str) -> datetime:
    raw = value.strip()
    if not raw:
        raise ValueError(f"{label} timestamp must not be empty")
    if raw.endswith("Z"):
        raw = f"{raw[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise ValueError(f"{label} timestamp must be ISO-8601 with a timezone") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def render_utc_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def audit_npm_token_secret_updated_at(
    secret_updated_at: dict[str, str],
) -> SecretUpdatedAtReadiness:
    required = parse_utc_timestamp(
        NPM_TOKEN_ROTATION_REQUIRED_AFTER,
        f"{NPM_TOKEN_SECRET_NAME} required rotation",
    )
    rendered_required = render_utc_timestamp(required)
    updated_at = secret_updated_at.get(NPM_TOKEN_SECRET_NAME, "").strip()
    if not updated_at:
        return SecretUpdatedAtReadiness(
            secret_name=NPM_TOKEN_SECRET_NAME,
            required_after=rendered_required,
            updated_at="",
            ready=False,
            issues=(f"{NPM_TOKEN_SECRET_NAME} update timestamp is missing",),
        )

    try:
        observed = parse_utc_timestamp(updated_at, f"{NPM_TOKEN_SECRET_NAME} updatedAt")
    except ValueError:
        return SecretUpdatedAtReadiness(
            secret_name=NPM_TOKEN_SECRET_NAME,
            required_after=rendered_required,
            updated_at="",
            ready=False,
            issues=(f"{NPM_TOKEN_SECRET_NAME} update timestamp is invalid",),
        )

    rendered_observed = render_utc_timestamp(observed)
    if observed <= required:
        return SecretUpdatedAtReadiness(
            secret_name=NPM_TOKEN_SECRET_NAME,
            required_after=rendered_required,
            updated_at=rendered_observed,
            ready=False,
            issues=(f"{NPM_TOKEN_SECRET_NAME} was not updated after required timestamp",),
        )

    return SecretUpdatedAtReadiness(
        secret_name=NPM_TOKEN_SECRET_NAME,
        required_after=rendered_required,
        updated_at=rendered_observed,
        ready=True,
        issues=(),
    )


def audit_secret_names_for_required(
    repo: str,
    configured_names: set[str],
    required_names: tuple[str, ...],
) -> SecretReadiness:
    repo = normalize_repo(repo)
    present = tuple(name for name in required_names if name in configured_names)
    missing = tuple(name for name in required_names if name not in configured_names)
    return SecretReadiness(
        repo=repo,
        required=required_names,
        present=present,
        missing=missing,
    )


def audit_release_secret_readiness(
    repo: str,
    secret_names: set[str],
    variable_values: dict[str, str],
    secret_updated_at: dict[str, str],
    *,
    simple_launch: bool = False,
) -> ReleaseSecretReadiness:
    repo = normalize_repo(repo)
    profile = SIMPLE_LAUNCH_PROFILE if simple_launch else FULL_RELEASE_PROFILE
    secrets = (
        audit_secret_names_for_required(repo, secret_names, SIMPLE_LAUNCH_REQUIRED_SECRETS)
        if simple_launch
        else audit_secret_names(repo, secret_names)
    )
    gate_module = load_script_module(
        "check-release-secret-rotation-gate.py",
        "check_release_secret_rotation_gate_for_secret_readiness",
    )
    npm_token_secret_updated_at = audit_npm_token_secret_updated_at(secret_updated_at)
    npm_rotation_marker = gate_module.audit_rotation_marker(
        secret_name=NPM_TOKEN_SECRET_NAME,
        marker_env=NPM_TOKEN_ROTATION_MARKER_VAR,
        required_after=NPM_TOKEN_ROTATION_REQUIRED_AFTER,
        rotated_after=variable_values.get(NPM_TOKEN_ROTATION_MARKER_VAR, ""),
    )
    return ReleaseSecretReadiness(
        repo=repo,
        profile=profile,
        secrets=secrets,
        npm_token_secret_updated_at=npm_token_secret_updated_at,
        npm_rotation_marker=npm_rotation_marker,
    )


def print_text_report(report: ReleaseSecretReadiness) -> None:
    if report.ready:
        print(
            "GitHub release secret readiness passed: "
            f"{len(report.secrets.present)}/{len(report.secrets.required)} required secret names "
            f"and {report.npm_rotation_marker.marker_env} configured "
            f"for {report.repo} ({report.profile})"
        )
        return

    secret_name_status = (
        "ready"
        if report.secrets.ready
        else f"{len(report.secrets.missing)}/{len(report.secrets.required)} missing"
    )
    updated_at_status = "ready" if report.npm_token_secret_updated_at.ready else "not ready"
    marker_status = "ready" if report.npm_rotation_marker.ready else "not ready"
    print(
        "GitHub release secret readiness failed: "
        f"secret names {secret_name_status}; "
        f"{NPM_TOKEN_SECRET_NAME} updatedAt {updated_at_status}; "
        f"{NPM_TOKEN_ROTATION_MARKER_VAR} {marker_status} "
        f"for {report.repo} ({report.profile})",
        file=sys.stderr,
    )
    for name in report.secrets.missing:
        print(f"missing: {name}", file=sys.stderr)
    for issue in report.npm_token_secret_updated_at.issues:
        print(f"secret: {issue}", file=sys.stderr)
    for issue in report.npm_rotation_marker.issues:
        print(f"marker: {issue}", file=sys.stderr)
    if (
        report.profile == SIMPLE_LAUNCH_PROFILE
        and report.secrets.ready
        and (
            not report.npm_token_secret_updated_at.ready
            or not report.npm_rotation_marker.ready
        )
    ):
        print(
            "next: rotate NPM_TOKEN in GitHub Secrets, then run:",
            file=sys.stderr,
        )
        print(
            "python scripts\\set-github-release-secrets.py "
            f"--repo {report.repo} --simple-launch "
            "--set-npm-token-rotation-marker-from-secret-updated-at "
            "--confirm-npm-token-rotated",
            file=sys.stderr,
        )


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
        help="print a machine-readable report containing secret names and non-secret marker status",
    )
    parser.add_argument(
        "--simple-launch",
        action="store_true",
        help=(
            "check only the unpaid simple launch/testing secret gate: NPM_TOKEN plus "
            "its non-secret rotation marker; full tagged releases still require all signing secrets"
        ),
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
        repo = normalize_repo(args.repo.strip() or infer_repo(gh))
        secret_records = load_secret_metadata(repo, gh)
        report = audit_release_secret_readiness(
            repo,
            set(secret_records),
            load_variable_values(repo, gh, REQUIRED_VARIABLE_VALUES),
            {
                name: record.updated_at
                for name, record in secret_records.items()
            },
            simple_launch=args.simple_launch,
        )
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
