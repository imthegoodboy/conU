#!/usr/bin/env python3
"""Audit GitHub Actions release secrets before creating a release tag."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from dataclasses import dataclass
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
    load_secret_names,
    load_variable_values,
    normalize_repo,
)


REQUIRED_VARIABLE_VALUES = (NPM_TOKEN_ROTATION_MARKER_VAR,)


@dataclass(frozen=True)
class ReleaseSecretReadiness:
    repo: str
    secrets: SecretReadiness
    npm_rotation_marker: Any

    @property
    def ready(self) -> bool:
        return self.secrets.ready and self.npm_rotation_marker.ready

    def as_json(self) -> dict[str, Any]:
        return {
            "schema": "conu.githubReleaseSecretReadiness.v1",
            "repo": self.repo,
            "ready": self.ready,
            "releaseSecrets": self.secrets.as_json(),
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


def audit_release_secret_readiness(
    repo: str,
    secret_names: set[str],
    variable_values: dict[str, str],
) -> ReleaseSecretReadiness:
    repo = normalize_repo(repo)
    secrets = audit_secret_names(repo, secret_names)
    gate_module = load_script_module(
        "check-release-secret-rotation-gate.py",
        "check_release_secret_rotation_gate_for_secret_readiness",
    )
    npm_rotation_marker = gate_module.audit_rotation_marker(
        secret_name=NPM_TOKEN_SECRET_NAME,
        marker_env=NPM_TOKEN_ROTATION_MARKER_VAR,
        required_after=NPM_TOKEN_ROTATION_REQUIRED_AFTER,
        rotated_after=variable_values.get(NPM_TOKEN_ROTATION_MARKER_VAR, ""),
    )
    return ReleaseSecretReadiness(
        repo=repo,
        secrets=secrets,
        npm_rotation_marker=npm_rotation_marker,
    )


def print_text_report(report: ReleaseSecretReadiness) -> None:
    if report.ready:
        print(
            "GitHub release secret readiness passed: "
            f"{len(report.secrets.present)}/{len(report.secrets.required)} required secret names "
            f"and {report.npm_rotation_marker.marker_env} configured "
            f"for {report.repo}"
        )
        return

    print(
        "GitHub release secret readiness failed: "
        f"{len(report.secrets.missing)}/{len(report.secrets.required)} required secret names missing "
        f"for {report.repo}",
        file=sys.stderr,
    )
    for name in report.secrets.missing:
        print(f"missing: {name}", file=sys.stderr)
    for issue in report.npm_rotation_marker.issues:
        print(f"marker: {issue}", file=sys.stderr)


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
        report = audit_release_secret_readiness(
            repo,
            load_secret_names(repo, gh),
            load_variable_values(repo, gh, REQUIRED_VARIABLE_VALUES),
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
