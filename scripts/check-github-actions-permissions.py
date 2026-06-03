#!/usr/bin/env python3
"""Audit GitHub Actions repository permissions for production release hygiene."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from github_release_secrets import find_gh, infer_repo, normalize_repo


DEFAULT_REQUIRED_SELECTED_PATTERNS = ("dtolnay/rust-toolchain@stable",)
BROAD_PATTERNS = {
    "*",
    "*@*",
    "*/*",
    "*/*@*",
    "**",
    "**@*",
}


@dataclass(frozen=True)
class ActionsPermissionsReadiness:
    repo: str
    ready: bool
    actions_enabled: bool
    allowed_actions: str
    sha_pinning_required: bool
    default_workflow_permissions: str
    can_approve_pull_request_reviews: bool
    github_owned_allowed: bool
    verified_allowed: bool
    patterns_allowed: tuple[str, ...]
    required_patterns: tuple[str, ...]
    missing_patterns: tuple[str, ...]
    extra_patterns: tuple[str, ...]
    issues: tuple[str, ...]

    def as_json(self) -> dict[str, Any]:
        return {
            "schema": "conu.githubActionsPermissions.v1",
            "repo": self.repo,
            "ready": self.ready,
            "actionsEnabled": self.actions_enabled,
            "allowedActions": self.allowed_actions,
            "shaPinningRequired": self.sha_pinning_required,
            "defaultWorkflowPermissions": self.default_workflow_permissions,
            "canApprovePullRequestReviews": self.can_approve_pull_request_reviews,
            "githubOwnedAllowed": self.github_owned_allowed,
            "verifiedAllowed": self.verified_allowed,
            "patternsAllowed": list(self.patterns_allowed),
            "requiredPatterns": list(self.required_patterns),
            "missingPatterns": list(self.missing_patterns),
            "extraPatterns": list(self.extra_patterns),
            "issues": list(self.issues),
            "payloadDisplayed": False,
            "tokenDisplayed": False,
            "tokenHashDisplayed": False,
            "keyMaterialDisplayed": False,
            "contentsDisplayed": False,
        }


def run_gh_json(gh: str, args: list[str], description: str) -> dict[str, Any]:
    result = subprocess.run(
        [gh, *args],
        check=False,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise ValueError(f"{description} failed with exit code {result.returncode}; run gh auth status")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{description} returned invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{description} returned an unexpected payload")
    return payload


def load_json_fixture(path: Path, description: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"failed to read {description}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{description} was invalid: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{description} must contain a JSON object")
    return payload


def load_actions_permissions(repo: str, gh: str) -> dict[str, Any]:
    return run_gh_json(
        gh,
        ["api", f"repos/{repo}/actions/permissions"],
        "gh api GitHub Actions permissions",
    )


def load_workflow_permissions(repo: str, gh: str) -> dict[str, Any]:
    return run_gh_json(
        gh,
        ["api", f"repos/{repo}/actions/permissions/workflow"],
        "gh api GitHub workflow permissions",
    )


def load_selected_actions(repo: str, gh: str) -> dict[str, Any]:
    return run_gh_json(
        gh,
        ["api", f"repos/{repo}/actions/permissions/selected-actions"],
        "gh api selected GitHub Actions permissions",
    )


def normalize_patterns(patterns: tuple[str, ...] | list[Any]) -> tuple[str, ...]:
    normalized = {
        item.strip()
        for item in patterns
        if isinstance(item, str) and item.strip()
    }
    return tuple(sorted(normalized))


def audit_actions_permissions(
    *,
    repo: str,
    actions_payload: dict[str, Any],
    workflow_payload: dict[str, Any],
    selected_actions_payload: dict[str, Any] | None,
    required_patterns: tuple[str, ...],
    require_selected_actions: bool = True,
    allow_verified_actions: bool = False,
    allow_extra_patterns: bool = False,
    require_sha_pinning: bool = False,
) -> ActionsPermissionsReadiness:
    required = normalize_patterns(required_patterns)
    issues: list[str] = []

    actions_enabled = actions_payload.get("enabled") is True
    allowed_actions = actions_payload.get("allowed_actions")
    allowed_actions_value = allowed_actions if isinstance(allowed_actions, str) else ""
    sha_pinning_required = actions_payload.get("sha_pinning_required") is True

    default_workflow_permissions = workflow_payload.get("default_workflow_permissions")
    default_workflow_permissions_value = (
        default_workflow_permissions
        if isinstance(default_workflow_permissions, str)
        else ""
    )
    can_approve = workflow_payload.get("can_approve_pull_request_reviews") is True

    github_owned_allowed = False
    verified_allowed = False
    patterns_allowed: tuple[str, ...] = ()
    if selected_actions_payload is not None:
        github_owned_allowed = selected_actions_payload.get("github_owned_allowed") is True
        verified_allowed = selected_actions_payload.get("verified_allowed") is True
        raw_patterns = selected_actions_payload.get("patterns_allowed", [])
        patterns_allowed = normalize_patterns(raw_patterns if isinstance(raw_patterns, list) else [])

    missing_patterns = tuple(pattern for pattern in required if pattern not in set(patterns_allowed))
    extra_patterns = tuple(pattern for pattern in patterns_allowed if pattern not in set(required))

    if not actions_enabled:
        issues.append("GitHub Actions must be enabled")
    if require_selected_actions and allowed_actions_value != "selected":
        issues.append("repository actions must be restricted to selected actions")
    if default_workflow_permissions_value != "read":
        issues.append("default workflow token permissions must be read-only")
    if can_approve:
        issues.append("GitHub Actions must not be allowed to approve pull requests")
    if require_sha_pinning and not sha_pinning_required:
        issues.append("repository actions must require full-length SHA pinning")

    selected_config_required = allowed_actions_value == "selected" or selected_actions_payload is not None
    if selected_config_required:
        if selected_actions_payload is None:
            issues.append("selected actions allowlist metadata is unavailable")
        else:
            if not github_owned_allowed:
                issues.append("GitHub-owned actions must be allowed for repository workflows")
            if verified_allowed and not allow_verified_actions:
                issues.append("verified marketplace actions must not be broadly allowed")
            for pattern in missing_patterns:
                issues.append(f"missing selected action pattern: {pattern}")
            if extra_patterns and not allow_extra_patterns:
                for pattern in extra_patterns:
                    issues.append(f"unexpected selected action pattern: {pattern}")
            for pattern in patterns_allowed:
                if pattern in BROAD_PATTERNS:
                    issues.append(f"selected action pattern is too broad: {pattern}")

    return ActionsPermissionsReadiness(
        repo=repo,
        ready=not issues,
        actions_enabled=actions_enabled,
        allowed_actions=allowed_actions_value,
        sha_pinning_required=sha_pinning_required,
        default_workflow_permissions=default_workflow_permissions_value,
        can_approve_pull_request_reviews=can_approve,
        github_owned_allowed=github_owned_allowed,
        verified_allowed=verified_allowed,
        patterns_allowed=patterns_allowed,
        required_patterns=required,
        missing_patterns=missing_patterns,
        extra_patterns=extra_patterns,
        issues=tuple(issues),
    )


def print_text_report(report: ActionsPermissionsReadiness) -> None:
    if report.ready:
        print(f"GitHub Actions permissions readiness passed: {report.repo}")
        return
    print(f"GitHub Actions permissions readiness failed for {report.repo}", file=sys.stderr)
    for issue in report.issues:
        print(f"issue: {issue}", file=sys.stderr)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo",
        default="",
        help="GitHub repository in owner/name form; defaults to GH_REPO or gh repo view",
    )
    parser.add_argument(
        "--required-selected-pattern",
        action="append",
        default=[],
        help="required selected action pattern; may be repeated. Defaults to dtolnay/rust-toolchain@stable.",
    )
    parser.add_argument(
        "--allow-verified-actions",
        action="store_true",
        help="allow all verified marketplace actions in selected-action mode",
    )
    parser.add_argument(
        "--allow-extra-selected-patterns",
        action="store_true",
        help="allow selected action patterns beyond the required list",
    )
    parser.add_argument(
        "--allow-all-actions",
        action="store_true",
        help="do not require repository actions to be restricted to selected actions",
    )
    parser.add_argument(
        "--require-sha-pinning",
        action="store_true",
        help="require repository Actions SHA pinning",
    )
    parser.add_argument(
        "--actions-json",
        type=Path,
        default=None,
        help="read repository Actions permissions from a JSON fixture instead of gh api",
    )
    parser.add_argument(
        "--workflow-json",
        type=Path,
        default=None,
        help="read workflow token permissions from a JSON fixture instead of gh api",
    )
    parser.add_argument(
        "--selected-actions-json",
        type=Path,
        default=None,
        help="read selected action allowlist permissions from a JSON fixture instead of gh api",
    )
    parser.add_argument("--json", action="store_true", help="print a machine-readable report")
    parser.add_argument("--gh", default="", help=argparse.SUPPRESS)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        gh = args.gh or find_gh()
        repo = normalize_repo(args.repo.strip() or infer_repo(gh))
        if args.actions_json is None:
            actions_payload = load_actions_permissions(repo, gh)
        else:
            actions_payload = load_json_fixture(args.actions_json, "Actions permissions fixture JSON")
        if args.workflow_json is None:
            workflow_payload = load_workflow_permissions(repo, gh)
        else:
            workflow_payload = load_json_fixture(args.workflow_json, "workflow permissions fixture JSON")

        selected_actions_payload: dict[str, Any] | None = None
        if args.selected_actions_json is not None:
            selected_actions_payload = load_json_fixture(
                args.selected_actions_json,
                "selected actions permissions fixture JSON",
            )
        elif actions_payload.get("allowed_actions") == "selected":
            selected_actions_payload = load_selected_actions(repo, gh)

        required_patterns = tuple(args.required_selected_pattern or DEFAULT_REQUIRED_SELECTED_PATTERNS)
        report = audit_actions_permissions(
            repo=repo,
            actions_payload=actions_payload,
            workflow_payload=workflow_payload,
            selected_actions_payload=selected_actions_payload,
            required_patterns=required_patterns,
            require_selected_actions=not args.allow_all_actions,
            allow_verified_actions=args.allow_verified_actions,
            allow_extra_patterns=args.allow_extra_selected_patterns,
            require_sha_pinning=args.require_sha_pinning,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"GitHub Actions permissions readiness failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report.as_json(), indent=2, sort_keys=True))
    else:
        print_text_report(report)
    return 0 if report.ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
