#!/usr/bin/env python3
"""Audit GitHub default branch protection for production release hygiene."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

from github_release_secrets import find_gh, infer_repo, normalize_repo
from json_safety import load_json, loads_json


DEFAULT_BRANCH = "main"
DEFAULT_REQUIRED_STATUS_CHECKS = (
    "Packages",
    "Rust (ubuntu-latest)",
    "Rust (macos-15)",
    "Rust (windows-2025-vs2026)",
)


@dataclass(frozen=True)
class BranchProtectionReadiness:
    repo: str
    branch: str
    ready: bool
    protected: bool
    strict_status_checks: bool
    required_status_checks: tuple[str, ...]
    configured_status_checks: tuple[str, ...]
    missing_status_checks: tuple[str, ...]
    force_pushes_allowed: bool
    deletions_allowed: bool
    required_pull_request_reviews: bool
    required_approving_review_count: int
    stale_review_dismissal: bool
    admins_enforced: bool
    issues: tuple[str, ...]

    def as_json(self) -> dict[str, Any]:
        return {
            "schema": "conu.githubMainBranchProtection.v1",
            "repo": self.repo,
            "branch": self.branch,
            "ready": self.ready,
            "protected": self.protected,
            "strictStatusChecks": self.strict_status_checks,
            "requiredStatusChecks": list(self.required_status_checks),
            "configuredStatusChecks": list(self.configured_status_checks),
            "missingStatusChecks": list(self.missing_status_checks),
            "forcePushesAllowed": self.force_pushes_allowed,
            "deletionsAllowed": self.deletions_allowed,
            "requiredPullRequestReviews": self.required_pull_request_reviews,
            "requiredApprovingReviewCount": self.required_approving_review_count,
            "staleReviewDismissal": self.stale_review_dismissal,
            "adminsEnforced": self.admins_enforced,
            "issues": list(self.issues),
            "payloadDisplayed": False,
            "tokenDisplayed": False,
            "tokenHashDisplayed": False,
            "keyMaterialDisplayed": False,
            "contentsDisplayed": False,
        }


def run_gh_json_or_none(gh: str, args: list[str], description: str) -> Any | None:
    result = subprocess.run(
        [gh, *args],
        check=False,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode == 0:
        try:
            return loads_json(result.stdout)
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"{description} returned invalid JSON: {exc}") from exc
    stderr = result.stderr.lower()
    if "http 404" in stderr or "branch not protected" in stderr:
        return None
    raise ValueError(f"{description} failed with exit code {result.returncode}; run gh auth status")


def load_branch_protection(repo: str, branch: str, gh: str) -> dict[str, Any] | None:
    normalized_branch = branch.strip()
    if not normalized_branch:
        raise ValueError("branch name is required")
    payload = run_gh_json_or_none(
        gh,
        ["api", f"repos/{repo}/branches/{quote(normalized_branch, safe='')}/protection"],
        "gh api branch protection",
    )
    if payload is None:
        return None
    if not isinstance(payload, dict):
        raise ValueError("gh api branch protection returned an unexpected payload")
    return payload


def load_protection_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = load_json(path, encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"failed to read protection fixture JSON: {exc}") from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"protection fixture JSON was invalid: {exc}") from exc
    if payload is None:
        return None
    if not isinstance(payload, dict):
        raise ValueError("protection fixture JSON must contain an object or null")
    return payload


def bool_enabled(payload: dict[str, Any], key: str) -> bool:
    value = payload.get(key)
    if isinstance(value, dict):
        return value.get("enabled") is True
    return False


def configured_status_contexts(payload: dict[str, Any]) -> tuple[str, ...]:
    status_payload = payload.get("required_status_checks")
    if not isinstance(status_payload, dict):
        return ()
    contexts: set[str] = set()
    for item in status_payload.get("contexts", []):
        if isinstance(item, str) and item.strip():
            contexts.add(item.strip())
    for item in status_payload.get("checks", []):
        if not isinstance(item, dict):
            continue
        context = item.get("context")
        if isinstance(context, str) and context.strip():
            contexts.add(context.strip())
    return tuple(sorted(contexts))


def status_checks_are_strict(payload: dict[str, Any]) -> bool:
    status_payload = payload.get("required_status_checks")
    return isinstance(status_payload, dict) and status_payload.get("strict") is True


def pr_review_payload(payload: dict[str, Any]) -> dict[str, Any]:
    reviews = payload.get("required_pull_request_reviews")
    return reviews if isinstance(reviews, dict) else {}


def audit_branch_protection(
    *,
    repo: str,
    branch: str,
    protection_payload: dict[str, Any] | None,
    required_status_checks: tuple[str, ...],
    require_strict_status_checks: bool = True,
    require_pr_reviews: bool = False,
    require_stale_review_dismissal: bool = False,
    require_admin_enforcement: bool = False,
) -> BranchProtectionReadiness:
    normalized_branch = branch.strip() or DEFAULT_BRANCH
    required_checks = tuple(check.strip() for check in required_status_checks if check.strip())
    issues: list[str] = []
    if protection_payload is None:
        return BranchProtectionReadiness(
            repo=repo,
            branch=normalized_branch,
            ready=False,
            protected=False,
            strict_status_checks=False,
            required_status_checks=required_checks,
            configured_status_checks=(),
            missing_status_checks=required_checks,
            force_pushes_allowed=False,
            deletions_allowed=False,
            required_pull_request_reviews=False,
            required_approving_review_count=0,
            stale_review_dismissal=False,
            admins_enforced=False,
            issues=(f"{normalized_branch} is not protected",),
        )

    configured_checks = configured_status_contexts(protection_payload)
    configured_set = set(configured_checks)
    missing_checks = tuple(check for check in required_checks if check not in configured_set)
    strict = status_checks_are_strict(protection_payload)
    force_pushes_allowed = bool_enabled(protection_payload, "allow_force_pushes")
    deletions_allowed = bool_enabled(protection_payload, "allow_deletions")
    reviews = pr_review_payload(protection_payload)
    required_review_count = reviews.get("required_approving_review_count")
    required_review_count_value = required_review_count if isinstance(required_review_count, int) else 0
    stale_review_dismissal = reviews.get("dismiss_stale_reviews") is True
    admins_enforced = bool_enabled(protection_payload, "enforce_admins")

    if require_strict_status_checks and not strict:
        issues.append("required status checks must be strict")
    for check in missing_checks:
        issues.append(f"missing required status check: {check}")
    if force_pushes_allowed:
        issues.append("force pushes must be disabled")
    if deletions_allowed:
        issues.append("branch deletion must be disabled")
    if require_pr_reviews:
        if required_review_count_value < 1:
            issues.append("pull request review protection must require at least one approval")
        if require_stale_review_dismissal and not stale_review_dismissal:
            issues.append("stale pull request review dismissal must be enabled")
    if require_admin_enforcement and not admins_enforced:
        issues.append("branch protection must apply to administrators")

    return BranchProtectionReadiness(
        repo=repo,
        branch=normalized_branch,
        ready=not issues,
        protected=True,
        strict_status_checks=strict,
        required_status_checks=required_checks,
        configured_status_checks=configured_checks,
        missing_status_checks=missing_checks,
        force_pushes_allowed=force_pushes_allowed,
        deletions_allowed=deletions_allowed,
        required_pull_request_reviews=required_review_count_value > 0,
        required_approving_review_count=required_review_count_value,
        stale_review_dismissal=stale_review_dismissal,
        admins_enforced=admins_enforced,
        issues=tuple(issues),
    )


def print_text_report(report: BranchProtectionReadiness) -> None:
    if report.ready:
        print(
            "GitHub main branch protection readiness passed: "
            f"{report.repo}@{report.branch}"
        )
        return
    print(
        f"GitHub main branch protection readiness failed for {report.repo}@{report.branch}",
        file=sys.stderr,
    )
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
        "--branch",
        default=DEFAULT_BRANCH,
        help=f"branch to audit; defaults to {DEFAULT_BRANCH}",
    )
    parser.add_argument(
        "--required-status",
        action="append",
        default=[],
        help="required status context; may be repeated. Defaults to conU CI package/Rust checks.",
    )
    parser.add_argument(
        "--require-pr-reviews",
        action="store_true",
        help="also require at least one approving pull request review",
    )
    parser.add_argument(
        "--require-stale-review-dismissal",
        action="store_true",
        help="when requiring PR reviews, require stale review dismissal",
    )
    parser.add_argument(
        "--require-admin-enforcement",
        action="store_true",
        help="require branch protection to apply to repository administrators",
    )
    parser.add_argument(
        "--protection-json",
        type=Path,
        default=None,
        help="read branch protection metadata from a JSON fixture instead of gh api",
    )
    parser.add_argument("--json", action="store_true", help="print a machine-readable report")
    parser.add_argument("--gh", default="", help=argparse.SUPPRESS)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        gh = args.gh or find_gh()
        repo = normalize_repo(args.repo.strip() or infer_repo(gh))
        required_status = tuple(args.required_status or DEFAULT_REQUIRED_STATUS_CHECKS)
        if args.protection_json is None:
            payload = load_branch_protection(repo, args.branch, gh)
        else:
            payload = load_protection_json(args.protection_json)
        report = audit_branch_protection(
            repo=repo,
            branch=args.branch,
            protection_payload=payload,
            required_status_checks=required_status,
            require_pr_reviews=args.require_pr_reviews,
            require_stale_review_dismissal=args.require_stale_review_dismissal,
            require_admin_enforcement=args.require_admin_enforcement,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"GitHub main branch protection readiness failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report.as_json(), indent=2, sort_keys=True))
    else:
        print_text_report(report)
    return 0 if report.ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
