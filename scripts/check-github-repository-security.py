#!/usr/bin/env python3
"""Audit GitHub repository security settings for production release hygiene."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from github_release_secrets import find_gh, infer_repo


@dataclass(frozen=True)
class RepositorySecurityReadiness:
    repo: str
    ready: bool
    visibility: str
    archived: bool
    disabled: bool
    vulnerability_alerts_enabled: bool | None
    dependabot_security_updates: str
    secret_scanning: str
    secret_scanning_push_protection: str
    secret_scanning_non_provider_patterns: str
    secret_scanning_validity_checks: str
    open_dependabot_alert_count: int | None
    open_secret_scanning_alert_count: int | None
    issues: tuple[str, ...]

    def as_json(self) -> dict[str, Any]:
        return {
            "schema": "conu.githubRepositorySecurity.v1",
            "repo": self.repo,
            "ready": self.ready,
            "visibility": self.visibility,
            "archived": self.archived,
            "disabled": self.disabled,
            "vulnerabilityAlertsEnabled": self.vulnerability_alerts_enabled,
            "dependabotSecurityUpdates": self.dependabot_security_updates,
            "secretScanning": self.secret_scanning,
            "secretScanningPushProtection": self.secret_scanning_push_protection,
            "secretScanningNonProviderPatterns": self.secret_scanning_non_provider_patterns,
            "secretScanningValidityChecks": self.secret_scanning_validity_checks,
            "openDependabotAlertCount": self.open_dependabot_alert_count,
            "openSecretScanningAlertCount": self.open_secret_scanning_alert_count,
            "issues": list(self.issues),
            "payloadDisplayed": False,
            "tokenDisplayed": False,
            "tokenHashDisplayed": False,
            "keyMaterialDisplayed": False,
            "contentsDisplayed": False,
            "alertBodiesDisplayed": False,
        }


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
        raise ValueError(f"{description} failed with exit code {result.returncode}; run gh auth status")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{description} returned invalid JSON: {exc}") from exc


def run_gh_status(gh: str, args: list[str], description: str) -> int | None:
    result = subprocess.run(
        [gh, *args],
        check=False,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    for line in result.stdout.splitlines():
        if line.startswith("HTTP/"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1])
    if result.returncode != 0:
        return None
    raise ValueError(f"{description} did not include an HTTP status line")


def load_json_fixture(path: Path, description: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"failed to read {description}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{description} was invalid: {exc}") from exc


def load_repo_payload(repo: str, gh: str) -> dict[str, Any]:
    payload = run_gh_json(gh, ["api", f"repos/{repo}"], "gh api repository metadata")
    if not isinstance(payload, dict):
        raise ValueError("repository metadata returned an unexpected payload")
    return payload


def load_vulnerability_alert_status(repo: str, gh: str) -> bool | None:
    status = run_gh_status(
        gh,
        ["api", f"repos/{repo}/vulnerability-alerts", "--silent", "--include"],
        "gh api vulnerability alerts",
    )
    if status == 204:
        return True
    if status == 404:
        return False
    return None


def load_alerts(repo: str, gh: str, endpoint: str, description: str) -> list[Any] | None:
    result = subprocess.run(
        [gh, "api", f"repos/{repo}/{endpoint}?state=open&per_page=100"],
        check=False,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        return None
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{description} returned invalid JSON: {exc}") from exc
    if not isinstance(payload, list):
        raise ValueError(f"{description} returned an unexpected payload")
    return payload


def security_status(repo_payload: dict[str, Any], key: str) -> str:
    security = repo_payload.get("security_and_analysis")
    if not isinstance(security, dict):
        return "unavailable"
    value = security.get(key)
    if not isinstance(value, dict):
        return "unavailable"
    status = value.get("status")
    return status if isinstance(status, str) else "unavailable"


def alert_count(alerts: list[Any] | None) -> int | None:
    if alerts is None:
        return None
    return len(alerts)


def audit_repository_security(
    *,
    repo: str,
    repo_payload: dict[str, Any],
    vulnerability_alerts_enabled: bool | None,
    dependabot_alerts: list[Any] | None,
    secret_scanning_alerts: list[Any] | None,
    require_non_provider_patterns: bool = False,
    require_validity_checks: bool = False,
    require_no_open_alerts: bool = True,
) -> RepositorySecurityReadiness:
    issues: list[str] = []

    visibility = repo_payload.get("visibility")
    visibility_value = visibility if isinstance(visibility, str) else ""
    archived = repo_payload.get("archived") is True
    disabled = repo_payload.get("disabled") is True

    dependabot_status = security_status(repo_payload, "dependabot_security_updates")
    secret_scanning_status = security_status(repo_payload, "secret_scanning")
    push_protection_status = security_status(repo_payload, "secret_scanning_push_protection")
    non_provider_status = security_status(repo_payload, "secret_scanning_non_provider_patterns")
    validity_status = security_status(repo_payload, "secret_scanning_validity_checks")

    open_dependabot_alerts = alert_count(dependabot_alerts)
    open_secret_scanning_alerts = alert_count(secret_scanning_alerts)

    if archived:
        issues.append("repository must not be archived")
    if disabled:
        issues.append("repository must not be disabled")
    if visibility_value not in {"public", "private", "internal"}:
        issues.append("repository visibility metadata is unavailable")
    if vulnerability_alerts_enabled is not True:
        issues.append("Dependabot vulnerability alerts must be enabled")
    if dependabot_status != "enabled":
        issues.append("Dependabot security updates must be enabled")
    if secret_scanning_status != "enabled":
        issues.append("secret scanning must be enabled")
    if push_protection_status != "enabled":
        issues.append("secret scanning push protection must be enabled")
    if require_non_provider_patterns and non_provider_status != "enabled":
        issues.append("secret scanning non-provider patterns must be enabled")
    if require_validity_checks and validity_status != "enabled":
        issues.append("secret scanning validity checks must be enabled")

    if require_no_open_alerts:
        if open_dependabot_alerts is None:
            issues.append("open Dependabot alert count could not be checked")
        elif open_dependabot_alerts > 0:
            issues.append("open Dependabot alerts must be resolved before production release")
        if open_secret_scanning_alerts is None:
            issues.append("open secret scanning alert count could not be checked")
        elif open_secret_scanning_alerts > 0:
            issues.append("open secret scanning alerts must be resolved before production release")

    return RepositorySecurityReadiness(
        repo=repo,
        ready=not issues,
        visibility=visibility_value,
        archived=archived,
        disabled=disabled,
        vulnerability_alerts_enabled=vulnerability_alerts_enabled,
        dependabot_security_updates=dependabot_status,
        secret_scanning=secret_scanning_status,
        secret_scanning_push_protection=push_protection_status,
        secret_scanning_non_provider_patterns=non_provider_status,
        secret_scanning_validity_checks=validity_status,
        open_dependabot_alert_count=open_dependabot_alerts,
        open_secret_scanning_alert_count=open_secret_scanning_alerts,
        issues=tuple(issues),
    )


def print_text_report(report: RepositorySecurityReadiness) -> None:
    if report.ready:
        print(f"GitHub repository security readiness passed: {report.repo}")
        return
    print(f"GitHub repository security readiness failed for {report.repo}", file=sys.stderr)
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
        "--allow-open-alerts",
        action="store_true",
        help="do not fail when open Dependabot or secret-scanning alerts exist",
    )
    parser.add_argument(
        "--require-secret-scanning-non-provider-patterns",
        action="store_true",
        help="require GitHub secret scanning non-provider patterns",
    )
    parser.add_argument(
        "--require-secret-scanning-validity-checks",
        action="store_true",
        help="require GitHub secret scanning validity checks",
    )
    parser.add_argument(
        "--repo-json",
        type=Path,
        default=None,
        help="read repository metadata from a JSON fixture instead of gh api",
    )
    parser.add_argument(
        "--vulnerability-alerts-enabled",
        choices=("true", "false", "unknown"),
        default="",
        help="fixture override for vulnerability alert status",
    )
    parser.add_argument(
        "--dependabot-alerts-json",
        type=Path,
        default=None,
        help="read open Dependabot alerts from a JSON fixture instead of gh api",
    )
    parser.add_argument(
        "--secret-scanning-alerts-json",
        type=Path,
        default=None,
        help="read open secret scanning alerts from a JSON fixture instead of gh api",
    )
    parser.add_argument("--json", action="store_true", help="print a machine-readable report")
    parser.add_argument("--gh", default="", help=argparse.SUPPRESS)
    return parser.parse_args()


def fixture_bool(value: str) -> bool | None:
    if value == "true":
        return True
    if value == "false":
        return False
    if value == "unknown":
        return None
    raise ValueError("fixture boolean was not provided")


def main() -> int:
    args = parse_args()
    try:
        gh = args.gh or find_gh()
        repo = args.repo.strip() or infer_repo(gh)
        repo_payload = (
            load_repo_payload(repo, gh)
            if args.repo_json is None
            else load_json_fixture(args.repo_json, "repository metadata fixture JSON")
        )
        if not isinstance(repo_payload, dict):
            raise ValueError("repository metadata fixture must contain a JSON object")

        vulnerability_alerts_enabled = (
            load_vulnerability_alert_status(repo, gh)
            if not args.vulnerability_alerts_enabled
            else fixture_bool(args.vulnerability_alerts_enabled)
        )

        dependabot_alerts = (
            load_alerts(repo, gh, "dependabot/alerts", "gh api Dependabot alerts")
            if args.dependabot_alerts_json is None
            else load_json_fixture(args.dependabot_alerts_json, "Dependabot alerts fixture JSON")
        )
        secret_scanning_alerts = (
            load_alerts(repo, gh, "secret-scanning/alerts", "gh api secret scanning alerts")
            if args.secret_scanning_alerts_json is None
            else load_json_fixture(args.secret_scanning_alerts_json, "secret scanning alerts fixture JSON")
        )
        if dependabot_alerts is not None and not isinstance(dependabot_alerts, list):
            raise ValueError("Dependabot alerts fixture must contain a JSON array")
        if secret_scanning_alerts is not None and not isinstance(secret_scanning_alerts, list):
            raise ValueError("secret scanning alerts fixture must contain a JSON array")

        report = audit_repository_security(
            repo=repo,
            repo_payload=repo_payload,
            vulnerability_alerts_enabled=vulnerability_alerts_enabled,
            dependabot_alerts=dependabot_alerts,
            secret_scanning_alerts=secret_scanning_alerts,
            require_non_provider_patterns=args.require_secret_scanning_non_provider_patterns,
            require_validity_checks=args.require_secret_scanning_validity_checks,
            require_no_open_alerts=not args.allow_open_alerts,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"GitHub repository security readiness failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report.as_json(), indent=2, sort_keys=True))
    else:
        print_text_report(report)
    return 0 if report.ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
