#!/usr/bin/env python3
"""Regression checks for GitHub repository security readiness."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-github-repository-security.py")
SENSITIVE_SENTINEL = "do-not-print-this-secret-alert-body-or-payload"


def load_module():
    spec = importlib.util.spec_from_file_location("check_github_repository_security", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load GitHub repository security module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def ready_repo_payload() -> dict[str, object]:
    return {
        "visibility": "public",
        "archived": False,
        "disabled": False,
        "description": SENSITIVE_SENTINEL,
        "security_and_analysis": {
            "dependabot_security_updates": {"status": "enabled"},
            "secret_scanning": {"status": "enabled"},
            "secret_scanning_push_protection": {"status": "enabled"},
            "secret_scanning_non_provider_patterns": {"status": "disabled"},
            "secret_scanning_validity_checks": {"status": "disabled"},
        },
    }


def audit(module, repo_payload, **kwargs):
    return module.audit_repository_security(
        repo="owner/repo",
        repo_payload=repo_payload,
        vulnerability_alerts_enabled=kwargs.pop("vulnerability_alerts_enabled", True),
        dependabot_alerts=kwargs.pop("dependabot_alerts", []),
        secret_scanning_alerts=kwargs.pop("secret_scanning_alerts", []),
        **kwargs,
    )


def assert_safe_report(report) -> dict[str, object]:
    rendered = json.dumps(report.as_json(), sort_keys=True)
    if SENSITIVE_SENTINEL in rendered:
        raise AssertionError("repository security report leaked unrelated alert or repository text")
    parsed = json.loads(rendered)
    for field in (
        "payloadDisplayed",
        "tokenDisplayed",
        "tokenHashDisplayed",
        "keyMaterialDisplayed",
        "contentsDisplayed",
        "alertBodiesDisplayed",
    ):
        if parsed.get(field) is not False:
            raise AssertionError(f"expected {field}=false")
    return parsed


def run_ready_tests(module) -> None:
    report = audit(module, ready_repo_payload())
    if not report.ready:
        raise AssertionError(f"expected repository security readiness to pass: {report.issues!r}")
    parsed = assert_safe_report(report)
    if parsed["dependabotSecurityUpdates"] != "enabled":
        raise AssertionError("Dependabot security update status should be reported")
    if parsed["secretScanningPushProtection"] != "enabled":
        raise AssertionError("secret scanning push protection should be reported")
    if parsed["openDependabotAlertCount"] != 0:
        raise AssertionError("open Dependabot alert count should be reported")


def run_disabled_feature_tests(module) -> None:
    payload = ready_repo_payload()
    security = payload["security_and_analysis"]
    assert isinstance(security, dict)
    security["dependabot_security_updates"] = {"status": "disabled"}
    security["secret_scanning"] = {"status": "disabled"}
    security["secret_scanning_push_protection"] = {"status": "disabled"}
    report = audit(module, payload, vulnerability_alerts_enabled=False)
    if report.ready:
        raise AssertionError("disabled repository security features should fail")
    rendered = json.dumps(assert_safe_report(report))
    for expected in (
        "Dependabot vulnerability alerts must be enabled",
        "Dependabot security updates must be enabled",
        "secret scanning must be enabled",
        "secret scanning push protection must be enabled",
    ):
        if expected not in rendered:
            raise AssertionError(f"expected disabled-feature issue missing: {expected}")


def run_repository_state_tests(module) -> None:
    payload = ready_repo_payload()
    payload["archived"] = True
    payload["disabled"] = True
    payload["visibility"] = None
    report = audit(module, payload)
    if report.ready:
        raise AssertionError("archived/disabled repository should fail")
    rendered = json.dumps(assert_safe_report(report))
    for expected in (
        "repository must not be archived",
        "repository must not be disabled",
        "repository visibility metadata is unavailable",
    ):
        if expected not in rendered:
            raise AssertionError(f"expected repository-state issue missing: {expected}")


def run_open_alert_tests(module) -> None:
    alert = {"state": "open", "html_url": f"https://example.invalid/{SENSITIVE_SENTINEL}"}
    report = audit(
        module,
        ready_repo_payload(),
        dependabot_alerts=[alert],
        secret_scanning_alerts=[alert],
    )
    if report.ready:
        raise AssertionError("open security alerts should fail")
    rendered = json.dumps(assert_safe_report(report))
    for expected in (
        "open Dependabot alerts must be resolved before production release",
        "open secret scanning alerts must be resolved before production release",
    ):
        if expected not in rendered:
            raise AssertionError(f"expected open-alert issue missing: {expected}")

    relaxed = audit(
        module,
        ready_repo_payload(),
        dependabot_alerts=[alert],
        secret_scanning_alerts=[alert],
        require_no_open_alerts=False,
    )
    if not relaxed.ready:
        raise AssertionError("open alerts should be optional only when explicitly relaxed")
    assert_safe_report(relaxed)


def run_unavailable_alert_tests(module) -> None:
    report = audit(
        module,
        ready_repo_payload(),
        dependabot_alerts=None,
        secret_scanning_alerts=None,
    )
    if report.ready:
        raise AssertionError("unavailable alert counts should fail")
    rendered = json.dumps(assert_safe_report(report))
    for expected in (
        "open Dependabot alert count could not be checked",
        "open secret scanning alert count could not be checked",
    ):
        if expected not in rendered:
            raise AssertionError(f"expected unavailable-alert issue missing: {expected}")


def run_optional_secret_scanning_tests(module) -> None:
    payload = ready_repo_payload()
    report = audit(
        module,
        payload,
        require_non_provider_patterns=True,
        require_validity_checks=True,
    )
    if report.ready:
        raise AssertionError("optional secret-scanning policy should fail when requested and disabled")
    rendered = json.dumps(assert_safe_report(report))
    for expected in (
        "secret scanning non-provider patterns must be enabled",
        "secret scanning validity checks must be enabled",
    ):
        if expected not in rendered:
            raise AssertionError(f"expected optional-policy issue missing: {expected}")


def main() -> int:
    module = load_module()
    run_ready_tests(module)
    run_disabled_feature_tests(module)
    run_repository_state_tests(module)
    run_open_alert_tests(module)
    run_unavailable_alert_tests(module)
    run_optional_secret_scanning_tests(module)
    print("GitHub repository security regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
