#!/usr/bin/env python3
"""Regression checks for GitHub Actions permissions readiness."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-github-actions-permissions.py")
SENSITIVE_SENTINEL = "do-not-print-this-token-or-payload"


def load_module():
    spec = importlib.util.spec_from_file_location("check_github_actions_permissions", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load GitHub Actions permissions module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def ready_payloads() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    return (
        {
            "enabled": True,
            "allowed_actions": "selected",
            "sha_pinning_required": False,
            "url": f"https://example.invalid/{SENSITIVE_SENTINEL}",
        },
        {
            "default_workflow_permissions": "read",
            "can_approve_pull_request_reviews": False,
            "body": SENSITIVE_SENTINEL,
        },
        {
            "github_owned_allowed": True,
            "verified_allowed": False,
            "patterns_allowed": ["dtolnay/rust-toolchain@stable"],
            "selected_actions_url": f"https://example.invalid/{SENSITIVE_SENTINEL}",
        },
    )


def audit(module, actions_payload, workflow_payload, selected_payload, **kwargs):
    return module.audit_actions_permissions(
        repo="owner/repo",
        actions_payload=actions_payload,
        workflow_payload=workflow_payload,
        selected_actions_payload=selected_payload,
        required_patterns=module.DEFAULT_REQUIRED_SELECTED_PATTERNS,
        **kwargs,
    )


def assert_safe_report(report) -> dict[str, object]:
    rendered = json.dumps(report.as_json(), sort_keys=True)
    if SENSITIVE_SENTINEL in rendered:
        raise AssertionError("GitHub Actions permissions report leaked unrelated sensitive text")
    parsed = json.loads(rendered)
    for field in (
        "payloadDisplayed",
        "tokenDisplayed",
        "tokenHashDisplayed",
        "keyMaterialDisplayed",
        "contentsDisplayed",
    ):
        if parsed.get(field) is not False:
            raise AssertionError(f"expected {field}=false")
    return parsed


def run_ready_tests(module) -> None:
    actions_payload, workflow_payload, selected_payload = ready_payloads()
    report = audit(module, actions_payload, workflow_payload, selected_payload)
    if not report.ready:
        raise AssertionError(f"expected GitHub Actions permissions readiness to pass: {report.issues!r}")
    parsed = assert_safe_report(report)
    if parsed["allowedActions"] != "selected":
        raise AssertionError("selected action mode should be reported")
    if parsed["defaultWorkflowPermissions"] != "read":
        raise AssertionError("read-only workflow token permissions should be reported")
    if parsed["patternsAllowed"] != ["dtolnay/rust-toolchain@stable"]:
        raise AssertionError("selected action pattern should be reported")


def run_repository_permission_tests(module) -> None:
    actions_payload, workflow_payload, selected_payload = ready_payloads()
    actions_payload["allowed_actions"] = "all"
    report = audit(module, actions_payload, workflow_payload, selected_payload)
    if report.ready:
        raise AssertionError("all actions mode should fail")
    if "repository actions must be restricted to selected actions" not in json.dumps(assert_safe_report(report)):
        raise AssertionError("all actions issue was not reported")

    actions_payload, workflow_payload, selected_payload = ready_payloads()
    actions_payload["enabled"] = False
    report = audit(module, actions_payload, workflow_payload, selected_payload)
    if report.ready:
        raise AssertionError("disabled GitHub Actions should fail")
    if "GitHub Actions must be enabled" not in json.dumps(assert_safe_report(report)):
        raise AssertionError("disabled Actions issue was not reported")


def run_workflow_permission_tests(module) -> None:
    actions_payload, workflow_payload, selected_payload = ready_payloads()
    workflow_payload["default_workflow_permissions"] = "write"
    workflow_payload["can_approve_pull_request_reviews"] = True
    report = audit(module, actions_payload, workflow_payload, selected_payload)
    if report.ready:
        raise AssertionError("write token/PR approval permissions should fail")
    rendered = json.dumps(assert_safe_report(report))
    if "default workflow token permissions must be read-only" not in rendered:
        raise AssertionError("write token issue was not reported")
    if "GitHub Actions must not be allowed to approve pull requests" not in rendered:
        raise AssertionError("PR approval issue was not reported")


def run_selected_action_tests(module) -> None:
    actions_payload, workflow_payload, selected_payload = ready_payloads()
    selected_payload["github_owned_allowed"] = False
    selected_payload["verified_allowed"] = True
    selected_payload["patterns_allowed"] = ["owner/unsafe@main", "*/*@*"]
    report = audit(module, actions_payload, workflow_payload, selected_payload)
    if report.ready:
        raise AssertionError("unsafe selected action settings should fail")
    rendered = json.dumps(assert_safe_report(report))
    for expected in (
        "GitHub-owned actions must be allowed for repository workflows",
        "verified marketplace actions must not be broadly allowed",
        "missing selected action pattern: dtolnay/rust-toolchain@stable",
        "unexpected selected action pattern: */*@*",
        "unexpected selected action pattern: owner/unsafe@main",
        "selected action pattern is too broad: */*@*",
    ):
        if expected not in rendered:
            raise AssertionError(f"expected selected-action issue missing: {expected}")

    actions_payload, workflow_payload, _ = ready_payloads()
    report = audit(module, actions_payload, workflow_payload, None)
    if report.ready:
        raise AssertionError("selected mode without allowlist metadata should fail")
    if "selected actions allowlist metadata is unavailable" not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing selected allowlist issue was not reported")


def run_optional_policy_tests(module) -> None:
    actions_payload, workflow_payload, selected_payload = ready_payloads()
    actions_payload["allowed_actions"] = "all"
    report = audit(
        module,
        actions_payload,
        workflow_payload,
        selected_payload,
        require_selected_actions=False,
    )
    if not report.ready:
        raise AssertionError("selected mode should be optional when explicitly relaxed")
    assert_safe_report(report)

    actions_payload, workflow_payload, selected_payload = ready_payloads()
    actions_payload["sha_pinning_required"] = False
    report = audit(
        module,
        actions_payload,
        workflow_payload,
        selected_payload,
        require_sha_pinning=True,
    )
    if report.ready:
        raise AssertionError("missing SHA pinning should fail when requested")
    if "repository actions must require full-length SHA pinning" not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing SHA pinning issue was not reported")


def main() -> int:
    module = load_module()
    run_ready_tests(module)
    run_repository_permission_tests(module)
    run_workflow_permission_tests(module)
    run_selected_action_tests(module)
    run_optional_policy_tests(module)
    print("GitHub Actions permissions regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
