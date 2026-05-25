#!/usr/bin/env python3
"""Regression checks for GitHub main branch protection readiness."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-github-main-protection.py")
SENSITIVE_SENTINEL = "do-not-print-this-token-or-payload"


def load_module():
    spec = importlib.util.spec_from_file_location("check_github_main_protection", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load GitHub main protection module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def ready_payload(module) -> dict[str, object]:
    return {
        "required_status_checks": {
            "strict": True,
            "contexts": [
                "Packages",
                "Rust (ubuntu-latest)",
            ],
            "checks": [
                {"context": "Rust (macos-15)", "app_id": 15368},
                {"context": "Rust (windows-2025-vs2026)", "app_id": 15368},
            ],
        },
        "allow_force_pushes": {"enabled": False},
        "allow_deletions": {"enabled": False},
        "required_pull_request_reviews": {
            "required_approving_review_count": 1,
            "dismiss_stale_reviews": True,
            "body": SENSITIVE_SENTINEL,
        },
        "enforce_admins": {"enabled": True},
        "url": f"https://example.invalid/{SENSITIVE_SENTINEL}",
    }


def assert_safe_report(report) -> dict[str, object]:
    rendered = json.dumps(report.as_json(), sort_keys=True)
    if SENSITIVE_SENTINEL in rendered:
        raise AssertionError("branch protection report leaked unrelated sensitive text")
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


def audit(module, payload, **kwargs):
    return module.audit_branch_protection(
        repo="owner/repo",
        branch="main",
        protection_payload=payload,
        required_status_checks=module.DEFAULT_REQUIRED_STATUS_CHECKS,
        **kwargs,
    )


def run_ready_tests(module) -> None:
    report = audit(module, ready_payload(module))
    if not report.ready:
        raise AssertionError(f"expected branch protection readiness to pass: {report.issues!r}")
    parsed = assert_safe_report(report)
    if parsed["protected"] is not True:
        raise AssertionError("protected flag should be true")
    if parsed["missingStatusChecks"]:
        raise AssertionError("no status checks should be missing")
    if parsed["strictStatusChecks"] is not True:
        raise AssertionError("strict status checks should be reported")


def run_unprotected_tests(module) -> None:
    report = audit(module, None)
    if report.ready:
        raise AssertionError("unprotected branch should fail")
    parsed = assert_safe_report(report)
    if parsed["protected"] is not False:
        raise AssertionError("protected flag should be false")
    if "main is not protected" not in json.dumps(parsed):
        raise AssertionError("unprotected issue was not reported")


def run_status_check_tests(module) -> None:
    payload = ready_payload(module)
    payload["required_status_checks"] = {
        "strict": False,
        "contexts": ["Packages"],
        "checks": [],
    }
    report = audit(module, payload)
    if report.ready:
        raise AssertionError("non-strict/missing status checks should fail")
    parsed = assert_safe_report(report)
    rendered = json.dumps(parsed)
    if "required status checks must be strict" not in rendered:
        raise AssertionError("strict status check issue was not reported")
    if "missing required status check: Rust (ubuntu-latest)" not in rendered:
        raise AssertionError("missing CI context was not reported")


def run_mutation_guard_tests(module) -> None:
    payload = ready_payload(module)
    payload["allow_force_pushes"] = {"enabled": True}
    payload["allow_deletions"] = {"enabled": True}
    report = audit(module, payload)
    if report.ready:
        raise AssertionError("force push/deletion allowances should fail")
    parsed = assert_safe_report(report)
    rendered = json.dumps(parsed)
    for expected in ("force pushes must be disabled", "branch deletion must be disabled"):
        if expected not in rendered:
            raise AssertionError(f"expected mutation guard issue missing: {expected}")


def run_optional_review_tests(module) -> None:
    payload = ready_payload(module)
    payload["required_pull_request_reviews"] = None
    report = audit(module, payload, require_pr_reviews=False)
    if not report.ready:
        raise AssertionError("PR reviews should be optional by default")
    assert_safe_report(report)

    required = audit(
        module,
        payload,
        require_pr_reviews=True,
        require_stale_review_dismissal=True,
    )
    if required.ready:
        raise AssertionError("missing required PR reviews should fail when requested")
    rendered = json.dumps(assert_safe_report(required))
    if "pull request review protection must require at least one approval" not in rendered:
        raise AssertionError("missing PR review issue was not reported")
    if "stale pull request review dismissal must be enabled" not in rendered:
        raise AssertionError("missing stale dismissal issue was not reported")


def run_optional_admin_tests(module) -> None:
    payload = ready_payload(module)
    payload["enforce_admins"] = {"enabled": False}
    report = audit(module, payload, require_admin_enforcement=False)
    if not report.ready:
        raise AssertionError("admin enforcement should be optional by default")
    assert_safe_report(report)

    required = audit(module, payload, require_admin_enforcement=True)
    if required.ready:
        raise AssertionError("missing admin enforcement should fail when requested")
    if "branch protection must apply to administrators" not in json.dumps(assert_safe_report(required)):
        raise AssertionError("missing admin enforcement issue was not reported")


def main() -> int:
    module = load_module()
    run_ready_tests(module)
    run_unprotected_tests(module)
    run_status_check_tests(module)
    run_mutation_guard_tests(module)
    run_optional_review_tests(module)
    run_optional_admin_tests(module)
    print("GitHub main branch protection regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
