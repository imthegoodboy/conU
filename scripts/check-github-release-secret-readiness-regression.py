#!/usr/bin/env python3
"""Regression checks for GitHub release secret readiness auditing."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace


SCRIPT = Path(__file__).with_name("check-github-release-secret-readiness.py")
SENSITIVE_SENTINEL = "do-not-print-this-secret-value"


def load_module():
    spec = importlib.util.spec_from_file_location("check_github_release_secret_readiness", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load GitHub release secret readiness module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def assert_raises(func, pattern: str) -> None:
    try:
        func()
    except ValueError as exc:
        if pattern not in str(exc):
            raise AssertionError(f"expected {pattern!r} in {exc!r}") from exc
        return
    raise AssertionError(f"expected ValueError containing {pattern!r}")


def run_audit_tests(module) -> None:
    configured = set(module.REQUIRED_RELEASE_SECRETS)
    ready = module.audit_secret_names("owner/repo", configured)
    if not ready.ready:
        raise AssertionError("all required secret names should be ready")
    if ready.missing:
        raise AssertionError(f"unexpected missing secret names: {ready.missing}")

    missing_name = module.REQUIRED_RELEASE_SECRETS[0]
    configured.remove(missing_name)
    not_ready = module.audit_secret_names("owner/repo", configured)
    if not not_ready.missing == (missing_name,):
        raise AssertionError(f"expected only {missing_name} missing, got {not_ready.missing}")


def run_gh_payload_tests(module) -> None:
    def fake_secret_list(args, **_kwargs):
        if args[1:4] != ["secret", "list", "--repo"]:
            raise AssertionError(f"unexpected gh args: {args!r}")
        payload = [
            {"name": name, "value": SENSITIVE_SENTINEL}
            for name in module.REQUIRED_RELEASE_SECRETS
        ]
        return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")

    original_run = subprocess.run
    module.subprocess.run = fake_secret_list
    try:
        names = module.load_secret_names("owner/repo", "gh")
    finally:
        module.subprocess.run = original_run

    if names != set(module.REQUIRED_RELEASE_SECRETS):
        raise AssertionError("loaded secret names did not match required names")
    report = module.audit_secret_names("owner/repo", names)
    rendered = json.dumps(report.as_json())
    if SENSITIVE_SENTINEL in rendered:
        raise AssertionError("secret readiness report included a secret value")


def run_error_tests(module) -> None:
    def invalid_json(*_args, **_kwargs):
        return SimpleNamespace(returncode=0, stdout="{not-json", stderr="")

    original_run = subprocess.run
    module.subprocess.run = invalid_json
    try:
        assert_raises(
            lambda: module.load_secret_names("owner/repo", "gh"),
            "invalid JSON",
        )
    finally:
        module.subprocess.run = original_run

    def failed_command(*_args, **_kwargs):
        return SimpleNamespace(returncode=1, stdout="", stderr=SENSITIVE_SENTINEL)

    module.subprocess.run = failed_command
    try:
        assert_raises(
            lambda: module.load_secret_names("owner/repo", "gh"),
            "gh secret list failed",
        )
    finally:
        module.subprocess.run = original_run


def main() -> int:
    module = load_module()
    run_audit_tests(module)
    run_gh_payload_tests(module)
    run_error_tests(module)
    print("GitHub release secret readiness regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
