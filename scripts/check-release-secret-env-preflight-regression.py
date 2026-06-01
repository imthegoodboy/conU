#!/usr/bin/env python3
"""Regression checks for tagged release secret environment preflight."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import sys
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-release-secret-env-preflight.py")
SENSITIVE_SENTINEL = "do-not-print-this-secret-value"


def main() -> int:
    module = load_module()
    run_audit_tests(module)
    run_main_tests(module)
    print("Tagged release secret environment preflight regression checks passed")
    return 0


def load_module():
    spec = importlib.util.spec_from_file_location(
        "check_release_secret_env_preflight",
        SCRIPT,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load release secret env preflight module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def run_audit_tests(module) -> None:
    ready_env = {
        name: f"{SENSITIVE_SENTINEL}-{index}"
        for index, name in enumerate(module.REQUIRED_RELEASE_SECRETS)
    }
    ready = module.audit_environment(ready_env)
    assert_safe_report(ready)
    if not ready["ready"]:
        raise AssertionError(f"expected ready release secret env report: {ready!r}")
    if tuple(ready["present"]) != module.REQUIRED_RELEASE_SECRETS:
        raise AssertionError("ready report did not preserve required secret order")

    missing_env = dict(ready_env)
    missing_env.pop("NPM_TOKEN")
    missing_env["CONU_LINUX_GPG_PASSPHRASE"] = "   "
    missing = module.audit_environment(missing_env)
    assert_safe_report(missing)
    if missing["ready"]:
        raise AssertionError("missing release secret env report unexpectedly passed")
    for name in ("CONU_LINUX_GPG_PASSPHRASE", "NPM_TOKEN"):
        if name not in missing["missing"]:
            raise AssertionError(f"missing release secret env report omitted {name}")


def run_main_tests(module) -> None:
    original_env = os.environ.copy()
    original_argv = sys.argv
    stdout = io.StringIO()
    stderr = io.StringIO()
    try:
        os.environ.clear()
        os.environ.update(
            {
                name: f"{SENSITIVE_SENTINEL}-{index}"
                for index, name in enumerate(module.REQUIRED_RELEASE_SECRETS)
            }
        )
        sys.argv = ["check-release-secret-env-preflight.py", "--json"]
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = module.main()
    finally:
        os.environ.clear()
        os.environ.update(original_env)
        sys.argv = original_argv

    if exit_code != 0:
        raise AssertionError(f"expected main() to pass, got {exit_code}: {stderr.getvalue()}")
    rendered = stdout.getvalue() + stderr.getvalue()
    if SENSITIVE_SENTINEL in rendered:
        raise AssertionError("release secret env preflight leaked a secret value")
    report = json.loads(stdout.getvalue())
    assert_safe_report(report)


def assert_safe_report(report: dict[str, object]) -> None:
    rendered = json.dumps(report)
    if SENSITIVE_SENTINEL in rendered:
        raise AssertionError("release secret env preflight report leaked a secret value")
    for flag in (
        "payloadDisplayed",
        "contentsDisplayed",
        "tokenDisplayed",
        "tokenHashDisplayed",
        "keyMaterialDisplayed",
        "secretValuesDisplayed",
    ):
        if report.get(flag) is not False:
            raise AssertionError(f"release secret env preflight report did not set {flag}=false")


if __name__ == "__main__":
    raise SystemExit(main())
