#!/usr/bin/env python3
"""Regression checks for the release secret rotation marker gate."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import sys
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-release-secret-rotation-gate.py")
SENSITIVE_SENTINEL = "do-not-print-this-token-value"


def load_module():
    spec = importlib.util.spec_from_file_location("check_release_secret_rotation_gate", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load release secret rotation gate module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def assert_safe_report(report) -> dict[str, object]:
    rendered = json.dumps(report.as_json(), sort_keys=True)
    if SENSITIVE_SENTINEL in rendered:
        raise AssertionError("rotation gate report leaked the marker value")
    parsed = json.loads(rendered)
    for field in (
        "payloadDisplayed",
        "tokenDisplayed",
        "tokenHashDisplayed",
        "keyMaterialDisplayed",
        "contentsDisplayed",
        "secretValuesDisplayed",
    ):
        if parsed.get(field) is not False:
            raise AssertionError(f"expected {field}=false")
    return parsed


def run_audit_tests(module) -> None:
    ready = module.audit_rotation_marker(
        secret_name="NPM_TOKEN",
        marker_env="CONU_NPM_TOKEN_ROTATED_AFTER",
        required_after="2026-06-03T00:00:00Z",
        rotated_after="2026-06-03T00:00:01+00:00",
    )
    if not ready.ready:
        raise AssertionError(f"expected fresh rotation marker to pass: {ready.issues!r}")
    parsed_ready = assert_safe_report(ready)
    if parsed_ready["rotatedAfter"] != "2026-06-03T00:00:01Z":
        raise AssertionError("rotation marker timestamp was not normalized")

    stale = module.audit_rotation_marker(
        secret_name="NPM_TOKEN",
        marker_env="CONU_NPM_TOKEN_ROTATED_AFTER",
        required_after="2026-06-03T00:00:00Z",
        rotated_after="2026-06-03T00:00:00Z",
    )
    if stale.ready:
        raise AssertionError("stale rotation marker should fail")
    parsed_stale = assert_safe_report(stale)
    if "NPM_TOKEN rotation marker is not after required timestamp" not in json.dumps(parsed_stale):
        raise AssertionError("stale rotation marker issue was not reported")

    missing = module.audit_rotation_marker(
        secret_name="NPM_TOKEN",
        marker_env="CONU_NPM_TOKEN_ROTATED_AFTER",
        required_after="2026-06-03T00:00:00Z",
        rotated_after="",
    )
    if missing.ready:
        raise AssertionError("missing rotation marker should fail")
    parsed_missing = assert_safe_report(missing)
    if "CONU_NPM_TOKEN_ROTATED_AFTER" not in json.dumps(parsed_missing):
        raise AssertionError("missing marker env name was not reported")

    invalid = module.audit_rotation_marker(
        secret_name="NPM_TOKEN",
        marker_env="CONU_NPM_TOKEN_ROTATED_AFTER",
        required_after="2026-06-03T00:00:00Z",
        rotated_after=SENSITIVE_SENTINEL,
    )
    if invalid.ready:
        raise AssertionError("invalid rotation marker should fail")
    parsed_invalid = assert_safe_report(invalid)
    if parsed_invalid["rotatedAfter"] != "":
        raise AssertionError("invalid marker value should not be echoed")
    if "NPM_TOKEN rotation marker timestamp is invalid" not in json.dumps(parsed_invalid):
        raise AssertionError("invalid rotation marker issue was not reported")


def run_parse_tests(module) -> None:
    for kwargs, expected in (
        (
            {
                "secret_name": "UNKNOWN",
                "marker_env": "CONU_NPM_TOKEN_ROTATED_AFTER",
                "required_after": "2026-06-03T00:00:00Z",
                "rotated_after": "2026-06-03T00:00:01Z",
            },
            "unknown required secret",
        ),
        (
            {
                "secret_name": "NPM_TOKEN",
                "marker_env": "CONU_NPM_TOKEN_ROTATED_AFTER",
                "required_after": "2026-06-03T00:00:00",
                "rotated_after": "2026-06-03T00:00:01Z",
            },
            "must include a timezone",
        ),
    ):
        try:
            module.audit_rotation_marker(**kwargs)
        except ValueError as exc:
            if expected not in str(exc):
                raise AssertionError(f"unexpected parse error: {exc}") from exc
        else:
            raise AssertionError("expected rotation marker parse failure")


def run_cli_tests(module) -> None:
    original_argv = sys.argv[:]
    original_env = os.environ.get("CONU_NPM_TOKEN_ROTATED_AFTER")
    try:
        os.environ["CONU_NPM_TOKEN_ROTATED_AFTER"] = SENSITIVE_SENTINEL
        sys.argv = [
            "check-release-secret-rotation-gate.py",
            "--secret-name",
            "NPM_TOKEN",
            "--rotated-after-env",
            "CONU_NPM_TOKEN_ROTATED_AFTER",
            "--required-after",
            "2026-06-03T00:00:00Z",
            "--json",
        ]
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = module.main()
        rendered = stdout.getvalue() + stderr.getvalue()
        if exit_code != 1:
            raise AssertionError("invalid CLI marker should fail")
        if SENSITIVE_SENTINEL in rendered:
            raise AssertionError("invalid CLI marker leaked the marker value")

        os.environ["CONU_NPM_TOKEN_ROTATED_AFTER"] = "2026-06-03T00:00:01Z"
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = module.main()
        if exit_code != 0:
            raise AssertionError(f"valid CLI marker should pass: {stderr.getvalue()}")
    finally:
        sys.argv = original_argv
        if original_env is None:
            os.environ.pop("CONU_NPM_TOKEN_ROTATED_AFTER", None)
        else:
            os.environ["CONU_NPM_TOKEN_ROTATED_AFTER"] = original_env


def main() -> int:
    module = load_module()
    run_audit_tests(module)
    run_parse_tests(module)
    run_cli_tests(module)
    print("Release secret rotation gate regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
