#!/usr/bin/env python3
"""Validate custom hosted Linux repository publication config before release."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Mapping


ROOT = Path(__file__).resolve().parents[1]
TAGGED_READINESS = Path(__file__).with_name("check-tagged-release-readiness.py")

BASE_URL_ENV = "CONU_LINUX_REPOSITORY_BASE_URL"
BUCKET_ENV = "CONU_LINUX_REPOSITORY_S3_BUCKET"
PREFIX_ENV = "CONU_LINUX_REPOSITORY_S3_PREFIX"
ENDPOINT_ENV = "CONU_LINUX_REPOSITORY_S3_ENDPOINT_URL"
REGION_ENV = "CONU_LINUX_REPOSITORY_AWS_REGION"
ACCESS_KEY_ENV = "CONU_LINUX_REPOSITORY_AWS_ACCESS_KEY_ID"
SECRET_KEY_ENV = "CONU_LINUX_REPOSITORY_AWS_SECRET_ACCESS_KEY"
SESSION_TOKEN_ENV = "CONU_LINUX_REPOSITORY_AWS_SESSION_TOKEN"
MAX_SECRET_VALUE_BYTES = 8192


def main() -> int:
    args = parse_args()
    try:
        os.chdir(ROOT)
        report = audit_environment(os.environ)
    except (OSError, ValueError) as exc:
        report = failure_report(str(exc))

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    elif report["ready"]:
        print("Custom Linux repository publication preflight passed.")
    else:
        print("Custom Linux repository publication preflight failed.")
        if report["missing"]:
            print("Missing required environment variable(s):")
            for name in report["missing"]:
                print(f"  - {name}")
        if report["issues"]:
            print("Issue(s):")
            for issue in report["issues"]:
                print(f"  - {issue}")

    return 0 if report["ready"] else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json",
        action="store_true",
        help="print a machine-readable report without secret values",
    )
    return parser.parse_args()


def audit_environment(env: Mapping[str, str]) -> dict[str, object]:
    readiness = load_tagged_readiness()
    missing: list[str] = []
    issues: list[str] = []
    checks: dict[str, bool] = {}

    validate_required_variable(
        env,
        BASE_URL_ENV,
        readiness.normalize_custom_base_url,
        "customBaseUrl",
        missing,
        issues,
        checks,
    )
    validate_required_variable(
        env,
        BUCKET_ENV,
        readiness.validate_bucket,
        "customBucket",
        missing,
        issues,
        checks,
    )
    validate_optional_variable(
        env,
        PREFIX_ENV,
        readiness.validate_prefix,
        "customPrefixValid",
        issues,
        checks,
    )
    validate_optional_variable(
        env,
        ENDPOINT_ENV,
        readiness.validate_endpoint_url,
        "customEndpointValid",
        issues,
        checks,
    )
    validate_optional_variable(
        env,
        REGION_ENV,
        readiness.validate_region,
        "customRegionValid",
        issues,
        checks,
    )

    for name in (ACCESS_KEY_ENV, SECRET_KEY_ENV):
        validate_required_secret(env, name, missing, issues, checks)
    validate_optional_secret(env, SESSION_TOKEN_ENV, issues, checks)

    ready = not missing and not issues
    return {
        "schema": "conu.customLinuxRepositoryPublicationPreflight.v1",
        "ready": ready,
        "checks": checks,
        "missing": tuple(sorted(set(missing))),
        "issues": tuple(issues),
        "payloadDisplayed": False,
        "contentsDisplayed": False,
        "tokenDisplayed": False,
        "tokenHashDisplayed": False,
        "keyMaterialDisplayed": False,
        "secretValuesDisplayed": False,
    }


def load_tagged_readiness():
    spec = importlib.util.spec_from_file_location(
        "check_tagged_release_readiness_for_custom_repository_preflight",
        TAGGED_READINESS,
    )
    if spec is None or spec.loader is None:
        raise ValueError("could not load tagged release readiness validators")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def validate_required_variable(
    env: Mapping[str, str],
    name: str,
    validator,
    key: str,
    missing: list[str],
    issues: list[str],
    checks: dict[str, bool],
) -> None:
    value = env.get(name, "")
    configured = value.strip() != ""
    checks[f"{key}Configured"] = configured
    checks[f"{key}Valid"] = False
    if not configured:
        missing.append(name)
        return
    try:
        validator(value)
    except ValueError as exc:
        issues.append(str(exc))
        return
    checks[f"{key}Valid"] = True


def validate_optional_variable(
    env: Mapping[str, str],
    name: str,
    validator,
    check_name: str,
    issues: list[str],
    checks: dict[str, bool],
) -> None:
    value = env.get(name, "")
    checks[check_name] = True
    if value.strip() == "":
        return
    try:
        validator(value)
    except ValueError as exc:
        checks[check_name] = False
        issues.append(str(exc))


def validate_required_secret(
    env: Mapping[str, str],
    name: str,
    missing: list[str],
    issues: list[str],
    checks: dict[str, bool],
) -> None:
    value = env.get(name, "")
    configured = value.strip() != ""
    checks[f"{name}Configured"] = configured
    checks[f"{name}ShapeValid"] = False
    if not configured:
        missing.append(name)
        return
    if validate_secret_shape(name, value, issues):
        checks[f"{name}ShapeValid"] = True


def validate_optional_secret(
    env: Mapping[str, str],
    name: str,
    issues: list[str],
    checks: dict[str, bool],
) -> None:
    value = env.get(name, "")
    configured = value != ""
    checks[f"{name}Configured"] = configured
    checks[f"{name}ShapeValid"] = True
    if not configured:
        return
    if value.strip() == "":
        checks[f"{name}ShapeValid"] = False
        issues.append(f"{name} must not be blank when configured")
        return
    if not validate_secret_shape(name, value, issues):
        checks[f"{name}ShapeValid"] = False


def validate_secret_shape(name: str, value: str, issues: list[str]) -> bool:
    valid = True
    if len(value.encode("utf-8")) > MAX_SECRET_VALUE_BYTES:
        issues.append(f"{name} is too large")
        valid = False
    if not is_single_line_secret_value(value):
        issues.append(f"{name} must be a single-line secret value without whitespace or control characters")
        valid = False
    return valid


def is_single_line_secret_value(value: str) -> bool:
    return all(character > " " and character != "\x7f" for character in value)


def failure_report(issue: str) -> dict[str, object]:
    return {
        "schema": "conu.customLinuxRepositoryPublicationPreflight.v1",
        "ready": False,
        "checks": {},
        "missing": (),
        "issues": (issue,),
        "payloadDisplayed": False,
        "contentsDisplayed": False,
        "tokenDisplayed": False,
        "tokenHashDisplayed": False,
        "keyMaterialDisplayed": False,
        "secretValuesDisplayed": False,
    }


if __name__ == "__main__":
    raise SystemExit(main())
