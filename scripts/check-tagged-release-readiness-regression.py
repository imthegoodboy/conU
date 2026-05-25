#!/usr/bin/env python3
"""Regression checks for the live tagged-release readiness audit."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-tagged-release-readiness.py")
VERSION = "0.1.0"
TAG = "v0.1.0"
SENSITIVE_SENTINEL = "do-not-print-this-secret-value"


def load_module():
    spec = importlib.util.spec_from_file_location("check_tagged_release_readiness", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load tagged-release readiness module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def pages_payload() -> dict[str, object]:
    return {
        "html_url": "https://owner.github.io/repo/",
        "build_type": "workflow",
        "https_enforced": True,
        "public": True,
        "source": {"branch": "main", "path": "/"},
    }


def release_payload() -> dict[str, object]:
    return {
        "tag_name": TAG,
        "draft": False,
        "prerelease": False,
        "assets": [
            {
                "name": "conu-0.1.0-linux-x64.tar.gz",
                "browser_download_url": f"https://example.invalid/{SENSITIVE_SENTINEL}",
            }
        ],
        "body": SENSITIVE_SENTINEL,
    }


def all_release_secrets(module) -> set[str]:
    return set(module.REQUIRED_RELEASE_SECRETS)


def all_custom_secrets(module) -> set[str]:
    return set(module.REQUIRED_RELEASE_SECRETS) | set(module.CUSTOM_REPOSITORY_REQUIRED_SECRETS)


def assert_safe_report(report) -> dict[str, object]:
    rendered = json.dumps(report.as_json(), sort_keys=True)
    if SENSITIVE_SENTINEL in rendered:
        raise AssertionError("tagged-release readiness report leaked unrelated sensitive text")
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


def run_ready_pages_tests(module) -> None:
    report = module.audit_tagged_release_readiness(
        repo="owner/repo",
        tag=TAG,
        version=VERSION,
        secret_names=all_release_secrets(module),
        variable_values={},
        pages_payload=pages_payload(),
        release_payload=None,
        npm_registry_check=False,
    )
    if not report.ready:
        raise AssertionError(f"expected default Pages readiness to pass: {report.issues!r}")
    parsed = assert_safe_report(report)
    if parsed["linuxRepository"]["mode"] != "github-pages":
        raise AssertionError("expected github-pages repository mode")
    if parsed["npmRegistry"]["checked"] is not False:
        raise AssertionError("npm registry should be skipped by default")


def run_missing_secret_tests(module) -> None:
    names = all_release_secrets(module)
    names.remove("NPM_TOKEN")
    report = module.audit_tagged_release_readiness(
        repo="owner/repo",
        tag=TAG,
        version=VERSION,
        secret_names=names,
        variable_values={},
        pages_payload=pages_payload(),
        release_payload=None,
        npm_registry_check=False,
    )
    if report.ready:
        raise AssertionError("missing release secret should fail readiness")
    parsed = assert_safe_report(report)
    if "NPM_TOKEN" not in parsed["releaseSecrets"]["missing"]:
        raise AssertionError("missing release secret name was not reported")


def run_custom_repository_tests(module) -> None:
    report = module.audit_tagged_release_readiness(
        repo="owner/repo",
        tag=TAG,
        version=VERSION,
        secret_names=all_custom_secrets(module),
        variable_values={
            module.CUSTOM_REPOSITORY_BASE_URL_VAR: "https://packages.example.com/conu/",
            module.CUSTOM_REPOSITORY_BUCKET_VAR: "conu-packages",
            module.CUSTOM_REPOSITORY_PREFIX_VAR: "stable/conu",
            module.CUSTOM_REPOSITORY_ENDPOINT_VAR: "https://s3.example.com",
            module.CUSTOM_REPOSITORY_REGION_VAR: "us-east-1",
        },
        pages_payload=None,
        release_payload=None,
        npm_registry_check=False,
    )
    if not report.ready:
        raise AssertionError(f"expected custom repository readiness to pass: {report.issues!r}")
    parsed = assert_safe_report(report)
    if parsed["linuxRepository"]["mode"] != "custom-s3":
        raise AssertionError("expected custom-s3 repository mode")

    missing = module.audit_tagged_release_readiness(
        repo="owner/repo",
        tag=TAG,
        version=VERSION,
        secret_names=all_release_secrets(module),
        variable_values={
            module.CUSTOM_REPOSITORY_BASE_URL_VAR: "https://packages.example.com/conu/",
        },
        pages_payload=None,
        release_payload=None,
        npm_registry_check=False,
    )
    if missing.ready:
        raise AssertionError("missing custom bucket/secrets should fail")
    parsed_missing = assert_safe_report(missing)
    if module.CUSTOM_REPOSITORY_BUCKET_VAR not in parsed_missing["linuxRepository"]["missingVariables"]:
        raise AssertionError("missing custom bucket variable was not reported")
    for name in module.CUSTOM_REPOSITORY_REQUIRED_SECRETS:
        if name not in parsed_missing["linuxRepository"]["missingSecrets"]:
            raise AssertionError(f"missing custom secret was not reported: {name}")

    invalid_optional = module.audit_tagged_release_readiness(
        repo="owner/repo",
        tag=TAG,
        version=VERSION,
        secret_names=all_custom_secrets(module),
        variable_values={
            module.CUSTOM_REPOSITORY_BASE_URL_VAR: "https://packages.example.com/conu/",
            module.CUSTOM_REPOSITORY_BUCKET_VAR: "conu-packages",
            module.CUSTOM_REPOSITORY_PREFIX_VAR: "bad//prefix",
            module.CUSTOM_REPOSITORY_ENDPOINT_VAR: f"https://user:{SENSITIVE_SENTINEL}@s3.example.com",
            module.CUSTOM_REPOSITORY_REGION_VAR: "us east 1",
        },
        pages_payload=None,
        release_payload=None,
        npm_registry_check=False,
    )
    if invalid_optional.ready:
        raise AssertionError("invalid optional custom repository variables should fail")
    parsed_invalid_optional = assert_safe_report(invalid_optional)
    rendered_invalid_optional = json.dumps(parsed_invalid_optional)
    for expected in (
        "custom repository S3 prefix must not contain empty path segments",
        "custom repository S3 endpoint URL must not include credentials",
        "custom repository AWS region must not contain whitespace",
    ):
        if expected not in rendered_invalid_optional:
            raise AssertionError(f"expected optional variable failure was missing: {expected}")


def run_safe_failure_tests(module) -> None:
    invalid = module.audit_tagged_release_readiness(
        repo="owner/repo",
        tag=TAG,
        version=VERSION,
        secret_names=all_custom_secrets(module),
        variable_values={
            module.CUSTOM_REPOSITORY_BASE_URL_VAR: f"https://user:{SENSITIVE_SENTINEL}@example.com/conu",
            module.CUSTOM_REPOSITORY_BUCKET_VAR: "s3://bad/bucket",
        },
        pages_payload=None,
        release_payload=release_payload(),
        npm_registry_check=False,
    )
    if invalid.ready:
        raise AssertionError("invalid custom repository plus existing release should fail")
    parsed = assert_safe_report(invalid)
    rendered = json.dumps(parsed)
    for expected in (
        "custom repository base URL must not include credentials",
        "custom repository S3 bucket must be a bucket name",
        "already exists",
    ):
        if expected not in rendered:
            raise AssertionError(f"expected failure issue was missing: {expected}")


def run_tag_validation_tests(module) -> None:
    if module.validate_tag_for_version(TAG, VERSION) != TAG:
        raise AssertionError("expected valid tag to pass")
    for bad_tag in ("0.1.0", "vlatest", "v0.2.0"):
        try:
            module.validate_tag_for_version(bad_tag, VERSION)
        except ValueError:
            continue
        raise AssertionError(f"expected tag validation failure for {bad_tag}")

    original_env = {
        name: os.environ.get(name)
        for name in ("CONU_RELEASE_TAG", "GITHUB_REF_NAME", "GITHUB_REF_TYPE", "TAG_NAME")
    }
    try:
        for name in original_env:
            os.environ.pop(name, None)
        os.environ["GITHUB_REF_NAME"] = "main"
        if module.default_tag(VERSION) != TAG:
            raise AssertionError("branch ref name should not override the version-derived default tag")
        os.environ["GITHUB_REF_TYPE"] = "tag"
        os.environ["GITHUB_REF_NAME"] = TAG
        if module.default_tag(VERSION) != TAG:
            raise AssertionError("tag ref name should provide the default tag")
    finally:
        for name, value in original_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def main() -> int:
    module = load_module()
    run_tag_validation_tests(module)
    run_ready_pages_tests(module)
    run_missing_secret_tests(module)
    run_custom_repository_tests(module)
    run_safe_failure_tests(module)
    print("Tagged release readiness regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
