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


def ci_success_payload(module) -> list[dict[str, object]]:
    return [
        {
            "workflowName": module.DEFAULT_CI_WORKFLOW,
            "headSha": "a" * 40,
            "databaseId": 123,
            "status": "completed",
            "conclusion": "success",
            "event": "push",
            "createdAt": "2026-05-25T00:00:00Z",
            "displayTitle": SENSITIVE_SENTINEL,
        }
    ]


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


class WorkflowPermissionsFixture:
    def __init__(self, *, ready: bool, issues: tuple[str, ...] = ()) -> None:
        self.ready = ready
        self.issues = issues

    def as_json(self) -> dict[str, object]:
        return {
            "schema": "conu.githubWorkflowPermissions.v1",
            "ready": self.ready,
            "workflowCount": 2,
            "checkedWorkflows": ["ci.yml", "release.yml"],
            "workflowsWithExplicitTopLevelPermissions": ["ci.yml", "release.yml"],
            "jobsWithWritePermissions": ["release.yml:github-release"],
            "unsafeEnvironmentFileWrites": [],
            "forbiddenEvents": [],
            "issues": list(self.issues),
            "payloadDisplayed": False,
            "tokenDisplayed": False,
            "tokenHashDisplayed": False,
            "keyMaterialDisplayed": False,
            "contentsDisplayed": False,
        }


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
    if parsed["ci"]["checked"] is not False:
        raise AssertionError("CI check should be skipped by default")
    if parsed["releaseBranch"]["checked"] is not False:
        raise AssertionError("release branch check should be skipped by default")
    if parsed["workflowPermissions"]["ready"] is not True:
        raise AssertionError("workflow permissions should be included in tagged release readiness")


def run_workflow_permissions_tests(module) -> None:
    report = module.audit_tagged_release_readiness(
        repo="owner/repo",
        tag=TAG,
        version=VERSION,
        secret_names=all_release_secrets(module),
        variable_values={},
        pages_payload=pages_payload(),
        release_payload=None,
        npm_registry_check=False,
        workflow_permissions=WorkflowPermissionsFixture(
            ready=False,
            issues=("release.yml must define release-preflight job",),
        ),
    )
    if report.ready:
        raise AssertionError("workflow permissions failure should fail tagged release readiness")
    parsed = assert_safe_report(report)
    if parsed["workflowPermissions"]["ready"] is not False:
        raise AssertionError("workflow permissions readiness should be reported as failed")
    if "workflow readiness: release.yml must define release-preflight job" not in json.dumps(parsed):
        raise AssertionError("workflow permissions issue was not included in top-level issues")


def run_ci_readiness_tests(module) -> None:
    report = module.audit_tagged_release_readiness(
        repo="owner/repo",
        tag=TAG,
        version=VERSION,
        secret_names=all_release_secrets(module),
        variable_values={},
        pages_payload=pages_payload(),
        release_payload=None,
        npm_registry_check=False,
        ci_required=True,
        ci_head_sha="a" * 40,
        ci_runs_payload=ci_success_payload(module),
    )
    if not report.ready:
        raise AssertionError(f"expected CI readiness to pass: {report.issues!r}")
    parsed = assert_safe_report(report)
    if parsed["ci"]["checked"] is not True:
        raise AssertionError("CI readiness should be checked when required")
    if parsed["ci"]["ready"] is not True:
        raise AssertionError("successful CI run should be ready")
    if parsed["ci"]["runId"] != 123:
        raise AssertionError("CI run id should be reported as metadata")

    missing = module.audit_tagged_release_readiness(
        repo="owner/repo",
        tag=TAG,
        version=VERSION,
        secret_names=all_release_secrets(module),
        variable_values={},
        pages_payload=pages_payload(),
        release_payload=None,
        npm_registry_check=False,
        ci_required=True,
        ci_head_sha="b" * 40,
        ci_runs_payload=ci_success_payload(module),
    )
    if missing.ready:
        raise AssertionError("missing CI run should fail readiness")
    parsed_missing = assert_safe_report(missing)
    if "no CI workflow run found" not in json.dumps(parsed_missing):
        raise AssertionError("missing CI run issue was not reported")

    failed = module.audit_tagged_release_readiness(
        repo="owner/repo",
        tag=TAG,
        version=VERSION,
        secret_names=all_release_secrets(module),
        variable_values={},
        pages_payload=pages_payload(),
        release_payload=None,
        npm_registry_check=False,
        ci_required=True,
        ci_head_sha="c" * 40,
        ci_runs_payload=[
            {
                "workflowName": module.DEFAULT_CI_WORKFLOW,
                "headSha": "c" * 40,
                "databaseId": 456,
                "status": "completed",
                "conclusion": "failure",
                "event": "push",
                "createdAt": "2026-05-25T00:00:00Z",
                "url": f"https://example.invalid/{SENSITIVE_SENTINEL}",
            }
        ],
    )
    if failed.ready:
        raise AssertionError("failed CI run should fail readiness")
    parsed_failed = assert_safe_report(failed)
    if "concluded failure" not in json.dumps(parsed_failed):
        raise AssertionError("failed CI conclusion was not reported")

    running = module.audit_ci_readiness(
        required=True,
        workflow=module.DEFAULT_CI_WORKFLOW,
        head_sha="d" * 40,
        runs_payload=[
            {
                "workflowName": module.DEFAULT_CI_WORKFLOW,
                "headSha": "d" * 40,
                "databaseId": 789,
                "status": "in_progress",
                "conclusion": "",
            }
        ],
    )
    if running.ready:
        raise AssertionError("running CI run should fail readiness")
    if "in_progress" not in json.dumps(running.as_json()):
        raise AssertionError("running CI status was not reported")

    invalid = module.audit_ci_readiness(
        required=True,
        workflow=module.DEFAULT_CI_WORKFLOW,
        head_sha="not-a-sha",
        runs_payload=[],
    )
    if invalid.ready:
        raise AssertionError("invalid CI head SHA should fail readiness")
    if SENSITIVE_SENTINEL in json.dumps(invalid.as_json()):
        raise AssertionError("invalid CI readiness report leaked sensitive text")


def run_release_branch_readiness_tests(module) -> None:
    report = module.audit_tagged_release_readiness(
        repo="owner/repo",
        tag=TAG,
        version=VERSION,
        secret_names=all_release_secrets(module),
        variable_values={},
        pages_payload=pages_payload(),
        release_payload=None,
        npm_registry_check=False,
        ci_required=True,
        ci_head_sha="a" * 40,
        ci_runs_payload=ci_success_payload(module),
        release_branch_required=True,
        release_branch="main",
        release_target_sha="a" * 40,
        release_branch_sha="a" * 40,
    )
    if not report.ready:
        raise AssertionError(f"expected release branch readiness to pass: {report.issues!r}")
    parsed = assert_safe_report(report)
    if parsed["releaseBranch"]["checked"] is not True:
        raise AssertionError("release branch readiness should be checked when required")
    if parsed["releaseBranch"]["ready"] is not True:
        raise AssertionError("matching branch head should be ready")
    if parsed["releaseBranch"]["branchSha"] != "a" * 40:
        raise AssertionError("branch SHA should be reported as metadata")

    mismatch = module.audit_tagged_release_readiness(
        repo="owner/repo",
        tag=TAG,
        version=VERSION,
        secret_names=all_release_secrets(module),
        variable_values={},
        pages_payload=pages_payload(),
        release_payload=None,
        npm_registry_check=False,
        release_branch_required=True,
        release_branch="main",
        release_target_sha="b" * 40,
        release_branch_sha="c" * 40,
    )
    if mismatch.ready:
        raise AssertionError("mismatched release target and branch head should fail")
    parsed_mismatch = assert_safe_report(mismatch)
    if "does not match main head" not in json.dumps(parsed_mismatch):
        raise AssertionError("release branch mismatch issue was not reported")

    invalid = module.audit_release_branch_readiness(
        required=True,
        branch="main",
        target_sha="not-a-sha",
        branch_sha="d" * 40,
    )
    if invalid.ready:
        raise AssertionError("invalid release target SHA should fail")
    if SENSITIVE_SENTINEL in json.dumps(invalid.as_json()):
        raise AssertionError("invalid release branch report leaked sensitive text")

    missing_branch = module.audit_release_branch_readiness(
        required=True,
        branch="main",
        target_sha="e" * 40,
        branch_sha="",
    )
    if missing_branch.ready:
        raise AssertionError("missing release branch SHA should fail")
    if "head SHA is missing or invalid" not in json.dumps(missing_branch.as_json()):
        raise AssertionError("missing release branch SHA issue was not reported")


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

    invalid_base_paths = module.audit_tagged_release_readiness(
        repo="owner/repo",
        tag=TAG,
        version=VERSION,
        secret_names=all_custom_secrets(module),
        variable_values={
            module.CUSTOM_REPOSITORY_BASE_URL_VAR: "https://packages.example.com/conu/%2e%2e/v0.1.0",
            module.CUSTOM_REPOSITORY_BUCKET_VAR: "conu-packages",
            module.CUSTOM_REPOSITORY_PREFIX_VAR: "stable/conu",
            module.CUSTOM_REPOSITORY_ENDPOINT_VAR: "https://s3.example.com",
            module.CUSTOM_REPOSITORY_REGION_VAR: "us-east-1",
        },
        pages_payload=None,
        release_payload=None,
        npm_registry_check=False,
    )
    if invalid_base_paths.ready:
        raise AssertionError("encoded custom repository base URL dot segment should fail")
    parsed_invalid_base_paths = assert_safe_report(invalid_base_paths)
    if (
        "custom repository base URL path must not contain dot segments"
        not in json.dumps(parsed_invalid_base_paths)
    ):
        raise AssertionError("encoded custom repository base URL dot segment failure was missing")

    invalid_base_separator = module.audit_tagged_release_readiness(
        repo="owner/repo",
        tag=TAG,
        version=VERSION,
        secret_names=all_custom_secrets(module),
        variable_values={
            module.CUSTOM_REPOSITORY_BASE_URL_VAR: "https://packages.example.com/conu/v0.1.0%2fother",
            module.CUSTOM_REPOSITORY_BUCKET_VAR: "conu-packages",
            module.CUSTOM_REPOSITORY_PREFIX_VAR: "stable/conu",
            module.CUSTOM_REPOSITORY_ENDPOINT_VAR: "https://s3.example.com",
            module.CUSTOM_REPOSITORY_REGION_VAR: "us-east-1",
        },
        pages_payload=None,
        release_payload=None,
        npm_registry_check=False,
    )
    if invalid_base_separator.ready:
        raise AssertionError("encoded custom repository base URL separator should fail")
    parsed_invalid_base_separator = assert_safe_report(invalid_base_separator)
    if (
        "custom repository base URL path must not contain encoded separators"
        not in json.dumps(parsed_invalid_base_separator)
    ):
        raise AssertionError("encoded custom repository base URL separator failure was missing")

    invalid_base_authority = module.audit_tagged_release_readiness(
        repo="owner/repo",
        tag=TAG,
        version=VERSION,
        secret_names=all_custom_secrets(module),
        variable_values={
            module.CUSTOM_REPOSITORY_BASE_URL_VAR: "https://packages.example.com:bad/conu",
            module.CUSTOM_REPOSITORY_BUCKET_VAR: "conu-packages",
            module.CUSTOM_REPOSITORY_PREFIX_VAR: "stable/conu",
            module.CUSTOM_REPOSITORY_ENDPOINT_VAR: "https://s3.example.com",
            module.CUSTOM_REPOSITORY_REGION_VAR: "us-east-1",
        },
        pages_payload=None,
        release_payload=None,
        npm_registry_check=False,
    )
    if invalid_base_authority.ready:
        raise AssertionError("malformed custom repository base URL authority should fail")
    parsed_invalid_base_authority = assert_safe_report(invalid_base_authority)
    if (
        "custom repository base URL authority is invalid"
        not in json.dumps(parsed_invalid_base_authority)
    ):
        raise AssertionError("malformed custom repository base URL authority failure was missing")

    invalid_endpoint_paths = module.audit_tagged_release_readiness(
        repo="owner/repo",
        tag=TAG,
        version=VERSION,
        secret_names=all_custom_secrets(module),
        variable_values={
            module.CUSTOM_REPOSITORY_BASE_URL_VAR: "https://packages.example.com/conu/",
            module.CUSTOM_REPOSITORY_BUCKET_VAR: "conu-packages",
            module.CUSTOM_REPOSITORY_PREFIX_VAR: "stable/conu",
            module.CUSTOM_REPOSITORY_ENDPOINT_VAR: "https://s3.example.com/api/%2e%2e/v1",
            module.CUSTOM_REPOSITORY_REGION_VAR: "us-east-1",
        },
        pages_payload=None,
        release_payload=None,
        npm_registry_check=False,
    )
    if invalid_endpoint_paths.ready:
        raise AssertionError("encoded custom repository endpoint URL dot segment should fail")
    parsed_invalid_endpoint_paths = assert_safe_report(invalid_endpoint_paths)
    if (
        "custom repository S3 endpoint URL path must not contain dot segments"
        not in json.dumps(parsed_invalid_endpoint_paths)
    ):
        raise AssertionError("encoded custom repository endpoint URL dot segment failure was missing")

    invalid_endpoint_separator = module.audit_tagged_release_readiness(
        repo="owner/repo",
        tag=TAG,
        version=VERSION,
        secret_names=all_custom_secrets(module),
        variable_values={
            module.CUSTOM_REPOSITORY_BASE_URL_VAR: "https://packages.example.com/conu/",
            module.CUSTOM_REPOSITORY_BUCKET_VAR: "conu-packages",
            module.CUSTOM_REPOSITORY_PREFIX_VAR: "stable/conu",
            module.CUSTOM_REPOSITORY_ENDPOINT_VAR: "https://s3.example.com/api%2fv1",
            module.CUSTOM_REPOSITORY_REGION_VAR: "us-east-1",
        },
        pages_payload=None,
        release_payload=None,
        npm_registry_check=False,
    )
    if invalid_endpoint_separator.ready:
        raise AssertionError("encoded custom repository endpoint URL separator should fail")
    parsed_invalid_endpoint_separator = assert_safe_report(invalid_endpoint_separator)
    if (
        "custom repository S3 endpoint URL path must not contain encoded separators"
        not in json.dumps(parsed_invalid_endpoint_separator)
    ):
        raise AssertionError("encoded custom repository endpoint URL separator failure was missing")

    invalid_endpoint_authority = module.audit_tagged_release_readiness(
        repo="owner/repo",
        tag=TAG,
        version=VERSION,
        secret_names=all_custom_secrets(module),
        variable_values={
            module.CUSTOM_REPOSITORY_BASE_URL_VAR: "https://packages.example.com/conu/",
            module.CUSTOM_REPOSITORY_BUCKET_VAR: "conu-packages",
            module.CUSTOM_REPOSITORY_PREFIX_VAR: "stable/conu",
            module.CUSTOM_REPOSITORY_ENDPOINT_VAR: "https://s3.example.com:/api",
            module.CUSTOM_REPOSITORY_REGION_VAR: "us-east-1",
        },
        pages_payload=None,
        release_payload=None,
        npm_registry_check=False,
    )
    if invalid_endpoint_authority.ready:
        raise AssertionError("malformed custom repository endpoint URL authority should fail")
    parsed_invalid_endpoint_authority = assert_safe_report(invalid_endpoint_authority)
    if (
        "custom repository S3 endpoint URL authority is invalid"
        not in json.dumps(parsed_invalid_endpoint_authority)
    ):
        raise AssertionError("malformed custom repository endpoint URL authority failure was missing")


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
    run_workflow_permissions_tests(module)
    run_ci_readiness_tests(module)
    run_release_branch_readiness_tests(module)
    run_missing_secret_tests(module)
    run_custom_repository_tests(module)
    run_safe_failure_tests(module)
    print("Tagged release readiness regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
