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


def all_secret_update_times(module, updated_at: str = "2026-06-03T02:00:00Z") -> dict[str, str]:
    return {name: updated_at for name in module.REQUIRED_RELEASE_SECRETS}


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


class GovernanceFixture:
    def __init__(self, *, schema: str, ready: bool, issues: tuple[str, ...] = ()) -> None:
        self.schema = schema
        self.ready = ready
        self.issues = issues

    def as_json(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "ready": self.ready,
            "issues": list(self.issues),
            "payloadDisplayed": False,
            "tokenDisplayed": False,
            "tokenHashDisplayed": False,
            "keyMaterialDisplayed": False,
            "contentsDisplayed": False,
            "alertBodiesDisplayed": False,
        }


def ready_governance_kwargs() -> dict[str, GovernanceFixture]:
    return {
        "main_branch_protection": GovernanceFixture(
            schema="conu.githubMainBranchProtection.v1",
            ready=True,
        ),
        "actions_permissions": GovernanceFixture(
            schema="conu.githubActionsPermissions.v1",
            ready=True,
        ),
        "repository_security": GovernanceFixture(
            schema="conu.githubRepositorySecurity.v1",
            ready=True,
        ),
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
        **ready_governance_kwargs(),
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
    if parsed["mainBranchProtection"]["ready"] is not True:
        raise AssertionError("main branch protection should be included in tagged release readiness")
    if parsed["actionsPermissions"]["ready"] is not True:
        raise AssertionError("Actions permissions should be included in tagged release readiness")
    if parsed["repositorySecurity"]["ready"] is not True:
        raise AssertionError("repository security should be included in tagged release readiness")
    if parsed["secretRotation"]["checked"] is not False:
        raise AssertionError("secret rotation readiness should be skipped by default")


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
        **ready_governance_kwargs(),
    )
    if report.ready:
        raise AssertionError("workflow permissions failure should fail tagged release readiness")
    parsed = assert_safe_report(report)
    if parsed["workflowPermissions"]["ready"] is not False:
        raise AssertionError("workflow permissions readiness should be reported as failed")
    if "workflow readiness: release.yml must define release-preflight job" not in json.dumps(parsed):
        raise AssertionError("workflow permissions issue was not included in top-level issues")


def run_repository_governance_tests(module) -> None:
    report = module.audit_tagged_release_readiness(
        repo="owner/repo",
        tag=TAG,
        version=VERSION,
        secret_names=all_release_secrets(module),
        variable_values={},
        pages_payload=pages_payload(),
        release_payload=None,
        npm_registry_check=False,
        workflow_permissions=WorkflowPermissionsFixture(ready=True),
        main_branch_protection=GovernanceFixture(
            schema="conu.githubMainBranchProtection.v1",
            ready=False,
            issues=("missing required status check: Packages",),
        ),
        actions_permissions=GovernanceFixture(
            schema="conu.githubActionsPermissions.v1",
            ready=False,
            issues=("default workflow token permissions must be read-only",),
        ),
        repository_security=GovernanceFixture(
            schema="conu.githubRepositorySecurity.v1",
            ready=False,
            issues=("secret scanning push protection must be enabled",),
        ),
    )
    if report.ready:
        raise AssertionError("repository governance failures should fail tagged release readiness")
    parsed = assert_safe_report(report)
    rendered = json.dumps(parsed)
    for expected in (
        "main branch protection readiness: missing required status check: Packages",
        "GitHub Actions permissions readiness: default workflow token permissions must be read-only",
        "GitHub repository security readiness: secret scanning push protection must be enabled",
    ):
        if expected not in rendered:
            raise AssertionError(f"repository governance issue was not reported: {expected}")


def run_main_branch_protection_caller_tests(module) -> None:
    original_loader = module.load_script_module
    captured: dict[str, object] = {}

    class BranchModuleFixture:
        DEFAULT_BRANCH = "main"
        DEFAULT_REQUIRED_STATUS_CHECKS = ("Packages",)

        @staticmethod
        def load_branch_protection(repo: str, branch: str, gh: str) -> dict[str, object]:
            captured["repo"] = repo
            captured["branch"] = branch
            captured["gh"] = gh
            return {}

        @staticmethod
        def audit_branch_protection(**kwargs):
            captured.update(kwargs)
            return GovernanceFixture(
                schema="conu.githubMainBranchProtection.v1",
                ready=True,
            )

    try:
        module.load_script_module = lambda script, name: BranchModuleFixture
        report = module.audit_main_branch_protection("owner/repo", "gh", "main")
    finally:
        module.load_script_module = original_loader

    if report.ready is not True:
        raise AssertionError("expected branch protection fixture to pass")
    if captured.get("require_admin_enforcement") is not True:
        raise AssertionError("tagged release readiness must require admin enforcement")
    if captured.get("required_status_checks") != BranchModuleFixture.DEFAULT_REQUIRED_STATUS_CHECKS:
        raise AssertionError("tagged release readiness must keep default required status checks")


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
        **ready_governance_kwargs(),
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
        **ready_governance_kwargs(),
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
        **ready_governance_kwargs(),
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
        **ready_governance_kwargs(),
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
        **ready_governance_kwargs(),
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
        **ready_governance_kwargs(),
    )
    if report.ready:
        raise AssertionError("missing release secret should fail readiness")
    parsed = assert_safe_report(report)
    if "NPM_TOKEN" not in parsed["releaseSecrets"]["missing"]:
        raise AssertionError("missing release secret name was not reported")


def run_secret_rotation_tests(module) -> None:
    requirement = module.SecretRotationRequirement(
        name="NPM_TOKEN",
        updated_after="2026-06-03T00:00:00Z",
    )
    ready = module.audit_tagged_release_readiness(
        repo="owner/repo",
        tag=TAG,
        version=VERSION,
        secret_names=all_release_secrets(module),
        secret_updated_at=all_secret_update_times(module, "2026-06-03T00:00:01Z"),
        secret_rotation_requirements=(requirement,),
        variable_values={},
        pages_payload=pages_payload(),
        release_payload=None,
        npm_registry_check=False,
        **ready_governance_kwargs(),
    )
    if not ready.ready:
        raise AssertionError(f"expected fresh secret rotation readiness to pass: {ready.issues!r}")
    parsed_ready = assert_safe_report(ready)
    if parsed_ready["secretRotation"]["checked"] is not True:
        raise AssertionError("secret rotation readiness should be checked")
    if parsed_ready["secretRotation"]["requirements"][0]["name"] != "NPM_TOKEN":
        raise AssertionError("secret rotation report should identify the checked secret name")

    stale = module.audit_tagged_release_readiness(
        repo="owner/repo",
        tag=TAG,
        version=VERSION,
        secret_names=all_release_secrets(module),
        secret_updated_at=all_secret_update_times(module, "2026-06-02T23:59:59Z"),
        secret_rotation_requirements=(requirement,),
        variable_values={},
        pages_payload=pages_payload(),
        release_payload=None,
        npm_registry_check=False,
        **ready_governance_kwargs(),
    )
    if stale.ready:
        raise AssertionError("stale secret rotation should fail readiness")
    parsed_stale = assert_safe_report(stale)
    if (
        "release secret rotation readiness: NPM_TOKEN was not rotated after required timestamp"
        not in json.dumps(parsed_stale)
    ):
        raise AssertionError("stale secret rotation issue was not reported")

    missing = module.audit_tagged_release_readiness(
        repo="owner/repo",
        tag=TAG,
        version=VERSION,
        secret_names=all_release_secrets(module),
        secret_updated_at={},
        secret_rotation_requirements=(requirement,),
        variable_values={},
        pages_payload=pages_payload(),
        release_payload=None,
        npm_registry_check=False,
        **ready_governance_kwargs(),
    )
    if missing.ready:
        raise AssertionError("missing secret update timestamp should fail readiness")
    parsed_missing = assert_safe_report(missing)
    if "NPM_TOKEN update timestamp is missing" not in json.dumps(parsed_missing):
        raise AssertionError("missing secret update timestamp issue was not reported")

    invalid = module.audit_secret_rotation(
        {"NPM_TOKEN": "not-a-timestamp"},
        (requirement,),
    )
    if invalid.ready:
        raise AssertionError("invalid secret update timestamp should fail readiness")
    if "NPM_TOKEN update timestamp is invalid" not in json.dumps(invalid.as_json()):
        raise AssertionError("invalid secret update timestamp issue was not reported")

    parsed = module.parse_secret_rotation_requirement(
        "NPM_TOKEN=2026-06-03T00:00:00+00:00"
    )
    if parsed.updated_after != "2026-06-03T00:00:00Z":
        raise AssertionError("secret rotation requirement timestamp was not normalized")
    for raw, expected in (
        ("NPM_TOKEN", "NAME=ISO-8601_TIMESTAMP"),
        ("UNKNOWN=2026-06-03T00:00:00Z", "unknown required secret"),
        ("NPM_TOKEN=2026-06-03T00:00:00", "must include a timezone"),
    ):
        try:
            module.parse_secret_rotation_requirement(raw)
        except ValueError as exc:
            if expected not in str(exc):
                raise AssertionError(f"unexpected parse error for {raw!r}: {exc}") from exc
        else:
            raise AssertionError(f"expected secret rotation parse failure for {raw!r}")


def run_secret_rotation_marker_tests(module) -> None:
    requirement = module.default_secret_rotation_marker_requirements()[0]
    ready = module.audit_tagged_release_readiness(
        repo="owner/repo",
        tag=TAG,
        version=VERSION,
        secret_names=all_release_secrets(module),
        variable_values={
            module.NPM_TOKEN_ROTATION_MARKER_VAR: "2026-06-03T00:00:01Z",
        },
        secret_rotation_marker_requirements=(requirement,),
        pages_payload=pages_payload(),
        release_payload=None,
        npm_registry_check=False,
        **ready_governance_kwargs(),
    )
    if not ready.ready:
        raise AssertionError(f"expected fresh rotation marker readiness to pass: {ready.issues!r}")
    parsed_ready = assert_safe_report(ready)
    marker_report = parsed_ready["secretRotationMarkers"]
    if marker_report["checked"] is not True:
        raise AssertionError("secret rotation marker readiness should be checked")
    if marker_report["markers"][0]["markerEnv"] != module.NPM_TOKEN_ROTATION_MARKER_VAR:
        raise AssertionError("secret rotation marker report should identify the marker variable")
    if marker_report["markers"][0]["rotatedAfter"] != "2026-06-03T00:00:01Z":
        raise AssertionError("secret rotation marker timestamp should be reported when valid")

    missing = module.audit_tagged_release_readiness(
        repo="owner/repo",
        tag=TAG,
        version=VERSION,
        secret_names=all_release_secrets(module),
        variable_values={},
        secret_rotation_marker_requirements=(requirement,),
        pages_payload=pages_payload(),
        release_payload=None,
        npm_registry_check=False,
        **ready_governance_kwargs(),
    )
    if missing.ready:
        raise AssertionError("missing rotation marker should fail tagged release readiness")
    parsed_missing = assert_safe_report(missing)
    if (
        "release secret rotation marker readiness: NPM_TOKEN rotation marker "
        "CONU_NPM_TOKEN_ROTATED_AFTER is missing"
        not in json.dumps(parsed_missing)
    ):
        raise AssertionError("missing rotation marker issue was not reported")

    stale = module.audit_tagged_release_readiness(
        repo="owner/repo",
        tag=TAG,
        version=VERSION,
        secret_names=all_release_secrets(module),
        variable_values={
            module.NPM_TOKEN_ROTATION_MARKER_VAR: "2026-06-03T00:00:00Z",
        },
        secret_rotation_marker_requirements=(requirement,),
        pages_payload=pages_payload(),
        release_payload=None,
        npm_registry_check=False,
        **ready_governance_kwargs(),
    )
    if stale.ready:
        raise AssertionError("stale rotation marker should fail tagged release readiness")
    parsed_stale = assert_safe_report(stale)
    if "NPM_TOKEN rotation marker is not after required timestamp" not in json.dumps(parsed_stale):
        raise AssertionError("stale rotation marker issue was not reported")

    invalid = module.audit_tagged_release_readiness(
        repo="owner/repo",
        tag=TAG,
        version=VERSION,
        secret_names=all_release_secrets(module),
        variable_values={
            module.NPM_TOKEN_ROTATION_MARKER_VAR: SENSITIVE_SENTINEL,
        },
        secret_rotation_marker_requirements=(requirement,),
        pages_payload=pages_payload(),
        release_payload=None,
        npm_registry_check=False,
        **ready_governance_kwargs(),
    )
    if invalid.ready:
        raise AssertionError("invalid rotation marker should fail tagged release readiness")
    parsed_invalid = assert_safe_report(invalid)
    if parsed_invalid["secretRotationMarkers"]["markers"][0]["rotatedAfter"] != "":
        raise AssertionError("invalid rotation marker value should not be echoed")
    if "NPM_TOKEN rotation marker timestamp is invalid" not in json.dumps(parsed_invalid):
        raise AssertionError("invalid rotation marker issue was not reported")


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
        **ready_governance_kwargs(),
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
        **ready_governance_kwargs(),
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
        **ready_governance_kwargs(),
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
        **ready_governance_kwargs(),
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
        **ready_governance_kwargs(),
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
        **ready_governance_kwargs(),
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
        **ready_governance_kwargs(),
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
        **ready_governance_kwargs(),
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
        **ready_governance_kwargs(),
    )
    if invalid_endpoint_authority.ready:
        raise AssertionError("malformed custom repository endpoint URL authority should fail")
    parsed_invalid_endpoint_authority = assert_safe_report(invalid_endpoint_authority)
    if (
        "custom repository S3 endpoint URL authority is invalid"
        not in json.dumps(parsed_invalid_endpoint_authority)
    ):
        raise AssertionError("malformed custom repository endpoint URL authority failure was missing")

    loopback_endpoint = module.audit_tagged_release_readiness(
        repo="owner/repo",
        tag=TAG,
        version=VERSION,
        secret_names=all_custom_secrets(module),
        variable_values={
            module.CUSTOM_REPOSITORY_BASE_URL_VAR: "https://packages.example.com/conu/",
            module.CUSTOM_REPOSITORY_BUCKET_VAR: "conu-packages",
            module.CUSTOM_REPOSITORY_PREFIX_VAR: "stable/conu",
            module.CUSTOM_REPOSITORY_ENDPOINT_VAR: "http://127.0.0.1:9000",
            module.CUSTOM_REPOSITORY_REGION_VAR: "us-east-1",
        },
        pages_payload=None,
        release_payload=None,
        npm_registry_check=False,
        **ready_governance_kwargs(),
    )
    if loopback_endpoint.ready:
        raise AssertionError("loopback custom repository endpoint URL should fail")
    parsed_loopback_endpoint = assert_safe_report(loopback_endpoint)
    if (
        "custom repository S3 endpoint URL must use HTTPS"
        not in json.dumps(parsed_loopback_endpoint)
    ):
        raise AssertionError("loopback custom repository endpoint URL failure was missing")

    normalized_loopback_endpoint = module.validate_endpoint_url(
        "http://127.0.0.1:9000",
        allow_loopback_http=True,
    )
    if normalized_loopback_endpoint != "http://127.0.0.1:9000":
        raise AssertionError("explicit loopback endpoint allowance should normalize URL")


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
        **ready_governance_kwargs(),
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
    run_repository_governance_tests(module)
    run_main_branch_protection_caller_tests(module)
    run_ci_readiness_tests(module)
    run_release_branch_readiness_tests(module)
    run_missing_secret_tests(module)
    run_secret_rotation_tests(module)
    run_secret_rotation_marker_tests(module)
    run_custom_repository_tests(module)
    run_safe_failure_tests(module)
    print("Tagged release readiness regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
