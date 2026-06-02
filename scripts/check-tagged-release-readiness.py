#!/usr/bin/env python3
"""Audit live production readiness before creating a conU release tag."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlparse, urlunparse

from github_release_secrets import (
    REQUIRED_RELEASE_SECRETS,
    audit_secret_names,
    find_gh,
    infer_repo,
    load_secret_names,
    run_gh_json,
)


ROOT = Path(__file__).resolve().parents[1]
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
BUCKET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,253}[A-Za-z0-9]$")
CUSTOM_REPOSITORY_BASE_URL_VAR = "CONU_LINUX_REPOSITORY_BASE_URL"
CUSTOM_REPOSITORY_BUCKET_VAR = "CONU_LINUX_REPOSITORY_S3_BUCKET"
CUSTOM_REPOSITORY_PREFIX_VAR = "CONU_LINUX_REPOSITORY_S3_PREFIX"
CUSTOM_REPOSITORY_ENDPOINT_VAR = "CONU_LINUX_REPOSITORY_S3_ENDPOINT_URL"
CUSTOM_REPOSITORY_REGION_VAR = "CONU_LINUX_REPOSITORY_AWS_REGION"
CUSTOM_REPOSITORY_REQUIRED_SECRETS = (
    "CONU_LINUX_REPOSITORY_AWS_ACCESS_KEY_ID",
    "CONU_LINUX_REPOSITORY_AWS_SECRET_ACCESS_KEY",
)
CRATE_MANIFESTS = (
    Path("crates/conu-cli/Cargo.toml"),
    Path("crates/conud/Cargo.toml"),
    Path("crates/conu-core/Cargo.toml"),
    Path("crates/conu-protocol/Cargo.toml"),
    Path("crates/conu-relay/Cargo.toml"),
    Path("crates/conu-sdk/Cargo.toml"),
    Path("crates/conu-mcp/Cargo.toml"),
)
NPM_MANIFESTS = (
    Path("packaging/npm/conu-cli/package.json"),
    Path("sdk/typescript/package.json"),
)
DEFAULT_CI_WORKFLOW = "CI"
DEFAULT_RELEASE_BRANCH = "main"
SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")


@dataclass(frozen=True)
class LinuxRepositoryReadiness:
    mode: str
    ready: bool
    checks: dict[str, bool]
    missing_variables: tuple[str, ...]
    missing_secrets: tuple[str, ...]
    issues: tuple[str, ...]

    def as_json(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "ready": self.ready,
            "checks": self.checks,
            "missingVariables": list(self.missing_variables),
            "missingSecrets": list(self.missing_secrets),
            "issues": list(self.issues),
        }


@dataclass(frozen=True)
class NpmRegistryReadiness:
    checked: bool
    ready: bool
    packages: tuple[str, ...]
    issues: tuple[str, ...]

    def as_json(self) -> dict[str, Any]:
        return {
            "checked": self.checked,
            "ready": self.ready,
            "packages": list(self.packages),
            "issues": list(self.issues),
        }


@dataclass(frozen=True)
class CiReadiness:
    checked: bool
    required: bool
    ready: bool
    workflow: str
    head_sha: str
    run_id: int | None
    status: str
    conclusion: str
    event: str
    created_at: str
    issues: tuple[str, ...]

    def as_json(self) -> dict[str, Any]:
        return {
            "checked": self.checked,
            "required": self.required,
            "ready": self.ready,
            "workflow": self.workflow,
            "headSha": self.head_sha,
            "runId": self.run_id,
            "status": self.status,
            "conclusion": self.conclusion,
            "event": self.event,
            "createdAt": self.created_at,
            "issues": list(self.issues),
        }


@dataclass(frozen=True)
class ReleaseBranchReadiness:
    checked: bool
    required: bool
    ready: bool
    branch: str
    target_sha: str
    branch_sha: str
    issues: tuple[str, ...]

    def as_json(self) -> dict[str, Any]:
        return {
            "checked": self.checked,
            "required": self.required,
            "ready": self.ready,
            "branch": self.branch,
            "targetSha": self.target_sha,
            "branchSha": self.branch_sha,
            "issues": list(self.issues),
        }


@dataclass(frozen=True)
class TaggedReleaseReadiness:
    repo: str
    tag: str
    version: str
    ready: bool
    release_secrets: Any
    linux_repository: LinuxRepositoryReadiness
    release_clobber: Any
    npm_registry: NpmRegistryReadiness
    ci: CiReadiness
    release_branch: ReleaseBranchReadiness
    workflow_permissions: Any
    issues: tuple[str, ...]

    def as_json(self) -> dict[str, Any]:
        return {
            "schema": "conu.githubTaggedReleaseReadiness.v1",
            "repo": self.repo,
            "tag": self.tag,
            "version": self.version,
            "ready": self.ready,
            "releaseSecrets": self.release_secrets.as_json(),
            "linuxRepository": self.linux_repository.as_json(),
            "releaseClobber": self.release_clobber.as_json(),
            "npmRegistry": self.npm_registry.as_json(),
            "ci": self.ci.as_json(),
            "releaseBranch": self.release_branch.as_json(),
            "workflowPermissions": self.workflow_permissions.as_json(),
            "issues": list(self.issues),
            "payloadDisplayed": False,
            "tokenDisplayed": False,
            "tokenHashDisplayed": False,
            "keyMaterialDisplayed": False,
            "contentsDisplayed": False,
        }


def load_script_module(filename: str, module_name: str):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"could not load {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def read_repo_version() -> str:
    try:
        import tomllib
    except ModuleNotFoundError as exc:  # pragma: no cover - CI uses Python 3.11+.
        raise ValueError("Python 3.11+ is required for TOML parsing") from exc

    versions: dict[str, str] = {}
    for manifest in CRATE_MANIFESTS:
        with (ROOT / manifest).open("rb") as handle:
            payload = tomllib.load(handle)
        version = payload.get("package", {}).get("version")
        if not isinstance(version, str) or not version.strip():
            raise ValueError(f"{manifest} does not contain package.version")
        versions[str(manifest)] = version.strip()

    for manifest in NPM_MANIFESTS:
        payload = json.loads((ROOT / manifest).read_text(encoding="utf-8"))
        version = payload.get("version")
        if not isinstance(version, str) or not version.strip():
            raise ValueError(f"{manifest} does not contain version")
        versions[str(manifest)] = version.strip()

    unique = sorted(set(versions.values()))
    if len(unique) != 1:
        raise ValueError("release versions are inconsistent")
    version = unique[0]
    if not SEMVER_RE.fullmatch(version):
        raise ValueError(f"release version is not semver-like: {version}")
    return version


def default_tag(version: str) -> str:
    explicit = os.environ.get("CONU_RELEASE_TAG", "").strip()
    if explicit:
        return explicit
    github_ref = os.environ.get("GITHUB_REF_NAME", "").strip()
    github_ref_type = os.environ.get("GITHUB_REF_TYPE", "").strip()
    if github_ref and (github_ref_type == "tag" or github_ref.startswith("v")):
        return github_ref
    tag_name = os.environ.get("TAG_NAME", "").strip()
    if tag_name:
        return tag_name
    return f"v{version}"


def validate_tag_for_version(tag: str, version: str) -> str:
    raw = tag.strip()
    if not raw.startswith("v"):
        raise ValueError(f"release tag must start with 'v': {tag}")
    tag_version = raw[1:]
    if not SEMVER_RE.fullmatch(tag_version):
        raise ValueError(f"release tag version is not semver-like: {tag}")
    if tag_version != version:
        raise ValueError(f"release tag {raw} does not match package version {version}")
    return raw


def load_variable_values(repo: str, gh: str) -> dict[str, str]:
    payload = run_gh_json(
        gh,
        ["variable", "list", "--repo", repo, "--json", "name,value"],
        "gh variable list",
    )
    if not isinstance(payload, list):
        raise ValueError("gh variable list returned an unexpected payload")
    values: dict[str, str] = {}
    for item in payload:
        if not isinstance(item, dict):
            raise ValueError("gh variable list returned a non-object variable entry")
        name = item.get("name")
        value = item.get("value", "")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("gh variable list returned a variable entry without a name")
        if not isinstance(value, str):
            raise ValueError(f"gh variable list returned a non-string value for {name}")
        values[name.strip()] = value.strip()
    return values


def normalize_custom_base_url(raw: str) -> str:
    value = raw.strip()
    parsed = urlparse(value)
    if parsed.username or parsed.password:
        raise ValueError("custom repository base URL must not include credentials")
    if parsed.scheme.lower() != "https" or not parsed.netloc:
        raise ValueError("custom repository base URL must be an absolute HTTPS URL")
    if parsed.params or parsed.query or parsed.fragment:
        raise ValueError("custom repository base URL must not include params, query, or fragment")
    netloc = normalize_url_netloc(parsed, "custom repository base URL")
    parts = [part for part in parsed.path.split("/") if part]
    if any(part in {".", ".."} for part in parts):
        raise ValueError("custom repository base URL path must not contain dot segments")
    decoded_parts = [unquote(part) for part in parts]
    if any(part in {".", ".."} for part in decoded_parts):
        raise ValueError("custom repository base URL path must not contain dot segments")
    if any("/" in part or "\\" in part for part in decoded_parts):
        raise ValueError("custom repository base URL path must not contain encoded separators")
    path = "/" + "/".join(parts) if parts else ""
    return urlunparse(("https", netloc, path, "", "", ""))


def validate_bucket(raw: str) -> str:
    bucket = raw.strip()
    if not bucket:
        raise ValueError("custom repository S3 bucket is required")
    if bucket.startswith("s3://") or "/" in bucket or "\\" in bucket or " " in bucket:
        raise ValueError("custom repository S3 bucket must be a bucket name, not a URL or path")
    if not BUCKET_RE.fullmatch(bucket):
        raise ValueError("custom repository S3 bucket contains unsupported characters")
    return bucket


def validate_prefix(raw: str) -> str:
    prefix = raw.strip().replace("\\", "/").strip("/")
    if not prefix:
        return ""
    if "?" in prefix or "#" in prefix:
        raise ValueError("custom repository S3 prefix must not contain query or fragment markers")
    parts = [part for part in prefix.split("/") if part]
    if any(part in {".", ".."} for part in parts):
        raise ValueError("custom repository S3 prefix must not contain dot segments")
    if len(parts) != len(prefix.split("/")):
        raise ValueError("custom repository S3 prefix must not contain empty path segments")
    return "/".join(parts)


def is_loopback_host(host: str) -> bool:
    return host in {"localhost", "127.0.0.1", "::1"} or host.startswith("127.")


def validate_endpoint_url(raw: str) -> str:
    value = raw.strip()
    if not value:
        return ""
    parsed = urlparse(value)
    if parsed.username or parsed.password:
        raise ValueError("custom repository S3 endpoint URL must not include credentials")
    if parsed.params or parsed.query or parsed.fragment:
        raise ValueError("custom repository S3 endpoint URL must not include params, query, or fragment")
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("custom repository S3 endpoint URL must be absolute")
    netloc = normalize_url_netloc(parsed, "custom repository S3 endpoint URL")
    host = (parsed.hostname or "").lower()
    scheme = parsed.scheme.lower()
    if scheme != "https" and not (scheme == "http" and is_loopback_host(host)):
        raise ValueError("custom repository S3 endpoint URL must use HTTPS except loopback HTTP")
    parts = [part for part in parsed.path.split("/") if part]
    if any(part in {".", ".."} for part in parts):
        raise ValueError("custom repository S3 endpoint URL path must not contain dot segments")
    decoded_parts = [unquote(part) for part in parts]
    if any(part in {".", ".."} for part in decoded_parts):
        raise ValueError("custom repository S3 endpoint URL path must not contain dot segments")
    if any("/" in part or "\\" in part for part in decoded_parts):
        raise ValueError("custom repository S3 endpoint URL path must not contain encoded separators")
    path = "/" + "/".join(parts) if parts else ""
    return urlunparse((scheme, netloc, path, "", "", ""))


def normalize_url_netloc(parsed, label: str) -> str:
    try:
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{label} authority is invalid") from exc
    if not host:
        raise ValueError(f"{label} authority must include a host")
    if port is None and parsed.netloc.rsplit("@", 1)[-1].endswith(":"):
        raise ValueError(f"{label} authority is invalid")
    host = host.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if port is None:
        return host
    return f"{host}:{port}"


def validate_region(raw: str) -> str:
    region = raw.strip()
    if not region:
        return ""
    if any(char.isspace() for char in region):
        raise ValueError("custom repository AWS region must not contain whitespace")
    if "/" in region or "\\" in region or "?" in region or "#" in region:
        raise ValueError("custom repository AWS region must be a region name, not a URL or path")
    return region


def audit_linux_repository(
    repo: str,
    variable_values: dict[str, str],
    secret_names: set[str],
    pages_payload: dict[str, Any] | None,
) -> LinuxRepositoryReadiness:
    custom_base_url = variable_values.get(CUSTOM_REPOSITORY_BASE_URL_VAR, "").strip()
    if not custom_base_url:
        pages_module = load_script_module(
            "check-github-pages-readiness.py",
            "check_github_pages_readiness_for_tagged_release",
        )
        pages_report = pages_module.audit_pages_readiness(repo, pages_payload, "")
        return LinuxRepositoryReadiness(
            mode="github-pages",
            ready=pages_report.ready,
            checks={f"pages.{key}": value for key, value in pages_report.checks.items()},
            missing_variables=(),
            missing_secrets=(),
            issues=tuple(pages_report.issues),
        )

    checks: dict[str, bool] = {
        "customBaseUrlConfigured": True,
        "customBaseUrlValid": False,
        "customBucketConfigured": False,
        "customBucketValid": False,
        "customPrefixValid": True,
        "customEndpointValid": True,
        "customRegionValid": True,
        "customSecretsConfigured": False,
    }
    issues: list[str] = []
    missing_variables: list[str] = []

    try:
        normalize_custom_base_url(custom_base_url)
        checks["customBaseUrlValid"] = True
    except ValueError as exc:
        issues.append(str(exc))

    bucket = variable_values.get(CUSTOM_REPOSITORY_BUCKET_VAR, "").strip()
    if not bucket:
        missing_variables.append(CUSTOM_REPOSITORY_BUCKET_VAR)
    else:
        checks["customBucketConfigured"] = True
        try:
            validate_bucket(bucket)
            checks["customBucketValid"] = True
        except ValueError as exc:
            issues.append(str(exc))

    for name, validator, check_name in (
        (CUSTOM_REPOSITORY_PREFIX_VAR, validate_prefix, "customPrefixValid"),
        (CUSTOM_REPOSITORY_ENDPOINT_VAR, validate_endpoint_url, "customEndpointValid"),
        (CUSTOM_REPOSITORY_REGION_VAR, validate_region, "customRegionValid"),
    ):
        raw = variable_values.get(name, "").strip()
        if raw:
            try:
                validator(raw)
            except ValueError as exc:
                checks[check_name] = False
                issues.append(str(exc))

    missing_secrets = tuple(
        name for name in CUSTOM_REPOSITORY_REQUIRED_SECRETS if name not in secret_names
    )
    checks["customSecretsConfigured"] = not missing_secrets
    ready = not issues and not missing_variables and not missing_secrets
    return LinuxRepositoryReadiness(
        mode="custom-s3",
        ready=ready,
        checks=checks,
        missing_variables=tuple(missing_variables),
        missing_secrets=missing_secrets,
        issues=tuple(issues),
    )


def audit_npm_registry(*, registry_check: bool, npm: str = "") -> NpmRegistryReadiness:
    npm_module = load_script_module(
        "check-npm-publish-preflight.py",
        "check_npm_publish_preflight_for_tagged_release",
    )
    packages = tuple(
        npm_module.validate_manifest(ROOT, rule) for rule in npm_module.PACKAGES
    )
    package_names = tuple(f"{package.name}@{package.version}" for package in packages)
    if not registry_check:
        return NpmRegistryReadiness(
            checked=False,
            ready=True,
            packages=package_names,
            issues=(),
        )
    try:
        npm_binary = npm or npm_module.find_npm()
        npm_module.check_registry_availability(npm_binary, packages)
    except (OSError, ValueError) as exc:
        return NpmRegistryReadiness(
            checked=True,
            ready=False,
            packages=package_names,
            issues=(str(exc),),
        )
    return NpmRegistryReadiness(
        checked=True,
        ready=True,
        packages=package_names,
        issues=(),
    )


def resolve_git_head() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        check=False,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise ValueError(f"git rev-parse HEAD failed with exit code {result.returncode}")
    head_sha = result.stdout.strip()
    if not head_sha:
        raise ValueError("git rev-parse HEAD did not return a commit SHA")
    return head_sha


def load_ci_runs(repo: str, gh: str, workflow: str, head_sha: str) -> list[Any]:
    payload = run_gh_json(
        gh,
        [
            "run",
            "list",
            "--repo",
            repo,
            "--workflow",
            workflow,
            "--commit",
            head_sha,
            "--json",
            "databaseId,headSha,conclusion,status,workflowName,event,createdAt",
            "--limit",
            "10",
        ],
        "gh run list",
    )
    if not isinstance(payload, list):
        raise ValueError("gh run list returned an unexpected payload")
    return payload


def load_default_branch(repo: str, gh: str) -> str:
    payload = run_gh_json(
        gh,
        ["repo", "view", repo, "--json", "defaultBranchRef"],
        "gh repo view default branch",
    )
    if not isinstance(payload, dict):
        raise ValueError("gh repo view returned an unexpected default branch payload")
    default_branch = payload.get("defaultBranchRef")
    if not isinstance(default_branch, dict):
        raise ValueError("gh repo view did not return defaultBranchRef")
    name = default_branch.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("gh repo view did not return a default branch name")
    return name.strip()


def load_branch_head(repo: str, gh: str, branch: str) -> str:
    normalized_branch = branch.strip()
    if not normalized_branch:
        raise ValueError("release branch name is required")
    payload = run_gh_json(
        gh,
        ["api", f"repos/{repo}/branches/{quote(normalized_branch, safe='')}"],
        "gh api branch",
    )
    if not isinstance(payload, dict):
        raise ValueError("gh api branch returned an unexpected payload")
    commit = payload.get("commit")
    if not isinstance(commit, dict):
        raise ValueError("gh api branch did not return commit metadata")
    sha = commit.get("sha")
    if not isinstance(sha, str) or not sha.strip():
        raise ValueError("gh api branch did not return a commit SHA")
    return sha.strip()


def audit_ci_readiness(
    *,
    required: bool,
    workflow: str,
    head_sha: str,
    runs_payload: list[Any] | None,
) -> CiReadiness:
    normalized_workflow = workflow.strip() or DEFAULT_CI_WORKFLOW
    normalized_head = head_sha.strip()
    if not required:
        return CiReadiness(
            checked=False,
            required=False,
            ready=True,
            workflow=normalized_workflow,
            head_sha=normalized_head,
            run_id=None,
            status="",
            conclusion="",
            event="",
            created_at="",
            issues=(),
        )

    if not SHA_RE.fullmatch(normalized_head):
        return CiReadiness(
            checked=True,
            required=True,
            ready=False,
            workflow=normalized_workflow,
            head_sha=normalized_head,
            run_id=None,
            status="",
            conclusion="",
            event="",
            created_at="",
            issues=("CI head SHA is missing or invalid",),
        )

    short_sha = normalized_head[:12]
    runs = runs_payload or []
    latest: dict[str, Any] | None = None
    for item in runs:
        if not isinstance(item, dict):
            continue
        item_workflow = item.get("workflowName")
        item_head = item.get("headSha")
        if not isinstance(item_workflow, str) or item_workflow != normalized_workflow:
            continue
        if not isinstance(item_head, str) or item_head.lower() != normalized_head.lower():
            continue
        latest = item
        break

    if latest is None:
        return CiReadiness(
            checked=True,
            required=True,
            ready=False,
            workflow=normalized_workflow,
            head_sha=normalized_head,
            run_id=None,
            status="",
            conclusion="",
            event="",
            created_at="",
            issues=(f"no {normalized_workflow} workflow run found for {short_sha}",),
        )

    status = latest.get("status")
    conclusion = latest.get("conclusion")
    event = latest.get("event")
    created_at = latest.get("createdAt")
    run_id = latest.get("databaseId")
    status_value = status if isinstance(status, str) else ""
    conclusion_value = conclusion if isinstance(conclusion, str) else ""
    event_value = event if isinstance(event, str) else ""
    created_at_value = created_at if isinstance(created_at, str) else ""
    run_id_value = run_id if isinstance(run_id, int) else None
    ready = status_value.lower() == "completed" and conclusion_value.lower() == "success"
    issues: tuple[str, ...] = ()
    if not ready:
        if status_value.lower() != "completed":
            issues = (f"{normalized_workflow} workflow run for {short_sha} is {status_value or 'unknown'}",)
        else:
            issues = (
                f"{normalized_workflow} workflow run for {short_sha} concluded "
                f"{conclusion_value or 'unknown'}",
            )
    return CiReadiness(
        checked=True,
        required=True,
        ready=ready,
        workflow=normalized_workflow,
        head_sha=normalized_head,
        run_id=run_id_value,
        status=status_value,
        conclusion=conclusion_value,
        event=event_value,
        created_at=created_at_value,
        issues=issues,
    )


def audit_release_branch_readiness(
    *,
    required: bool,
    branch: str,
    target_sha: str,
    branch_sha: str,
) -> ReleaseBranchReadiness:
    normalized_branch = branch.strip() or DEFAULT_RELEASE_BRANCH
    normalized_target = target_sha.strip()
    normalized_branch_sha = branch_sha.strip()
    if not required:
        return ReleaseBranchReadiness(
            checked=False,
            required=False,
            ready=True,
            branch=normalized_branch,
            target_sha=normalized_target,
            branch_sha=normalized_branch_sha,
            issues=(),
        )

    issues: list[str] = []
    if not SHA_RE.fullmatch(normalized_target):
        issues.append("release target SHA is missing or invalid")
    if not SHA_RE.fullmatch(normalized_branch_sha):
        issues.append(f"release branch {normalized_branch} head SHA is missing or invalid")
    if not issues and normalized_target.lower() != normalized_branch_sha.lower():
        issues.append(
            "release target "
            f"{normalized_target[:12]} does not match {normalized_branch} head "
            f"{normalized_branch_sha[:12]}"
        )
    return ReleaseBranchReadiness(
        checked=True,
        required=True,
        ready=not issues,
        branch=normalized_branch,
        target_sha=normalized_target,
        branch_sha=normalized_branch_sha,
        issues=tuple(issues),
    )


def audit_workflow_permissions(workflow_dir: Path | None = None) -> Any:
    workflow_module = load_script_module(
        "check-github-workflow-permissions.py",
        "check_github_workflow_permissions_for_tagged_release",
    )
    target_dir = workflow_dir if workflow_dir is not None else ROOT / ".github" / "workflows"
    return workflow_module.audit_workflows(workflow_module.find_workflow_paths(target_dir))


def combine_issues(
    release_secrets: Any,
    linux_repository: LinuxRepositoryReadiness,
    release_clobber: Any,
    npm_registry: NpmRegistryReadiness,
    ci: CiReadiness,
    release_branch: ReleaseBranchReadiness,
    workflow_permissions: Any,
) -> tuple[str, ...]:
    issues: list[str] = []
    for name in release_secrets.missing:
        issues.append(f"missing release secret: {name}")
    for name in linux_repository.missing_variables:
        issues.append(f"missing repository variable: {name}")
    for name in linux_repository.missing_secrets:
        issues.append(f"missing repository secret: {name}")
    for issue in linux_repository.issues:
        issues.append(f"Linux repository readiness: {issue}")
    for issue in release_clobber.issues:
        issues.append(f"GitHub Release readiness: {issue}")
    for issue in npm_registry.issues:
        issues.append(f"npm registry readiness: {issue}")
    for issue in ci.issues:
        issues.append(f"CI readiness: {issue}")
    for issue in release_branch.issues:
        issues.append(f"release branch readiness: {issue}")
    for issue in workflow_permissions.issues:
        issues.append(f"workflow readiness: {issue}")
    return tuple(issues)


def audit_tagged_release_readiness(
    *,
    repo: str,
    tag: str,
    version: str,
    secret_names: set[str],
    variable_values: dict[str, str],
    pages_payload: dict[str, Any] | None,
    release_payload: dict[str, Any] | None,
    npm_registry_check: bool,
    npm: str = "",
    ci_required: bool = False,
    ci_workflow: str = DEFAULT_CI_WORKFLOW,
    ci_head_sha: str = "",
    ci_runs_payload: list[Any] | None = None,
    release_branch_required: bool = False,
    release_branch: str = DEFAULT_RELEASE_BRANCH,
    release_target_sha: str = "",
    release_branch_sha: str = "",
    workflow_permissions: Any | None = None,
    workflow_dir: Path | None = None,
) -> TaggedReleaseReadiness:
    release_secrets = audit_secret_names(repo, secret_names)
    linux_repository = audit_linux_repository(repo, variable_values, secret_names, pages_payload)
    clobber_module = load_script_module(
        "check-github-release-clobber-preflight.py",
        "check_github_release_clobber_for_tagged_release",
    )
    release_clobber = clobber_module.audit_release_clobber(repo, tag, release_payload)
    npm_registry = audit_npm_registry(registry_check=npm_registry_check, npm=npm)
    ci = audit_ci_readiness(
        required=ci_required,
        workflow=ci_workflow,
        head_sha=ci_head_sha,
        runs_payload=ci_runs_payload,
    )
    branch_readiness = audit_release_branch_readiness(
        required=release_branch_required,
        branch=release_branch,
        target_sha=release_target_sha,
        branch_sha=release_branch_sha,
    )
    workflow_readiness = (
        workflow_permissions
        if workflow_permissions is not None
        else audit_workflow_permissions(workflow_dir)
    )
    issues = combine_issues(
        release_secrets,
        linux_repository,
        release_clobber,
        npm_registry,
        ci,
        branch_readiness,
        workflow_readiness,
    )
    return TaggedReleaseReadiness(
        repo=repo,
        tag=tag,
        version=version,
        ready=not issues,
        release_secrets=release_secrets,
        linux_repository=linux_repository,
        release_clobber=release_clobber,
        npm_registry=npm_registry,
        ci=ci,
        release_branch=branch_readiness,
        workflow_permissions=workflow_readiness,
        issues=issues,
    )


def print_text_report(report: TaggedReleaseReadiness) -> None:
    if report.ready:
        npm_note = " with npm registry check" if report.npm_registry.checked else ""
        ci_note = " and CI check" if report.ci.checked else ""
        branch_note = " and release branch check" if report.release_branch.checked else ""
        print(
            "Tagged release readiness passed"
            f"{npm_note}{ci_note}{branch_note} and workflow permissions check: "
            f"{report.repo}@{report.tag} ({report.linux_repository.mode})"
        )
        return

    print(
        f"Tagged release readiness failed for {report.repo}@{report.tag}",
        file=sys.stderr,
    )
    for issue in report.issues:
        print(f"issue: {issue}", file=sys.stderr)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo",
        default="",
        help="GitHub repository in owner/name form; defaults to GH_REPO or gh repo view",
    )
    parser.add_argument(
        "--tag",
        default="",
        help="release tag to audit; defaults to CONU_RELEASE_TAG, GITHUB_REF_NAME, TAG_NAME, or v<package-version>",
    )
    parser.add_argument(
        "--npm-registry-check",
        action="store_true",
        help="query npm and fail if any configured package version already exists",
    )
    parser.add_argument(
        "--require-ci",
        action="store_true",
        help="fail unless the tag target commit has a successful CI workflow run",
    )
    parser.add_argument(
        "--ci-head",
        default="",
        help="commit SHA to require CI for; defaults to the current git HEAD when --require-ci is used",
    )
    parser.add_argument(
        "--ci-workflow",
        default=DEFAULT_CI_WORKFLOW,
        help="GitHub Actions workflow name to require when --require-ci is used",
    )
    parser.add_argument(
        "--ci-only",
        action="store_true",
        help="only check tag target CI/default-branch status and skip release secret/repository checks",
    )
    parser.add_argument(
        "--require-default-branch-head",
        action="store_true",
        help="fail unless the release target commit matches the repository default branch head",
    )
    parser.add_argument(
        "--release-branch",
        default="",
        help="release branch name to compare against; defaults to the repository default branch",
    )
    parser.add_argument(
        "--release-target-head",
        default="",
        help="commit SHA to compare against the release branch head; defaults to --ci-head or current git HEAD",
    )
    parser.add_argument("--json", action="store_true", help="print a machine-readable report")
    parser.add_argument("--gh", default="", help=argparse.SUPPRESS)
    parser.add_argument("--npm", default="", help=argparse.SUPPRESS)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        os.chdir(ROOT)
        version = read_repo_version()
        tag = validate_tag_for_version(args.tag or default_tag(version), version)
        gh = args.gh or find_gh()
        repo = args.repo.strip() or infer_repo(gh)
        if args.ci_only:
            release_target_sha = args.release_target_head.strip()
            ci_head_sha = args.ci_head.strip() or release_target_sha or resolve_git_head()
            release_target_sha = release_target_sha or ci_head_sha
            if (
                args.ci_head.strip()
                and args.release_target_head.strip()
                and args.ci_head.strip().lower() != args.release_target_head.strip().lower()
            ):
                raise ValueError("CI head and release target head must match")
            ci_runs_payload = load_ci_runs(repo, gh, args.ci_workflow, ci_head_sha)
            ci_report = audit_ci_readiness(
                required=True,
                workflow=args.ci_workflow,
                head_sha=ci_head_sha,
                runs_payload=ci_runs_payload,
            )
            release_branch = ""
            release_branch_sha = ""
            if args.require_default_branch_head:
                release_branch = args.release_branch.strip() or load_default_branch(repo, gh)
                release_branch_sha = load_branch_head(repo, gh, release_branch)
            branch_report = audit_release_branch_readiness(
                required=args.require_default_branch_head,
                branch=release_branch,
                target_sha=release_target_sha,
                branch_sha=release_branch_sha,
            )
            ready = ci_report.ready and branch_report.ready
            if args.json:
                payload = ci_report.as_json()
                payload.update(
                    {
                        "schema": "conu.githubTaggedReleaseCiReadiness.v1",
                        "repo": repo,
                        "tag": tag,
                        "ready": ready,
                        "releaseBranch": branch_report.as_json(),
                        "payloadDisplayed": False,
                        "tokenDisplayed": False,
                        "tokenHashDisplayed": False,
                        "keyMaterialDisplayed": False,
                        "contentsDisplayed": False,
                    }
                )
                print(json.dumps(payload, indent=2, sort_keys=True))
            elif ready:
                print(
                    "Tagged release CI readiness passed: "
                    f"{repo}@{tag} {ci_report.workflow} {ci_report.head_sha[:12]}"
                )
            else:
                print(f"Tagged release CI readiness failed for {repo}@{tag}", file=sys.stderr)
                for issue in ci_report.issues:
                    print(f"issue: {issue}", file=sys.stderr)
                for issue in branch_report.issues:
                    print(f"issue: {issue}", file=sys.stderr)
            return 0 if ready else 1

        secret_names = load_secret_names(repo, gh)
        variable_values = load_variable_values(repo, gh)
        ci_head_sha = args.ci_head.strip()
        release_target_sha = args.release_target_head.strip()
        if (
            args.require_ci
            and args.require_default_branch_head
            and ci_head_sha
            and release_target_sha
            and ci_head_sha.lower() != release_target_sha.lower()
        ):
            raise ValueError("CI head and release target head must match")
        resolved_head = ""
        if args.require_ci or args.require_default_branch_head:
            resolved_head = ci_head_sha or release_target_sha or resolve_git_head()
        ci_runs_payload = None
        if args.require_ci:
            ci_head_sha = ci_head_sha or resolved_head
            ci_runs_payload = load_ci_runs(repo, gh, args.ci_workflow, ci_head_sha)
        release_branch = ""
        release_branch_sha = ""
        if args.require_default_branch_head:
            release_target_sha = release_target_sha or ci_head_sha or resolved_head
            release_branch = args.release_branch.strip() or load_default_branch(repo, gh)
            release_branch_sha = load_branch_head(repo, gh, release_branch)
        release_module = load_script_module(
            "check-github-release-clobber-preflight.py",
            "check_github_release_clobber_loader_for_tagged_release",
        )
        release_payload = release_module.load_release_metadata(repo, tag, gh)
        pages_payload = None
        if not variable_values.get(CUSTOM_REPOSITORY_BASE_URL_VAR, "").strip():
            pages_module = load_script_module(
                "check-github-pages-readiness.py",
                "check_github_pages_loader_for_tagged_release",
            )
            pages_payload = pages_module.load_pages_metadata(repo, gh)
        report = audit_tagged_release_readiness(
            repo=repo,
            tag=tag,
            version=version,
            secret_names=secret_names,
            variable_values=variable_values,
            pages_payload=pages_payload,
            release_payload=release_payload,
            npm_registry_check=args.npm_registry_check,
            npm=args.npm,
            ci_required=args.require_ci,
            ci_workflow=args.ci_workflow,
            ci_head_sha=ci_head_sha,
            ci_runs_payload=ci_runs_payload,
            release_branch_required=args.require_default_branch_head,
            release_branch=release_branch,
            release_target_sha=release_target_sha,
            release_branch_sha=release_branch_sha,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Tagged release readiness failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report.as_json(), indent=2, sort_keys=True))
    else:
        print_text_report(report)
    return 0 if report.ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
