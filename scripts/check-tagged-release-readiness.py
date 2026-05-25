#!/usr/bin/env python3
"""Audit live production readiness before creating a conU release tag."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

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
class TaggedReleaseReadiness:
    repo: str
    tag: str
    version: str
    ready: bool
    release_secrets: Any
    linux_repository: LinuxRepositoryReadiness
    release_clobber: Any
    npm_registry: NpmRegistryReadiness
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
    parts = [part for part in parsed.path.split("/") if part]
    if any(part in {".", ".."} for part in parts):
        raise ValueError("custom repository base URL path must not contain dot segments")
    path = "/" + "/".join(parts) if parts else ""
    return urlunparse(("https", parsed.netloc.lower(), path, "", "", ""))


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
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" and not (parsed.scheme == "http" and is_loopback_host(host)):
        raise ValueError("custom repository S3 endpoint URL must use HTTPS except loopback HTTP")
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))


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


def combine_issues(
    release_secrets: Any,
    linux_repository: LinuxRepositoryReadiness,
    release_clobber: Any,
    npm_registry: NpmRegistryReadiness,
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
) -> TaggedReleaseReadiness:
    release_secrets = audit_secret_names(repo, secret_names)
    linux_repository = audit_linux_repository(repo, variable_values, secret_names, pages_payload)
    clobber_module = load_script_module(
        "check-github-release-clobber-preflight.py",
        "check_github_release_clobber_for_tagged_release",
    )
    release_clobber = clobber_module.audit_release_clobber(repo, tag, release_payload)
    npm_registry = audit_npm_registry(registry_check=npm_registry_check, npm=npm)
    issues = combine_issues(release_secrets, linux_repository, release_clobber, npm_registry)
    return TaggedReleaseReadiness(
        repo=repo,
        tag=tag,
        version=version,
        ready=not issues,
        release_secrets=release_secrets,
        linux_repository=linux_repository,
        release_clobber=release_clobber,
        npm_registry=npm_registry,
        issues=issues,
    )


def print_text_report(report: TaggedReleaseReadiness) -> None:
    if report.ready:
        npm_note = " with npm registry check" if report.npm_registry.checked else ""
        print(
            "Tagged release readiness passed"
            f"{npm_note}: {report.repo}@{report.tag} ({report.linux_repository.mode})"
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
        secret_names = load_secret_names(repo, gh)
        variable_values = load_variable_values(repo, gh)
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
