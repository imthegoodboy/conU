#!/usr/bin/env python3
"""Publish a verified hosted Linux repository site to an S3-compatible target."""

from __future__ import annotations

import argparse
import errno
import fnmatch
import importlib.util
import json
import mimetypes
import os
import re
import shlex
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import unquote, urlparse, urlunparse


ROOT = Path(__file__).resolve().parents[1]
ENDPOINT_CHECKER = ROOT / "scripts" / "check-hosted-linux-repository-endpoint.py"
SITE_SCHEMA = "conu.hostedLinuxRepository.site.v1"
CACHE_POLICY_SCHEMA = "conu.hostedLinuxRepository.cachePolicy.v1"
MAX_FILES = 10000
MAX_METADATA_BYTES = 1024 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAX_CACHE_CONTROL_BYTES = 256
PUBLIC_KEY_NAME = "conu-linux-gpg-key.asc"
BUCKET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,253}[A-Za-z0-9]$")
SAFE_REGION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
OPEN_BINARY = getattr(os, "O_BINARY", 0)
OPEN_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
FORBIDDEN_SEGMENTS = {
    ".conu",
    ".git",
    ".github",
    "logs",
    "messages",
    "node_modules",
    "routes",
    "runtime",
    "security",
}
FORBIDDEN_TEXT = (
    "BEGIN PGP PRIVATE KEY BLOCK",
    "BEGIN PRIVATE KEY",
    "NPM_TOKEN",
    "CONU_RELAY_TOKEN",
    "token_sha256_hex",
    "payloadHex",
    "payload_hex",
    "ciphertext_body",
)
TEXT_SUFFIXES = (".txt", ".json", ".html", ".list", ".repo", ".asc", ".sha256")
TEXT_MEMBER_NAMES = {"_headers", ".nojekyll"}


class PublicationError(ValueError):
    """Raised when custom repository publication is not safe to run."""


@dataclass(frozen=True)
class PublishFile:
    path: Path
    relative_path: str
    size: int
    cache_control: str
    content_type: str
    s3_uri: str


@dataclass(frozen=True)
class PublishPlan:
    site_dir: Path
    base_url: str
    version: str
    bucket: str
    prefix: str
    files: list[PublishFile]

    def as_json(self, *, mode: str, published: bool, endpoint_checked: bool) -> dict[str, Any]:
        cache_classes: dict[str, dict[str, int]] = {}
        for file in self.files:
            bucket = cache_classes.setdefault(file.cache_control, {"files": 0, "bytes": 0})
            bucket["files"] += 1
            bucket["bytes"] += file.size
        return {
            "schema": "conu.hostedLinuxRepository.s3Publication.v1",
            "mode": mode,
            "published": published,
            "endpointChecked": endpoint_checked,
            "baseUrl": self.base_url,
            "version": self.version,
            "bucket": self.bucket,
            "prefix": self.prefix,
            "fileCount": len(self.files),
            "totalBytes": sum(file.size for file in self.files),
            "cacheClasses": cache_classes,
            "payloadDisplayed": False,
            "tokenDisplayed": False,
            "keyMaterialDisplayed": False,
        }


def main() -> int:
    args = parse_args()
    try:
        plan = build_publish_plan(args)
        endpoint_checked = False
        if args.confirm:
            publish_plan(plan, args)
            if args.post_upload_check:
                run_endpoint_check(plan, args)
                endpoint_checked = True
        elif args.post_upload_check:
            raise PublicationError("--post-upload-check requires --confirm")
    except (PublicationError, OSError, subprocess.CalledProcessError, ValueError) as exc:
        if args.json:
            print(
                json.dumps(
                    {
                        "schema": "conu.hostedLinuxRepository.s3Publication.v1",
                        "published": False,
                        "endpointChecked": False,
                        "issues": [str(exc)],
                        "payloadDisplayed": False,
                        "tokenDisplayed": False,
                        "keyMaterialDisplayed": False,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            print(f"Hosted Linux repository S3 publication failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(
            json.dumps(
                plan.as_json(
                    mode="confirm" if args.confirm else "dry-run",
                    published=args.confirm,
                    endpoint_checked=endpoint_checked,
                ),
                indent=2,
                sort_keys=True,
            )
        )
    else:
        action = "published" if args.confirm else "dry-run planned"
        print(
            f"Hosted Linux repository S3 publication {action}: "
            f"{len(plan.files)} files for {plan.base_url}"
        )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("site_dir", type=Path, help="verified extracted hosted repository site directory")
    parser.add_argument(
        "--base-url",
        default=os.environ.get("CONU_LINUX_REPOSITORY_BASE_URL", ""),
        help="expected custom repository HTTPS base URL",
    )
    parser.add_argument(
        "--expected-version",
        default="",
        help="expected repository version",
    )
    parser.add_argument(
        "--bucket",
        default=os.environ.get("CONU_LINUX_REPOSITORY_S3_BUCKET", ""),
        help="S3-compatible bucket name",
    )
    parser.add_argument(
        "--prefix",
        default=os.environ.get("CONU_LINUX_REPOSITORY_S3_PREFIX", ""),
        help="optional key prefix inside the bucket",
    )
    parser.add_argument(
        "--endpoint-url",
        default=os.environ.get("CONU_LINUX_REPOSITORY_S3_ENDPOINT_URL", ""),
        help="optional S3-compatible endpoint URL; HTTPS required",
    )
    parser.add_argument(
        "--region",
        default=os.environ.get("CONU_LINUX_REPOSITORY_AWS_REGION", ""),
        help="optional AWS region to pass to the CLI",
    )
    parser.add_argument(
        "--aws-cli",
        default=os.environ.get("CONU_AWS_CLI", "aws"),
        help="AWS CLI command; defaults to aws",
    )
    parser.add_argument(
        "--post-upload-check",
        action="store_true",
        help="run the live endpoint readiness check after confirmed upload",
    )
    parser.add_argument(
        "--post-upload-retries",
        type=int,
        default=6,
        help="endpoint readiness attempts after upload, default 6",
    )
    parser.add_argument(
        "--post-upload-retry-seconds",
        type=float,
        default=10.0,
        help="delay between endpoint readiness attempts, default 10 seconds",
    )
    parser.add_argument(
        "--check-timeout",
        type=float,
        default=15.0,
        help="HTTP timeout for post-upload readiness checks, default 15 seconds",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print a machine-readable publication report",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="validate and print a plan without uploading")
    mode.add_argument("--confirm", action="store_true", help="upload the site files")
    return parser.parse_args()


def build_publish_plan(args: argparse.Namespace) -> PublishPlan:
    site_dir = validate_site_directory(args.site_dir)
    bucket = validate_bucket(args.bucket)
    prefix = validate_prefix(args.prefix)
    validate_endpoint_url(args.endpoint_url)
    validate_region(args.region)
    if args.post_upload_retries < 1:
        raise PublicationError("--post-upload-retries must be at least 1")
    if args.post_upload_retry_seconds < 0:
        raise PublicationError("--post-upload-retry-seconds must not be negative")
    if args.check_timeout <= 0:
        raise PublicationError("--check-timeout must be positive")

    repository = read_json_file(site_dir / "repository.json", "repository.json")
    cache_policy = read_json_file(site_dir / "cache-policy.json", "cache-policy.json")
    headers_text = read_bounded_ascii_file(site_dir / "_headers", "_headers", max_bytes=MAX_METADATA_BYTES)
    assert_no_forbidden_text(headers_text, "_headers")
    base_url = validate_base_url(args.base_url or str(repository.get("baseUrl", "")))
    version = validate_repository_json(repository, base_url, args.expected_version)
    validate_cache_policy_json(cache_policy, base_url, version)
    rules = parse_cache_rules(cache_policy)
    headers_entries = parse_headers_file(headers_text)
    validate_headers_match_policy(headers_entries, rules)

    files = collect_files(site_dir, bucket, prefix, rules)
    if not files:
        raise PublicationError("site directory contains no files to publish")
    return PublishPlan(
        site_dir=site_dir,
        base_url=base_url,
        version=version,
        bucket=bucket,
        prefix=prefix,
        files=files,
    )


def validate_site_directory(path: Path) -> Path:
    site_dir = path.expanduser()
    if site_dir.is_symlink():
        raise PublicationError(f"site directory must not be a symlink: {path}")
    if not site_dir.exists() or not site_dir.is_dir():
        raise PublicationError(f"site directory does not exist: {path}")
    return site_dir.resolve()


def validate_bucket(raw: str) -> str:
    bucket = raw.strip()
    if not bucket:
        raise PublicationError(
            "S3 bucket is required; pass --bucket or set CONU_LINUX_REPOSITORY_S3_BUCKET"
        )
    if bucket.startswith("s3://") or "/" in bucket or "\\" in bucket or " " in bucket:
        raise PublicationError("S3 bucket must be a bucket name, not a URL or path")
    if not BUCKET_RE.fullmatch(bucket):
        raise PublicationError("S3 bucket contains unsupported characters")
    return bucket


def validate_prefix(raw: str) -> str:
    prefix = raw.strip().replace("\\", "/").strip("/")
    if not prefix:
        return ""
    if "?" in prefix or "#" in prefix:
        raise PublicationError("S3 prefix must not contain query or fragment markers")
    parts = [part for part in prefix.split("/") if part]
    if len(parts) != len(prefix.split("/")):
        raise PublicationError("S3 prefix must not contain empty path segments")
    if any(has_url_path_control(part) for part in parts):
        raise PublicationError("S3 prefix must not contain whitespace or control characters")
    if any(part in {".", ".."} for part in parts):
        raise PublicationError("S3 prefix must not contain dot segments")
    decoded_parts = [unquote(part) for part in parts]
    if any(part in {".", ".."} for part in decoded_parts):
        raise PublicationError("S3 prefix must not contain dot segments")
    if any("/" in part or "\\" in part for part in decoded_parts):
        raise PublicationError("S3 prefix must not contain encoded separators")
    if any(has_url_path_control(part) for part in decoded_parts):
        raise PublicationError("S3 prefix must not contain whitespace or control characters")
    return "/".join(parts)


def validate_endpoint_url(raw: str, *, allow_loopback_http: bool = False) -> str:
    value = raw.strip()
    if not value:
        return ""
    parsed = urlparse(value)
    if parsed.username or parsed.password:
        raise PublicationError("S3 endpoint URL must not include credentials")
    if parsed.params or parsed.query or parsed.fragment:
        raise PublicationError("S3 endpoint URL must not include params, query, or fragment")
    if not parsed.scheme or not parsed.netloc:
        raise PublicationError("S3 endpoint URL must be absolute")
    netloc = normalize_url_netloc(parsed, "S3 endpoint URL")
    host = (parsed.hostname or "").lower()
    scheme = parsed.scheme.lower()
    if scheme != "https" and not (
        allow_loopback_http and scheme == "http" and is_loopback_host(host)
    ):
        raise PublicationError("S3 endpoint URL must use HTTPS")
    parts = [part for part in parsed.path.split("/") if part]
    if any(part in {".", ".."} for part in parts):
        raise PublicationError("S3 endpoint URL path must not contain dot segments")
    decoded_parts = [unquote(part) for part in parts]
    if any(part in {".", ".."} for part in decoded_parts):
        raise PublicationError("S3 endpoint URL path must not contain dot segments")
    if any("/" in part or "\\" in part for part in decoded_parts):
        raise PublicationError("S3 endpoint URL path must not contain encoded separators")
    if any(has_url_path_control(part) for part in decoded_parts):
        raise PublicationError("S3 endpoint URL path must not contain whitespace or control characters")
    path = "/" + "/".join(parts) if parts else ""
    return urlunparse((scheme, netloc, path, "", "", ""))


def is_loopback_host(host: str) -> bool:
    return host in {"localhost", "127.0.0.1", "::1"} or host.startswith("127.")


def validate_base_url(raw: str) -> str:
    value = raw.strip()
    parsed = urlparse(value)
    if parsed.username or parsed.password:
        raise PublicationError("repository base URL must not include credentials")
    if parsed.scheme != "https" or not parsed.netloc:
        raise PublicationError("repository base URL must be an absolute HTTPS URL")
    if parsed.params or parsed.query or parsed.fragment:
        raise PublicationError("repository base URL must not include params, query, or fragment")
    netloc = normalize_url_netloc(parsed, "repository base URL")
    parts = [part for part in parsed.path.split("/") if part]
    if any(part in {".", ".."} for part in parts):
        raise PublicationError("repository base URL path must not contain dot segments")
    decoded_parts = [unquote(part) for part in parts]
    if any(part in {".", ".."} for part in decoded_parts):
        raise PublicationError("repository base URL path must not contain dot segments")
    if any("/" in part or "\\" in part for part in decoded_parts):
        raise PublicationError("repository base URL path must not contain encoded separators")
    if any(has_url_path_control(part) for part in decoded_parts):
        raise PublicationError("repository base URL path must not contain whitespace or control characters")
    normalized_path = "/" + "/".join(parts) if parts else ""
    return urlunparse(("https", netloc, normalized_path, "", "", ""))


def normalize_url_netloc(parsed, label: str) -> str:
    try:
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise PublicationError(f"{label} authority is invalid") from exc
    if not host:
        raise PublicationError(f"{label} authority must include a host")
    if port is None and parsed.netloc.rsplit("@", 1)[-1].endswith(":"):
        raise PublicationError(f"{label} authority is invalid")
    raw_authority = parsed.netloc.rsplit("@", 1)[-1]
    if has_url_authority_control(raw_authority) or has_url_authority_control(host):
        raise PublicationError(f"{label} authority is invalid")
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
        raise PublicationError("AWS region must not contain whitespace")
    if "/" in region or "\\" in region or "?" in region or "#" in region:
        raise PublicationError("AWS region must be a region name, not a URL or path")
    if not SAFE_REGION_RE.fullmatch(region):
        raise PublicationError("AWS region contains unsupported characters")
    return region


def has_url_authority_control(value: str) -> bool:
    return any(ord(char) <= 32 or ord(char) == 127 or char in {"\\", "%"} for char in value)


def has_url_path_control(value: str) -> bool:
    return any(ord(char) <= 32 or ord(char) == 127 for char in value)


def read_json_file(path: Path, label: str) -> dict[str, Any]:
    text = read_bounded_ascii_file(path, label, max_bytes=MAX_METADATA_BYTES)
    assert_no_forbidden_text(text, label)
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PublicationError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise PublicationError(f"{label} must be a JSON object")
    return value


def validate_repository_json(
    repository: dict[str, Any],
    base_url: str,
    expected_version: str,
) -> str:
    if repository.get("schema") != SITE_SCHEMA:
        raise PublicationError("repository.json has unexpected schema")
    version = repository.get("version")
    if not isinstance(version, str) or not version:
        raise PublicationError("repository.json version is missing")
    if expected_version and version != expected_version:
        raise PublicationError(
            f"repository.json version {version!r} did not match expected {expected_version!r}"
        )
    if repository.get("baseUrl") != base_url:
        raise PublicationError("repository.json baseUrl does not match requested base URL")
    for guard in ("payloadDisplayed", "tokenDisplayed", "keyMaterialDisplayed"):
        if repository.get(guard) is not False:
            raise PublicationError(f"repository.json expected {guard}=false")
    apt = require_object(repository, "apt", "repository.json")
    rpm = require_object(repository, "rpm", "repository.json")
    downloads = require_object(repository, "downloads", "repository.json")
    cache_policy = require_object(repository, "cachePolicy", "repository.json")

    expected_fields = {
        "apt.repositoryUrl": (apt.get("repositoryUrl"), f"{base_url}/apt"),
        "apt.keyUrl": (apt.get("keyUrl"), f"{base_url}/apt/{PUBLIC_KEY_NAME}"),
        "rpm.repositoryUrl": (rpm.get("repositoryUrl"), f"{base_url}/rpm"),
        "rpm.repoFileUrl": (rpm.get("repoFileUrl"), f"{base_url}/install/conu.repo"),
        "rpm.keyUrl": (rpm.get("keyUrl"), f"{base_url}/rpm/{PUBLIC_KEY_NAME}"),
        "cachePolicy.policyUrl": (cache_policy.get("policyUrl"), f"{base_url}/cache-policy.json"),
        "cachePolicy.headersFileUrl": (cache_policy.get("headersFileUrl"), f"{base_url}/_headers"),
    }
    for name, (actual, expected) in expected_fields.items():
        if actual != expected:
            raise PublicationError(f"repository.json {name} does not match baseUrl")
    if cache_policy.get("hostMustApply") is not True:
        raise PublicationError("repository.json expected cachePolicy.hostMustApply=true")
    for field in ("hostedBundleUrl", "hostedBundleChecksumUrl", "hostedBundleSignatureUrl"):
        path = url_to_base_path(base_url, downloads.get(field), f"repository.json downloads.{field}")
        if not path.startswith("/downloads/"):
            raise PublicationError(f"repository.json downloads.{field} must point under baseUrl")
    return version


def require_object(parent: dict[str, Any], key: str, label: str) -> dict[str, Any]:
    value = parent.get(key)
    if not isinstance(value, dict):
        raise PublicationError(f"{label} {key} metadata is missing")
    return value


def url_to_base_path(base_url: str, value: str, label: str) -> str:
    if not isinstance(value, str):
        raise PublicationError(f"{label} must be a URL string")
    parsed_base = urlparse(base_url)
    parsed_value = urlparse(value)
    if parsed_value.username or parsed_value.password:
        raise PublicationError(f"{label} must not include credentials")
    if parsed_value.params or parsed_value.query or parsed_value.fragment:
        raise PublicationError(f"{label} must not include params, query, or fragment")
    if (parsed_value.scheme, parsed_value.netloc) != (parsed_base.scheme, parsed_base.netloc):
        raise PublicationError(f"{label} points outside repository origin")
    base_path = parsed_base.path.rstrip("/")
    value_path = parsed_value.path.rstrip("/")
    path_parts = [part for part in parsed_value.path.split("/") if part]
    if any(part in {".", ".."} for part in path_parts):
        raise PublicationError(f"{label} path must not contain dot segments")
    decoded_path_parts = [unquote(part) for part in path_parts]
    if any(part in {".", ".."} for part in decoded_path_parts):
        raise PublicationError(f"{label} path must not contain dot segments")
    if any("/" in part or "\\" in part for part in decoded_path_parts):
        raise PublicationError(f"{label} path must not contain encoded separators")
    if any(has_url_path_control(part) for part in decoded_path_parts):
        raise PublicationError(f"{label} path must not contain whitespace or control characters")
    forbidden = sorted({part.lower() for part in decoded_path_parts} & FORBIDDEN_SEGMENTS)
    if forbidden:
        raise PublicationError(
            f"{label} path contains forbidden local-state segment: {', '.join(forbidden)}"
        )
    if base_path:
        if value_path != base_path and not value_path.startswith(f"{base_path}/"):
            raise PublicationError(f"{label} points outside repository path")
        relative = value_path[len(base_path) :]
    else:
        relative = value_path
    if not relative.startswith("/"):
        relative = f"/{relative}"
    return validate_cache_path(relative or "/", f"{label} path")


def validate_cache_policy_json(
    cache_policy: dict[str, Any],
    base_url: str,
    version: str,
) -> None:
    if cache_policy.get("schema") != CACHE_POLICY_SCHEMA:
        raise PublicationError("cache-policy.json has unexpected schema")
    if cache_policy.get("version") != version:
        raise PublicationError("cache-policy.json version does not match repository.json")
    if cache_policy.get("baseUrl") != base_url:
        raise PublicationError("cache-policy.json baseUrl does not match repository.json")
    if cache_policy.get("headersFile") != "_headers":
        raise PublicationError("cache-policy.json headersFile must be _headers")
    if cache_policy.get("hostMustApply") is not True:
        raise PublicationError("cache-policy.json expected hostMustApply=true")
    for guard in ("payloadDisplayed", "tokenDisplayed", "keyMaterialDisplayed"):
        if cache_policy.get(guard) is not False:
            raise PublicationError(f"cache-policy.json expected {guard}=false")


def parse_cache_rules(cache_policy: dict[str, Any]) -> list[dict[str, Any]]:
    raw_rules = cache_policy.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise PublicationError("cache-policy.json rules must be a non-empty array")
    rules: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for rule in raw_rules:
        if not isinstance(rule, dict):
            raise PublicationError("cache-policy.json contains a non-object cache rule")
        kind = rule.get("kind")
        cache_control = rule.get("cacheControl")
        paths = rule.get("paths")
        if not isinstance(kind, str) or not kind:
            raise PublicationError("cache-policy.json cache rule kind is missing")
        if not isinstance(cache_control, str) or not cache_control:
            raise PublicationError(f"cache-policy.json cache rule {kind} cacheControl is missing")
        validate_cache_control_value(cache_control, f"cache-policy.json cache rule {kind}")
        if not isinstance(paths, list) or not paths:
            raise PublicationError(f"cache-policy.json cache rule {kind} paths are missing")
        clean_paths: list[str] = []
        for path in paths:
            clean_path = validate_cache_path(path, f"cache-policy.json cache rule {kind} path")
            if clean_path in seen_paths:
                raise PublicationError(f"cache-policy.json duplicates cache path {clean_path}")
            seen_paths.add(clean_path)
            clean_paths.append(clean_path)
        rules.append({"kind": kind, "paths": tuple(clean_paths), "cacheControl": cache_control})
    return rules


def validate_cache_path(path: str, label: str) -> str:
    if not isinstance(path, str) or not path.startswith("/"):
        raise PublicationError(f"{label} must be an absolute path")
    if "\\" in path:
        raise PublicationError(f"{label} must not contain backslashes")
    if "?" in path or "#" in path:
        raise PublicationError(f"{label} must not contain query or fragment")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts[1:]):
        raise PublicationError(f"{label} must not contain empty or dot segments")
    if any(has_url_path_control(part) for part in parts[1:]):
        raise PublicationError(f"{label} must not contain whitespace or control characters")
    forbidden = sorted({part.lower() for part in parts[1:]} & FORBIDDEN_SEGMENTS)
    if forbidden:
        raise PublicationError(
            f"{label} contains forbidden local-state segment: {', '.join(forbidden)}"
        )
    return path


def parse_headers_file(text: str) -> dict[str, dict[str, str]]:
    entries: dict[str, dict[str, str]] = {}
    current_path: str | None = None
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if line.startswith(" ") or line.startswith("\t"):
            if current_path is None:
                raise PublicationError("_headers contains a header before any path")
            stripped = line.strip()
            if ":" not in stripped:
                raise PublicationError("_headers contains a malformed header line")
            name, value = stripped.split(":", 1)
            entries[current_path][name.strip().lower()] = value.strip()
            continue
        current_path = validate_cache_path(line.strip(), "_headers path")
        if current_path in entries:
            raise PublicationError(f"_headers contains duplicate path: {current_path}")
        entries[current_path] = {}
    return entries


def validate_headers_match_policy(
    headers_entries: dict[str, dict[str, str]],
    rules: list[dict[str, Any]],
) -> None:
    expected = {
        path: {"cache-control": rule["cacheControl"]}
        for rule in rules
        for path in rule["paths"]
    }
    actual = {
        path: {"cache-control": headers.get("cache-control", "")}
        for path, headers in headers_entries.items()
    }
    if actual != expected:
        raise PublicationError("_headers Cache-Control rules do not match cache-policy.json")


def collect_files(
    site_dir: Path,
    bucket: str,
    prefix: str,
    rules: list[dict[str, Any]],
) -> list[PublishFile]:
    files: list[PublishFile] = []
    total_size = 0
    for path in sorted(site_dir.rglob("*")):
        relative_path = relative_name(site_dir, path)
        if path.is_symlink():
            raise PublicationError(f"site entry must not be a symlink: {relative_path}")
        if path.is_dir():
            continue
        validate_relative_path(relative_path)
        size = validate_regular_file(
            path,
            f"site file {relative_path}",
            max_bytes=MAX_FILE_BYTES,
        )
        total_size += size
        if total_size > MAX_TOTAL_BYTES:
            raise PublicationError("site directory is too large to publish")
        if len(files) >= MAX_FILES:
            raise PublicationError("site directory has too many files to publish")
        if is_text_member(relative_path):
            try:
                assert_no_forbidden_text(
                    read_text_file(path, relative_path, max_bytes=MAX_FILE_BYTES),
                    relative_path,
                )
            except UnicodeDecodeError as exc:
                raise PublicationError(f"{relative_path} must be UTF-8 text") from exc
        cache_control = cache_control_for_path(f"/{relative_path}", rules)
        files.append(
            PublishFile(
                path=path,
                relative_path=relative_path,
                size=size,
                cache_control=cache_control,
                content_type=content_type_for_path(relative_path),
                s3_uri=s3_uri(bucket, prefix, relative_path),
            )
        )
    return files


def relative_name(site_dir: Path, path: Path) -> str:
    return path.relative_to(site_dir).as_posix()


def validate_relative_path(relative_path: str) -> None:
    parts = relative_path.split("/")
    if not relative_path or relative_path.startswith("/") or "\\" in relative_path:
        raise PublicationError(f"unsafe site path: {relative_path}")
    if any(part in {"", ".", ".."} for part in parts):
        raise PublicationError(f"unsafe site path: {relative_path}")
    forbidden = sorted({part.lower() for part in parts} & FORBIDDEN_SEGMENTS)
    if forbidden:
        raise PublicationError(f"site path contains forbidden local-state segment: {relative_path}")


def is_text_member(relative_path: str) -> bool:
    name = relative_path.rsplit("/", 1)[-1]
    return name in TEXT_MEMBER_NAMES or relative_path.endswith(TEXT_SUFFIXES)


def assert_no_forbidden_text(text: str, label: str) -> None:
    for forbidden in FORBIDDEN_TEXT:
        if forbidden in text:
            raise PublicationError(f"{label} contains forbidden repository publication text: {forbidden}")


def validate_cache_control_value(value: str, label: str) -> None:
    if len(value) > MAX_CACHE_CONTROL_BYTES:
        raise PublicationError(f"{label} Cache-Control is too long")
    if value != value.strip():
        raise PublicationError(f"{label} Cache-Control must not have leading or trailing whitespace")
    for character in value:
        codepoint = ord(character)
        if codepoint < 32 or codepoint == 127 or codepoint > 126:
            raise PublicationError(
                f"{label} Cache-Control must be printable ASCII without control characters"
            )


def read_bounded_ascii_file(path: Path, label: str, *, max_bytes: int) -> str:
    data = read_regular_file(path, label, max_bytes=max_bytes)
    try:
        return data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise PublicationError(f"{label} must be ASCII") from exc


def read_text_file(path: Path, label: str, *, max_bytes: int) -> str:
    data = read_regular_file(path, label, max_bytes=max_bytes)
    return data.decode("utf-8")


def read_regular_file(path: Path, label: str, *, max_bytes: int) -> bytes:
    handle, _size = open_regular_file(path, label, max_bytes=max_bytes)
    with handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise PublicationError(f"{label} is larger than {max_bytes} bytes")
    return data


def validate_regular_file(path: Path, label: str, *, max_bytes: int) -> int:
    handle, size = open_regular_file(path, label, max_bytes=max_bytes)
    handle.close()
    return size


def open_regular_file(path: Path, label: str, *, max_bytes: int) -> tuple[BinaryIO, int]:
    if path.is_symlink():
        raise PublicationError(f"{label} must not be a symlink: {path.name}")
    if not path.exists():
        raise PublicationError(f"missing {label} in site directory")
    try:
        fd = os.open(path, os.O_RDONLY | OPEN_BINARY | OPEN_NOFOLLOW)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise PublicationError(f"{label} must not be a symlink: {path.name}") from exc
        if not path.exists():
            raise PublicationError(f"missing {label} in site directory") from exc
        if not path.is_file():
            raise PublicationError(f"{label} must be a regular file") from exc
        raise PublicationError(f"{label} could not be opened") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise PublicationError(f"{label} must be a regular file")
        if metadata.st_size > max_bytes:
            raise PublicationError(f"{label} is larger than {max_bytes} bytes")
        return os.fdopen(fd, "rb"), metadata.st_size
    except BaseException:
        os.close(fd)
        raise


def validate_open_regular_file(handle: BinaryIO, label: str, *, max_bytes: int) -> int:
    metadata = os.fstat(handle.fileno())
    if not stat.S_ISREG(metadata.st_mode):
        raise PublicationError(f"{label} must be a regular file")
    if metadata.st_size > max_bytes:
        raise PublicationError(f"{label} is larger than {max_bytes} bytes")
    return metadata.st_size


def cache_control_for_path(path: str, rules: list[dict[str, Any]]) -> str:
    matches = [
        rule["cacheControl"]
        for rule in rules
        if any(fnmatch.fnmatchcase(path, pattern) for pattern in rule["paths"])
    ]
    if not matches:
        raise PublicationError(f"{path} is not covered by cache-policy.json")
    unique = sorted(set(matches))
    if len(unique) != 1:
        raise PublicationError(f"{path} is covered by conflicting cache-policy.json rules")
    return unique[0]


def content_type_for_path(relative_path: str) -> str:
    if relative_path == "_headers":
        return "text/plain; charset=utf-8"
    if relative_path.endswith(".json"):
        return "application/json; charset=utf-8"
    if relative_path.endswith((".txt", ".list", ".repo", ".sha256", ".asc")):
        return "text/plain; charset=utf-8"
    guessed, _encoding = mimetypes.guess_type(relative_path)
    return guessed or "application/octet-stream"


def s3_uri(bucket: str, prefix: str, relative_path: str) -> str:
    key = f"{prefix}/{relative_path}" if prefix else relative_path
    return f"s3://{bucket}/{key}"


def publish_plan(plan: PublishPlan, args: argparse.Namespace) -> None:
    aws_command = parse_aws_cli(args.aws_cli)
    global_args: list[str] = []
    endpoint_url = validate_endpoint_url(args.endpoint_url)
    if endpoint_url:
        global_args.extend(["--endpoint-url", endpoint_url])
    region = validate_region(args.region)
    if region:
        global_args.extend(["--region", region])
    for file in plan.files:
        label = f"site file {file.relative_path}"
        handle, size = open_regular_file(file.path, label, max_bytes=MAX_FILE_BYTES)
        with handle:
            if size != file.size:
                raise PublicationError(f"{label} changed after publication planning")
            if is_text_member(file.relative_path):
                try:
                    assert_no_forbidden_text(
                        handle.read(MAX_FILE_BYTES + 1).decode("utf-8"),
                        file.relative_path,
                    )
                except UnicodeDecodeError as exc:
                    raise PublicationError(f"{file.relative_path} must be UTF-8 text") from exc
                validate_open_regular_file(handle, label, max_bytes=MAX_FILE_BYTES)
                handle.seek(0)
            command = [
                *aws_command,
                *global_args,
                "s3",
                "cp",
                "-",
                file.s3_uri,
                "--cache-control",
                file.cache_control,
                "--content-type",
                file.content_type,
                "--expected-size",
                str(file.size),
                "--only-show-errors",
            ]
            subprocess.run(command, stdin=handle, check=True)


def parse_aws_cli(raw: str) -> list[str]:
    command = raw.strip()
    if not command:
        raise PublicationError("AWS CLI command must not be empty")
    try:
        parsed = shlex.split(command, posix=os.name != "nt")
    except ValueError as exc:
        raise PublicationError(f"AWS CLI command could not be parsed: {exc}") from exc
    if os.name == "nt":
        parsed = [strip_matching_quotes(item) for item in parsed]
    if not parsed:
        raise PublicationError("AWS CLI command must not be empty")
    return parsed


def strip_matching_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def run_endpoint_check(plan: PublishPlan, args: argparse.Namespace) -> None:
    checker = load_endpoint_checker()
    attempts = args.post_upload_retries
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            checker.audit_endpoint(
                base_url=plan.base_url,
                expected_version=args.expected_version or plan.version,
                timeout=args.check_timeout,
                allow_loopback_http=False,
            )
            return
        except Exception as exc:  # The checker owns its exact exception type.
            last_error = exc
            if attempt < attempts:
                time.sleep(args.post_upload_retry_seconds)
    raise PublicationError(
        f"live endpoint readiness failed after {attempts} attempt(s): {last_error}"
    )


def load_endpoint_checker() -> Any:
    spec = importlib.util.spec_from_file_location("check_hosted_linux_repository_endpoint", ENDPOINT_CHECKER)
    if spec is None or spec.loader is None:
        raise PublicationError("could not load hosted Linux repository endpoint checker")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


if __name__ == "__main__":
    raise SystemExit(main())
