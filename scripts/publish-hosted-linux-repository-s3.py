#!/usr/bin/env python3
"""Publish a verified hosted Linux repository site to an S3-compatible target."""

from __future__ import annotations

import argparse
import fnmatch
import importlib.util
import json
import mimetypes
import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse


ROOT = Path(__file__).resolve().parents[1]
ENDPOINT_CHECKER = ROOT / "scripts" / "check-hosted-linux-repository-endpoint.py"
SITE_SCHEMA = "conu.hostedLinuxRepository.site.v1"
CACHE_POLICY_SCHEMA = "conu.hostedLinuxRepository.cachePolicy.v1"
MAX_FILES = 10000
MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
PUBLIC_KEY_NAME = "conu-linux-gpg-key.asc"
BUCKET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,253}[A-Za-z0-9]$")
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
        help="optional S3-compatible endpoint URL; HTTPS required except loopback HTTP",
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
    site_dir = args.site_dir.resolve()
    if not site_dir.exists() or not site_dir.is_dir():
        raise PublicationError(f"site directory does not exist: {args.site_dir}")
    bucket = validate_bucket(args.bucket)
    prefix = validate_prefix(args.prefix)
    validate_endpoint_url(args.endpoint_url)
    if args.post_upload_retries < 1:
        raise PublicationError("--post-upload-retries must be at least 1")
    if args.post_upload_retry_seconds < 0:
        raise PublicationError("--post-upload-retry-seconds must not be negative")
    if args.check_timeout <= 0:
        raise PublicationError("--check-timeout must be positive")

    repository = read_json_file(site_dir / "repository.json", "repository.json")
    cache_policy = read_json_file(site_dir / "cache-policy.json", "cache-policy.json")
    base_url = validate_base_url(args.base_url or str(repository.get("baseUrl", "")))
    version = validate_repository_json(repository, base_url, args.expected_version)
    validate_cache_policy_json(cache_policy, base_url, version)
    rules = parse_cache_rules(cache_policy)

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
    if any(part in {".", ".."} for part in parts):
        raise PublicationError("S3 prefix must not contain dot segments")
    if len(parts) != len(prefix.split("/")):
        raise PublicationError("S3 prefix must not contain empty path segments")
    return "/".join(parts)


def validate_endpoint_url(raw: str) -> str:
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
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" and not (parsed.scheme == "http" and is_loopback_host(host)):
        raise PublicationError("S3 endpoint URL must use HTTPS except loopback HTTP")
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))


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
    parts = [part for part in parsed.path.split("/") if part]
    if any(part in {".", ".."} for part in parts):
        raise PublicationError("repository base URL path must not contain dot segments")
    normalized_path = "/" + "/".join(parts) if parts else ""
    return urlunparse(("https", parsed.netloc.lower(), normalized_path, "", "", ""))


def read_json_file(path: Path, label: str) -> dict[str, Any]:
    if not path.exists() or not path.is_file():
        raise PublicationError(f"missing {label} in site directory")
    try:
        text = path.read_text(encoding="ascii")
    except UnicodeDecodeError as exc:
        raise PublicationError(f"{label} must be ASCII JSON") from exc
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
    for key in ("apt", "rpm", "downloads", "cachePolicy"):
        if not isinstance(repository.get(key), dict):
            raise PublicationError(f"repository.json {key} metadata is missing")
    return version


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
        if not isinstance(paths, list) or not paths:
            raise PublicationError(f"cache-policy.json cache rule {kind} paths are missing")
        clean_paths: list[str] = []
        for path in paths:
            if not isinstance(path, str) or not path.startswith("/"):
                raise PublicationError(f"cache-policy.json cache rule {kind} contains a non-absolute path")
            if "?" in path or "#" in path:
                raise PublicationError(f"cache-policy.json cache rule {kind} contains a query or fragment")
            if path in seen_paths:
                raise PublicationError(f"cache-policy.json duplicates cache path {path}")
            seen_paths.add(path)
            clean_paths.append(path)
        rules.append({"kind": kind, "paths": tuple(clean_paths), "cacheControl": cache_control})
    return rules


def collect_files(
    site_dir: Path,
    bucket: str,
    prefix: str,
    rules: list[dict[str, Any]],
) -> list[PublishFile]:
    files: list[PublishFile] = []
    total_size = 0
    for path in sorted(site_dir.rglob("*")):
        if path.is_dir():
            continue
        if path.is_symlink():
            raise PublicationError(f"site file must not be a symlink: {relative_name(site_dir, path)}")
        if not path.is_file():
            raise PublicationError(f"site entry must be a regular file: {relative_name(site_dir, path)}")
        relative_path = relative_name(site_dir, path)
        validate_relative_path(relative_path)
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            raise PublicationError(f"site file is too large: {relative_path}")
        total_size += size
        if total_size > MAX_TOTAL_BYTES:
            raise PublicationError("site directory is too large to publish")
        if len(files) >= MAX_FILES:
            raise PublicationError("site directory has too many files to publish")
        if is_text_member(relative_path):
            try:
                assert_no_forbidden_text(path.read_text(encoding="utf-8"), relative_path)
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
    if args.region.strip():
        global_args.extend(["--region", args.region.strip()])
    for file in plan.files:
        command = [
            *aws_command,
            *global_args,
            "s3",
            "cp",
            str(file.path),
            file.s3_uri,
            "--cache-control",
            file.cache_control,
            "--content-type",
            file.content_type,
            "--only-show-errors",
        ]
        subprocess.run(command, check=True)


def parse_aws_cli(raw: str) -> list[str]:
    command = raw.strip()
    if not command:
        raise PublicationError("AWS CLI command must not be empty")
    try:
        parsed = shlex.split(command, posix=os.name != "nt")
    except ValueError as exc:
        raise PublicationError(f"AWS CLI command could not be parsed: {exc}") from exc
    if not parsed:
        raise PublicationError("AWS CLI command must not be empty")
    return parsed


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
