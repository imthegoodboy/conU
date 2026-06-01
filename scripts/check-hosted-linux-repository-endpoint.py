#!/usr/bin/env python3
"""Audit a live hosted Linux repository endpoint and its cache policy."""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import socket
import sys
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen


CACHE_POLICY_SCHEMA = "conu.hostedLinuxRepository.cachePolicy.v1"
SITE_SCHEMA = "conu.hostedLinuxRepository.site.v1"
PUBLIC_KEY_NAME = "conu-linux-gpg-key.asc"
MAX_JSON_BYTES = 1024 * 1024
MAX_TEXT_BYTES = 1024 * 1024
MAX_HEAD_BYTES = 0
DEFAULT_TIMEOUT_SECONDS = 15.0
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
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
FORBIDDEN_PATH_SEGMENTS = {
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


class EndpointReadinessError(ValueError):
    """Raised when a hosted repository endpoint is not production-ready."""


@dataclass(frozen=True)
class EndpointFetch:
    path: str
    url: str
    final_url: str
    status: int
    cache_control: str
    body: bytes


@dataclass(frozen=True)
class EndpointReport:
    base_url: str
    version: str
    ready: bool
    checks: dict[str, bool]
    sampled_paths: list[dict[str, str]]
    issues: list[str]

    def as_json(self) -> dict[str, Any]:
        return {
            "baseUrl": self.base_url,
            "version": self.version,
            "ready": self.ready,
            "checks": self.checks,
            "sampledPaths": self.sampled_paths,
            "issues": self.issues,
        }


def main() -> int:
    args = parse_args()
    try:
        base_url = normalize_base_url(
            args.base_url or os.environ.get("CONU_LINUX_REPOSITORY_BASE_URL", ""),
            allow_loopback_http=args.allow_loopback_http,
        )
        report = audit_endpoint(
            base_url=base_url,
            expected_version=args.expected_version,
            timeout=args.timeout,
            allow_loopback_http=args.allow_loopback_http,
        )
    except (EndpointReadinessError, OSError, ValueError) as exc:
        if args.json:
            base_url = args.base_url or os.environ.get("CONU_LINUX_REPOSITORY_BASE_URL", "")
            print(
                json.dumps(
                    {
                        "baseUrl": base_url,
                        "ready": False,
                        "checks": {},
                        "sampledPaths": [],
                        "issues": [str(exc)],
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            print(f"Hosted Linux repository endpoint readiness failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report.as_json(), indent=2, sort_keys=True))
    else:
        print(
            "Hosted Linux repository endpoint readiness passed: "
            f"{report.base_url} serves version {report.version} with checked cache headers"
        )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url",
        default="",
        help="hosted Linux repository base URL; defaults to CONU_LINUX_REPOSITORY_BASE_URL",
    )
    parser.add_argument(
        "--expected-version",
        default="",
        help="expected hosted repository version from repository.json and cache-policy.json",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"HTTP timeout in seconds, default {DEFAULT_TIMEOUT_SECONDS:g}",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print a machine-readable readiness report",
    )
    parser.add_argument(
        "--allow-loopback-http",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    return parser.parse_args()


def audit_endpoint(
    *,
    base_url: str,
    expected_version: str,
    timeout: float,
    allow_loopback_http: bool,
) -> EndpointReport:
    if timeout <= 0:
        raise EndpointReadinessError("timeout must be positive")

    repository_fetch = fetch_path(
        base_url,
        "/repository.json",
        timeout=timeout,
        max_body_bytes=MAX_JSON_BYTES,
        allow_loopback_http=allow_loopback_http,
    )
    cache_policy_fetch = fetch_path(
        base_url,
        "/cache-policy.json",
        timeout=timeout,
        max_body_bytes=MAX_JSON_BYTES,
        allow_loopback_http=allow_loopback_http,
    )
    headers_fetch = fetch_path(
        base_url,
        "/_headers",
        timeout=timeout,
        max_body_bytes=MAX_TEXT_BYTES,
        allow_loopback_http=allow_loopback_http,
    )

    repository = decode_json(repository_fetch.body, "repository.json")
    cache_policy = decode_json(cache_policy_fetch.body, "cache-policy.json")
    headers_entries = parse_headers_file(decode_ascii(headers_fetch.body, "_headers"))

    version = validate_repository_json(base_url, repository)
    validate_cache_policy_json(base_url, cache_policy, expected_version or version)
    if expected_version and version != expected_version:
        raise EndpointReadinessError(
            f"repository.json version {version!r} did not match expected {expected_version!r}"
        )

    rules = parse_cache_rules(cache_policy)
    validate_headers_match_policy(headers_entries, rules)

    sample_paths = select_sample_paths(base_url, repository)
    sampled_reports: list[dict[str, str]] = []
    for path in sample_paths:
        expected_cache_control = cache_control_for_path(path, rules)
        fetch = fetch_path(
            base_url,
            path,
            timeout=timeout,
            max_body_bytes=MAX_HEAD_BYTES,
            allow_loopback_http=allow_loopback_http,
            method="HEAD",
        )
        validate_cache_control(path, fetch.cache_control, expected_cache_control)
        sampled_reports.append(
            {
                "path": path,
                "cacheControl": fetch.cache_control,
            }
        )

    return EndpointReport(
        base_url=base_url,
        version=version,
        ready=True,
        checks={
            "httpsOrLoopback": True,
            "repositoryJson": True,
            "cachePolicyJson": True,
            "headersFile": True,
            "headersMatchCachePolicy": True,
            "liveCacheHeaders": True,
            "displayGuards": True,
        },
        sampled_paths=sampled_reports,
        issues=[],
    )


def normalize_base_url(raw_value: str, *, allow_loopback_http: bool) -> str:
    raw = raw_value.strip()
    if not raw:
        raise EndpointReadinessError(
            "hosted Linux repository base URL is required; pass --base-url or set "
            "CONU_LINUX_REPOSITORY_BASE_URL"
        )
    parsed = urlparse(raw)
    if parsed.username or parsed.password:
        raise EndpointReadinessError("hosted Linux repository base URL must not include credentials")
    if parsed.params or parsed.query or parsed.fragment:
        raise EndpointReadinessError(
            "hosted Linux repository base URL must not include params, query, or fragment"
        )
    host = parsed.hostname
    if not host:
        raise EndpointReadinessError("hosted Linux repository base URL must include a host")
    scheme = parsed.scheme.lower()
    host_lower = host.lower()
    if scheme != "https":
        if not (allow_loopback_http and scheme == "http" and is_loopback_host(host_lower)):
            raise EndpointReadinessError(
                "hosted Linux repository base URL must be an absolute HTTPS URL"
            )
    path_parts = [part for part in parsed.path.split("/") if part]
    if any(part in {".", ".."} for part in path_parts):
        raise EndpointReadinessError("hosted Linux repository base URL path must not contain dot segments")
    path = "/" + "/".join(path_parts) if path_parts else ""
    netloc = normalize_netloc(host_lower, parsed.port)
    return urlunparse((scheme, netloc, path, "", "", ""))


def normalize_netloc(host: str, port: int | None) -> str:
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if port is None:
        return host
    return f"{host}:{port}"


def is_loopback_host(host: str) -> bool:
    if host in LOOPBACK_HOSTS:
        return True
    try:
        return socket.gethostbyname(host).startswith("127.")
    except OSError:
        return False


def fetch_path(
    base_url: str,
    path: str,
    *,
    timeout: float,
    max_body_bytes: int,
    allow_loopback_http: bool,
    method: str = "GET",
) -> EndpointFetch:
    if not path.startswith("/"):
        raise EndpointReadinessError(f"internal error: endpoint path must be absolute: {path}")
    url = urljoin(f"{base_url.rstrip('/')}/", path.lstrip("/"))
    request = Request(
        url,
        method=method,
        headers={
            "User-Agent": "conu-hosted-linux-repository-endpoint-check/1",
            "Accept": "application/json,text/plain,*/*",
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            final_url = response.geturl()
            ensure_final_url_under_base(
                final_url,
                base_url,
                allow_loopback_http=allow_loopback_http,
            )
            body = b""
            if method != "HEAD" and max_body_bytes >= 0:
                body = read_bounded(response, max_body_bytes, path)
            return EndpointFetch(
                path=path,
                url=url,
                final_url=final_url,
                status=response.status,
                cache_control=response.headers.get("Cache-Control", ""),
                body=body,
            )
    except HTTPError as exc:
        raise EndpointReadinessError(f"{path} returned HTTP {exc.code}") from exc
    except URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise EndpointReadinessError(f"{path} could not be fetched: {reason}") from exc


def ensure_final_url_under_base(
    final_url: str,
    base_url: str,
    *,
    allow_loopback_http: bool,
) -> None:
    normalized_final = normalize_base_url(final_url, allow_loopback_http=allow_loopback_http)
    final = urlparse(normalized_final)
    base = urlparse(base_url)
    if (final.scheme, final.netloc) != (base.scheme, base.netloc):
        raise EndpointReadinessError(f"request redirected outside repository origin: {final_url}")
    base_path = base.path.rstrip("/")
    final_path = final.path.rstrip("/")
    if base_path and final_path != base_path and not final_path.startswith(f"{base_path}/"):
        raise EndpointReadinessError(f"request redirected outside repository path: {final_url}")


def read_bounded(response: Any, max_bytes: int, path: str) -> bytes:
    body = response.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise EndpointReadinessError(f"{path} response exceeded {max_bytes} bytes")
    return body


def decode_json(data: bytes, label: str) -> dict[str, Any]:
    text = decode_ascii(data, label)
    assert_no_forbidden_text(text, label)
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise EndpointReadinessError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise EndpointReadinessError(f"{label} must be a JSON object")
    return value


def decode_ascii(data: bytes, label: str) -> str:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise EndpointReadinessError(f"{label} must be ASCII") from exc
    assert_no_forbidden_text(text, label)
    return text


def assert_no_forbidden_text(text: str, label: str) -> None:
    for forbidden in FORBIDDEN_TEXT:
        if forbidden in text:
            raise EndpointReadinessError(f"{label} contains forbidden hosted repository text: {forbidden}")


def validate_repository_json(base_url: str, repository: dict[str, Any]) -> str:
    if repository.get("schema") != SITE_SCHEMA:
        raise EndpointReadinessError("repository.json has unexpected schema")
    version = repository.get("version")
    if not isinstance(version, str) or not version:
        raise EndpointReadinessError("repository.json version is missing")
    if repository.get("baseUrl") != base_url:
        raise EndpointReadinessError("repository.json baseUrl does not match the checked endpoint")
    for key in ("payloadDisplayed", "tokenDisplayed", "keyMaterialDisplayed"):
        if repository.get(key) is not False:
            raise EndpointReadinessError(f"repository.json expected {key}=false")

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
            raise EndpointReadinessError(f"repository.json {name} does not match baseUrl")
    if cache_policy.get("hostMustApply") is not True:
        raise EndpointReadinessError("repository.json expected cachePolicy.hostMustApply=true")
    for field in ("hostedBundleUrl", "hostedBundleChecksumUrl", "hostedBundleSignatureUrl"):
        value = downloads.get(field)
        path = url_to_base_path(base_url, value, f"repository.json downloads.{field}")
        if not path.startswith("/downloads/"):
            raise EndpointReadinessError(f"repository.json downloads.{field} must point under baseUrl")
    return version


def validate_cache_policy_json(
    base_url: str,
    cache_policy: dict[str, Any],
    expected_version: str,
) -> None:
    if cache_policy.get("schema") != CACHE_POLICY_SCHEMA:
        raise EndpointReadinessError("cache-policy.json has unexpected schema")
    if cache_policy.get("version") != expected_version:
        raise EndpointReadinessError("cache-policy.json version does not match repository.json")
    if cache_policy.get("baseUrl") != base_url:
        raise EndpointReadinessError("cache-policy.json baseUrl does not match the checked endpoint")
    if cache_policy.get("headersFile") != "_headers":
        raise EndpointReadinessError("cache-policy.json headersFile must be _headers")
    if cache_policy.get("hostMustApply") is not True:
        raise EndpointReadinessError("cache-policy.json expected hostMustApply=true")
    for key in ("payloadDisplayed", "tokenDisplayed", "keyMaterialDisplayed"):
        if cache_policy.get(key) is not False:
            raise EndpointReadinessError(f"cache-policy.json expected {key}=false")


def require_object(parent: dict[str, Any], key: str, label: str) -> dict[str, Any]:
    value = parent.get(key)
    if not isinstance(value, dict):
        raise EndpointReadinessError(f"{label} {key} metadata is missing")
    return value


def validate_repository_path(path: str, label: str) -> str:
    if not isinstance(path, str) or not path.startswith("/"):
        raise EndpointReadinessError(f"{label} must be an absolute path")
    if "\\" in path:
        raise EndpointReadinessError(f"{label} must not contain backslashes")
    if "?" in path or "#" in path:
        raise EndpointReadinessError(f"{label} must not contain query or fragment")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts[1:]):
        raise EndpointReadinessError(f"{label} must not contain empty or dot segments")
    forbidden = sorted({part.lower() for part in parts[1:]} & FORBIDDEN_PATH_SEGMENTS)
    if forbidden:
        raise EndpointReadinessError(
            f"{label} contains forbidden local-state segment: {', '.join(forbidden)}"
        )
    return path


def parse_cache_rules(cache_policy: dict[str, Any]) -> list[dict[str, Any]]:
    raw_rules = cache_policy.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise EndpointReadinessError("cache-policy.json rules must be a non-empty array")
    rules: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for rule in raw_rules:
        if not isinstance(rule, dict):
            raise EndpointReadinessError("cache-policy.json contains a non-object cache rule")
        kind = rule.get("kind")
        cache_control = rule.get("cacheControl")
        paths = rule.get("paths")
        if not isinstance(kind, str) or not kind:
            raise EndpointReadinessError("cache-policy.json cache rule kind is missing")
        if not isinstance(cache_control, str) or not cache_control:
            raise EndpointReadinessError(f"cache-policy.json cache rule {kind} cacheControl is missing")
        if not isinstance(paths, list) or not paths:
            raise EndpointReadinessError(f"cache-policy.json cache rule {kind} paths are missing")
        clean_paths: list[str] = []
        for path in paths:
            clean_path = validate_repository_path(
                path,
                f"cache-policy.json cache rule {kind} path",
            )
            if clean_path in seen_paths:
                raise EndpointReadinessError(f"cache-policy.json duplicates cache path {clean_path}")
            seen_paths.add(clean_path)
            clean_paths.append(clean_path)
        rules.append(
            {
                "kind": kind,
                "paths": tuple(clean_paths),
                "cacheControl": cache_control,
            }
        )
    return rules


def parse_headers_file(text: str) -> dict[str, dict[str, str]]:
    entries: dict[str, dict[str, str]] = {}
    current_path: str | None = None
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if line.startswith(" ") or line.startswith("\t"):
            if current_path is None:
                raise EndpointReadinessError("_headers contains a header before any path")
            stripped = line.strip()
            if ":" not in stripped:
                raise EndpointReadinessError("_headers contains a malformed header line")
            name, value = stripped.split(":", 1)
            entries[current_path][name.strip().lower()] = value.strip()
            continue
        current_path = validate_repository_path(line.strip(), "_headers path")
        if current_path in entries:
            raise EndpointReadinessError(f"_headers contains duplicate path: {current_path}")
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
        raise EndpointReadinessError("_headers Cache-Control rules do not match cache-policy.json")


def select_sample_paths(base_url: str, repository: dict[str, Any]) -> list[str]:
    apt = require_object(repository, "apt", "repository.json")
    rpm = require_object(repository, "rpm", "repository.json")
    downloads = require_object(repository, "downloads", "repository.json")
    paths = [
        "/repository.json",
        "/cache-policy.json",
        "/_headers",
        "/install/conu.list",
        "/install/conu.repo",
        f"/{PUBLIC_KEY_NAME}",
        url_to_base_path(base_url, apt["keyUrl"], "repository.json apt.keyUrl"),
        f"{url_to_base_path(base_url, apt['repositoryUrl'], 'repository.json apt.repositoryUrl')}/Packages",
        f"{url_to_base_path(base_url, apt['repositoryUrl'], 'repository.json apt.repositoryUrl')}/InRelease",
        url_to_base_path(base_url, rpm["keyUrl"], "repository.json rpm.keyUrl"),
        f"{url_to_base_path(base_url, rpm['repositoryUrl'], 'repository.json rpm.repositoryUrl')}/repodata/repomd.xml",
        f"{url_to_base_path(base_url, rpm['repositoryUrl'], 'repository.json rpm.repositoryUrl')}/repodata/repomd.xml.asc",
        url_to_base_path(
            base_url,
            downloads["hostedBundleUrl"],
            "repository.json downloads.hostedBundleUrl",
        ),
        url_to_base_path(
            base_url,
            downloads["hostedBundleChecksumUrl"],
            "repository.json downloads.hostedBundleChecksumUrl",
        ),
        url_to_base_path(
            base_url,
            downloads["hostedBundleSignatureUrl"],
            "repository.json downloads.hostedBundleSignatureUrl",
        ),
    ]
    deduped: list[str] = []
    for path in paths:
        if path not in deduped:
            deduped.append(path)
    return deduped


def url_to_base_path(base_url: str, value: str, label: str) -> str:
    if not isinstance(value, str):
        raise EndpointReadinessError(f"{label} must be a URL string")
    parsed_base = urlparse(base_url)
    parsed_value = urlparse(value)
    if parsed_value.username or parsed_value.password:
        raise EndpointReadinessError(f"{label} must not include credentials")
    if parsed_value.params or parsed_value.query or parsed_value.fragment:
        raise EndpointReadinessError(f"{label} must not include params, query, or fragment")
    if (parsed_value.scheme, parsed_value.netloc) != (parsed_base.scheme, parsed_base.netloc):
        raise EndpointReadinessError(f"{label} points outside repository origin")
    base_path = parsed_base.path.rstrip("/")
    value_path = parsed_value.path.rstrip("/")
    path_parts = [part for part in parsed_value.path.split("/") if part]
    if any(part in {".", ".."} for part in path_parts):
        raise EndpointReadinessError(f"{label} path must not contain dot segments")
    if base_path:
        if value_path != base_path and not value_path.startswith(f"{base_path}/"):
            raise EndpointReadinessError(f"{label} points outside repository path")
        relative = value_path[len(base_path) :]
    else:
        relative = value_path
    if not relative.startswith("/"):
        relative = f"/{relative}"
    return validate_repository_path(relative or "/", f"{label} path")


def cache_control_for_path(path: str, rules: list[dict[str, Any]]) -> str:
    matches = [
        rule["cacheControl"]
        for rule in rules
        if any(fnmatch.fnmatchcase(path, pattern) for pattern in rule["paths"])
    ]
    if not matches:
        raise EndpointReadinessError(f"{path} is not covered by cache-policy.json")
    unique = sorted(set(matches))
    if len(unique) != 1:
        raise EndpointReadinessError(f"{path} is covered by conflicting cache-policy.json rules")
    return unique[0]


def validate_cache_control(path: str, actual: str, expected: str) -> None:
    if normalize_cache_control(actual) != normalize_cache_control(expected):
        raise EndpointReadinessError(
            f"{path} Cache-Control {actual!r} did not match cache-policy.json {expected!r}"
        )


def normalize_cache_control(value: str) -> tuple[str, ...]:
    return tuple(sorted(part.strip().lower() for part in value.split(",") if part.strip()))


if __name__ == "__main__":
    raise SystemExit(main())
