#!/usr/bin/env python3
"""Audit GitHub Pages readiness for the default hosted Linux repository site."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse, urlunparse

from github_release_secrets import find_gh, infer_repo, normalize_repo, run_gh_json


@dataclass(frozen=True)
class PagesReadiness:
    repo: str
    expected_base_url: str
    actual_base_url: str
    pages_required: bool
    ready: bool
    checks: dict[str, bool]
    issues: tuple[str, ...]

    def as_json(self) -> dict[str, Any]:
        return {
            "repo": self.repo,
            "expectedBaseUrl": self.expected_base_url,
            "actualBaseUrl": self.actual_base_url,
            "pagesRequired": self.pages_required,
            "ready": self.ready,
            "checks": self.checks,
            "issues": list(self.issues),
        }


def split_repo(repo: str) -> tuple[str, str]:
    owner, name = normalize_repo(repo).split("/", 1)
    return owner, name


def normalize_https_url(value: str, field_name: str) -> str:
    raw = value.strip()
    if not raw:
        raise ValueError(f"{field_name} must not be empty")
    parsed = urlparse(raw)
    if parsed.username or parsed.password:
        raise ValueError(f"{field_name} must not include credentials")
    if parsed.scheme.lower() != "https" or not parsed.netloc:
        raise ValueError(f"{field_name} must be an absolute HTTPS URL")
    if parsed.params or parsed.query or parsed.fragment:
        raise ValueError(f"{field_name} must not contain params, query, or fragment")
    netloc = normalize_url_netloc(parsed, field_name)
    parts = [part for part in parsed.path.split("/") if part]
    if any(part in {".", ".."} for part in parts):
        raise ValueError(f"{field_name} path must not contain dot segments")
    decoded_parts = [unquote(part) for part in parts]
    if any(part in {".", ".."} for part in decoded_parts):
        raise ValueError(f"{field_name} path must not contain dot segments")
    if any("/" in part or "\\" in part for part in decoded_parts):
        raise ValueError(f"{field_name} path must not contain encoded separators")
    path = "/" + "/".join(parts) if parts else ""
    return urlunparse(("https", netloc, path, "", "", ""))


def normalize_url_netloc(parsed, field_name: str) -> str:
    try:
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{field_name} authority is invalid") from exc
    if not host:
        raise ValueError(f"{field_name} authority must include a host")
    if port is None and parsed.netloc.rsplit("@", 1)[-1].endswith(":"):
        raise ValueError(f"{field_name} authority is invalid")
    host = host.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if port is None:
        return host
    return f"{host}:{port}"


def default_pages_base_url(repo: str) -> str:
    owner, name = split_repo(repo)
    return normalize_https_url(f"https://{owner.lower()}.github.io/{name}", "default Pages URL")


def normalize_payload_url(payload: dict[str, Any]) -> str:
    value = payload.get("html_url")
    if not isinstance(value, str) or not value.strip():
        return ""
    try:
        return normalize_https_url(value, "GitHub Pages html_url")
    except ValueError:
        return ""


def source_is_main_root(payload: dict[str, Any]) -> bool:
    source = payload.get("source")
    if not isinstance(source, dict):
        return False
    return source.get("branch") == "main" and source.get("path") == "/"


def audit_pages_readiness(
    repo: str,
    pages_payload: dict[str, Any] | None,
    linux_repository_base_url: str = "",
) -> PagesReadiness:
    expected_base_url = default_pages_base_url(repo)
    custom_base_url = linux_repository_base_url.strip()

    if custom_base_url:
        actual_base_url = normalize_https_url(
            custom_base_url,
            "CONU_LINUX_REPOSITORY_BASE_URL",
        )
        issues: list[str] = []
        if actual_base_url == expected_base_url:
            issues.append(
                "CONU_LINUX_REPOSITORY_BASE_URL matches the default GitHub Pages URL; "
                "leave it unset so the release workflow deploys Pages"
            )
        return PagesReadiness(
            repo=repo,
            expected_base_url=expected_base_url,
            actual_base_url=actual_base_url,
            pages_required=False,
            ready=not issues,
            checks={
                "customBaseUrlConfigured": True,
                "customBaseUrlHttps": True,
                "customBaseUrlIsNotDefaultPagesUrl": not issues,
            },
            issues=tuple(issues),
        )

    if pages_payload is None:
        raise ValueError("GitHub Pages metadata is required when the Linux repository base URL is unset")
    if not isinstance(pages_payload, dict):
        raise ValueError("GitHub Pages metadata must be a JSON object")

    actual_base_url = normalize_payload_url(pages_payload)
    checks = {
        "pagesConfigured": True,
        "buildTypeWorkflow": pages_payload.get("build_type") == "workflow",
        "httpsEnforced": pages_payload.get("https_enforced") is True,
        "public": pages_payload.get("public") is True,
        "urlMatchesDefaultBaseUrl": actual_base_url == expected_base_url,
        "sourceMainRoot": source_is_main_root(pages_payload),
    }
    issue_messages = {
        "buildTypeWorkflow": "GitHub Pages build_type must be workflow",
        "httpsEnforced": "GitHub Pages must enforce HTTPS",
        "public": "GitHub Pages site must be public for public package repository use",
        "urlMatchesDefaultBaseUrl": (
            f"GitHub Pages html_url must match the generated default base URL {expected_base_url}"
        ),
        "sourceMainRoot": "GitHub Pages source metadata should remain main:/ for this repository",
    }
    issues = tuple(message for key, message in issue_messages.items() if not checks[key])

    return PagesReadiness(
        repo=repo,
        expected_base_url=expected_base_url,
        actual_base_url=actual_base_url,
        pages_required=True,
        ready=not issues,
        checks=checks,
        issues=issues,
    )


def load_pages_metadata(repo: str, gh: str) -> dict[str, Any]:
    payload = run_gh_json(
        gh,
        ["api", f"repos/{repo}/pages"],
        "gh api GitHub Pages metadata",
    )
    if not isinstance(payload, dict):
        raise ValueError("gh api GitHub Pages metadata returned an unexpected payload")
    return payload


def load_pages_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"failed to read Pages fixture JSON: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Pages fixture JSON was invalid: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("Pages fixture JSON must contain an object")
    return payload


def print_text_report(report: PagesReadiness) -> None:
    if report.ready:
        if report.pages_required:
            print(
                "GitHub Pages readiness passed: "
                f"{report.repo} deploys from GitHub Actions at {report.actual_base_url}"
            )
        else:
            print(
                "Linux repository base URL readiness passed: "
                f"{report.actual_base_url} is configured; GitHub Pages deployment is not required"
            )
        return

    print(f"GitHub Pages readiness failed for {report.repo}", file=sys.stderr)
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
        "--linux-repository-base-url",
        default=os.environ.get("CONU_LINUX_REPOSITORY_BASE_URL", ""),
        help="custom hosted Linux repository base URL; defaults to CONU_LINUX_REPOSITORY_BASE_URL",
    )
    parser.add_argument(
        "--pages-json",
        type=Path,
        default=None,
        help="read GitHub Pages metadata from a JSON fixture instead of gh api",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print a machine-readable readiness report",
    )
    parser.add_argument(
        "--gh",
        default="",
        help=argparse.SUPPRESS,
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        repo_root = Path(__file__).resolve().parents[1]
        os.chdir(repo_root)

        gh = args.gh.strip()
        repo = args.repo.strip()
        custom_base_url = args.linux_repository_base_url.strip()
        if not repo:
            gh = gh or find_gh()
            repo = infer_repo(gh)
        repo = normalize_repo(repo)
        pages_payload = None
        if not custom_base_url:
            if args.pages_json:
                pages_payload = load_pages_json(args.pages_json)
            else:
                gh = gh or find_gh()
                pages_payload = load_pages_metadata(repo, gh)

        report = audit_pages_readiness(repo, pages_payload, custom_base_url)
    except (OSError, ValueError) as exc:
        print(f"GitHub Pages readiness failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report.as_json(), indent=2, sort_keys=True))
    else:
        print_text_report(report)
    return 0 if report.ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
