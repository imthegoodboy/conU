#!/usr/bin/env python3
"""Audit GitHub workflow permissions for production release hygiene."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - exercised by dependency-free runners.
    yaml = None  # type: ignore[assignment]


DEFAULT_WORKFLOW_DIR = Path(".github/workflows")
FORBIDDEN_EVENTS = ("pull_request_target", "workflow_run")
ALLOWED_PERMISSION_KEYS = (
    "actions",
    "attestations",
    "contents",
    "id-token",
    "pages",
    "security-events",
)
TOP_LEVEL_PERMISSIONS = {
    "contents": "read",
}
SECRET_LIKE_ENV_TOKENS = (
    "PASSWORD",
    "TOKEN",
    "SECRET",
    "KEY",
    "IDENTITY",
    "P12",
    "PFX",
    "GPG",
)
UNSAFE_GITHUB_ENV_ECHO_RE = re.compile(
    r"\becho\s+[\"']?([A-Z0-9_]+)=\$([A-Z0-9_]+)"
)
EXPECTED_JOB_PERMISSIONS: dict[tuple[str, str], dict[str, str]] = {
    ("release.yml", "release-preflight"): {
        "actions": "read",
        "contents": "read",
        "pages": "read",
        "security-events": "read",
    },
    ("release.yml", "build"): {
        "contents": "read",
        "id-token": "write",
        "attestations": "write",
    },
    ("release.yml", "github-release"): {
        "contents": "write",
    },
    ("release.yml", "linux-repository-pages"): {
        "contents": "read",
        "pages": "write",
        "id-token": "write",
    },
    ("release.yml", "custom-linux-repository-publish"): {
        "contents": "read",
    },
    ("release.yml", "npm-publish"): {
        "contents": "read",
        "id-token": "write",
    },
}


@dataclass(frozen=True)
class WorkflowPermissionsReadiness:
    ready: bool
    workflow_count: int
    checked_workflows: tuple[str, ...]
    workflows_with_explicit_top_level_permissions: tuple[str, ...]
    jobs_with_write_permissions: tuple[str, ...]
    unsafe_environment_file_writes: tuple[str, ...]
    forbidden_events: tuple[str, ...]
    issues: tuple[str, ...]

    def as_json(self) -> dict[str, Any]:
        return {
            "schema": "conu.githubWorkflowPermissions.v1",
            "ready": self.ready,
            "workflowCount": self.workflow_count,
            "checkedWorkflows": list(self.checked_workflows),
            "workflowsWithExplicitTopLevelPermissions": list(
                self.workflows_with_explicit_top_level_permissions
            ),
            "jobsWithWritePermissions": list(self.jobs_with_write_permissions),
            "unsafeEnvironmentFileWrites": list(self.unsafe_environment_file_writes),
            "forbiddenEvents": list(self.forbidden_events),
            "issues": list(self.issues),
            "payloadDisplayed": False,
            "tokenDisplayed": False,
            "tokenHashDisplayed": False,
            "keyMaterialDisplayed": False,
            "contentsDisplayed": False,
        }


def yaml_items(text: str) -> list[tuple[int, str, str]]:
    items: list[tuple[int, str, str]] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        content = line.strip()
        if content.startswith("- "):
            items.append((indent, "-", content[2:].strip()))
            continue
        if ":" not in content:
            continue
        key, value = content.split(":", 1)
        items.append((indent, key.strip().strip("\"'"), value.strip()))
    return items


def scalar_value(value: str) -> str:
    return value.strip().strip("\"'")


def parse_mapping_at(items: list[tuple[int, str, str]], start: int, base_indent: int, value: str) -> dict[str, str] | str:
    if value:
        return scalar_value(value)
    mapping: dict[str, str] = {}
    for indent, key, child_value in items[start + 1 :]:
        if indent <= base_indent:
            break
        if key == "-" or indent != base_indent + 2:
            continue
        mapping[key] = scalar_value(child_value)
    return mapping


def parse_events_at(items: list[tuple[int, str, str]], start: int, base_indent: int, value: str) -> str | dict[str, Any]:
    if value:
        return scalar_value(value)
    events: dict[str, Any] = {}
    for indent, key, child_value in items[start + 1 :]:
        if indent <= base_indent:
            break
        if indent != base_indent + 2:
            continue
        if key == "-":
            events[scalar_value(child_value)] = {}
        else:
            events[key] = {}
    return events


def parse_jobs_at(items: list[tuple[int, str, str]], start: int, base_indent: int) -> dict[str, Any]:
    jobs: dict[str, Any] = {}
    job_indexes: list[tuple[int, str]] = []
    for index, (indent, key, _value) in enumerate(items[start + 1 :], start + 1):
        if indent <= base_indent:
            break
        if indent == base_indent + 2 and key != "-":
            job_indexes.append((index, key))
            jobs[key] = {}
    for job_index, job_name in job_indexes:
        for index, (indent, key, value) in enumerate(items[job_index + 1 :], job_index + 1):
            if indent <= base_indent + 2:
                break
            if indent == base_indent + 4 and key == "permissions":
                jobs[job_name]["permissions"] = parse_mapping_at(items, index, indent, value)
    return jobs


def load_workflow_minimal(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"failed to read workflow {path.name}: {exc}") from exc
    items = yaml_items(text)
    payload: dict[str, Any] = {}
    for index, (indent, key, value) in enumerate(items):
        if indent != 0:
            continue
        if key == "on":
            payload["on"] = parse_events_at(items, index, indent, value)
        elif key == "permissions":
            payload["permissions"] = parse_mapping_at(items, index, indent, value)
        elif key == "jobs":
            payload["jobs"] = parse_jobs_at(items, index, indent)
    return payload


def load_workflow(path: Path) -> dict[str, Any]:
    if yaml is None:
        return load_workflow_minimal(path)
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"failed to read workflow {path.name}: {exc}") from exc
    except yaml.YAMLError as exc:  # type: ignore[union-attr]
        raise ValueError(f"workflow {path.name} is invalid YAML: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"workflow {path.name} must contain a YAML mapping")
    return payload


def audit_environment_file_writes(path: Path) -> tuple[str, ...]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError(f"failed to read workflow {path.name}: {exc}") from exc

    findings: list[str] = []
    for index, line in enumerate(lines):
        match = UNSAFE_GITHUB_ENV_ECHO_RE.search(line.strip())
        if match is None:
            continue
        output_name, source_name = match.groups()
        if not is_secret_like_env_name(output_name) and not is_secret_like_env_name(source_name):
            continue
        if not has_nearby_github_env_redirect(lines, index):
            continue
        findings.append(
            f"{path.name}:line {index + 1} echoes secret-derived {source_name} directly to GITHUB_ENV"
        )
    return tuple(findings)


def is_secret_like_env_name(name: str) -> bool:
    return any(token in name for token in SECRET_LIKE_ENV_TOKENS)


def has_nearby_github_env_redirect(lines: list[str], index: int) -> bool:
    start = max(0, index - 3)
    end = min(len(lines), index + 4)
    return any("GITHUB_ENV" in lines[position] for position in range(start, end))


def workflow_trigger(payload: dict[str, Any]) -> Any:
    if "on" in payload:
        return payload["on"]
    # PyYAML's YAML 1.1 resolver treats unquoted "on" as a boolean key.
    return payload.get(True)


def event_names(trigger: Any) -> tuple[str, ...]:
    if isinstance(trigger, str):
        return (trigger,)
    if isinstance(trigger, list):
        return tuple(sorted(item for item in trigger if isinstance(item, str)))
    if isinstance(trigger, dict):
        return tuple(sorted(str(key) for key in trigger.keys()))
    return ()


def normalize_permissions(value: Any, *, scope: str) -> dict[str, str] | str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if not isinstance(value, dict):
        raise ValueError(f"{scope} permissions must be a mapping or permission shorthand")
    normalized: dict[str, str] = {}
    for key, permission_value in value.items():
        if not isinstance(key, str):
            raise ValueError(f"{scope} permission keys must be strings")
        if not isinstance(permission_value, str):
            raise ValueError(f"{scope} permission values must be strings")
        normalized[key] = permission_value
    return normalized


def format_job(workflow_name: str, job_name: str) -> str:
    return f"{workflow_name}:{job_name}"


def mapping_contains_write(permissions: dict[str, str]) -> bool:
    return any(value == "write" for value in permissions.values())


def audit_mapping(
    *,
    permissions: dict[str, str],
    expected: dict[str, str],
    scope: str,
    allow_write: bool,
) -> list[str]:
    issues: list[str] = []
    allowed_values = {"read", "write", "none"}
    for key, value in permissions.items():
        if key not in ALLOWED_PERMISSION_KEYS:
            issues.append(f"{scope} uses unexpected permission key: {key}")
        if value not in allowed_values:
            issues.append(f"{scope} uses unexpected permission value for {key}: {value}")
        if value == "write" and not allow_write:
            issues.append(f"{scope} must not request write permission for {key}")
    for key, expected_value in expected.items():
        actual_value = permissions.get(key)
        if actual_value != expected_value:
            issues.append(
                f"{scope} must set {key}={expected_value}; found {actual_value or 'unset'}"
            )
    for key, value in permissions.items():
        if key not in expected:
            issues.append(f"{scope} has extra permission {key}={value}")
    return issues


def audit_workflows(workflow_paths: tuple[Path, ...]) -> WorkflowPermissionsReadiness:
    issues: list[str] = []
    checked: list[str] = []
    explicit_top_level: list[str] = []
    write_jobs: list[str] = []
    unsafe_env_writes: list[str] = []
    forbidden_events_seen: set[str] = set()

    if not workflow_paths:
        issues.append("no workflow files found")

    for path in workflow_paths:
        workflow_name = path.name
        checked.append(workflow_name)
        payload = load_workflow(path)
        for finding in audit_environment_file_writes(path):
            unsafe_env_writes.append(finding)
            issues.append(finding)

        events = event_names(workflow_trigger(payload))
        for event in events:
            if event in FORBIDDEN_EVENTS:
                forbidden_events_seen.add(f"{workflow_name}:{event}")
                issues.append(f"{workflow_name} uses forbidden event: {event}")

        top_permissions = normalize_permissions(
            payload.get("permissions"),
            scope=f"{workflow_name} top-level",
        )
        if top_permissions is None:
            issues.append(f"{workflow_name} must declare explicit top-level permissions")
        elif isinstance(top_permissions, str):
            issues.append(f"{workflow_name} must not use top-level permissions shorthand: {top_permissions}")
        else:
            explicit_top_level.append(workflow_name)
            issues.extend(
                audit_mapping(
                    permissions=top_permissions,
                    expected=TOP_LEVEL_PERMISSIONS,
                    scope=f"{workflow_name} top-level",
                    allow_write=False,
                )
            )

        jobs = payload.get("jobs")
        if not isinstance(jobs, dict):
            issues.append(f"{workflow_name} must define jobs as a mapping")
            continue

        for job_name, job_payload in jobs.items():
            if not isinstance(job_name, str):
                issues.append(f"{workflow_name} contains a non-string job id")
                continue
            if not isinstance(job_payload, dict):
                issues.append(f"{format_job(workflow_name, job_name)} must be a mapping")
                continue
            scope = format_job(workflow_name, job_name)
            expected_permissions = EXPECTED_JOB_PERMISSIONS.get((workflow_name, job_name))
            job_permissions = normalize_permissions(
                job_payload.get("permissions"),
                scope=scope,
            )
            if job_permissions is None:
                continue
            if isinstance(job_permissions, str):
                issues.append(f"{scope} must not use permissions shorthand: {job_permissions}")
                continue
            has_write = mapping_contains_write(job_permissions)
            if has_write:
                write_jobs.append(scope)
            if expected_permissions is None:
                issues.extend(
                    audit_mapping(
                        permissions=job_permissions,
                        expected=TOP_LEVEL_PERMISSIONS,
                        scope=scope,
                        allow_write=False,
                    )
                )
            else:
                issues.extend(
                    audit_mapping(
                        permissions=job_permissions,
                        expected=expected_permissions,
                        scope=scope,
                        allow_write=True,
                    )
                )

    return WorkflowPermissionsReadiness(
        ready=not issues,
        workflow_count=len(workflow_paths),
        checked_workflows=tuple(sorted(checked)),
        workflows_with_explicit_top_level_permissions=tuple(sorted(explicit_top_level)),
        jobs_with_write_permissions=tuple(sorted(write_jobs)),
        unsafe_environment_file_writes=tuple(sorted(unsafe_env_writes)),
        forbidden_events=tuple(sorted(forbidden_events_seen)),
        issues=tuple(issues),
    )


def find_workflow_paths(workflow_dir: Path) -> tuple[Path, ...]:
    if not workflow_dir.exists():
        return ()
    paths = [
        path
        for path in workflow_dir.iterdir()
        if path.is_file() and path.suffix.lower() in {".yml", ".yaml"}
    ]
    return tuple(sorted(paths, key=lambda item: item.name))


def print_text_report(report: WorkflowPermissionsReadiness) -> None:
    if report.ready:
        print("GitHub workflow permissions readiness passed")
        return
    print("GitHub workflow permissions readiness failed", file=sys.stderr)
    for issue in report.issues:
        print(f"issue: {issue}", file=sys.stderr)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workflow-dir",
        type=Path,
        default=DEFAULT_WORKFLOW_DIR,
        help="directory containing GitHub workflow YAML files",
    )
    parser.add_argument("--json", action="store_true", help="print a machine-readable report")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        report = audit_workflows(find_workflow_paths(args.workflow_dir))
    except (OSError, ValueError) as exc:
        print(f"GitHub workflow permissions readiness failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report.as_json(), indent=2, sort_keys=True))
    else:
        print_text_report(report)
    return 0 if report.ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
