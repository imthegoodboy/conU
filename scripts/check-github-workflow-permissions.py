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
RELEASE_PREFLIGHT_NPM_AUTH_COMMAND = (
    "python scripts/check-npm-publish-preflight.py "
    "--registry-check --require-token-env NODE_AUTH_TOKEN --token-auth-check"
)
RELEASE_PREFLIGHT_REQUIRED_STEPS: tuple[
    tuple[str, str, tuple[tuple[str, str], ...]],
    ...,
] = (
    (
        "Validate tag target CI and release branch",
        "validate tag target CI and release branch",
        (
            ("tag gate", "if: startsWith(github.ref, 'refs/tags/v')"),
            ("GitHub token env", "GH_TOKEN: ${{ github.token }}"),
            (
                "tagged release readiness command",
                "python scripts/check-tagged-release-readiness.py --repo "
                '"$GITHUB_REPOSITORY" --tag "$GITHUB_REF_NAME" --ci-only '
                '--ci-head "$GITHUB_SHA" --require-default-branch-head',
            ),
        ),
    ),
    (
        "Validate GitHub main branch protection",
        "validate GitHub main branch protection",
        (
            ("tag gate", "if: startsWith(github.ref, 'refs/tags/v')"),
            ("GitHub token env", "GH_TOKEN: ${{ github.token }}"),
            (
                "main branch protection command",
                'python scripts/check-github-main-protection.py --repo "$GITHUB_REPOSITORY"',
            ),
        ),
    ),
    (
        "Validate GitHub Actions permissions",
        "validate GitHub Actions permissions",
        (
            ("tag gate", "if: startsWith(github.ref, 'refs/tags/v')"),
            ("GitHub token env", "GH_TOKEN: ${{ github.token }}"),
            (
                "Actions permissions command",
                'python scripts/check-github-actions-permissions.py --repo "$GITHUB_REPOSITORY"',
            ),
        ),
    ),
    (
        "Validate GitHub workflow permissions",
        "validate GitHub workflow permissions",
        (
            ("tag gate", "if: startsWith(github.ref, 'refs/tags/v')"),
            (
                "workflow permissions command",
                "python scripts/check-github-workflow-permissions.py",
            ),
        ),
    ),
    (
        "Validate GitHub repository security",
        "validate GitHub repository security",
        (
            ("tag gate", "if: startsWith(github.ref, 'refs/tags/v')"),
            ("GitHub token env", "GH_TOKEN: ${{ github.token }}"),
            (
                "repository security command",
                'python scripts/check-github-repository-security.py --repo "$GITHUB_REPOSITORY"',
            ),
        ),
    ),
    (
        "Validate npm token authentication and registry availability",
        "validate npm token authentication and registry availability",
        (
            ("tag gate", "if: startsWith(github.ref, 'refs/tags/v')"),
            ("NPM token env", "NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}"),
            ("npm auth/registry command", RELEASE_PREFLIGHT_NPM_AUTH_COMMAND),
        ),
    ),
)
RELEASE_PUBLICATION_GATE_STEP = "Check Linux repository publication result"
RELEASE_PUBLICATION_GATE_SNIPPETS: tuple[tuple[str, str], ...] = (
    (
        "base URL mode selector",
        "CONU_LINUX_REPOSITORY_BASE_URL: ${{ vars.CONU_LINUX_REPOSITORY_BASE_URL }}",
    ),
    (
        "GitHub Release result",
        "GITHUB_RELEASE_RESULT: ${{ needs.github-release.result }}",
    ),
    ("Pages result", "PAGES_RESULT: ${{ needs.linux-repository-pages.result }}"),
    (
        "custom repository result",
        "CUSTOM_RESULT: ${{ needs.custom-linux-repository-publish.result }}",
    ),
    (
        "GitHub Release success check",
        'if [ "$GITHUB_RELEASE_RESULT" != "success" ]; then',
    ),
    (
        "default repository mode check",
        'if [ -z "${CONU_LINUX_REPOSITORY_BASE_URL:-}" ]; then',
    ),
    ("Pages success check", 'if [ "$PAGES_RESULT" != "success" ]; then'),
    ("custom repository success check", 'if [ "$CUSTOM_RESULT" != "success" ]; then'),
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
EXPECTED_RELEASE_JOB_NEEDS: dict[tuple[str, str], tuple[str, ...]] = {
    ("release.yml", "packages"): ("release-preflight",),
    ("release.yml", "production-readiness"): ("release-preflight",),
    ("release.yml", "build"): ("packages", "production-readiness"),
    ("release.yml", "github-release"): ("build",),
    ("release.yml", "linux-repository-pages"): ("github-release",),
    ("release.yml", "custom-linux-repository-publish"): ("github-release",),
    (
        "release.yml",
        "linux-repository-publication",
    ): ("github-release", "linux-repository-pages", "custom-linux-repository-publish"),
    ("release.yml", "npm-publish"): ("github-release", "linux-repository-publication"),
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


def parse_inline_sequence(value: str) -> list[str] | None:
    text = scalar_value(value)
    if not text.startswith("[") or not text.endswith("]"):
        return None
    inner = text[1:-1].strip()
    if not inner:
        return []
    return [scalar_value(item.strip()) for item in inner.split(",")]


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


def parse_sequence_at(
    items: list[tuple[int, str, str]],
    start: int,
    base_indent: int,
    value: str,
) -> list[str] | str:
    inline_sequence = parse_inline_sequence(value)
    if inline_sequence is not None:
        return inline_sequence
    if value:
        return scalar_value(value)
    sequence: list[str] = []
    for indent, key, child_value in items[start + 1 :]:
        if indent <= base_indent:
            break
        if indent == base_indent + 2 and key == "-":
            sequence.append(scalar_value(child_value))
    return sequence


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
            elif indent == base_indent + 4 and key == "needs":
                jobs[job_name]["needs"] = parse_sequence_at(items, index, indent, value)
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


def extract_job_block(text: str, job_name: str) -> str:
    lines = text.splitlines()
    start_index = None
    for index, line in enumerate(lines):
        if line == f"  {job_name}:":
            start_index = index
            break
    if start_index is None:
        return ""

    block = [lines[start_index]]
    for line in lines[start_index + 1 :]:
        if line.startswith("  ") and not line.startswith("    ") and line.strip().endswith(":"):
            break
        block.append(line)
    return "\n".join(block)


def extract_named_step_block(job_block: str, step_name: str) -> str:
    lines = job_block.splitlines()
    start_index = None
    for index, line in enumerate(lines):
        if line.strip() == f"- name: {step_name}":
            start_index = index
            break
    if start_index is None:
        return ""

    block = [lines[start_index]]
    for line in lines[start_index + 1 :]:
        if line.startswith("      - "):
            break
        block.append(line)
    return "\n".join(block)


def audit_required_release_preflight_steps(path: Path) -> tuple[str, ...]:
    if path.name != "release.yml":
        return ()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"failed to read workflow {path.name}: {exc}") from exc

    block = extract_job_block(text, "release-preflight")
    issues: list[str] = []
    if not block:
        return ("release.yml must define release-preflight job",)

    for step_name, description, required_snippets in RELEASE_PREFLIGHT_REQUIRED_STEPS:
        step = extract_named_step_block(block, step_name)
        if not step:
            issues.append(f"release.yml:release-preflight must {description}")
            continue
        for label, snippet in required_snippets:
            if snippet not in step:
                issues.append(
                    f"release.yml:release-preflight {description} is missing {label}"
                )
    return tuple(issues)


def audit_required_release_publication_gate(path: Path) -> tuple[str, ...]:
    if path.name != "release.yml":
        return ()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"failed to read workflow {path.name}: {exc}") from exc

    block = extract_job_block(text, "linux-repository-publication")
    issues: list[str] = []
    if not block:
        return ("release.yml must define linux-repository-publication job",)
    if "if: always() && startsWith(github.ref, 'refs/tags/v')" not in block:
        issues.append(
            "release.yml:linux-repository-publication must be tag-gated "
            "and always evaluate upstream results"
        )

    step = extract_named_step_block(block, RELEASE_PUBLICATION_GATE_STEP)
    if not step:
        issues.append(
            "release.yml:linux-repository-publication must check "
            "Linux repository publication results"
        )
        return tuple(issues)
    for label, snippet in RELEASE_PUBLICATION_GATE_SNIPPETS:
        if snippet not in step:
            issues.append(f"release.yml:linux-repository-publication gate is missing {label}")
    return tuple(issues)


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


def normalize_needs(value: Any, *, scope: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if not isinstance(value, list):
        raise ValueError(f"{scope} needs must be a string or list of strings")
    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{scope} needs entries must be strings")
        normalized.append(item)
    return tuple(normalized)


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


def audit_release_job_needs(workflow_name: str, jobs: dict[str, Any]) -> tuple[str, ...]:
    issues: list[str] = []
    for (expected_workflow, job_name), expected_needs in EXPECTED_RELEASE_JOB_NEEDS.items():
        if expected_workflow != workflow_name:
            continue
        scope = format_job(workflow_name, job_name)
        job_payload = jobs.get(job_name)
        if job_payload is None:
            issues.append(f"{workflow_name} must define {job_name} job")
            continue
        if not isinstance(job_payload, dict):
            continue
        actual_needs = normalize_needs(job_payload.get("needs"), scope=scope)
        actual_needs_set = set(actual_needs)
        for expected_need in expected_needs:
            if expected_need not in actual_needs_set:
                issues.append(f"{scope} must depend on {expected_need}")
    return tuple(issues)


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
        issues.extend(audit_required_release_preflight_steps(path))
        issues.extend(audit_required_release_publication_gate(path))

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

        issues.extend(audit_release_job_needs(workflow_name, jobs))

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
