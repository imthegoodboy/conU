#!/usr/bin/env python3
"""Regression checks for GitHub workflow permissions readiness."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-github-workflow-permissions.py")
SENSITIVE_SENTINEL = "do-not-print-this-token-or-payload"


def load_module():
    spec = importlib.util.spec_from_file_location("check_github_workflow_permissions", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load GitHub workflow permissions module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def ready_ci() -> str:
    return f"""
name: CI
on:
  push:
    branches: ["main"]
  pull_request:
permissions:
  contents: read
jobs:
  packages:
    runs-on: ubuntu-latest
    steps:
      - run: echo {SENSITIVE_SENTINEL}
"""


def ready_release() -> str:
    return """
name: Release Artifacts
on:
  push:
    tags:
      - "v*"
  workflow_dispatch:
permissions:
  contents: read
jobs:
  release-preflight:
    permissions:
      actions: read
      contents: read
      pages: read
      security-events: read
    runs-on: ubuntu-latest
    steps:
      - run: echo preflight
  build:
    permissions:
      contents: read
      id-token: write
      attestations: write
    runs-on: ubuntu-latest
    steps:
      - run: echo build
  github-release:
    permissions:
      contents: write
    runs-on: ubuntu-latest
    steps:
      - run: echo release
  linux-repository-pages:
    permissions:
      contents: read
      pages: write
      id-token: write
    runs-on: ubuntu-latest
    steps:
      - run: echo pages
  custom-linux-repository-publish:
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - run: echo custom
  npm-publish:
    permissions:
      contents: read
      id-token: write
    runs-on: ubuntu-latest
    steps:
      - run: echo npm
"""


def build_fixture(ci_text: str | None = None, release_text: str | None = None) -> Path:
    root = Path(tempfile.mkdtemp(prefix="conu-workflow-permissions-"))
    write(root / "ci.yml", ci_text if ci_text is not None else ready_ci())
    write(root / "release.yml", release_text if release_text is not None else ready_release())
    return root


def audit(module, workflow_dir: Path):
    return module.audit_workflows(module.find_workflow_paths(workflow_dir))


def assert_safe_report(report) -> dict[str, object]:
    rendered = json.dumps(report.as_json(), sort_keys=True)
    if SENSITIVE_SENTINEL in rendered:
        raise AssertionError("workflow permissions report leaked workflow contents")
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


def with_fixture(module, ci_text: str | None, release_text: str | None):
    root = build_fixture(ci_text, release_text)
    try:
        return audit(module, root)
    finally:
        shutil.rmtree(root)


def run_ready_tests(module) -> None:
    report = with_fixture(module, None, None)
    if not report.ready:
        raise AssertionError(f"expected workflow permissions readiness to pass: {report.issues!r}")
    parsed = assert_safe_report(report)
    if parsed["workflowCount"] != 2:
        raise AssertionError("expected two workflows")
    if "release.yml:github-release" not in parsed["jobsWithWritePermissions"]:
        raise AssertionError("expected release write job to be reported")

    yaml_module = module.yaml
    module.yaml = None
    try:
        fallback_report = with_fixture(module, None, None)
    finally:
        module.yaml = yaml_module
    if not fallback_report.ready:
        raise AssertionError(
            f"expected dependency-free workflow parser to pass: {fallback_report.issues!r}"
        )
    assert_safe_report(fallback_report)


def run_top_level_permission_tests(module) -> None:
    report = with_fixture(
        module,
        ready_ci().replace("permissions:\n  contents: read\n", ""),
        None,
    )
    if report.ready:
        raise AssertionError("missing top-level permissions should fail")
    if "ci.yml must declare explicit top-level permissions" not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing top-level permissions issue was not reported")

    report = with_fixture(
        module,
        ready_ci().replace("permissions:\n  contents: read\n", "permissions: write-all\n"),
        None,
    )
    if report.ready:
        raise AssertionError("top-level permission shorthand should fail")
    if "ci.yml must not use top-level permissions shorthand: write-all" not in json.dumps(assert_safe_report(report)):
        raise AssertionError("top-level shorthand issue was not reported")


def run_forbidden_event_tests(module) -> None:
    report = with_fixture(
        module,
        ready_ci().replace("  pull_request:\n", "  pull_request_target:\n"),
        None,
    )
    if report.ready:
        raise AssertionError("pull_request_target should fail")
    if "ci.yml uses forbidden event: pull_request_target" not in json.dumps(assert_safe_report(report)):
        raise AssertionError("forbidden event issue was not reported")


def run_unexpected_job_write_tests(module) -> None:
    report = with_fixture(
        module,
        ready_ci().replace(
            "    runs-on: ubuntu-latest\n",
            "    permissions:\n      contents: write\n    runs-on: ubuntu-latest\n",
        ),
        None,
    )
    if report.ready:
        raise AssertionError("unexpected CI write permission should fail")
    rendered = json.dumps(assert_safe_report(report))
    if "ci.yml:packages must not request write permission for contents" not in rendered:
        raise AssertionError("unexpected write issue was not reported")


def run_expected_job_permission_tests(module) -> None:
    report = with_fixture(
        module,
        None,
        ready_release().replace("      id-token: write\n      attestations: write\n", "      id-token: write\n"),
    )
    if report.ready:
        raise AssertionError("missing expected release job permission should fail")
    if "release.yml:build must set attestations=write; found unset" not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing expected permission issue was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace("      contents: write\n    runs-on", "      contents: write\n      actions: read\n    runs-on"),
    )
    if report.ready:
        raise AssertionError("extra release job permission should fail")
    if "release.yml:github-release has extra permission actions=read" not in json.dumps(assert_safe_report(report)):
        raise AssertionError("extra expected permission issue was not reported")


def run_unsafe_environment_file_write_tests(module) -> None:
    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - run: echo build\n",
            "      - run: |\n"
            "          {\n"
            "            echo \"CONU_MACOS_CODESIGN_IDENTITY=$MACOS_CODESIGN_IDENTITY\"\n"
            "          } >> \"$GITHUB_ENV\"\n",
        ),
    )
    if report.ready:
        raise AssertionError("unsafe GITHUB_ENV secret-derived echo should fail")
    parsed = assert_safe_report(report)
    rendered = json.dumps(parsed)
    if "echoes secret-derived MACOS_CODESIGN_IDENTITY directly to GITHUB_ENV" not in rendered:
        raise AssertionError("unsafe GITHUB_ENV write issue was not reported")
    if not parsed["unsafeEnvironmentFileWrites"]:
        raise AssertionError("unsafe GITHUB_ENV write finding was not listed")


def main() -> int:
    module = load_module()
    run_ready_tests(module)
    run_top_level_permission_tests(module)
    run_forbidden_event_tests(module)
    run_unexpected_job_write_tests(module)
    run_expected_job_permission_tests(module)
    run_unsafe_environment_file_write_tests(module)
    print("GitHub workflow permissions regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
