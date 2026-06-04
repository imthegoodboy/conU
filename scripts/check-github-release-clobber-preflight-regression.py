#!/usr/bin/env python3
"""Regression checks for GitHub Release clobber preflight."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-github-release-clobber-preflight.py")
SENSITIVE_SENTINEL = "do-not-print-this-secret-value"
TEST_TAG = "v0.1.0"


def load_module():
    spec = importlib.util.spec_from_file_location("check_github_release_clobber_preflight", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load GitHub Release clobber preflight module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def existing_release_payload(tag: str = TEST_TAG) -> dict[str, object]:
    return {
        "id": 12345,
        "tag_name": tag,
        "draft": False,
        "prerelease": False,
        "assets": [
            {
                "name": "conu-0.1.0-linux-x64.tar.gz",
                "size": 123,
                "browser_download_url": f"https://example.invalid/{SENSITIVE_SENTINEL}",
            }
        ],
        "body": SENSITIVE_SENTINEL,
    }


def assert_raises(func, pattern: str) -> None:
    try:
        func()
    except ValueError as exc:
        rendered = str(exc)
        if SENSITIVE_SENTINEL in rendered:
            raise AssertionError("error message leaked a sensitive fixture value") from exc
        if pattern not in rendered:
            raise AssertionError(f"expected {pattern!r} in {exc!r}") from exc
        return
    raise AssertionError(f"expected ValueError containing {pattern!r}")


def assert_not_ready(report, pattern: str) -> None:
    if report.ready:
        raise AssertionError("expected GitHub Release clobber report to fail")
    rendered = json.dumps(report.as_json())
    if pattern not in rendered:
        raise AssertionError(f"expected {pattern!r} in report: {rendered}")


def run_audit_tests(module) -> None:
    absent = module.audit_release_clobber("owner/repo", TEST_TAG, None)
    if not absent.ready or absent.existing_release:
        raise AssertionError(f"expected absent release to pass, got {absent!r}")

    existing = module.audit_release_clobber("owner/repo", TEST_TAG, existing_release_payload())
    assert_not_ready(existing, "already exists")
    rendered = json.dumps(existing.as_json())
    if SENSITIVE_SENTINEL in rendered:
        raise AssertionError("clobber readiness report included unrelated release metadata")

    allowed = module.audit_release_clobber(
        "owner/repo",
        TEST_TAG,
        existing_release_payload(),
        allow_existing_release=True,
    )
    if not allowed.ready or not allowed.allowed_existing_release:
        raise AssertionError(f"expected explicit allow to pass, got {allowed!r}")

    draft_payload = existing_release_payload()
    draft_payload["draft"] = True
    draft = module.audit_release_clobber("owner/repo", TEST_TAG, draft_payload)
    assert_not_ready(draft, "already exists")
    if not draft.draft:
        raise AssertionError("draft release metadata was not preserved")

    mismatch = module.audit_release_clobber(
        "owner/repo",
        TEST_TAG,
        existing_release_payload("v0.2.0"),
    )
    assert_not_ready(mismatch, "expected v0.1.0")

    bad_assets = existing_release_payload()
    bad_assets["assets"] = {"name": "not-a-list"}
    assert_raises(
        lambda: module.audit_release_clobber("owner/repo", TEST_TAG, bad_assets),
        "assets field must be a list",
    )

    assert_raises(lambda: module.validate_tag("0.1.0"), "must start with")
    assert_raises(lambda: module.validate_tag("vlatest"), "semver")


def run_loader_tests(module) -> None:
    original_run = module.subprocess.run
    calls: list[list[str]] = []

    def fake_not_found_run(args, **_kwargs):
        calls.append(list(args))
        if args == ["gh", "api", "repos/owner/repo"]:
            return subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout=json.dumps({"full_name": "owner/repo"}),
                stderr="",
            )
        return subprocess.CompletedProcess(
            args=args,
            returncode=1,
            stdout="",
            stderr=f"gh: Not Found (HTTP 404) {SENSITIVE_SENTINEL}",
        )

    module.subprocess.run = fake_not_found_run
    try:
        if module.load_release_metadata("owner/repo", TEST_TAG, "gh") is not None:
            raise AssertionError("expected 404 release lookup to return None")
    finally:
        module.subprocess.run = original_run
    if calls != [
        ["gh", "api", "repos/owner/repo/releases/tags/v0.1.0"],
        ["gh", "api", "repos/owner/repo"],
    ]:
        raise AssertionError(f"expected release then repo lookup calls, got {calls!r}")

    def fake_repo_access_failure_run(args, **_kwargs):
        if args == ["gh", "api", "repos/owner/repo"]:
            return subprocess.CompletedProcess(
                args=args,
                returncode=1,
                stdout="",
                stderr=f"repo failure {SENSITIVE_SENTINEL}",
            )
        return subprocess.CompletedProcess(
            args=args,
            returncode=1,
            stdout="",
            stderr="gh: Not Found (HTTP 404)",
        )

    module.subprocess.run = fake_repo_access_failure_run
    try:
        assert_raises(
            lambda: module.load_release_metadata("owner/repo", TEST_TAG, "gh"),
            "repository lookup failed",
        )
    finally:
        module.subprocess.run = original_run

    def fake_found_run(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            args=["gh"],
            returncode=0,
            stdout=json.dumps(existing_release_payload()),
            stderr="",
        )

    module.subprocess.run = fake_found_run
    try:
        payload = module.load_release_metadata("owner/repo", TEST_TAG, "gh")
    finally:
        module.subprocess.run = original_run
    if payload is None or payload.get("tag_name") != TEST_TAG:
        raise AssertionError("expected loader to return release metadata")

    def fake_duplicate_release_json_run(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            args=["gh"],
            returncode=0,
            stdout=(
                '{"tag_name":"v0.1.0",'
                f'"tag_name":"{SENSITIVE_SENTINEL}",'
                '"draft":false,"prerelease":false,"assets":[]}\n'
            ),
            stderr="",
        )

    module.subprocess.run = fake_duplicate_release_json_run
    try:
        assert_raises(
            lambda: module.load_release_metadata("owner/repo", TEST_TAG, "gh"),
            "duplicate JSON key",
        )
    finally:
        module.subprocess.run = original_run

    def fake_duplicate_repo_json_run(args, **_kwargs):
        return subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout=(
                '{"full_name":"owner/repo",'
                f'"full_name":"{SENSITIVE_SENTINEL}"}}\n'
            ),
            stderr="",
        )

    module.subprocess.run = fake_duplicate_repo_json_run
    try:
        assert_raises(
            lambda: module.verify_repo_access("owner/repo", "gh"),
            "duplicate JSON key",
        )
    finally:
        module.subprocess.run = original_run

    def fake_failure_run(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            args=["gh"],
            returncode=2,
            stdout="",
            stderr=f"gh failure {SENSITIVE_SENTINEL}",
        )

    module.subprocess.run = fake_failure_run
    try:
        assert_raises(
            lambda: module.load_release_metadata("owner/repo", TEST_TAG, "gh"),
            "exit code 2",
        )
    finally:
        module.subprocess.run = original_run

    def fake_invalid_json_run(*_args, **_kwargs):
        return subprocess.CompletedProcess(args=["gh"], returncode=0, stdout="{", stderr="")

    module.subprocess.run = fake_invalid_json_run
    try:
        assert_raises(
            lambda: module.load_release_metadata("owner/repo", TEST_TAG, "gh"),
            "invalid JSON",
        )
    finally:
        module.subprocess.run = original_run


def run_fixture_tests(module) -> None:
    with tempfile.TemporaryDirectory(prefix="conu-release-clobber-") as temp_dir:
        absent_path = Path(temp_dir) / "absent.json"
        existing_path = Path(temp_dir) / "existing.json"
        absent_path.write_text("null", encoding="utf-8")
        existing_path.write_text(json.dumps(existing_release_payload()), encoding="utf-8")

        absent_payload = module.load_release_json(absent_path)
        if absent_payload is not None:
            raise AssertionError("expected JSON null fixture to load as absent release")
        existing_payload = module.load_release_json(existing_path)
        if existing_payload is None:
            raise AssertionError("expected existing release fixture to load")

        duplicate_path = Path(temp_dir) / "duplicate.json"
        duplicate_path.write_text(
            (
                '{"tag_name":"v0.1.0",'
                f'"tag_name":"{SENSITIVE_SENTINEL}",'
                '"draft":false,"prerelease":false,"assets":[]}\n'
            ),
            encoding="utf-8",
        )
        assert_raises(
            lambda: module.load_release_json(duplicate_path),
            "duplicate JSON key",
        )


def run_main_tests(module) -> None:
    with tempfile.TemporaryDirectory(prefix="conu-release-clobber-") as temp_dir:
        absent_json = Path(temp_dir) / "absent.json"
        existing_json = Path(temp_dir) / "existing.json"
        absent_json.write_text("null", encoding="utf-8")
        existing_json.write_text(json.dumps(existing_release_payload()), encoding="utf-8")

        original_argv = sys.argv
        stdout = io.StringIO()
        stderr = io.StringIO()
        sys.argv = [
            "check-github-release-clobber-preflight.py",
            "--repo",
            "owner/repo",
            "--tag",
            TEST_TAG,
            "--release-json",
            str(absent_json),
            "--gh",
            "gh",
        ]
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                absent_exit = module.main()
        finally:
            sys.argv = original_argv

        original_argv = sys.argv
        existing_stdout = io.StringIO()
        existing_stderr = io.StringIO()
        sys.argv = [
            "check-github-release-clobber-preflight.py",
            "--repo",
            "owner/repo",
            "--tag",
            TEST_TAG,
            "--release-json",
            str(existing_json),
            "--gh",
            "gh",
        ]
        try:
            with contextlib.redirect_stdout(existing_stdout), contextlib.redirect_stderr(existing_stderr):
                existing_exit = module.main()
        finally:
            sys.argv = original_argv

    if absent_exit != 0:
        raise AssertionError(f"expected absent release main() to pass, got {absent_exit}")
    if existing_exit == 0:
        raise AssertionError("expected existing release main() to fail")
    rendered = (
        stdout.getvalue()
        + stderr.getvalue()
        + existing_stdout.getvalue()
        + existing_stderr.getvalue()
    )
    if SENSITIVE_SENTINEL in rendered:
        raise AssertionError("main() output leaked unrelated release metadata")


def main() -> int:
    module = load_module()
    run_audit_tests(module)
    run_loader_tests(module)
    run_fixture_tests(module)
    run_main_tests(module)
    print("GitHub Release clobber preflight regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
