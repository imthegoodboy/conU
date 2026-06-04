#!/usr/bin/env python3
"""Regression checks for GitHub Pages readiness auditing."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-github-pages-readiness.py")
SENSITIVE_SENTINEL = "do-not-print-this-secret-value"


def load_module():
    spec = importlib.util.spec_from_file_location("check_github_pages_readiness", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load GitHub Pages readiness module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def ready_payload() -> dict[str, object]:
    return {
        "url": "https://api.github.com/repos/owner/repo/pages",
        "status": None,
        "cname": None,
        "custom_404": False,
        "html_url": "https://owner.github.io/repo/",
        "build_type": "workflow",
        "source": {"branch": "main", "path": "/"},
        "public": True,
        "https_enforced": True,
        "private_key": SENSITIVE_SENTINEL,
    }


def assert_raises(func, pattern: str) -> None:
    try:
        func()
    except ValueError as exc:
        if pattern not in str(exc):
            raise AssertionError(f"expected {pattern!r} in {exc!r}") from exc
        return
    raise AssertionError(f"expected ValueError containing {pattern!r}")


def assert_not_ready_for(module, payload_key: str, value: object, expected_issue: str) -> None:
    payload = ready_payload()
    if payload_key == "source":
        payload[payload_key] = value
    else:
        payload[payload_key] = value
    report = module.audit_pages_readiness("owner/repo", payload)
    if report.ready:
        raise AssertionError(f"{payload_key}={value!r} should not be ready")
    if not any(expected_issue in issue for issue in report.issues):
        raise AssertionError(f"expected issue containing {expected_issue!r}, got {report.issues!r}")


def run_audit_tests(module) -> None:
    report = module.audit_pages_readiness("owner/repo", ready_payload())
    if not report.ready:
        raise AssertionError(f"expected ready Pages report, got {report.issues!r}")
    rendered = json.dumps(report.as_json())
    if SENSITIVE_SENTINEL in rendered:
        raise AssertionError("Pages readiness report included an unrelated payload field")

    assert_not_ready_for(module, "build_type", "legacy", "build_type")
    assert_not_ready_for(module, "https_enforced", False, "HTTPS")
    assert_not_ready_for(module, "public", False, "public")
    assert_not_ready_for(module, "html_url", "https://packages.example.com/conu/", "default base URL")
    assert_not_ready_for(module, "source", {"branch": "gh-pages", "path": "/"}, "main:/")
    credentialed_payload = ready_payload()
    credentialed_payload["html_url"] = f"https://user:{SENSITIVE_SENTINEL}@owner.github.io/repo/"
    credentialed_report = module.audit_pages_readiness("owner/repo", credentialed_payload)
    if credentialed_report.ready:
        raise AssertionError("credentialed Pages html_url should not be ready")
    if SENSITIVE_SENTINEL in json.dumps(credentialed_report.as_json()):
        raise AssertionError("credentialed Pages html_url leaked into readiness report")

    custom = module.audit_pages_readiness(
        "owner/repo",
        None,
        "https://packages.example.com/conu/",
    )
    if not custom.ready or custom.pages_required:
        raise AssertionError("custom HTTPS repository base URL should bypass Pages requirement")
    assert_raises(
        lambda: module.audit_pages_readiness("owner/repo", None, "http://packages.example.com/conu"),
        "HTTPS",
    )
    assert_raises(
        lambda: module.audit_pages_readiness(
            "owner/repo",
            None,
            f"https://user:{SENSITIVE_SENTINEL}@packages.example.com/conu",
        ),
        "credentials",
    )
    for bad_url, expected in (
        ("https://packages.example.com:bad/conu", "authority is invalid"),
        ("https://packages.example.com:/conu", "authority is invalid"),
        ("https://:443/conu", "authority must include a host"),
        ("https://packages.example.com:443x/conu", "authority is invalid"),
    ):
        assert_raises(
            lambda bad_url=bad_url: module.audit_pages_readiness("owner/repo", None, bad_url),
            expected,
        )
    assert_raises(
        lambda: module.audit_pages_readiness(
            "owner/repo",
            None,
            "https://packages.example.com/conu/%2e%2e/v0.1.0",
        ),
        "dot segments",
    )
    assert_raises(
        lambda: module.audit_pages_readiness(
            "owner/repo",
            None,
            "https://packages.example.com/conu/v0.1.0%2fother",
        ),
        "encoded separators",
    )
    for bad_url in (
        "https://127.0.0.1/conu",
        "https://10.0.0.1/conu",
        "https://[fc00::1]/conu",
        "https://[2001:db8:1::1]/conu",
        "https://[3fff::1]/conu",
        "https://[5f00::1]/conu",
        "https://[64:ff9b:1::1]/conu",
        "https://[64:ff9b::a00:1]/conu",
        "https://[100:0:0:1::1]/conu",
        "https://packages.local/conu",
    ):
        assert_raises(
            lambda bad_url=bad_url: module.audit_pages_readiness("owner/repo", None, bad_url),
            "host must be public",
        )
    default_custom = module.audit_pages_readiness(
        "owner/repo",
        None,
        "https://owner.github.io/repo/",
    )
    if default_custom.ready:
        raise AssertionError("default Pages URL configured as a custom base URL should fail")


def run_loader_tests(module) -> None:
    original_run_gh_json = module.run_gh_json

    def fake_run_gh_json(gh, args, description):
        if args != ["api", "repos/owner/repo/pages"]:
            raise AssertionError(f"unexpected gh args: {args!r}")
        if gh != "gh":
            raise AssertionError(f"unexpected gh executable: {gh!r}")
        if "Pages" not in description:
            raise AssertionError(f"unexpected description: {description!r}")
        return ready_payload()

    module.run_gh_json = fake_run_gh_json
    try:
        payload = module.load_pages_metadata("owner/repo", "gh")
    finally:
        module.run_gh_json = original_run_gh_json
    if payload.get("build_type") != "workflow":
        raise AssertionError("loader did not return fixture Pages metadata")

    module.run_gh_json = lambda *_args, **_kwargs: []
    try:
        assert_raises(
            lambda: module.load_pages_metadata("owner/repo", "gh"),
            "unexpected payload",
        )
    finally:
        module.run_gh_json = original_run_gh_json


def run_main_tests(module) -> None:
    with tempfile.TemporaryDirectory(prefix="conu-pages-readiness-") as temp_dir:
        pages_json = Path(temp_dir) / "pages.json"
        pages_json.write_text(json.dumps(ready_payload()), encoding="utf-8")

        original_argv = sys.argv
        stdout = io.StringIO()
        stderr = io.StringIO()
        sys.argv = [
            "check-github-pages-readiness.py",
            "--repo",
            "owner/repo",
            "--pages-json",
            str(pages_json),
            "--gh",
            "gh",
        ]
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = module.main()
        finally:
            sys.argv = original_argv

    if exit_code != 0:
        raise AssertionError(f"expected main() to pass, got {exit_code}: {stderr.getvalue()}")
    rendered = stdout.getvalue() + stderr.getvalue()
    if SENSITIVE_SENTINEL in rendered:
        raise AssertionError("main() output leaked an unrelated payload field")

    original_find_gh = module.find_gh
    original_argv = sys.argv
    stdout = io.StringIO()
    stderr = io.StringIO()
    module.find_gh = lambda: (_ for _ in ()).throw(AssertionError("find_gh should not run"))
    sys.argv = [
        "check-github-pages-readiness.py",
        "--repo",
        "owner/repo",
        "--linux-repository-base-url",
        "https://packages.example.com/conu/",
    ]
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = module.main()
    finally:
        module.find_gh = original_find_gh
        sys.argv = original_argv

    if exit_code != 0:
        raise AssertionError(
            f"expected custom base URL main() to pass without gh, got {exit_code}: {stderr.getvalue()}"
        )


def main() -> int:
    module = load_module()
    run_audit_tests(module)
    run_loader_tests(module)
    run_main_tests(module)
    print("GitHub Pages readiness regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
