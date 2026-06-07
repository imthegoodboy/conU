#!/usr/bin/env python3
"""Regression checks for GitHub release secret readiness auditing."""

from __future__ import annotations

import importlib.util
import json
import contextlib
import io
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace


SCRIPT = Path(__file__).with_name("check-github-release-secret-readiness.py")
SENSITIVE_SENTINEL = "do-not-print-this-secret-value"


def load_module():
    spec = importlib.util.spec_from_file_location("check_github_release_secret_readiness", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load GitHub release secret readiness module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def assert_raises(func, pattern: str) -> None:
    try:
        func()
    except ValueError as exc:
        if SENSITIVE_SENTINEL in str(exc):
            raise AssertionError("error message leaked a secret or variable value") from exc
        if pattern not in str(exc):
            raise AssertionError(f"expected {pattern!r} in {exc!r}") from exc
        return
    raise AssertionError(f"expected ValueError containing {pattern!r}")


def assert_safe_report(report) -> dict[str, object]:
    rendered = json.dumps(report.as_json(), sort_keys=True)
    if SENSITIVE_SENTINEL in rendered:
        raise AssertionError("release secret readiness report leaked a sensitive value")
    parsed = json.loads(rendered)
    for field in (
        "payloadDisplayed",
        "tokenDisplayed",
        "tokenHashDisplayed",
        "keyMaterialDisplayed",
        "contentsDisplayed",
        "secretValuesDisplayed",
    ):
        if parsed.get(field) is not False:
            raise AssertionError(f"expected {field}=false")
    return parsed


def run_audit_tests(module) -> None:
    configured = set(module.REQUIRED_RELEASE_SECRETS)
    ready = module.audit_secret_names("owner/repo", configured)
    if not ready.ready:
        raise AssertionError("all required secret names should be ready")
    if ready.missing:
        raise AssertionError(f"unexpected missing secret names: {ready.missing}")

    missing_name = module.REQUIRED_RELEASE_SECRETS[0]
    configured.remove(missing_name)
    not_ready = module.audit_secret_names("owner/repo", configured)
    if not not_ready.missing == (missing_name,):
        raise AssertionError(f"expected only {missing_name} missing, got {not_ready.missing}")


def secret_update_times(module, updated_at: str = "2026-06-05T00:00:01Z") -> dict[str, str]:
    return {name: updated_at for name in module.REQUIRED_RELEASE_SECRETS}


def run_rotation_marker_tests(module) -> None:
    configured = set(module.REQUIRED_RELEASE_SECRETS)
    ready = module.audit_release_secret_readiness(
        "owner/repo",
        configured,
        {module.NPM_TOKEN_ROTATION_MARKER_VAR: "2026-06-05T00:00:01Z"},
        secret_update_times(module),
    )
    if not ready.ready:
        raise AssertionError(f"expected ready marker report: {ready.as_json()!r}")
    parsed_ready = assert_safe_report(ready)
    if parsed_ready["npmTokenSecretUpdatedAt"]["updatedAt"] != "2026-06-05T00:00:01Z":
        raise AssertionError("valid NPM_TOKEN updatedAt timestamp was not reported")
    if parsed_ready["npmTokenRotationMarker"]["rotatedAfter"] != "2026-06-05T00:00:01Z":
        raise AssertionError("valid marker timestamp was not included in normalized form")

    missing = module.audit_release_secret_readiness(
        "owner/repo",
        configured,
        {},
        secret_update_times(module),
    )
    if missing.ready:
        raise AssertionError("missing npm rotation marker should fail readiness")
    parsed_missing = assert_safe_report(missing)
    if module.NPM_TOKEN_ROTATION_MARKER_VAR not in json.dumps(parsed_missing):
        raise AssertionError("missing marker report omitted marker variable name")

    stale = module.audit_release_secret_readiness(
        "owner/repo",
        configured,
        {module.NPM_TOKEN_ROTATION_MARKER_VAR: "2026-06-05T00:00:00Z"},
        secret_update_times(module),
    )
    if stale.ready:
        raise AssertionError("stale npm rotation marker should fail readiness")
    parsed_stale = assert_safe_report(stale)
    if "not after required timestamp" not in json.dumps(parsed_stale):
        raise AssertionError("stale marker issue was not reported")

    invalid = module.audit_release_secret_readiness(
        "owner/repo",
        configured,
        {module.NPM_TOKEN_ROTATION_MARKER_VAR: SENSITIVE_SENTINEL},
        secret_update_times(module),
    )
    if invalid.ready:
        raise AssertionError("invalid npm rotation marker should fail readiness")
    parsed_invalid = assert_safe_report(invalid)
    if parsed_invalid["npmTokenRotationMarker"]["rotatedAfter"] != "":
        raise AssertionError("invalid marker value should not be echoed")
    if "timestamp is invalid" not in json.dumps(parsed_invalid):
        raise AssertionError("invalid marker issue was not reported")

    stale_secret = module.audit_release_secret_readiness(
        "owner/repo",
        configured,
        {module.NPM_TOKEN_ROTATION_MARKER_VAR: "2026-06-05T00:00:01Z"},
        secret_update_times(module, "2026-06-05T00:00:00Z"),
    )
    if stale_secret.ready:
        raise AssertionError("stale NPM_TOKEN updatedAt should fail readiness")
    parsed_stale_secret = assert_safe_report(stale_secret)
    if "NPM_TOKEN was not updated after required timestamp" not in json.dumps(parsed_stale_secret):
        raise AssertionError("stale NPM_TOKEN updatedAt issue was not reported")

    missing_secret_metadata = module.audit_release_secret_readiness(
        "owner/repo",
        configured,
        {module.NPM_TOKEN_ROTATION_MARKER_VAR: "2026-06-05T00:00:01Z"},
        {},
    )
    if missing_secret_metadata.ready:
        raise AssertionError("missing NPM_TOKEN updatedAt should fail readiness")
    parsed_missing_secret = assert_safe_report(missing_secret_metadata)
    if "NPM_TOKEN update timestamp is missing" not in json.dumps(parsed_missing_secret):
        raise AssertionError("missing NPM_TOKEN updatedAt issue was not reported")

    invalid_secret_metadata = module.audit_release_secret_readiness(
        "owner/repo",
        configured,
        {module.NPM_TOKEN_ROTATION_MARKER_VAR: "2026-06-05T00:00:01Z"},
        {module.NPM_TOKEN_SECRET_NAME: SENSITIVE_SENTINEL},
    )
    if invalid_secret_metadata.ready:
        raise AssertionError("invalid NPM_TOKEN updatedAt should fail readiness")
    parsed_invalid_secret = assert_safe_report(invalid_secret_metadata)
    if parsed_invalid_secret["npmTokenSecretUpdatedAt"]["updatedAt"] != "":
        raise AssertionError("invalid NPM_TOKEN updatedAt should not be echoed")
    if "NPM_TOKEN update timestamp is invalid" not in json.dumps(parsed_invalid_secret):
        raise AssertionError("invalid NPM_TOKEN updatedAt issue was not reported")


def run_simple_launch_tests(module) -> None:
    configured = {module.NPM_TOKEN_SECRET_NAME}
    ready = module.audit_release_secret_readiness(
        "owner/repo",
        configured,
        {module.NPM_TOKEN_ROTATION_MARKER_VAR: "2026-06-05T00:00:01Z"},
        {module.NPM_TOKEN_SECRET_NAME: "2026-06-05T00:00:01Z"},
        simple_launch=True,
    )
    if not ready.ready:
        raise AssertionError(f"simple launch readiness should pass: {ready.as_json()!r}")
    parsed_ready = assert_safe_report(ready)
    if parsed_ready["profile"] != module.SIMPLE_LAUNCH_PROFILE:
        raise AssertionError("simple launch report omitted its profile")
    if parsed_ready["releaseSecrets"]["required"] != [module.NPM_TOKEN_SECRET_NAME]:
        raise AssertionError("simple launch mode should require only NPM_TOKEN")
    if any(
        "SIGN" in name or "MACOS" in name or "GPG" in name
        for name in parsed_ready["releaseSecrets"]["required"]
    ):
        raise AssertionError("simple launch mode must not require signing secrets")

    full_release = module.audit_release_secret_readiness(
        "owner/repo",
        configured,
        {module.NPM_TOKEN_ROTATION_MARKER_VAR: "2026-06-05T00:00:01Z"},
        {module.NPM_TOKEN_SECRET_NAME: "2026-06-05T00:00:01Z"},
    )
    if full_release.ready:
        raise AssertionError("full release readiness should still require signing secrets")
    parsed_full = assert_safe_report(full_release)
    if parsed_full["profile"] != module.FULL_RELEASE_PROFILE:
        raise AssertionError("full release report omitted its profile")
    if "CONU_WINDOWS_SIGN_CERT_PFX_BASE64" not in parsed_full["releaseSecrets"]["missing"]:
        raise AssertionError("full release mode no longer reports missing signing secrets")

    missing_token = module.audit_release_secret_readiness(
        "owner/repo",
        set(),
        {module.NPM_TOKEN_ROTATION_MARKER_VAR: "2026-06-05T00:00:01Z"},
        {},
        simple_launch=True,
    )
    if missing_token.ready:
        raise AssertionError("simple launch should fail without NPM_TOKEN")
    parsed_missing = assert_safe_report(missing_token)
    if parsed_missing["releaseSecrets"]["missing"] != [module.NPM_TOKEN_SECRET_NAME]:
        raise AssertionError("simple launch missing report should only mention NPM_TOKEN")


def run_repo_normalization_tests(module) -> None:
    helper = sys.modules["github_release_secrets"]

    for repo in ("owner/repo", "owner-name/repo.name", "owner/repo_name"):
        if helper.normalize_repo(repo) != repo:
            raise AssertionError(f"valid repository did not normalize cleanly: {repo}")

    for repo, expected in (
        ("owner/repo/branches/main", "owner/name form"),
        ("../repo", "owner contains unsupported characters"),
        ("owner/..", "repository name is invalid"),
        ("owner repo/name", "owner contains unsupported characters"),
        ("owner/repo?secret=value", "name contains unsupported characters"),
        ("https://github.com/owner/repo", "owner/name form"),
        ("owner/re%70o", "name contains unsupported characters"),
    ):
        assert_raises(lambda repo=repo: helper.normalize_repo(repo), expected)
        assert_raises(lambda repo=repo: module.audit_secret_names(repo, set()), expected)

    original = os.environ.get("GH_REPO")
    os.environ["GH_REPO"] = "owner/repo/extra"
    try:
        assert_raises(lambda: helper.infer_repo("gh"), "owner/name form")
    finally:
        if original is None:
            os.environ.pop("GH_REPO", None)
        else:
            os.environ["GH_REPO"] = original


def run_gh_payload_tests(module) -> None:
    helper = sys.modules["github_release_secrets"]

    def fake_gh_list(args, **_kwargs):
        if args[1:4] == ["secret", "list", "--repo"]:
            payload = [
                {
                    "name": name,
                    "updatedAt": "2026-06-05T00:00:01Z",
                    "value": SENSITIVE_SENTINEL,
                }
                for name in module.REQUIRED_RELEASE_SECRETS
            ]
            return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")
        if args[1:] == [
            "variable",
            "list",
            "--repo",
            "owner/repo",
            "--json",
            "name",
        ]:
            payload = [
                {"name": module.NPM_TOKEN_ROTATION_MARKER_VAR},
                {"name": "UNRELATED_VARIABLE"},
            ]
            return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")
        if args[1:] == [
            "variable",
            "get",
            module.NPM_TOKEN_ROTATION_MARKER_VAR,
            "--repo",
            "owner/repo",
            "--json",
            "name,value",
        ]:
            payload = {
                "name": module.NPM_TOKEN_ROTATION_MARKER_VAR,
                "value": "2026-06-05T00:00:01Z",
            }
            return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")
        if args[1:3] == ["variable", "get"]:
            raise AssertionError(f"unexpected variable value request: {args!r}")
        raise AssertionError(f"unexpected gh args: {args!r}")

    original_run = subprocess.run
    helper.subprocess.run = fake_gh_list
    try:
        names = module.load_secret_names("owner/repo", "gh")
        metadata = helper.load_secret_metadata("owner/repo", "gh")
        variables = module.load_variable_values(
            "owner/repo",
            "gh",
            module.REQUIRED_VARIABLE_VALUES,
        )
    finally:
        helper.subprocess.run = original_run

    if names != set(module.REQUIRED_RELEASE_SECRETS):
        raise AssertionError("loaded secret names did not match required names")
    if set(metadata) != names:
        raise AssertionError("loaded secret metadata did not match required names")
    for record in metadata.values():
        if record.updated_at != "2026-06-05T00:00:01Z":
            raise AssertionError("unexpected updatedAt value in fake metadata payload")
    if variables[module.NPM_TOKEN_ROTATION_MARKER_VAR] != "2026-06-05T00:00:01Z":
        raise AssertionError("loaded variable values did not include the rotation marker")
    if "UNRELATED_VARIABLE" in variables:
        raise AssertionError("loaded variable values included an unrelated variable")
    report = module.audit_release_secret_readiness(
        "owner/repo",
        names,
        variables,
        {name: record.updated_at for name, record in metadata.items()},
    )
    assert_safe_report(report)


def run_error_tests(module) -> None:
    helper = sys.modules["github_release_secrets"]

    def invalid_json(*_args, **_kwargs):
        return SimpleNamespace(returncode=0, stdout="{not-json", stderr="")

    original_run = subprocess.run
    helper.subprocess.run = invalid_json
    try:
        assert_raises(
            lambda: module.load_secret_names("owner/repo", "gh"),
            "invalid JSON",
        )
        assert_raises(
            lambda: module.load_variable_values(
                "owner/repo",
                "gh",
                module.REQUIRED_VARIABLE_VALUES,
            ),
            "invalid JSON",
        )
    finally:
        helper.subprocess.run = original_run

    def duplicate_json(*_args, **_kwargs):
        payload = (
            '[{"name":"'
            + module.REQUIRED_RELEASE_SECRETS[0]
            + '","name":"'
            + SENSITIVE_SENTINEL
            + '"}]'
        )
        return SimpleNamespace(returncode=0, stdout=payload, stderr="")

    helper.subprocess.run = duplicate_json
    try:
        assert_raises(
            lambda: module.load_secret_names("owner/repo", "gh"),
            "duplicate JSON key",
        )
    finally:
        helper.subprocess.run = original_run

    def failed_command(*_args, **_kwargs):
        return SimpleNamespace(returncode=1, stdout="", stderr=SENSITIVE_SENTINEL)

    helper.subprocess.run = failed_command
    try:
        assert_raises(
            lambda: module.load_secret_names("owner/repo", "gh"),
            "gh secret list failed",
        )
        assert_raises(
            lambda: module.load_variable_values(
                "owner/repo",
                "gh",
                module.REQUIRED_VARIABLE_VALUES,
            ),
            "gh variable list failed",
        )
    finally:
        helper.subprocess.run = original_run


def run_main_tests(module) -> None:
    helper = sys.modules["github_release_secrets"]

    def fake_gh_list(args, **_kwargs):
        if args[1:4] == ["secret", "list", "--repo"]:
            payload = [
                {"name": name, "updatedAt": "2026-06-05T00:00:01Z"}
                for name in module.REQUIRED_RELEASE_SECRETS
            ]
            return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")
        if args[1:] == [
            "variable",
            "list",
            "--repo",
            "owner/repo",
            "--json",
            "name",
        ]:
            payload = [
                {"name": module.NPM_TOKEN_ROTATION_MARKER_VAR},
                {"name": "UNRELATED_VARIABLE"},
            ]
            return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")
        if args[1:] == [
            "variable",
            "get",
            module.NPM_TOKEN_ROTATION_MARKER_VAR,
            "--repo",
            "owner/repo",
            "--json",
            "name,value",
        ]:
            payload = {
                "name": module.NPM_TOKEN_ROTATION_MARKER_VAR,
                "value": "2026-06-05T00:00:01Z",
            }
            return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")
        if args[1:3] == ["variable", "get"]:
            raise AssertionError(f"unexpected variable value request: {args!r}")
        raise AssertionError(f"unexpected gh args: {args!r}")

    original_run = subprocess.run
    original_argv = sys.argv
    stdout = io.StringIO()
    stderr = io.StringIO()
    helper.subprocess.run = fake_gh_list
    sys.argv = [
        "check-github-release-secret-readiness.py",
        "--repo",
        "owner/repo",
        "--gh",
        "gh",
    ]
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = module.main()
    finally:
        helper.subprocess.run = original_run
        sys.argv = original_argv

    if exit_code != 0:
        raise AssertionError(f"expected main() to pass, got {exit_code}: {stderr.getvalue()}")
    rendered = stdout.getvalue() + stderr.getvalue()
    if module.NPM_TOKEN_ROTATION_MARKER_VAR not in rendered:
        raise AssertionError("main() output omitted the rotation marker variable")
    if SENSITIVE_SENTINEL in rendered:
        raise AssertionError("main() output leaked a secret or variable value")

    sys.argv = [
        "check-github-release-secret-readiness.py",
        "--repo",
        "owner/repo/branches/main",
        "--gh",
        "gh",
    ]
    stdout = io.StringIO()
    stderr = io.StringIO()
    helper.subprocess.run = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        AssertionError("gh should not run for invalid repository names")
    )
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = module.main()
    finally:
        helper.subprocess.run = original_run
        sys.argv = original_argv

    rendered = stdout.getvalue() + stderr.getvalue()
    if exit_code == 0:
        raise AssertionError("invalid repository name should fail main()")
    if "owner/name form" not in rendered:
        raise AssertionError(f"invalid repository failure was not reported: {rendered!r}")
    if SENSITIVE_SENTINEL in rendered:
        raise AssertionError("invalid repository failure leaked a secret value")

    def fake_simple_launch_gh(args, **_kwargs):
        if args[1:4] == ["secret", "list", "--repo"]:
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    [
                        {
                            "name": module.NPM_TOKEN_SECRET_NAME,
                            "updatedAt": "2026-06-05T00:00:01Z",
                        }
                    ]
                ),
                stderr="",
            )
        if args[1:] == [
            "variable",
            "list",
            "--repo",
            "owner/repo",
            "--json",
            "name",
        ]:
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps([{"name": module.NPM_TOKEN_ROTATION_MARKER_VAR}]),
                stderr="",
            )
        if args[1:] == [
            "variable",
            "get",
            module.NPM_TOKEN_ROTATION_MARKER_VAR,
            "--repo",
            "owner/repo",
            "--json",
            "name,value",
        ]:
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    {
                        "name": module.NPM_TOKEN_ROTATION_MARKER_VAR,
                        "value": "2026-06-05T00:00:01Z",
                    }
                ),
                stderr="",
            )
        raise AssertionError(f"unexpected gh args: {args!r}")

    sys.argv = [
        "check-github-release-secret-readiness.py",
        "--repo",
        "owner/repo",
        "--gh",
        "gh",
        "--simple-launch",
        "--json",
    ]
    stdout = io.StringIO()
    stderr = io.StringIO()
    helper.subprocess.run = fake_simple_launch_gh
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = module.main()
    finally:
        helper.subprocess.run = original_run
        sys.argv = original_argv

    rendered = stdout.getvalue() + stderr.getvalue()
    if exit_code != 0:
        raise AssertionError(
            f"expected simple-launch main() to pass, got {exit_code}: {rendered}"
        )
    parsed = json.loads(stdout.getvalue())
    if parsed["profile"] != module.SIMPLE_LAUNCH_PROFILE:
        raise AssertionError("simple-launch main() JSON omitted the profile")
    if parsed["releaseSecrets"]["required"] != [module.NPM_TOKEN_SECRET_NAME]:
        raise AssertionError("simple-launch main() should not require signing secrets")
    if SENSITIVE_SENTINEL in rendered:
        raise AssertionError("simple-launch main() leaked a secret or variable value")


def main() -> int:
    module = load_module()
    run_audit_tests(module)
    run_rotation_marker_tests(module)
    run_simple_launch_tests(module)
    run_repo_normalization_tests(module)
    run_gh_payload_tests(module)
    run_error_tests(module)
    run_main_tests(module)
    print("GitHub release secret readiness regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
