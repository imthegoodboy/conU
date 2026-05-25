#!/usr/bin/env python3
"""Regression checks for GitHub release-secret setup behavior."""

from __future__ import annotations

import importlib.util
import io
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace


SCRIPT = Path(__file__).with_name("set-github-release-secrets.py")
SENSITIVE_SENTINEL = "do-not-print-or-argv-this-secret-value"


def load_module():
    spec = importlib.util.spec_from_file_location("set_github_release_secrets", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load GitHub release secret setup module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def assert_raises(func, pattern: str) -> None:
    try:
        func()
    except ValueError as exc:
        if pattern not in str(exc):
            raise AssertionError(f"expected {pattern!r} in {exc!r}") from exc
        return
    raise AssertionError(f"expected ValueError containing {pattern!r}")


def with_required_env(module, value: str):
    original = {name: os.environ.get(name) for name in module.REQUIRED_RELEASE_SECRETS}
    for name in module.REQUIRED_RELEASE_SECRETS:
        os.environ[name] = value
    return original


def restore_env(original: dict[str, str | None]) -> None:
    for name, value in original.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


def run_env_collection_tests(module) -> None:
    original = {name: os.environ.get(name) for name in module.REQUIRED_RELEASE_SECRETS}
    try:
        for name in module.REQUIRED_RELEASE_SECRETS:
            os.environ.pop(name, None)
        values, missing = module.collect_env_values(module.REQUIRED_RELEASE_SECRETS)
        if values:
            raise AssertionError("missing environment should not produce secret values")
        if missing != module.REQUIRED_RELEASE_SECRETS:
            raise AssertionError("all required secrets should be reported missing")

        os.environ[module.REQUIRED_RELEASE_SECRETS[0]] = SENSITIVE_SENTINEL
        values, missing = module.collect_env_values(module.REQUIRED_RELEASE_SECRETS)
        if values[module.REQUIRED_RELEASE_SECRETS[0]] != SENSITIVE_SENTINEL:
            raise AssertionError("expected configured environment value to be loaded")
        if SENSITIVE_SENTINEL in "\n".join(missing):
            raise AssertionError("missing-name report leaked a secret value")
    finally:
        restore_env(original)


def run_secret_set_tests(module) -> None:
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    original_run = subprocess.run
    module.subprocess.run = fake_run
    try:
        module.set_secret("gh", "owner/repo", "NPM_TOKEN", SENSITIVE_SENTINEL)
    finally:
        module.subprocess.run = original_run

    if len(calls) != 1:
        raise AssertionError(f"expected one gh secret set call, got {len(calls)}")
    args, kwargs = calls[0]
    rendered_args = " ".join(args)
    if SENSITIVE_SENTINEL in rendered_args:
        raise AssertionError("secret value was passed in command arguments")
    if kwargs.get("input") != SENSITIVE_SENTINEL:
        raise AssertionError("secret value was not passed through stdin")

    def failed_run(*_args, **_kwargs):
        return SimpleNamespace(returncode=1, stdout="", stderr=SENSITIVE_SENTINEL)

    module.subprocess.run = failed_run
    try:
        assert_raises(
            lambda: module.set_secret("gh", "owner/repo", "NPM_TOKEN", SENSITIVE_SENTINEL),
            "failed with exit code 1",
        )
    finally:
        module.subprocess.run = original_run


def run_value_preflight_tests(module) -> None:
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    original_run = subprocess.run
    module.subprocess.run = fake_run
    try:
        module.run_value_preflights(require_openssl=True, python_executable="python")
    finally:
        module.subprocess.run = original_run

    if len(calls) != 2:
        raise AssertionError(f"expected two value preflight calls, got {len(calls)}")
    rendered = "\n".join(" ".join(args) for args, _kwargs in calls)
    if "check-platform-signing-secrets-preflight.py" not in rendered:
        raise AssertionError("platform signing secret value preflight was not called")
    if "--require-openssl" not in rendered:
        raise AssertionError("OpenSSL requirement was not passed to platform preflight")
    if "check-linux-signing-secrets-preflight.py" not in rendered:
        raise AssertionError("Linux signing secret preflight was not called")
    if SENSITIVE_SENTINEL in rendered:
        raise AssertionError("secret value was passed in value preflight arguments")
    for _args, kwargs in calls:
        if kwargs.get("stdout") != subprocess.DEVNULL:
            raise AssertionError("value preflight stdout must be suppressed")
        if kwargs.get("stderr") != subprocess.DEVNULL:
            raise AssertionError("value preflight stderr must be suppressed")

    def failed_run(_args, **_kwargs):
        return SimpleNamespace(returncode=7, stdout=SENSITIVE_SENTINEL, stderr=SENSITIVE_SENTINEL)

    module.subprocess.run = failed_run
    try:
        try:
            module.run_value_preflights(require_openssl=False, python_executable="python")
        except ValueError as exc:
            rendered_error = str(exc)
            if "failed with exit code 7" not in rendered_error:
                raise AssertionError(f"unexpected preflight failure error: {rendered_error}")
            if SENSITIVE_SENTINEL in rendered_error:
                raise AssertionError("preflight failure leaked subprocess output")
        else:
            raise AssertionError("failing value preflight unexpectedly succeeded")
    finally:
        module.subprocess.run = original_run


def run_dry_run_tests(module) -> None:
    original = with_required_env(module, SENSITIVE_SENTINEL)
    try:
        values, missing = module.collect_env_values(module.REQUIRED_RELEASE_SECRETS)
        if missing:
            raise AssertionError("all required environment values should be present")

        partial = dict(values)
        missing_name = module.REQUIRED_RELEASE_SECRETS[0]
        partial.pop(missing_name)
        assert_raises(
            lambda: module.configure_release_secrets("owner/repo", "gh", partial, dry_run=True),
            missing_name,
        )

        calls = []

        def fake_run(args, **kwargs):
            calls.append((args, kwargs))
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        original_run = subprocess.run
        module.subprocess.run = fake_run
        try:
            configured = module.configure_release_secrets("owner/repo", "gh", values, dry_run=True)
        finally:
            module.subprocess.run = original_run

        if configured != module.REQUIRED_RELEASE_SECRETS:
            raise AssertionError("dry run should report every required secret name")
        if calls:
            raise AssertionError("dry run must not call gh secret set")
    finally:
        restore_env(original)


def run_missing_report_tests(module) -> None:
    buffer = io.StringIO()
    module.print_secret_names("missing:", ("NPM_TOKEN",), buffer)
    rendered = buffer.getvalue()
    if "NPM_TOKEN" not in rendered:
        raise AssertionError("secret name should be reported")
    if SENSITIVE_SENTINEL in rendered:
        raise AssertionError("secret report leaked a secret value")


def main() -> int:
    module = load_module()
    run_env_collection_tests(module)
    run_secret_set_tests(module)
    run_value_preflight_tests(module)
    run_dry_run_tests(module)
    run_missing_report_tests(module)
    print("GitHub release secret setup regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
