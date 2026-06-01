#!/usr/bin/env python3
"""Regression checks for npm publish preflight behavior."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace


SCRIPT = Path(__file__).with_name("check-npm-publish-preflight.py")


def load_module():
    spec = importlib.util.spec_from_file_location("check_npm_publish_preflight", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load npm publish preflight module")
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


def run_registry_tests(module) -> None:
    repo = Path(__file__).resolve().parents[1]
    packages = tuple(module.validate_manifest(repo, rule) for rule in module.PACKAGES)

    def missing_run(*_args, **_kwargs):
        return SimpleNamespace(returncode=1, stdout="", stderr="npm ERR! code E404\n")

    module.subprocess.run = missing_run
    module.check_registry_availability("npm", packages)

    def existing_run(args, **_kwargs):
        package_id = args[2]
        version = package_id.rsplit("@", 1)[1]
        return SimpleNamespace(returncode=0, stdout=f'"{version}"\n', stderr="")

    module.subprocess.run = existing_run
    assert_raises(
        lambda: module.check_registry_availability("npm", packages),
        "already exists",
    )

    def network_error_run(*_args, **_kwargs):
        return SimpleNamespace(returncode=1, stdout="", stderr="npm ERR! ECONNRESET\n")

    module.subprocess.run = network_error_run
    assert_raises(
        lambda: module.check_registry_availability("npm", packages),
        "availability check failed",
    )


def run_version_consistency_tests(module) -> None:
    packages = (
        module.PackageInfo("@conu/cli", "0.1.0", Path("packaging/npm/conu-cli")),
        module.PackageInfo("@conu/sdk", "0.1.0", Path("sdk/typescript")),
    )
    module.validate_package_version_consistency(packages)

    mismatched = (
        module.PackageInfo("@conu/cli", "0.1.0", Path("packaging/npm/conu-cli")),
        module.PackageInfo("@conu/sdk", "0.2.0", Path("sdk/typescript")),
    )
    assert_raises(
        lambda: module.validate_package_version_consistency(mismatched),
        "versions must match",
    )


def run_token_tests(module) -> None:
    env_name = "CONU_TEST_NPM_TOKEN"
    original = os.environ.pop(env_name, None)
    malformed_token = "token-value-with-hidden-whitespace"
    try:
        assert_raises(
            lambda: module.validate_required_token(env_name),
            "is required",
        )
        for value in (
            " token-value",
            "token-value ",
            f"{malformed_token}\ncontinued",
            f"{malformed_token}\tcontinued",
        ):
            os.environ[env_name] = value
            try:
                module.validate_required_token(env_name)
            except ValueError as exc:
                rendered = str(exc)
                if "single-line token value" not in rendered:
                    raise AssertionError(f"unexpected token validation error: {rendered}") from exc
                if malformed_token in rendered or value in rendered:
                    raise AssertionError("token validation error leaked the token value") from exc
            else:
                raise AssertionError("malformed token value unexpectedly passed validation")
        os.environ[env_name] = "token-value"
        module.validate_required_token(env_name)
    finally:
        if original is None:
            os.environ.pop(env_name, None)
        else:
            os.environ[env_name] = original


def main() -> int:
    module = load_module()
    original_run = subprocess.run
    try:
        run_registry_tests(module)
        run_version_consistency_tests(module)
        run_token_tests(module)
    finally:
        module.subprocess.run = original_run
    print("npm publish preflight regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
