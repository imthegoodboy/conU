#!/usr/bin/env python3
"""Regression checks for npm publish preflight behavior."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError


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


def run_manifest_version_tests(module) -> None:
    with tempfile.TemporaryDirectory(prefix="conu-npm-publish-preflight-") as temp_text:
        repo = Path(temp_text)
        package_dir = repo / "packaging" / "npm" / "conu-cli"
        package_dir.mkdir(parents=True)
        manifest = {
            "name": "@conu/cli",
            "version": "0.1.0\n",
        }
        (package_dir / "package.json").write_text(
            json.dumps(manifest),
            encoding="utf-8",
            newline="\n",
        )
        assert_raises(
            lambda: module.validate_manifest(
                repo,
                module.PackageRule("@conu/cli", Path("packaging/npm/conu-cli")),
            ),
            "version is not semver-like",
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


class FakeResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def read(self, _size: int) -> bytes:
        return self.body


def run_token_auth_tests(module) -> None:
    env_name = "CONU_TEST_NPM_TOKEN"
    original = os.environ.pop(env_name, None)
    original_urlopen = module.urlopen
    token = "token-value"
    try:
        assert_raises(
            lambda: module.validate_token_authentication(None),
            "requires --require-token-env",
        )

        os.environ[env_name] = token

        def successful_urlopen(request, timeout):
            if timeout != 15:
                raise AssertionError("unexpected token auth timeout")
            if request.get_header("Authorization") != f"Bearer {token}":
                raise AssertionError("token auth request did not use bearer authorization")
            return FakeResponse(200, b'{"username":"imthegoodboy"}')

        module.urlopen = successful_urlopen
        module.validate_token_authentication(env_name)

        def unauthorized_urlopen(*_args, **_kwargs):
            raise HTTPError(module.NPM_WHOAMI_URL, 401, "Unauthorized", {}, None)

        module.urlopen = unauthorized_urlopen
        try:
            module.validate_token_authentication(env_name)
        except ValueError as exc:
            rendered = str(exc)
            if "authentication failed" not in rendered:
                raise AssertionError(f"unexpected token auth error: {rendered}") from exc
            if token in rendered:
                raise AssertionError("token auth error leaked the token value") from exc
        else:
            raise AssertionError("invalid npm token unexpectedly passed authentication")

        def malformed_json_urlopen(*_args, **_kwargs):
            return FakeResponse(200, b'{"ok": true}')

        module.urlopen = malformed_json_urlopen
        assert_raises(
            lambda: module.validate_token_authentication(env_name),
            "did not return an npm username",
        )

        def oversized_urlopen(*_args, **_kwargs):
            return FakeResponse(200, b"x" * (module.MAX_WHOAMI_RESPONSE_BYTES + 1))

        module.urlopen = oversized_urlopen
        assert_raises(
            lambda: module.validate_token_authentication(env_name),
            "response was too large",
        )
    finally:
        module.urlopen = original_urlopen
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
        run_manifest_version_tests(module)
        run_token_tests(module)
        run_token_auth_tests(module)
    finally:
        module.subprocess.run = original_run
    print("npm publish preflight regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
