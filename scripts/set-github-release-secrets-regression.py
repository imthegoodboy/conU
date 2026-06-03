#!/usr/bin/env python3
"""Regression checks for GitHub release-secret setup behavior."""

from __future__ import annotations

import importlib.util
import io
import contextlib
import os
import subprocess
import sys
import tempfile
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
        if SENSITIVE_SENTINEL in str(exc):
            raise AssertionError("error message leaked a secret value") from exc
        if pattern not in str(exc):
            raise AssertionError(f"expected {pattern!r} in {exc!r}") from exc
        return
    raise AssertionError(f"expected ValueError containing {pattern!r}")


def try_symlink(link: Path, target: Path) -> bool:
    try:
        link.symlink_to(target)
        return True
    except (NotImplementedError, OSError):
        return False


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


def secure_write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    if os.name == "posix":
        path.chmod(0o600)


def call_main(module, argv: list[str]) -> tuple[int, str]:
    original_argv = sys.argv
    stdout = io.StringIO()
    stderr = io.StringIO()
    sys.argv = argv
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = module.main()
    finally:
        sys.argv = original_argv
    return exit_code, stdout.getvalue() + stderr.getvalue()


def write_required_env_file(path: Path, module, value: str) -> None:
    lines = ["# local release secrets for regression"]
    for index, name in enumerate(module.REQUIRED_RELEASE_SECRETS):
        prefix = "export " if index == 0 else ""
        lines.append(f"{prefix}{name}={value}")
    secure_write_text(path, "\n".join(lines) + "\n")


def run_env_template_tests(module) -> None:
    template = module.render_env_template(module.REQUIRED_RELEASE_SECRETS)
    if SENSITIVE_SENTINEL in template:
        raise AssertionError("env template leaked a secret value")
    if "--check-env-file" not in template:
        raise AssertionError("env template omitted local validation command")
    for name in module.REQUIRED_RELEASE_SECRETS:
        if f"{name}=" not in template:
            raise AssertionError(f"env template omitted {name}")
    if "UNRELATED_SECRET" in template:
        raise AssertionError("env template included an unsupported secret name")

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        env_file = temp_path / ".env.release"
        module.write_env_template(env_file, module.REQUIRED_RELEASE_SECRETS)
        written = env_file.read_text(encoding="utf-8")
        if written != template:
            raise AssertionError("written env template drifted from rendered template")
        values = module.load_env_file_values(env_file, module.REQUIRED_RELEASE_SECRETS)
        if set(values) != set(module.REQUIRED_RELEASE_SECRETS):
            raise AssertionError("empty env template should still contain every required key")
        if any(values.values()):
            raise AssertionError("empty env template should not contain configured values")
        if module.missing_required_values(values, module.REQUIRED_RELEASE_SECRETS) != module.REQUIRED_RELEASE_SECRETS:
            raise AssertionError("empty env template should fail the missing-value gate")
        assert_raises(
            lambda: module.write_env_template(env_file, module.REQUIRED_RELEASE_SECRETS),
            "already exists",
        )
        assert_raises(
            lambda: module.write_env_template(
                temp_path / "missing-parent" / ".env.release",
                module.REQUIRED_RELEASE_SECRETS,
            ),
            "parent directory does not exist",
        )


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


def run_env_file_tests(module) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        env_file = temp_path / ".env.release"
        write_required_env_file(env_file, module, SENSITIVE_SENTINEL)
        values = module.load_env_file_values(env_file, module.REQUIRED_RELEASE_SECRETS)
        if set(values) != set(module.REQUIRED_RELEASE_SECRETS):
            raise AssertionError("env file did not load every required secret name")
        if set(values.values()) != {SENSITIVE_SENTINEL}:
            raise AssertionError("env file did not preserve configured values")

        whitespace_env_file = temp_path / "whitespace.env"
        whitespace_secret = f"  {SENSITIVE_SENTINEL}  "
        secure_write_text(whitespace_env_file, f"NPM_TOKEN={whitespace_secret}\n")
        whitespace_values = module.load_env_file_values(
            whitespace_env_file,
            module.REQUIRED_RELEASE_SECRETS,
        )
        if whitespace_values["NPM_TOKEN"] != whitespace_secret:
            raise AssertionError("env file parser trimmed secret value whitespace")
        if module.missing_required_values(
            whitespace_values,
            ("NPM_TOKEN",),
        ):
            raise AssertionError("env file parser treated padded secret value as missing")
        if module.missing_required_values({"NPM_TOKEN": "   "}, ("NPM_TOKEN",)) != ("NPM_TOKEN",):
            raise AssertionError("whitespace-only env file secret value should be missing")

        directory_env_file = temp_path / "directory.env"
        directory_env_file.mkdir()
        assert_raises(
            lambda: module.load_env_file_values(
                directory_env_file,
                module.REQUIRED_RELEASE_SECRETS,
            ),
            "regular file",
        )

        oversized = temp_path / "oversized.env"
        secure_write_text(
            oversized,
            "NPM_TOKEN=" + ("x" * module.MAX_ENV_FILE_BYTES) + "\n",
        )
        assert_raises(
            lambda: module.load_env_file_values(oversized, module.REQUIRED_RELEASE_SECRETS),
            "too large",
        )

        if os.name == "posix":
            permissive = temp_path / "permissive.env"
            secure_write_text(permissive, "NPM_TOKEN=value\n")
            permissive.chmod(0o644)
            assert_raises(
                lambda: module.load_env_file_values(
                    permissive,
                    module.REQUIRED_RELEASE_SECRETS,
                ),
                "permissions",
            )

        symlink_target = temp_path / "real.env"
        symlink_link = temp_path / "linked.env"
        write_required_env_file(symlink_target, module, SENSITIVE_SENTINEL)
        if try_symlink(symlink_link, symlink_target):
            assert_raises(
                lambda: module.load_env_file_values(
                    symlink_link,
                    module.REQUIRED_RELEASE_SECRETS,
                ),
                "must not be a symlink",
            )

        malformed = temp_path / "malformed.env"
        secure_write_text(malformed, f"{SENSITIVE_SENTINEL}\n")
        assert_raises(
            lambda: module.load_env_file_values(malformed, module.REQUIRED_RELEASE_SECRETS),
            "line 1",
        )

        unsupported = temp_path / "unsupported.env"
        secure_write_text(unsupported, "UNRELATED_SECRET=value\n")
        assert_raises(
            lambda: module.load_env_file_values(unsupported, module.REQUIRED_RELEASE_SECRETS),
            "unsupported key",
        )

        duplicate = temp_path / "duplicate.env"
        secure_write_text(duplicate, "NPM_TOKEN=one\nNPM_TOKEN=two\n")
        assert_raises(
            lambda: module.load_env_file_values(duplicate, module.REQUIRED_RELEASE_SECRETS),
            "duplicates key",
        )


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


def run_rotation_marker_setup_tests(module) -> None:
    normalized = module.normalize_npm_rotation_marker_timestamp(
        "2026-06-03T05:30:01+05:30"
    )
    if normalized != "2026-06-03T00:00:01Z":
        raise AssertionError("rotation marker timestamp was not normalized to UTC")

    assert_raises(
        lambda: module.normalize_npm_rotation_marker_timestamp("2026-06-03T00:00:00Z"),
        "timestamp must be after",
    )
    assert_raises(
        lambda: module.normalize_npm_rotation_marker_timestamp(SENSITIVE_SENTINEL),
        "ISO-8601",
    )
    assert_raises(
        lambda: module.configure_npm_rotation_marker(
            "owner/repo",
            "gh",
            "2026-06-03T00:00:01Z",
            confirm_rotated=False,
            dry_run=True,
        ),
        "--confirm-npm-token-rotated",
    )

    original_loader = module.load_secret_metadata
    try:
        module.load_secret_metadata = lambda _repo, _gh: {
            module.NPM_TOKEN_SECRET_NAME: SimpleNamespace(
                updated_at="2026-06-03T00:00:04+00:00"
            )
        }
        metadata_timestamp = module.load_npm_rotation_marker_timestamp_from_secret_metadata(
            "owner/repo",
            "gh",
        )
        if metadata_timestamp != "2026-06-03T00:00:04Z":
            raise AssertionError("metadata-derived marker timestamp was not normalized")

        module.load_secret_metadata = lambda _repo, _gh: {}
        assert_raises(
            lambda: module.load_npm_rotation_marker_timestamp_from_secret_metadata(
                "owner/repo",
                "gh",
            ),
            "secret metadata is missing",
        )

        module.load_secret_metadata = lambda _repo, _gh: {
            module.NPM_TOKEN_SECRET_NAME: SimpleNamespace(
                updated_at="2026-06-03T00:00:00Z"
            )
        }
        assert_raises(
            lambda: module.load_npm_rotation_marker_timestamp_from_secret_metadata(
                "owner/repo",
                "gh",
            ),
            "timestamp must be after",
        )

        module.load_secret_metadata = lambda _repo, _gh: {
            module.NPM_TOKEN_SECRET_NAME: SimpleNamespace(updated_at=SENSITIVE_SENTINEL)
        }
        assert_raises(
            lambda: module.load_npm_rotation_marker_timestamp_from_secret_metadata(
                "owner/repo",
                "gh",
            ),
            "ISO-8601",
        )
    finally:
        module.load_secret_metadata = original_loader

    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    original_run = subprocess.run
    module.subprocess.run = fake_run
    try:
        configured = module.configure_npm_rotation_marker(
            "owner/repo",
            "gh",
            "2026-06-03T00:00:01+00:00",
            confirm_rotated=True,
            dry_run=True,
        )
        if configured != "2026-06-03T00:00:01Z":
            raise AssertionError("dry-run marker setup returned the wrong timestamp")
        if calls:
            raise AssertionError("dry-run marker setup must not call gh variable set")

        configured = module.configure_npm_rotation_marker(
            "owner/repo",
            "gh",
            "2026-06-03T00:00:02Z",
            confirm_rotated=True,
            dry_run=False,
        )
    finally:
        module.subprocess.run = original_run

    if configured != "2026-06-03T00:00:02Z":
        raise AssertionError("marker setup returned the wrong configured timestamp")
    if len(calls) != 1:
        raise AssertionError(f"expected one gh variable set call, got {len(calls)}")
    args, kwargs = calls[0]
    rendered_args = " ".join(args)
    expected = (
        f"variable set {module.NPM_TOKEN_ROTATION_MARKER_VAR} "
        "--repo owner/repo --body 2026-06-03T00:00:02Z"
    )
    if expected not in rendered_args:
        raise AssertionError(f"unexpected gh variable set arguments: {rendered_args}")
    if kwargs.get("input") is not None:
        raise AssertionError("repository variable value should be passed through --body")
    if SENSITIVE_SENTINEL in rendered_args:
        raise AssertionError("marker setup leaked an accidental secret-like value")

    def failed_run(*_args, **_kwargs):
        return SimpleNamespace(returncode=9, stdout=SENSITIVE_SENTINEL, stderr=SENSITIVE_SENTINEL)

    module.subprocess.run = failed_run
    try:
        assert_raises(
            lambda: module.set_variable(
                "gh",
                "owner/repo",
                module.NPM_TOKEN_ROTATION_MARKER_VAR,
                "2026-06-03T00:00:03Z",
            ),
            "failed with exit code 9",
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
        module.run_value_preflights(
            require_openssl=True,
            values={"NPM_TOKEN": SENSITIVE_SENTINEL},
            python_executable="python",
        )
    finally:
        module.subprocess.run = original_run

    if len(calls) != 3:
        raise AssertionError(f"expected three value preflight calls, got {len(calls)}")
    rendered = "\n".join(" ".join(args) for args, _kwargs in calls)
    if "check-platform-signing-secrets-preflight.py" not in rendered:
        raise AssertionError("platform signing secret value preflight was not called")
    if "--require-openssl" not in rendered:
        raise AssertionError("OpenSSL requirement was not passed to platform preflight")
    if "check-linux-signing-secrets-preflight.py" not in rendered:
        raise AssertionError("Linux signing secret preflight was not called")
    if "check-npm-publish-preflight.py" not in rendered:
        raise AssertionError("npm token authentication preflight was not called")
    if "--token-auth-check" not in rendered:
        raise AssertionError("npm token authentication flag was not passed")
    if SENSITIVE_SENTINEL in rendered:
        raise AssertionError("secret value was passed in value preflight arguments")
    for _args, kwargs in calls:
        if kwargs.get("stdout") != subprocess.DEVNULL:
            raise AssertionError("value preflight stdout must be suppressed")
        if kwargs.get("stderr") != subprocess.DEVNULL:
            raise AssertionError("value preflight stderr must be suppressed")
        if kwargs.get("env", {}).get("NPM_TOKEN") != SENSITIVE_SENTINEL:
            raise AssertionError("value preflight did not receive env-file values via env")

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
        blank = dict(values)
        blank[missing_name] = "   "
        assert_raises(
            lambda: module.configure_release_secrets("owner/repo", "gh", blank, dry_run=True),
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

        assert_raises(
            lambda: module.require_npm_rotation_marker_for_token_write(
                values=values,
                marker_requested=False,
                dry_run=True,
            ),
            module.NPM_TOKEN_ROTATION_MARKER_VAR,
        )
        module.require_npm_rotation_marker_for_token_write(
            values=values,
            marker_requested=True,
            dry_run=True,
        )
        module.require_npm_rotation_marker_for_token_write(
            values=values,
            marker_requested=True,
            dry_run=False,
        )
        assert_raises(
            lambda: module.require_npm_rotation_marker_for_token_write(
                values=values,
                marker_requested=False,
                dry_run=False,
            ),
            module.NPM_TOKEN_ROTATION_MARKER_VAR,
        )
    finally:
        restore_env(original)


def run_env_file_main_tests(module) -> None:
    original = {name: os.environ.get(name) for name in module.REQUIRED_RELEASE_SECRETS}
    try:
        for name in module.REQUIRED_RELEASE_SECRETS:
            os.environ.pop(name, None)
        with tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / ".env.release"
            write_required_env_file(env_file, module, SENSITIVE_SENTINEL)

            exit_code, rendered = call_main(
                module,
                [
                    "set-github-release-secrets.py",
                    "--repo",
                    "owner/repo",
                    "--gh",
                    "gh",
                    "--env-file",
                    str(env_file),
                    "--dry-run",
                ]
            )
            if exit_code == 0 or module.NPM_TOKEN_ROTATION_MARKER_VAR not in rendered:
                raise AssertionError(f"expected env-file dry run without marker to fail: {rendered}")
            if SENSITIVE_SENTINEL in rendered:
                raise AssertionError("env-file dry-run marker error leaked a secret value")

            exit_code, rendered = call_main(
                module,
                [
                    "set-github-release-secrets.py",
                    "--repo",
                    "owner/repo",
                    "--gh",
                    "gh",
                    "--env-file",
                    str(env_file),
                    "--env-file-only",
                    "--dry-run",
                ]
            )
            if exit_code == 0 or module.NPM_TOKEN_ROTATION_MARKER_VAR not in rendered:
                raise AssertionError(
                    f"expected env-file-only dry run without marker to fail: {rendered}"
                )
            if SENSITIVE_SENTINEL in rendered:
                raise AssertionError("env-file-only dry-run marker error leaked a secret value")

            exit_code, rendered = call_main(
                module,
                [
                    "set-github-release-secrets.py",
                    "--repo",
                    "owner/repo",
                    "--gh",
                    "gh",
                    "--env-file",
                    str(env_file),
                    "--env-file-only",
                    "--dry-run",
                    "--set-npm-token-rotation-marker",
                    "2026-06-03T00:00:01Z",
                    "--allow-unverified-npm-token-rotation-marker",
                    "--confirm-npm-token-rotated",
                ]
            )
            if exit_code != 0:
                raise AssertionError(f"expected env-file-only dry run with marker to pass: {rendered}")
            if module.NPM_TOKEN_ROTATION_MARKER_VAR not in rendered:
                raise AssertionError("env-file-only dry run with marker omitted marker variable")
            if SENSITIVE_SENTINEL in rendered:
                raise AssertionError("env-file-only dry-run with marker leaked a secret value")

            exit_code, rendered = call_main(
                module,
                [
                    "set-github-release-secrets.py",
                    "--repo",
                    "owner/repo",
                    "--gh",
                    "gh",
                    "--env-file",
                    str(env_file),
                    "--env-file-only",
                ]
            )
            if exit_code == 0 or module.NPM_TOKEN_ROTATION_MARKER_VAR not in rendered:
                raise AssertionError(
                    f"expected real NPM token setup without marker to fail: {rendered}"
                )
            if "missing local release secret values" in rendered:
                raise AssertionError("marker guard should run after complete env-file loading")
            if SENSITIVE_SENTINEL in rendered:
                raise AssertionError("marker guard error leaked a secret value")

            original_find_gh = module.find_gh
            original_infer_repo = module.infer_repo
            original_preflights = module.run_value_preflights

            def forbidden_call(*_args, **_kwargs):
                raise AssertionError("env-file check unexpectedly used setup dependency")

            module.find_gh = forbidden_call
            module.infer_repo = forbidden_call
            module.run_value_preflights = forbidden_call
            try:
                exit_code, rendered = call_main(
                    module,
                    [
                        "set-github-release-secrets.py",
                        "--env-file",
                        str(env_file),
                        "--check-env-file",
                    ]
                )
            finally:
                module.find_gh = original_find_gh
                module.infer_repo = original_infer_repo
                module.run_value_preflights = original_preflights
            if exit_code != 0:
                raise AssertionError(f"expected env-file check to pass: {rendered}")
            if "present: NPM_TOKEN" not in rendered:
                raise AssertionError("env-file check output omitted checked secret names")
            if SENSITIVE_SENTINEL in rendered:
                raise AssertionError("env-file check output leaked a secret value")

            blank_env_file = Path(temp_dir) / "blank.env"
            blank_lines = [
                f"{name}={SENSITIVE_SENTINEL}"
                for name in module.REQUIRED_RELEASE_SECRETS
            ]
            blank_lines[0] = f"{module.REQUIRED_RELEASE_SECRETS[0]}=   "
            secure_write_text(blank_env_file, "\n".join(blank_lines) + "\n")
            exit_code, rendered = call_main(
                module,
                [
                    "set-github-release-secrets.py",
                    "--env-file",
                    str(blank_env_file),
                    "--check-env-file",
                ]
            )
            if exit_code == 0:
                raise AssertionError("env-file check should fail on blank secret values")
            if module.REQUIRED_RELEASE_SECRETS[0] not in rendered:
                raise AssertionError("blank-value report omitted the blank secret name")
            if SENSITIVE_SENTINEL in rendered:
                raise AssertionError("blank-value report leaked a secret value")

            exit_code, rendered = call_main(
                module,
                [
                    "set-github-release-secrets.py",
                    "--env-file-only",
                    "--dry-run",
                ]
            )
            if exit_code == 0 or "--env-file-only requires --env-file" not in rendered:
                raise AssertionError(f"expected env-file-only without env-file to fail: {rendered}")
            if SENSITIVE_SENTINEL in rendered:
                raise AssertionError("env-file-only argument error leaked a secret value")

            exit_code, rendered = call_main(
                module,
                [
                    "set-github-release-secrets.py",
                    "--check-env-file",
                ]
            )
            if exit_code == 0 or "--check-env-file requires --env-file" not in rendered:
                raise AssertionError(f"expected check-env-file without env-file to fail: {rendered}")
            if SENSITIVE_SENTINEL in rendered:
                raise AssertionError("check-env-file argument error leaked a secret value")

            exit_code, rendered = call_main(
                module,
                [
                    "set-github-release-secrets.py",
                    "--env-file",
                    str(env_file),
                    "--check-env-file",
                    "--preflight-values",
                ]
            )
            if exit_code == 0 or "cannot be combined" not in rendered:
                raise AssertionError(f"expected check-env-file setup combination to fail: {rendered}")
            if SENSITIVE_SENTINEL in rendered:
                raise AssertionError("check-env-file combination error leaked a secret value")

            original_with_env = with_required_env(module, SENSITIVE_SENTINEL)
            try:
                missing_name = module.REQUIRED_RELEASE_SECRETS[0]
                partial_env_file = Path(temp_dir) / "partial.env"
                partial_lines = [
                    f"{name}={SENSITIVE_SENTINEL}"
                    for name in module.REQUIRED_RELEASE_SECRETS
                    if name != missing_name
                ]
                secure_write_text(partial_env_file, "\n".join(partial_lines) + "\n")
                exit_code, rendered = call_main(
                    module,
                    [
                        "set-github-release-secrets.py",
                        "--repo",
                        "owner/repo",
                        "--gh",
                        "gh",
                        "--env-file",
                        str(partial_env_file),
                        "--env-file-only",
                        "--dry-run",
                    ]
                )
                if exit_code == 0:
                    raise AssertionError("env-file-only should fail when the env file is incomplete")
                if missing_name not in rendered:
                    raise AssertionError("env-file-only missing-value report omitted the missing key")
                if SENSITIVE_SENTINEL in rendered:
                    raise AssertionError("env-file-only missing-value report leaked a secret value")

                exit_code, rendered = call_main(
                    module,
                    [
                        "set-github-release-secrets.py",
                        "--env-file",
                        str(partial_env_file),
                        "--check-env-file",
                    ]
                )
                if exit_code == 0:
                    raise AssertionError("env-file check should fail when the file is incomplete")
                if missing_name not in rendered:
                    raise AssertionError("env-file check missing-value report omitted the missing key")
                if SENSITIVE_SENTINEL in rendered:
                    raise AssertionError("env-file check missing-value report leaked a secret value")

                exit_code, rendered = call_main(
                    module,
                    [
                        "set-github-release-secrets.py",
                        "--repo",
                        "owner/repo",
                        "--gh",
                        "gh",
                        "--env-file",
                        str(partial_env_file),
                        "--dry-run",
                    ]
                )
                if exit_code == 0 or module.NPM_TOKEN_ROTATION_MARKER_VAR not in rendered:
                    raise AssertionError(
                        "normal env-file fallback should still require the npm rotation marker"
                    )
                if "missing local release secret values" in rendered:
                    raise AssertionError("normal env-file fallback should load environment values")
                if SENSITIVE_SENTINEL in rendered:
                    raise AssertionError("normal env-file fallback marker error leaked a secret value")
            finally:
                restore_env(original_with_env)
    finally:
        restore_env(original)


def run_rotation_marker_main_tests(module) -> None:
    original = {name: os.environ.get(name) for name in module.REQUIRED_RELEASE_SECRETS}
    try:
        for name in module.REQUIRED_RELEASE_SECRETS:
            os.environ.pop(name, None)

        exit_code, rendered = call_main(
            module,
            [
                "set-github-release-secrets.py",
                "--repo",
                "owner/repo",
                "--gh",
                "gh",
                "--set-npm-token-rotation-marker",
                "2026-06-03T00:00:01+00:00",
                "--confirm-npm-token-rotated",
                "--dry-run",
            ],
        )
        if exit_code == 0 or "--allow-unverified-npm-token-rotation-marker" not in rendered:
            raise AssertionError(
                f"expected manual marker dry-run without override to fail: {rendered}"
            )
        if SENSITIVE_SENTINEL in rendered:
            raise AssertionError("manual marker override error leaked a secret-like value")

        exit_code, rendered = call_main(
            module,
            [
                "set-github-release-secrets.py",
                "--repo",
                "owner/repo",
                "--gh",
                "gh",
                "--set-npm-token-rotation-marker",
                "2026-06-03T00:00:01+00:00",
                "--allow-unverified-npm-token-rotation-marker",
                "--confirm-npm-token-rotated",
                "--dry-run",
            ],
        )
        if exit_code != 0:
            raise AssertionError(f"expected unverified manual marker dry-run to pass: {rendered}")
        if module.NPM_TOKEN_ROTATION_MARKER_VAR not in rendered:
            raise AssertionError("marker dry-run output omitted the marker variable name")
        if "2026-06-03T00:00:01Z" not in rendered:
            raise AssertionError("marker dry-run output omitted the normalized timestamp")
        if "missing local release secret values" in rendered:
            raise AssertionError("marker-only dry-run should not require signing secrets")
        if SENSITIVE_SENTINEL in rendered:
            raise AssertionError("marker-only dry-run leaked a secret-like value")

        original_loader = module.load_secret_metadata
        try:
            module.load_secret_metadata = lambda _repo, _gh: {
                module.NPM_TOKEN_SECRET_NAME: SimpleNamespace(
                    updated_at="2026-06-03T00:00:03+00:00"
                )
            }
            exit_code, rendered = call_main(
                module,
                [
                    "set-github-release-secrets.py",
                    "--repo",
                    "owner/repo",
                    "--gh",
                    "gh",
                    "--set-npm-token-rotation-marker-from-secret-updated-at",
                    "--confirm-npm-token-rotated",
                    "--dry-run",
                ],
            )
        finally:
            module.load_secret_metadata = original_loader
        if exit_code != 0:
            raise AssertionError(f"expected metadata marker dry-run to pass: {rendered}")
        if "2026-06-03T00:00:03Z" not in rendered:
            raise AssertionError("metadata marker dry-run omitted normalized updatedAt")
        if "missing local release secret values" in rendered:
            raise AssertionError("metadata marker dry-run should not require signing secrets")
        if SENSITIVE_SENTINEL in rendered:
            raise AssertionError("metadata marker dry-run leaked a secret-like value")

        exit_code, rendered = call_main(
            module,
            [
                "set-github-release-secrets.py",
                "--repo",
                "owner/repo",
                "--gh",
                "gh",
                "--set-npm-token-rotation-marker",
                "2026-06-03T00:00:01Z",
                "--allow-unverified-npm-token-rotation-marker",
                "--dry-run",
            ],
        )
        if exit_code == 0 or "--confirm-npm-token-rotated" not in rendered:
            raise AssertionError(f"expected marker setup without confirmation to fail: {rendered}")
        if SENSITIVE_SENTINEL in rendered:
            raise AssertionError("missing-confirm marker error leaked a secret-like value")

        exit_code, rendered = call_main(
            module,
            [
                "set-github-release-secrets.py",
                "--repo",
                "owner/repo",
                "--gh",
                "gh",
                "--set-npm-token-rotation-marker-from-secret-updated-at",
                "--dry-run",
            ],
        )
        if exit_code == 0 or "--confirm-npm-token-rotated" not in rendered:
            raise AssertionError(
                f"expected metadata marker setup without confirmation to fail: {rendered}"
            )
        if SENSITIVE_SENTINEL in rendered:
            raise AssertionError("metadata missing-confirm marker error leaked a secret-like value")

        exit_code, rendered = call_main(
            module,
            [
                "set-github-release-secrets.py",
                "--repo",
                "owner/repo",
                "--gh",
                "gh",
                "--allow-unverified-npm-token-rotation-marker",
                "--confirm-npm-token-rotated",
                "--dry-run",
            ],
        )
        if exit_code == 0 or "requires --set-npm-token-rotation-marker" not in rendered:
            raise AssertionError(
                f"expected unverified override without manual marker to fail: {rendered}"
            )
        if SENSITIVE_SENTINEL in rendered:
            raise AssertionError("unverified override argument error leaked a secret-like value")

        exit_code, rendered = call_main(
            module,
            [
                "set-github-release-secrets.py",
                "--repo",
                "owner/repo",
                "--gh",
                "gh",
                "--set-npm-token-rotation-marker-from-secret-updated-at",
                "--allow-unverified-npm-token-rotation-marker",
                "--confirm-npm-token-rotated",
                "--dry-run",
            ],
        )
        if exit_code == 0 or "requires --set-npm-token-rotation-marker" not in rendered:
            raise AssertionError(
                f"expected unverified override with metadata marker to fail: {rendered}"
            )
        if SENSITIVE_SENTINEL in rendered:
            raise AssertionError("metadata override argument error leaked a secret-like value")

        exit_code, rendered = call_main(
            module,
            [
                "set-github-release-secrets.py",
                "--repo",
                "owner/repo",
                "--gh",
                "gh",
                "--confirm-npm-token-rotated",
                "--dry-run",
            ],
        )
        if exit_code == 0 or "requires a NPM token rotation marker setup option" not in rendered:
            raise AssertionError(f"expected confirmation without marker to fail: {rendered}")
        if SENSITIVE_SENTINEL in rendered:
            raise AssertionError("confirmation-only marker error leaked a secret-like value")

        exit_code, rendered = call_main(
            module,
            [
                "set-github-release-secrets.py",
                "--repo",
                "owner/repo",
                "--gh",
                "gh",
                "--set-npm-token-rotation-marker",
                "2026-06-03T00:00:01Z",
                "--allow-unverified-npm-token-rotation-marker",
                "--set-npm-token-rotation-marker-from-secret-updated-at",
                "--confirm-npm-token-rotated",
                "--dry-run",
            ],
        )
        if exit_code == 0 or "mutually exclusive" not in rendered:
            raise AssertionError(f"expected marker setup options to be mutually exclusive: {rendered}")
        if SENSITIVE_SENTINEL in rendered:
            raise AssertionError("mutual-exclusion marker error leaked a secret-like value")

        exit_code, rendered = call_main(
            module,
            [
                "set-github-release-secrets.py",
                "--repo",
                "owner/repo",
                "--gh",
                "gh",
                "--set-npm-token-rotation-marker",
                "2026-06-03T00:00:00Z",
                "--allow-unverified-npm-token-rotation-marker",
                "--confirm-npm-token-rotated",
                "--dry-run",
            ],
        )
        if exit_code == 0 or "timestamp must be after" not in rendered:
            raise AssertionError(f"expected stale marker setup to fail: {rendered}")
        if SENSITIVE_SENTINEL in rendered:
            raise AssertionError("stale marker error leaked a secret-like value")

        exit_code, rendered = call_main(
            module,
            [
                "set-github-release-secrets.py",
                "--repo",
                "owner/repo",
                "--gh",
                "gh",
                "--set-npm-token-rotation-marker",
                SENSITIVE_SENTINEL,
                "--allow-unverified-npm-token-rotation-marker",
                "--confirm-npm-token-rotated",
                "--dry-run",
            ],
        )
        if exit_code == 0 or "ISO-8601" not in rendered:
            raise AssertionError(f"expected invalid marker setup to fail: {rendered}")
        if SENSITIVE_SENTINEL in rendered:
            raise AssertionError("invalid marker error leaked the provided marker value")

        original_loader = module.load_secret_metadata
        try:
            module.load_secret_metadata = lambda _repo, _gh: {
                module.NPM_TOKEN_SECRET_NAME: SimpleNamespace(updated_at=SENSITIVE_SENTINEL)
            }
            exit_code, rendered = call_main(
                module,
                [
                    "set-github-release-secrets.py",
                    "--repo",
                    "owner/repo",
                    "--gh",
                    "gh",
                    "--set-npm-token-rotation-marker-from-secret-updated-at",
                    "--confirm-npm-token-rotated",
                    "--dry-run",
                ],
            )
        finally:
            module.load_secret_metadata = original_loader
        if exit_code == 0 or "ISO-8601" not in rendered:
            raise AssertionError(f"expected invalid metadata marker setup to fail: {rendered}")
        if SENSITIVE_SENTINEL in rendered:
            raise AssertionError("invalid metadata marker error leaked the updatedAt value")

        with tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / ".env.release"
            write_required_env_file(env_file, module, SENSITIVE_SENTINEL)
            exit_code, rendered = call_main(
                module,
                [
                    "set-github-release-secrets.py",
                    "--repo",
                    "owner/repo",
                    "--gh",
                    "gh",
                    "--env-file",
                    str(env_file),
                    "--env-file-only",
                    "--set-npm-token-rotation-marker",
                    "2026-06-03T00:00:02Z",
                    "--allow-unverified-npm-token-rotation-marker",
                    "--confirm-npm-token-rotated",
                    "--dry-run",
                ],
            )
            if exit_code != 0:
                raise AssertionError(f"expected env-file plus marker dry-run to pass: {rendered}")
            if "release secret setup" not in rendered:
                raise AssertionError("combined dry-run omitted release secret setup output")
            if module.NPM_TOKEN_ROTATION_MARKER_VAR not in rendered:
                raise AssertionError("combined dry-run omitted marker setup output")
            if SENSITIVE_SENTINEL in rendered:
                raise AssertionError("combined marker dry-run leaked a secret value")

            original_loader = module.load_secret_metadata
            try:
                module.load_secret_metadata = (
                    lambda _repo, _gh: (_ for _ in ()).throw(
                        AssertionError(
                            "full dry-run should not read existing NPM_TOKEN metadata"
                        )
                    )
                )
                exit_code, rendered = call_main(
                    module,
                    [
                        "set-github-release-secrets.py",
                        "--repo",
                        "owner/repo",
                        "--gh",
                        "gh",
                        "--env-file",
                        str(env_file),
                        "--env-file-only",
                        "--set-npm-token-rotation-marker-from-secret-updated-at",
                        "--confirm-npm-token-rotated",
                        "--dry-run",
                    ],
                )
            finally:
                module.load_secret_metadata = original_loader
            if exit_code != 0:
                raise AssertionError(
                    f"expected env-file plus updatedAt marker dry-run to pass: {rendered}"
                )
            if "release secret setup" not in rendered:
                raise AssertionError("updatedAt dry-run omitted release secret setup output")
            if module.NPM_TOKEN_ROTATION_MARKER_VAR not in rendered:
                raise AssertionError("updatedAt dry-run omitted marker setup output")
            if module.DRY_RUN_NPM_TOKEN_ROTATION_MARKER_FROM_UPDATED_AT not in rendered:
                raise AssertionError("updatedAt dry-run omitted deferred marker text")
            if SENSITIVE_SENTINEL in rendered:
                raise AssertionError("updatedAt marker dry-run leaked a secret value")
    finally:
        restore_env(original)


def run_env_template_main_tests(module) -> None:
    def call_main(argv: list[str]) -> tuple[int, str]:
        original_argv = sys.argv
        stdout = io.StringIO()
        stderr = io.StringIO()
        sys.argv = argv
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = module.main()
        finally:
            sys.argv = original_argv
        return exit_code, stdout.getvalue() + stderr.getvalue()

    original_argv = sys.argv
    stdout = io.StringIO()
    stderr = io.StringIO()
    sys.argv = ["set-github-release-secrets.py", "--print-env-template"]
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = module.main()
    finally:
        sys.argv = original_argv
    rendered = stdout.getvalue() + stderr.getvalue()
    if exit_code != 0:
        raise AssertionError(f"expected print template to pass: {rendered}")
    if SENSITIVE_SENTINEL in rendered:
        raise AssertionError("print template leaked a secret value")
    for name in module.REQUIRED_RELEASE_SECRETS:
        if f"{name}=" not in rendered:
            raise AssertionError(f"print template omitted {name}")

    with tempfile.TemporaryDirectory() as temp_dir:
        template_path = Path(temp_dir) / ".env.release"
        stdout = io.StringIO()
        stderr = io.StringIO()
        sys.argv = [
            "set-github-release-secrets.py",
            "--write-env-template",
            str(template_path),
        ]
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = module.main()
        finally:
            sys.argv = original_argv
        rendered = stdout.getvalue() + stderr.getvalue()
        if exit_code != 0:
            raise AssertionError(f"expected write template to pass: {rendered}")
        if SENSITIVE_SENTINEL in rendered:
            raise AssertionError("write template output leaked a secret value")
        if not template_path.exists():
            raise AssertionError("write template did not create the requested file")

    invalid_cases = (
        (
            [
                "set-github-release-secrets.py",
                "--print-env-template",
                "--write-env-template",
                ".env.release",
            ],
            "mutually exclusive",
        ),
        (
            ["set-github-release-secrets.py", "--print-env-template", "--dry-run"],
            "cannot be combined",
        ),
        (
            ["set-github-release-secrets.py", "--print-env-template", "--env-file-only"],
            "cannot be combined",
        ),
        (
            ["set-github-release-secrets.py", "--print-env-template", "--check-env-file"],
            "cannot be combined",
        ),
        (
            ["set-github-release-secrets.py", "--print-env-template", "--require-openssl"],
            "cannot be combined",
        ),
        (
            [
                "set-github-release-secrets.py",
                "--write-env-template",
                ".env.release",
                "--preflight-values",
            ],
            "cannot be combined",
        ),
    )
    for argv, expected in invalid_cases:
        exit_code, rendered = call_main(argv)
        if exit_code == 0:
            raise AssertionError(f"expected template flag combination to fail: {argv}")
        if expected not in rendered:
            raise AssertionError(f"expected {expected!r} in template flag error: {rendered}")
        if SENSITIVE_SENTINEL in rendered:
            raise AssertionError("template flag error leaked a secret value")


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
    run_env_template_tests(module)
    run_env_collection_tests(module)
    run_env_file_tests(module)
    run_secret_set_tests(module)
    run_rotation_marker_setup_tests(module)
    run_value_preflight_tests(module)
    run_dry_run_tests(module)
    run_env_file_main_tests(module)
    run_rotation_marker_main_tests(module)
    run_env_template_main_tests(module)
    run_missing_report_tests(module)
    print("GitHub release secret setup regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
