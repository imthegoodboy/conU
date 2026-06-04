#!/usr/bin/env python3
"""Regression checks for the Linux release GPG public-key export asset."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
EXPORTER = ROOT / "scripts" / "export-linux-gpg-public-key.py"
PASSPHRASE = "conu-linux-public-key-regression-passphrase"
USER_ID = "conU Linux Public Key Regression <noreply@github.com>"
PUBLIC_KEY_ASSET = "conu-linux-gpg-key.asc"
WRONG_FINGERPRINT = "F" * 40
PUBLIC_KEY_FIXTURE = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nfixture\n"
SENSITIVE_FAILURE_VALUES = (
    "npm_fakeLinuxPublicKeyToken1234567890",
    "ghp_fakeLinuxPublicKeyToken1234567890",
    "fake-bearer-token-1234567890",
    "fake-basic-token-1234567890",
    "fake-node-auth-token-1234567890",
    "fake-url-password-1234567890",
    "fake-query-token-1234567890",
    "fake-private-key-1234567890",
)


def main() -> int:
    run_output_file_preflights()
    run_command_output_redaction_preflight()

    gpg = shutil.which("gpg")
    if gpg is None:
        print(
            "Linux GPG public-key export preflight checks passed; "
            "GPG integration regression skipped: gpg is unavailable"
        )
        return 0

    with tempfile.TemporaryDirectory(prefix="conu-linux-public-key-check-") as temp_text:
        temp = Path(temp_text)
        dist = temp / "dist"
        key_home = temp / "key-home"
        verify_home = temp / "verify-home"
        dist.mkdir()
        key_home.mkdir(mode=0o700)
        verify_home.mkdir(mode=0o700)

        key_id = create_test_key(gpg, key_home)
        private_key = export_secret_key(gpg, key_home, key_id)

        env = os.environ.copy()
        env["CONU_LINUX_GPG_PRIVATE_KEY_BASE64"] = base64.b64encode(private_key).decode("ascii")
        env["CONU_LINUX_GPG_PASSPHRASE"] = PASSPHRASE
        env["CONU_LINUX_GPG_KEY_ID"] = key_id
        env["CONU_LINUX_GPG_KEY_FINGERPRINT"] = key_id
        subprocess.run(
            [sys.executable, str(EXPORTER), str(dist)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )

        public_key = dist / PUBLIC_KEY_ASSET
        if not public_key.exists():
            raise AssertionError(f"{PUBLIC_KEY_ASSET} was not generated")
        public_key_text = public_key.read_text(encoding="ascii")
        if "BEGIN PGP PUBLIC KEY BLOCK" not in public_key_text:
            raise AssertionError("exported key was not an armored public key")
        if "PRIVATE KEY BLOCK" in public_key_text:
            raise AssertionError("exported key included private key material")
        assert_sha256_sidecar(public_key)

        run_gpg_bytes(gpg, verify_home, ["--import"], input_bytes=public_key.read_bytes())
        fixture = temp / "fixture.txt"
        signature = temp / "fixture.txt.asc"
        fixture.write_text("conU release signature verification fixture\n", encoding="ascii")
        run_gpg_bytes(
            gpg,
            key_home,
            [
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                PASSPHRASE,
                "--local-user",
                key_id,
                "--armor",
                "--detach-sign",
                "--output",
                str(signature),
                str(fixture),
            ],
        )
        run_gpg_bytes(gpg, verify_home, ["--verify", str(signature), str(fixture)])

        missing_env = os.environ.copy()
        for name in (
            "CONU_LINUX_GPG_PRIVATE_KEY_BASE64",
            "CONU_LINUX_GPG_PASSPHRASE",
            "CONU_LINUX_GPG_KEY_ID",
            "CONU_LINUX_GPG_KEY_FINGERPRINT",
        ):
            missing_env.pop(name, None)
        failed = subprocess.run(
            [sys.executable, str(EXPORTER), str(dist)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=missing_env,
        )
        if failed.returncode == 0 or "missing required environment variable" not in failed.stdout:
            raise AssertionError("public-key exporter did not fail closed with missing secrets")

        mismatch_env = env.copy()
        mismatch_env["CONU_LINUX_GPG_KEY_FINGERPRINT"] = WRONG_FINGERPRINT
        failed = subprocess.run(
            [sys.executable, str(EXPORTER), str(dist)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=mismatch_env,
        )
        if failed.returncode == 0 or "fingerprint mismatch" not in failed.stdout:
            raise AssertionError(
                "public-key exporter did not fail closed when the key fingerprint mismatched"
            )

    print("Linux GPG public-key export regression checks passed")
    return 0


def run_output_file_preflights() -> None:
    exporter = load_exporter()
    with tempfile.TemporaryDirectory(prefix="conu-linux-public-key-output-check-") as temp_text:
        temp = Path(temp_text)

        with mock.patch.object(Path, "is_symlink", return_value=True):
            expect_action_failure(
                lambda: exporter.validate_input_directory(
                    temp / "dist",
                    "release dist directory",
                ),
                "must not be a symlink",
                "public-key symlink dist directory",
            )

        output = temp / PUBLIC_KEY_ASSET
        exporter.write_public_key_asset(output, PUBLIC_KEY_FIXTURE)
        exporter.write_sha256_sidecar(output)
        if output.read_bytes() != PUBLIC_KEY_FIXTURE:
            raise AssertionError("public-key exporter did not write the expected fixture bytes")
        assert_sha256_sidecar(output)

        expect_action_failure(
            lambda: exporter.validate_public_key_bytes(b""),
            "was empty",
            "public-key empty output bound",
        )
        expect_action_failure(
            lambda: exporter.validate_public_key_bytes(b"not a public key\n"),
            "not an armored public key",
            "public-key armor validation",
        )
        expect_action_failure(
            lambda: exporter.validate_public_key_bytes(
                b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
                b"-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
            ),
            "private key material",
            "public-key private material validation",
        )
        expect_constant_failure(
            exporter,
            "MAX_PUBLIC_KEY_BYTES",
            len(PUBLIC_KEY_FIXTURE) - 1,
            lambda: exporter.write_public_key_asset(temp / "oversized.asc", PUBLIC_KEY_FIXTURE),
            "exceeds",
            "public-key size bound",
        )

        output_directory = temp / "output-directory.asc"
        output_directory.mkdir()
        expect_action_failure(
            lambda: exporter.write_public_key_asset(output_directory, PUBLIC_KEY_FIXTURE),
            "must be a regular file",
            "public-key output directory",
        )

        sidecar_directory_output = temp / "sidecar-directory.asc"
        exporter.write_public_key_asset(sidecar_directory_output, PUBLIC_KEY_FIXTURE)
        sidecar_directory_output.with_name(f"{sidecar_directory_output.name}.sha256").mkdir()
        expect_action_failure(
            lambda: exporter.write_sha256_sidecar(sidecar_directory_output),
            "must be a regular file",
            "public-key sidecar output directory",
        )

        hash_directory = temp / "hash-directory.asc"
        hash_directory.mkdir()
        expect_action_failure(
            lambda: exporter.write_sha256_sidecar(hash_directory),
            "must be a regular file",
            "public-key hash source directory",
        )

        expect_constant_failure(
            exporter,
            "MAX_PUBLIC_KEY_BYTES",
            len(PUBLIC_KEY_FIXTURE) - 1,
            lambda: exporter.write_sha256_sidecar(output),
            "exceeds",
            "public-key hash source size bound",
        )

        symlink_output_target = temp / "real-output.asc"
        symlink_output_target.write_bytes(PUBLIC_KEY_FIXTURE)
        symlink_output = temp / "symlink-output.asc"
        if try_symlink(symlink_output, symlink_output_target):
            expect_action_failure(
                lambda: exporter.write_public_key_asset(symlink_output, PUBLIC_KEY_FIXTURE),
                "must not be a symlink",
                "public-key symlink output",
            )

        symlink_hash_target = temp / "real-hash-output.asc"
        exporter.write_public_key_asset(symlink_hash_target, PUBLIC_KEY_FIXTURE)
        symlink_hash = temp / "symlink-hash-output.asc"
        if try_symlink(symlink_hash, symlink_hash_target):
            expect_action_failure(
                lambda: exporter.write_sha256_sidecar(symlink_hash),
                "must not be a symlink",
                "public-key symlink hash source",
            )

        symlink_sidecar_output = temp / "symlink-sidecar.asc"
        symlink_sidecar_target = temp / "real-output.asc.sha256"
        exporter.write_public_key_asset(symlink_sidecar_output, PUBLIC_KEY_FIXTURE)
        write_sidecar_fixture(symlink_sidecar_output, symlink_sidecar_target)
        symlink_sidecar = symlink_sidecar_output.with_name(
            f"{symlink_sidecar_output.name}.sha256"
        )
        if try_symlink(symlink_sidecar, symlink_sidecar_target):
            expect_action_failure(
                lambda: exporter.write_sha256_sidecar(symlink_sidecar_output),
                "must not be a symlink",
                "public-key symlink sidecar output",
            )


def run_command_output_redaction_preflight() -> None:
    exporter = load_exporter()
    raw = sensitive_command_output()
    original_subprocess_run = exporter.subprocess.run
    try:

        def failed_run(*args, **_kwargs):
            command = args[0] if args else "gpg"
            raise subprocess.CalledProcessError(
                returncode=1,
                cmd=command,
                output=raw.encode("utf-8"),
                stderr=raw.encode("utf-8"),
            )

        exporter.subprocess.run = failed_run
        try:
            exporter.run_gpg("gpg", {}, ["--fixture"])
        except SystemExit as exc:
            rendered = str(exc)
        else:
            raise AssertionError("Linux public-key exporter unexpectedly passed")
    finally:
        exporter.subprocess.run = original_subprocess_run

    if "gpg failed with output:" not in rendered:
        raise AssertionError("public-key exporter failure output omitted the command failure label")
    for value in SENSITIVE_FAILURE_VALUES:
        if value in rendered:
            raise AssertionError("public-key exporter failure output leaked a sensitive value")


def sensitive_command_output() -> str:
    return "\n".join(
        [
            f"npm ERR! auth token {SENSITIVE_FAILURE_VALUES[0]}",
            f"gh token {SENSITIVE_FAILURE_VALUES[1]}",
            f"Authorization: Bearer {SENSITIVE_FAILURE_VALUES[2]}",
            f"Authorization: Basic {SENSITIVE_FAILURE_VALUES[3]}",
            f"NODE_AUTH_TOKEN={SENSITIVE_FAILURE_VALUES[4]}",
            f"https://user:{SENSITIVE_FAILURE_VALUES[5]}@example.invalid/conu",
            f"https://example.invalid/conu?token={SENSITIVE_FAILURE_VALUES[6]}",
            f"PRIVATE_KEY={SENSITIVE_FAILURE_VALUES[7]}",
        ]
    )


def load_exporter():
    script_dir = ROOT / "scripts"
    sys.path.insert(0, str(script_dir))
    try:
        spec = importlib.util.spec_from_file_location("export_linux_gpg_public_key", EXPORTER)
        if spec is None or spec.loader is None:
            raise RuntimeError("could not load Linux public-key exporter")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        try:
            sys.path.remove(str(script_dir))
        except ValueError:
            pass


def expect_constant_failure(
    module,
    constant_name: str,
    value: int,
    action,
    expected: str,
    label: str,
) -> None:
    original = getattr(module, constant_name)
    setattr(module, constant_name, value)
    try:
        expect_action_failure(action, expected, label)
    finally:
        setattr(module, constant_name, original)


def expect_action_failure(action, expected: str, label: str) -> None:
    try:
        action()
    except SystemExit as exc:
        message = str(exc)
        if expected in message:
            return
        raise AssertionError(f"{label}: expected {expected!r}, got {message!r}") from exc
    raise AssertionError(f"{label}: expected failure containing {expected!r}")


def try_symlink(link: Path, target: Path) -> bool:
    try:
        link.symlink_to(target)
        return True
    except (NotImplementedError, OSError):
        return False


def write_sidecar_fixture(path: Path, sidecar: Path) -> None:
    sidecar.write_text(
        f"{sha256_file(path)}  {path.name}\n",
        encoding="ascii",
        newline="\n",
    )


def assert_sha256_sidecar(path: Path) -> None:
    sidecar = path.with_name(f"{path.name}.sha256")
    expected = f"{sha256_file(path)}  {path.name}\n"
    if sidecar.read_text(encoding="ascii") != expected:
        raise AssertionError(f"{sidecar.name} did not name and hash the public key")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256(path.read_bytes())
    return digest.hexdigest()


def create_test_key(gpg: str, home: Path) -> str:
    run_gpg(
        gpg,
        home,
        [
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            PASSPHRASE,
            "--quick-gen-key",
            USER_ID,
            "rsa2048",
            "sign",
            "1d",
        ],
    )
    listing = run_gpg(gpg, home, ["--with-colons", "--list-secret-keys", USER_ID])
    for line in listing.splitlines():
        parts = line.split(":")
        if parts and parts[0] == "fpr" and len(parts) > 9 and parts[9]:
            return parts[9]
    raise AssertionError("could not find generated test signing key fingerprint")


def export_secret_key(gpg: str, home: Path, key_id: str) -> bytes:
    return run_gpg_bytes(
        gpg,
        home,
        [
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            PASSPHRASE,
            "--armor",
            "--export-secret-keys",
            key_id,
        ],
    )


def run_gpg(gpg: str, home: Path, args: list[str]) -> str:
    return run_gpg_bytes(gpg, home, args).decode("utf-8", errors="replace")


def run_gpg_bytes(
    gpg: str,
    home: Path,
    args: list[str],
    *,
    input_bytes: bytes | None = None,
) -> bytes:
    env = os.environ.copy()
    env["GNUPGHOME"] = str(home)
    result = subprocess.run(
        [gpg, "--batch", "--yes", "--no-tty", *args],
        input=input_bytes,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    return result.stdout


if __name__ == "__main__":
    sys.exit(main())
