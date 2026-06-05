#!/usr/bin/env python3
"""Regression checks for Linux release detached signing."""

from __future__ import annotations

import base64
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SIGNER = ROOT / "scripts" / "sign-linux-release-assets.py"
PASSPHRASE = "conu-linux-signing-regression-passphrase"
USER_ID = "conU Linux Signing Regression <noreply@github.com>"
WRONG_FINGERPRINT = "F" * 40
SIGNABLE_FIXTURES = (
    "conu-0.1.0-linux-x64.tar.gz",
    "conu-0.1.0-linux-arm64.tar.gz",
    "conu_0.1.0_amd64.deb",
    "conu_0.1.0_arm64.deb",
    "conu-0.1.0-1.x86_64.rpm",
    "conu-0.1.0-1.aarch64.rpm",
    "conu-0.1.0-apt-repository-metadata.zip",
    "conu-0.1.0-rpm-repository-metadata.zip",
    "conu-0.1.0-hosted-linux-repositories.zip",
    "conu-0.1.0-hosted-linux-repository-site.zip",
    "conu-0.1.0-update-policy.json",
    "conu-0.1.0-package-manager-submissions.zip",
)
UNSIGNED_FIXTURES = (
    "conu-0.1.0-windows-x64.zip",
    "conu-0.1.0-macos-arm64.zip",
    "conu-0.1.0-linux-x64.tar.gz.sha256",
    "conu.rb",
    "conu.spec",
)


def main() -> int:
    run_source_selection_checks()

    gpg = shutil.which("gpg")
    if gpg is None:
        print("Linux release signing regression skipped: gpg is unavailable")
        return 0

    with tempfile.TemporaryDirectory(prefix="conu-linux-signing-check-") as temp_text:
        temp = Path(temp_text)
        dist = temp / "dist"
        key_home = temp / "key-home"
        verify_home = temp / "verify-home"
        dist.mkdir()
        key_home.mkdir(mode=0o700)
        verify_home.mkdir(mode=0o700)
        for name in (*SIGNABLE_FIXTURES, *UNSIGNED_FIXTURES):
            (dist / name).write_bytes(f"{name}\n".encode("ascii"))

        key_id = create_test_key(gpg, key_home)
        private_key = export_secret_key(gpg, key_home, key_id)
        public_key = export_public_key(gpg, key_home, key_id)
        import_public_key(gpg, verify_home, public_key)

        env = os.environ.copy()
        env["CONU_LINUX_GPG_PRIVATE_KEY_BASE64"] = base64.b64encode(private_key).decode("ascii")
        env["CONU_LINUX_GPG_PASSPHRASE"] = PASSPHRASE
        env["CONU_LINUX_GPG_KEY_ID"] = key_id
        env["CONU_LINUX_GPG_KEY_FINGERPRINT"] = key_id
        subprocess.run(
            [sys.executable, str(SIGNER), str(dist)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )

        for name in SIGNABLE_FIXTURES:
            asset = dist / name
            signature = dist / f"{name}.asc"
            if not signature.exists():
                raise AssertionError(f"{signature.name} was not generated")
            signature_text = signature.read_text(encoding="ascii")
            if "BEGIN PGP SIGNATURE" not in signature_text:
                raise AssertionError(f"{signature.name} was not an armored detached signature")
            run_gpg(gpg, verify_home, ["--verify", str(signature), str(asset)])

        for name in UNSIGNED_FIXTURES:
            signature = dist / f"{name}.asc"
            if signature.exists():
                raise AssertionError(f"{signature.name} should not have been generated")

        missing_env = os.environ.copy()
        for name in (
            "CONU_LINUX_GPG_PRIVATE_KEY_BASE64",
            "CONU_LINUX_GPG_PASSPHRASE",
            "CONU_LINUX_GPG_KEY_ID",
            "CONU_LINUX_GPG_KEY_FINGERPRINT",
        ):
            missing_env.pop(name, None)
        failed = subprocess.run(
            [sys.executable, str(SIGNER), str(dist)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=missing_env,
        )
        if failed.returncode == 0 or "missing required environment variable" not in failed.stdout:
            raise AssertionError("signer did not fail closed when signing secrets were missing")

        mismatch_env = env.copy()
        mismatch_env["CONU_LINUX_GPG_KEY_FINGERPRINT"] = WRONG_FINGERPRINT
        failed = subprocess.run(
            [sys.executable, str(SIGNER), str(dist)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=mismatch_env,
        )
        if failed.returncode == 0 or "fingerprint mismatch" not in failed.stdout:
            raise AssertionError("signer did not fail closed when the key fingerprint mismatched")

        only_hosted_dist = temp / "only-hosted-dist"
        only_hosted_dist.mkdir()
        hosted_bundle = only_hosted_dist / "conu-0.1.0-hosted-linux-repositories.zip"
        hosted_bundle.write_bytes(b"hosted repository bundle fixture\n")
        linux_archive = only_hosted_dist / "conu-0.1.0-linux-x64.tar.gz"
        linux_archive.write_bytes(b"linux archive fixture\n")
        subprocess.run(
            [
                sys.executable,
                str(SIGNER),
                str(only_hosted_dist),
                "--only-hosted-repository-bundles",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )
        hosted_signature = only_hosted_dist / "conu-0.1.0-hosted-linux-repositories.zip.asc"
        if not hosted_signature.exists():
            raise AssertionError("hosted repository bundle signature was not generated")
        run_gpg(gpg, verify_home, ["--verify", str(hosted_signature), str(hosted_bundle)])
        if linux_archive.with_name(f"{linux_archive.name}.asc").exists():
            raise AssertionError("only-hosted signing mode signed a Linux archive")

        only_site_dist = temp / "only-site-dist"
        only_site_dist.mkdir()
        site_bundle = only_site_dist / "conu-0.1.0-hosted-linux-repository-site.zip"
        site_bundle.write_bytes(b"hosted repository site fixture\n")
        hosted_repo_bundle = only_site_dist / "conu-0.1.0-hosted-linux-repositories.zip"
        hosted_repo_bundle.write_bytes(b"hosted repository bundle fixture\n")
        subprocess.run(
            [
                sys.executable,
                str(SIGNER),
                str(only_site_dist),
                "--only-hosted-repository-sites",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )
        site_signature = only_site_dist / "conu-0.1.0-hosted-linux-repository-site.zip.asc"
        if not site_signature.exists():
            raise AssertionError("hosted repository site signature was not generated")
        run_gpg(gpg, verify_home, ["--verify", str(site_signature), str(site_bundle)])
        if hosted_repo_bundle.with_name(f"{hosted_repo_bundle.name}.asc").exists():
            raise AssertionError("only-site signing mode signed a hosted repository bundle")

        only_policy_dist = temp / "only-policy-dist"
        only_policy_dist.mkdir()
        update_policy = only_policy_dist / "conu-0.1.0-update-policy.json"
        update_policy.write_text('{"schema":"conu.releaseUpdatePolicy.v1"}\n', encoding="ascii")
        hosted_site = only_policy_dist / "conu-0.1.0-hosted-linux-repository-site.zip"
        hosted_site.write_bytes(b"hosted repository site fixture\n")
        subprocess.run(
            [
                sys.executable,
                str(SIGNER),
                str(only_policy_dist),
                "--only-update-policies",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )
        policy_signature = only_policy_dist / "conu-0.1.0-update-policy.json.asc"
        if not policy_signature.exists():
            raise AssertionError("update policy signature was not generated")
        run_gpg(gpg, verify_home, ["--verify", str(policy_signature), str(update_policy)])
        if hosted_site.with_name(f"{hosted_site.name}.asc").exists():
            raise AssertionError("only-policy signing mode signed a hosted repository site")

        only_submissions_dist = temp / "only-submissions-dist"
        only_submissions_dist.mkdir()
        submissions = only_submissions_dist / "conu-0.1.0-package-manager-submissions.zip"
        submissions.write_bytes(b"package manager submission bundle fixture\n")
        update_policy_extra = only_submissions_dist / "conu-0.1.0-update-policy.json"
        update_policy_extra.write_text('{"schema":"conu.releaseUpdatePolicy.v1"}\n', encoding="ascii")
        subprocess.run(
            [
                sys.executable,
                str(SIGNER),
                str(only_submissions_dist),
                "--only-package-manager-submissions",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )
        submissions_signature = only_submissions_dist / "conu-0.1.0-package-manager-submissions.zip.asc"
        if not submissions_signature.exists():
            raise AssertionError("package-manager submission bundle signature was not generated")
        run_gpg(gpg, verify_home, ["--verify", str(submissions_signature), str(submissions)])
        if update_policy_extra.with_name(f"{update_policy_extra.name}.asc").exists():
            raise AssertionError("only-submissions signing mode signed an update policy")

    print("Linux release signing regression checks passed")
    return 0


def run_source_selection_checks() -> None:
    signer = load_signer_module()
    with tempfile.TemporaryDirectory(prefix="conu-linux-signing-selection-") as temp_text:
        temp = Path(temp_text)
        dist = temp / "dist"
        dist.mkdir()

        asset = dist / SIGNABLE_FIXTURES[0]
        asset.write_bytes(b"linux asset fixture\n")
        selected = signer.signable_linux_assets(dist)
        if selected != (asset,):
            raise AssertionError("signable asset selection returned unexpected files")

        empty_dist = temp / "empty-dist"
        empty_dist.mkdir()
        empty_asset = empty_dist / SIGNABLE_FIXTURES[0]
        empty_asset.write_bytes(b"")
        expect_module_failure(
            "empty signable asset",
            lambda: signer.signable_linux_assets(empty_dist),
            "must not be empty",
        )

        expect_module_failure_with_limit(
            signer,
            "signable asset size bound",
            "MAX_SIGNABLE_ASSET_BYTES",
            1,
            lambda: signer.signable_linux_assets(dist),
            "is too large",
            asset.name,
        )

        expect_module_failure_with_limit(
            signer,
            "aggregate signable asset size bound",
            "MAX_TOTAL_SIGNABLE_ASSET_BYTES",
            1,
            lambda: signer.signable_linux_assets(dist),
            "signable Linux release assets exceed",
        )

        with mock.patch.object(Path, "is_symlink", return_value=True):
            expect_module_failure(
                "symlinked release dist directory",
                lambda: signer.validate_input_directory(
                    temp / "dist",
                    "release dist directory",
                ),
                "must not be a symlink",
            )
            expect_module_failure(
                "symlinked signable asset",
                lambda: signer.validate_signable_asset(
                    asset,
                    signer.SignableAssetBudget(),
                ),
                "must not be a symlink",
            )

        signature = dist / f"{asset.name}.asc"
        signature.write_bytes(b"existing signature\n")
        signer.prepare_signature_output(signature)
        expect_module_failure_with_limit(
            signer,
            "detached signature output size bound",
            "MAX_DETACHED_SIGNATURE_BYTES",
            1,
            lambda: signer.prepare_signature_output(signature),
            "is too large",
            signature.name,
        )

        empty_signature = dist / f"{asset.name}.empty.asc"
        empty_signature.write_bytes(b"")
        expect_module_failure(
            "empty generated signature",
            lambda: signer.validate_signature_output(empty_signature),
            "must not be empty",
        )

        with mock.patch.object(Path, "is_symlink", return_value=True):
            expect_module_failure(
                "symlinked signature output",
                lambda: signer.prepare_signature_output(signature),
                "must not be a symlink",
            )


def load_signer_module():
    spec = importlib.util.spec_from_file_location("sign_linux_release_assets", SIGNER)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load Linux release signer module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def expect_module_failure(
    description: str,
    action,
    expected: str,
    *forbidden_values: str,
) -> None:
    try:
        action()
    except SystemExit as exc:
        rendered = str(exc)
        if expected not in rendered:
            raise AssertionError(
                f"{description} failed with {rendered!r}, expected {expected!r}"
            ) from exc
        for value in forbidden_values:
            if value in rendered:
                raise AssertionError(
                    f"{description} leaked forbidden value {value!r}: {rendered!r}"
                ) from exc
        return
    raise AssertionError(f"{description} unexpectedly passed")


def expect_module_failure_with_limit(
    signer,
    description: str,
    attr: str,
    value: int,
    action,
    expected: str,
    *forbidden_values: str,
) -> None:
    original = getattr(signer, attr)
    setattr(signer, attr, value)
    try:
        expect_module_failure(description, action, expected, *forbidden_values)
    finally:
        setattr(signer, attr, original)


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


def export_public_key(gpg: str, home: Path, key_id: str) -> bytes:
    return run_gpg_bytes(gpg, home, ["--armor", "--export", key_id])


def import_public_key(gpg: str, home: Path, key_bytes: bytes) -> None:
    run_gpg_bytes(gpg, home, ["--import"], input_bytes=key_bytes)


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
        stderr=subprocess.STDOUT,
        env=env,
    )
    return result.stdout


if __name__ == "__main__":
    sys.exit(main())
