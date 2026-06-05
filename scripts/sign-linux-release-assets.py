#!/usr/bin/env python3
"""Create armored detached GPG signatures for conU Linux release assets."""

from __future__ import annotations

import argparse
import base64
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from linux_gpg_common import (
    add_fingerprint_env_argument,
    read_expected_fingerprint,
    redact_command_output,
    verify_imported_secret_key_fingerprint,
)


MAX_SIGNING_KEY_BYTES = 1024 * 1024
MAX_SIGNABLE_ASSET_BYTES = 2 * 1024 * 1024 * 1024
MAX_TOTAL_SIGNABLE_ASSET_BYTES = 10 * 1024 * 1024 * 1024
MAX_DETACHED_SIGNATURE_BYTES = 1024 * 1024
LINUX_ARCHIVE_RE = re.compile(r"^conu-[0-9A-Za-z.+_~-]+-linux-(x64|arm64)\.tar\.gz$")
DEBIAN_PACKAGE_RE = re.compile(r"^conu_[0-9A-Za-z.+_~-]+_(amd64|arm64)\.deb$")
RPM_PACKAGE_RE = re.compile(r"^conu-[0-9A-Za-z.+_~-]+-1\.(x86_64|aarch64)\.rpm$")
APT_METADATA_RE = re.compile(r"^conu-[0-9A-Za-z.+_~-]+-apt-repository-metadata\.zip$")
RPM_METADATA_RE = re.compile(r"^conu-[0-9A-Za-z.+_~-]+-rpm-repository-metadata\.zip$")
HOSTED_REPOSITORY_RE = re.compile(
    r"^conu-[0-9A-Za-z.+_~-]+-hosted-linux-repositories\.zip$"
)
HOSTED_REPOSITORY_SITE_RE = re.compile(
    r"^conu-[0-9A-Za-z.+_~-]+-hosted-linux-repository-site\.zip$"
)
UPDATE_POLICY_RE = re.compile(r"^conu-[0-9A-Za-z.+_~-]+-update-policy\.json$")
PACKAGE_MANAGER_SUBMISSIONS_RE = re.compile(
    r"^conu-[0-9A-Za-z.+_~-]+-package-manager-submissions\.zip$"
)


@dataclass
class SignableAssetBudget:
    total_bytes: int = 0

    def add(self, size: int) -> None:
        self.total_bytes += size
        if self.total_bytes > MAX_TOTAL_SIGNABLE_ASSET_BYTES:
            raise SystemExit(
                "signable Linux release assets exceed "
                f"{MAX_TOTAL_SIGNABLE_ASSET_BYTES} bytes"
            )


def main() -> int:
    args = parse_args()
    dist = validate_input_directory(args.dist, "release dist directory")

    gpg = shutil.which("gpg")
    if gpg is None:
        raise SystemExit("gpg is required to sign Linux release assets")

    signing_key = read_secret_key(args.key_env)
    passphrase = read_required_env(args.passphrase_env)
    key_id = read_required_env(args.key_id_env).strip()
    if not key_id:
        raise SystemExit(f"{args.key_id_env} must not be empty")
    expected_fingerprint = read_expected_fingerprint(os.environ, args.fingerprint_env)

    assets = signable_linux_assets(
        dist,
        only_hosted_repository_bundles=args.only_hosted_repository_bundles,
        only_hosted_repository_sites=args.only_hosted_repository_sites,
        only_update_policies=args.only_update_policies,
        only_package_manager_submissions=args.only_package_manager_submissions,
    )
    if not assets:
        raise SystemExit(f"no signable Linux release assets found in {dist}")

    with tempfile.TemporaryDirectory(prefix="conu-linux-signing-") as gnupg_home_text:
        gnupg_home = Path(gnupg_home_text)
        gnupg_home.chmod(0o700)
        env = os.environ.copy()
        env["GNUPGHOME"] = str(gnupg_home)

        run_gpg(gpg, env, ["--import"], input_bytes=signing_key)
        verify_imported_secret_key_fingerprint(gpg, env, key_id, expected_fingerprint)
        for asset in assets:
            signature = asset.with_name(f"{asset.name}.asc")
            prepare_signature_output(signature)
            run_gpg(
                gpg,
                env,
                [
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase-fd",
                    "0",
                    "--local-user",
                    key_id,
                    "--armor",
                    "--detach-sign",
                    "--output",
                    str(signature),
                    str(asset),
                ],
                input_bytes=(passphrase + "\n").encode("utf-8"),
            )
            validate_signature_output(signature)
            run_gpg(gpg, env, ["--verify", str(signature), str(asset)])

    print(
        "signed Linux release assets: "
        + ", ".join(str(asset.with_name(f"{asset.name}.asc")) for asset in assets)
    )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist", type=Path, help="directory containing release assets")
    parser.add_argument(
        "--key-env",
        default="CONU_LINUX_GPG_PRIVATE_KEY_BASE64",
        help="environment variable containing the base64-encoded armored or binary private key",
    )
    parser.add_argument(
        "--passphrase-env",
        default="CONU_LINUX_GPG_PASSPHRASE",
        help="environment variable containing the private-key passphrase",
    )
    parser.add_argument(
        "--key-id-env",
        default="CONU_LINUX_GPG_KEY_ID",
        help="environment variable containing the signing key id or fingerprint",
    )
    add_fingerprint_env_argument(parser)
    parser.add_argument(
        "--only-hosted-repository-bundles",
        action="store_true",
        help="sign only generated hosted Linux repository bundle ZIPs",
    )
    parser.add_argument(
        "--only-hosted-repository-sites",
        action="store_true",
        help="sign only generated hosted Linux repository site ZIPs",
    )
    parser.add_argument(
        "--only-update-policies",
        action="store_true",
        help="sign only generated release update policy JSON files",
    )
    parser.add_argument(
        "--only-package-manager-submissions",
        action="store_true",
        help="sign only generated package-manager submission bundle ZIPs",
    )
    return parser.parse_args()


def read_required_env(name: str) -> str:
    value = os.environ.get(name)
    if value is None or value == "":
        raise SystemExit(f"missing required environment variable: {name}")
    return value


def read_secret_key(name: str) -> bytes:
    raw = read_required_env(name)
    try:
        decoded = base64.b64decode(raw.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise SystemExit(f"{name} must contain strict base64 data") from exc
    if not decoded:
        raise SystemExit(f"{name} decoded to an empty key")
    if len(decoded) > MAX_SIGNING_KEY_BYTES:
        raise SystemExit(f"{name} decoded key is too large")
    return decoded


def signable_linux_assets(
    dist: Path,
    *,
    only_hosted_repository_bundles: bool = False,
    only_hosted_repository_sites: bool = False,
    only_update_policies: bool = False,
    only_package_manager_submissions: bool = False,
) -> tuple[Path, ...]:
    filter_count = sum(
        int(value)
        for value in (
            only_hosted_repository_bundles,
            only_hosted_repository_sites,
            only_update_policies,
            only_package_manager_submissions,
        )
    )
    if filter_count > 1:
        raise SystemExit(
            "choose only one Linux release asset signing filter at a time"
        )
    assets = []
    budget = SignableAssetBudget()
    for path in sorted(dist.iterdir(), key=lambda candidate: candidate.name):
        name = path.name
        if is_signable_asset_name(
            name,
            only_hosted_repository_bundles=only_hosted_repository_bundles,
            only_hosted_repository_sites=only_hosted_repository_sites,
            only_update_policies=only_update_policies,
            only_package_manager_submissions=only_package_manager_submissions,
        ):
            validate_signable_asset(path, budget)
            assets.append(path)
    return tuple(assets)


def is_signable_asset_name(
    name: str,
    *,
    only_hosted_repository_bundles: bool = False,
    only_hosted_repository_sites: bool = False,
    only_update_policies: bool = False,
    only_package_manager_submissions: bool = False,
) -> bool:
    if only_hosted_repository_bundles:
        return HOSTED_REPOSITORY_RE.fullmatch(name) is not None
    if only_hosted_repository_sites:
        return HOSTED_REPOSITORY_SITE_RE.fullmatch(name) is not None
    if only_update_policies:
        return UPDATE_POLICY_RE.fullmatch(name) is not None
    if only_package_manager_submissions:
        return PACKAGE_MANAGER_SUBMISSIONS_RE.fullmatch(name) is not None
    return any(
        pattern.fullmatch(name)
        for pattern in (
            LINUX_ARCHIVE_RE,
            DEBIAN_PACKAGE_RE,
            RPM_PACKAGE_RE,
            APT_METADATA_RE,
            RPM_METADATA_RE,
            HOSTED_REPOSITORY_RE,
            HOSTED_REPOSITORY_SITE_RE,
            UPDATE_POLICY_RE,
            PACKAGE_MANAGER_SUBMISSIONS_RE,
        )
    )


def validate_signable_asset(path: Path, budget: SignableAssetBudget) -> int:
    size = validate_regular_file(
        path,
        f"signable Linux release asset {path.name}",
        max_bytes=MAX_SIGNABLE_ASSET_BYTES,
        allow_empty=False,
        size_label="signable Linux release asset",
    )
    budget.add(size)
    return size


def validate_input_directory(path: Path, label: str) -> Path:
    path = path.expanduser()
    if path.is_symlink():
        raise SystemExit(f"{label} must not be a symlink: {path}")
    if not path.exists() or not path.is_dir():
        raise SystemExit(f"{label} does not exist: {path}")
    return path.resolve()


def prepare_signature_output(signature: Path) -> None:
    if signature.is_symlink():
        raise SystemExit(f"detached signature output must not be a symlink: {signature.name}")
    if not signature.exists():
        return
    validate_regular_file(
        signature,
        f"detached signature output {signature.name}",
        max_bytes=MAX_DETACHED_SIGNATURE_BYTES,
        allow_empty=True,
        size_label="detached signature output",
    )


def validate_signature_output(signature: Path) -> int:
    return validate_regular_file(
        signature,
        f"detached signature output {signature.name}",
        max_bytes=MAX_DETACHED_SIGNATURE_BYTES,
        allow_empty=False,
        size_label="detached signature output",
    )


def validate_regular_file(
    path: Path,
    label: str,
    *,
    max_bytes: int,
    allow_empty: bool,
    size_label: str | None = None,
) -> int:
    if path.is_symlink():
        raise SystemExit(f"{label} must not be a symlink: {path.name}")
    try:
        metadata = path.stat()
    except OSError as exc:
        raise SystemExit(f"missing {label}: {path.name}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"{label} must be a regular file: {path.name}")
    size = metadata.st_size
    if not allow_empty and size == 0:
        raise SystemExit(f"{label} must not be empty: {path.name}")
    if size > max_bytes:
        display_label = size_label or label
        raise SystemExit(f"{display_label} is too large: exceeds {max_bytes} bytes")
    return size


def run_gpg(
    gpg: str,
    env: dict[str, str],
    args: list[str],
    *,
    input_bytes: bytes | None = None,
) -> str:
    command = [gpg, "--batch", "--yes", "--no-tty", *args]
    try:
        result = subprocess.run(
            command,
            input=input_bytes,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
        )
    except subprocess.CalledProcessError as exc:
        output = exc.stdout.decode("utf-8", errors="replace") if exc.stdout else ""
        raise SystemExit(f"gpg failed with output:\n{redact_command_output(output)}") from exc
    return result.stdout.decode("utf-8", errors="replace")


if __name__ == "__main__":
    sys.exit(main())
