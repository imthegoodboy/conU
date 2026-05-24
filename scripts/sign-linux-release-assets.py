#!/usr/bin/env python3
"""Create armored detached GPG signatures for conU Linux release assets."""

from __future__ import annotations

import argparse
import base64
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from linux_gpg_common import (
    add_fingerprint_env_argument,
    read_expected_fingerprint,
    verify_imported_secret_key_fingerprint,
)


MAX_SIGNING_KEY_BYTES = 1024 * 1024
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


def main() -> int:
    args = parse_args()
    dist = args.dist.resolve()
    if not dist.exists() or not dist.is_dir():
        raise SystemExit(f"release dist directory does not exist: {dist}")

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
) -> tuple[Path, ...]:
    if only_hosted_repository_bundles and only_hosted_repository_sites:
        raise SystemExit(
            "choose only one hosted Linux repository signing filter at a time"
        )
    assets = []
    for path in sorted(dist.iterdir(), key=lambda candidate: candidate.name):
        if not path.is_file():
            continue
        name = path.name
        if only_hosted_repository_bundles:
            if HOSTED_REPOSITORY_RE.fullmatch(name):
                assets.append(path)
            continue
        if only_hosted_repository_sites:
            if HOSTED_REPOSITORY_SITE_RE.fullmatch(name):
                assets.append(path)
            continue
        if (
            LINUX_ARCHIVE_RE.fullmatch(name)
            or DEBIAN_PACKAGE_RE.fullmatch(name)
            or RPM_PACKAGE_RE.fullmatch(name)
            or APT_METADATA_RE.fullmatch(name)
            or RPM_METADATA_RE.fullmatch(name)
            or HOSTED_REPOSITORY_RE.fullmatch(name)
            or HOSTED_REPOSITORY_SITE_RE.fullmatch(name)
        ):
            assets.append(path)
    return tuple(assets)


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
        raise SystemExit(f"gpg failed with output:\n{output}") from exc
    return result.stdout.decode("utf-8", errors="replace")


if __name__ == "__main__":
    sys.exit(main())
