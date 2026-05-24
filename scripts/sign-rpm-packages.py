#!/usr/bin/env python3
"""Sign generated conU RPM package assets with the Linux release GPG key."""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


MAX_SIGNING_KEY_BYTES = 1024 * 1024
MAX_CHECKSUM_BYTES = 4096
HASH_CHUNK_BYTES = 1024 * 1024
CHECKSUM_RE = re.compile(r"^([0-9a-fA-F]{64})[ \t]+([^ \t\r\n]+)(?:\r?\n)?$")
RPM_PACKAGE_RE = re.compile(r"^conu-[0-9A-Za-z.+_~-]+-1\.(x86_64|aarch64)\.rpm$")
SIGNATURE_OUTPUT_RE = re.compile(r"(signature|pgp|rsa|dsa|openpgp)", re.IGNORECASE)


def main() -> int:
    args = parse_args()
    dist = args.dist.resolve()
    if not dist.exists() or not dist.is_dir():
        raise SystemExit(f"release dist directory does not exist: {dist}")

    gpg = shutil.which("gpg")
    if gpg is None:
        raise SystemExit("gpg is required to sign RPM packages")
    signer = shutil.which("rpmsign") or shutil.which("rpm")
    if signer is None:
        raise SystemExit("rpmsign or rpm is required to sign RPM packages")
    verifier = shutil.which("rpmkeys") or shutil.which("rpm")
    if verifier is None:
        raise SystemExit("rpmkeys or rpm is required to verify signed RPM packages")

    signing_key = read_secret_key(args.key_env)
    passphrase = read_required_env(args.passphrase_env)
    key_id = read_required_env(args.key_id_env).strip()
    if not key_id:
        raise SystemExit(f"{args.key_id_env} must not be empty")

    packages = rpm_package_assets(dist)
    if not packages:
        raise SystemExit(f"no generated conU RPM package assets found in {dist}")
    for package in packages:
        verify_sha256_sidecar(package, "generated RPM package")

    with tempfile.TemporaryDirectory(prefix="conu-rpm-package-signing-") as temp_text:
        temp = Path(temp_text)
        gnupg_home = temp / "gnupg"
        rpmdb = temp / "rpmdb"
        home = temp / "home"
        for directory in (gnupg_home, rpmdb, home):
            directory.mkdir(mode=0o700)

        env = os.environ.copy()
        env["GNUPGHOME"] = str(gnupg_home)
        env["HOME"] = str(home)

        run_gpg(gpg, env, ["--import"], input_bytes=signing_key)
        public_key = run_gpg(gpg, env, ["--armor", "--export", key_id])
        if b"BEGIN PGP PUBLIC KEY BLOCK" not in public_key:
            raise SystemExit("imported Linux GPG key did not export an armored public key")
        public_key_path = temp / "linux-public-key.asc"
        public_key_path.write_bytes(public_key)
        import_rpm_public_key(verifier, env, rpmdb, public_key_path)
        warm_gpg_agent(gpg, env, key_id, passphrase, temp)

        for package in packages:
            sign_rpm_package(signer, env, gpg, gnupg_home, key_id, package)
            verify_rpm_signature(verifier, env, rpmdb, package)
            write_sha256_sidecar(package)

    print("signed RPM package assets: " + ", ".join(package.name for package in packages))
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


def rpm_package_assets(dist: Path) -> tuple[Path, ...]:
    return tuple(
        path
        for path in sorted(dist.iterdir(), key=lambda candidate: candidate.name)
        if path.is_file() and RPM_PACKAGE_RE.fullmatch(path.name)
    )


def verify_sha256_sidecar(path: Path, label: str) -> str:
    sidecar = path.with_name(f"{path.name}.sha256")
    if not sidecar.exists() or not sidecar.is_file():
        raise SystemExit(f"missing SHA-256 sidecar for {label}: {path.name}")
    if sidecar.stat().st_size > MAX_CHECKSUM_BYTES:
        raise SystemExit(f"SHA-256 sidecar is too large for {label}: {path.name}")
    try:
        checksum_text = sidecar.read_text(encoding="ascii")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"SHA-256 sidecar is not ASCII for {label}: {path.name}") from exc
    match = CHECKSUM_RE.fullmatch(checksum_text)
    if match is None:
        raise SystemExit(f"SHA-256 sidecar has invalid format for {label}: {path.name}")
    named_path = match.group(2)
    if named_path != path.name:
        raise SystemExit(f"SHA-256 sidecar for {label} {path.name} names wrong file: {named_path}")
    expected = match.group(1).lower()
    actual = sha256_file(path)
    if expected != actual:
        raise SystemExit(f"SHA-256 mismatch for {label}: {path.name}")
    return expected


def write_sha256_sidecar(path: Path) -> None:
    path.with_name(f"{path.name}.sha256").write_text(
        f"{sha256_file(path)}  {path.name}\n",
        encoding="ascii",
        newline="\n",
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(HASH_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def warm_gpg_agent(gpg: str, env: dict[str, str], key_id: str, passphrase: str, temp: Path) -> None:
    payload = temp / "warmup.txt"
    signature = temp / "warmup.txt.asc"
    payload.write_text("conU RPM signing warmup\n", encoding="ascii", newline="\n")
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
            str(payload),
        ],
        input_bytes=(passphrase + "\n").encode("utf-8"),
    )


def sign_rpm_package(
    signer: str,
    env: dict[str, str],
    gpg: str,
    gnupg_home: Path,
    key_id: str,
    package: Path,
) -> None:
    args = [
        "--define",
        f"_gpg_name {key_id}",
        "--define",
        f"_openpgp_sign_id {key_id}",
        "--define",
        f"_gpg_path {gnupg_home}",
        "--define",
        f"__gpg {gpg}",
        "--define",
        "_gpg_digest_algo sha256",
        "--addsign",
        str(package),
    ]
    run_tool(signer, args, env=env, label=f"RPM signing failed for {package.name}")


def import_rpm_public_key(
    verifier: str,
    env: dict[str, str],
    rpmdb: Path,
    public_key: Path,
) -> None:
    run_tool(
        verifier,
        ["--define", f"_dbpath {rpmdb}", "--import", str(public_key)],
        env=env,
        label="RPM public-key import failed",
    )


def verify_rpm_signature(
    verifier: str,
    env: dict[str, str],
    rpmdb: Path,
    package: Path,
) -> str:
    output = run_tool(
        verifier,
        ["--define", f"_dbpath {rpmdb}", "--checksig", "--verbose", str(package)],
        env=env,
        label=f"RPM signature verification failed for {package.name}",
    )
    lowered = output.lower()
    if "nokey" in lowered or "not ok" in lowered or "missing" in lowered:
        raise SystemExit(f"RPM signature verification was not trusted for {package.name}:\n{output}")
    if SIGNATURE_OUTPUT_RE.search(output) is None:
        raise SystemExit(f"RPM signature verification did not report a package signature for {package.name}:\n{output}")
    return output


def run_gpg(
    gpg: str,
    env: dict[str, str],
    args: list[str],
    *,
    input_bytes: bytes | None = None,
) -> bytes:
    command = [gpg, "--batch", "--yes", "--no-tty", *args]
    try:
        result = subprocess.run(
            command,
            input=input_bytes,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
    except subprocess.CalledProcessError as exc:
        output = ""
        if exc.stdout:
            output += exc.stdout.decode("utf-8", errors="replace")
        if exc.stderr:
            output += exc.stderr.decode("utf-8", errors="replace")
        raise SystemExit(f"gpg failed with output:\n{output}") from exc
    return result.stdout


def run_tool(
    tool: str,
    args: list[str],
    *,
    env: dict[str, str],
    label: str,
) -> str:
    try:
        result = subprocess.run(
            [tool, *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"{label}:\n{exc.stdout}") from exc
    return result.stdout


if __name__ == "__main__":
    sys.exit(main())
