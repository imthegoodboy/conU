"""Shared helpers for conU Linux release GPG signing scripts."""

from __future__ import annotations

import re
import subprocess

from command_output_redaction import redact_command_output


DEFAULT_FINGERPRINT_ENV = "CONU_LINUX_GPG_KEY_FINGERPRINT"
FINGERPRINT_RE = re.compile(r"^[0-9A-F]{40}$")


def add_fingerprint_env_argument(parser) -> None:
    parser.add_argument(
        "--fingerprint-env",
        default=DEFAULT_FINGERPRINT_ENV,
        help="environment variable containing the expected full maintainer GPG fingerprint",
    )


def normalize_fingerprint(value: str, env_name: str) -> str:
    compact = value.strip()
    if compact.startswith(("0x", "0X")):
        compact = compact[2:]
    compact = re.sub(r"[\s:]", "", compact).upper()
    if FINGERPRINT_RE.fullmatch(compact) is None:
        raise SystemExit(f"{env_name} must contain a full 40-hex-character GPG fingerprint")
    return compact


def read_expected_fingerprint(env: dict[str, str], env_name: str) -> str:
    value = env.get(env_name)
    if value is None or value == "":
        raise SystemExit(f"missing required environment variable: {env_name}")
    return normalize_fingerprint(value, env_name)


def verify_imported_secret_key_fingerprint(
    gpg: str,
    env: dict[str, str],
    key_id: str,
    expected_fingerprint: str,
) -> None:
    output = run_gpg_text(
        gpg,
        env,
        ["--with-colons", "--fingerprint", "--list-secret-keys", key_id],
    )
    fingerprints = primary_secret_fingerprints(output)
    if len(fingerprints) != 1:
        raise SystemExit(
            "Linux GPG key id must resolve to exactly one primary secret key "
            f"(found {len(fingerprints)} primary secret key(s))"
        )
    actual = fingerprints[0]
    if actual != expected_fingerprint:
        raise SystemExit("Linux GPG signing key fingerprint mismatch")


def primary_secret_fingerprints(colon_listing: str) -> list[str]:
    fingerprints: list[str] = []
    waiting_for_primary_fingerprint = False
    for line in colon_listing.splitlines():
        parts = line.split(":")
        if not parts:
            continue
        record_type = parts[0]
        if record_type == "sec":
            waiting_for_primary_fingerprint = True
            continue
        if record_type == "fpr" and waiting_for_primary_fingerprint:
            if len(parts) > 9 and parts[9]:
                fingerprints.append(normalize_fingerprint(parts[9], "imported GPG fingerprint"))
            waiting_for_primary_fingerprint = False
            continue
        if record_type in {"pub", "ssb", "sub"}:
            waiting_for_primary_fingerprint = False
    return fingerprints


def run_gpg_text(gpg: str, env: dict[str, str], args: list[str]) -> str:
    try:
        result = subprocess.run(
            [gpg, "--batch", "--yes", "--no-tty", *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
        )
    except subprocess.CalledProcessError as exc:
        output = exc.stdout.decode("utf-8", errors="replace") if exc.stdout else ""
        raise SystemExit(f"gpg failed with output:\n{redact_command_output(output)}") from exc
    return result.stdout.decode("utf-8", errors="replace")
