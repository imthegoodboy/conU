#!/usr/bin/env python3
"""Configure required GitHub Actions release secrets from local environment values."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from github_release_secrets import REQUIRED_RELEASE_SECRETS, find_gh, infer_repo


SCRIPT_DIR = Path(__file__).resolve().parent


def collect_env_values(names: tuple[str, ...]) -> tuple[dict[str, str], tuple[str, ...]]:
    values: dict[str, str] = {}
    missing: list[str] = []
    for name in names:
        value = os.environ.get(name)
        if value is None or value == "":
            missing.append(name)
        else:
            values[name] = value
    return values, tuple(missing)


def set_secret(gh: str, repo: str, name: str, value: str) -> None:
    result = subprocess.run(
        [gh, "secret", "set", name, "--repo", repo],
        check=False,
        encoding="utf-8",
        errors="replace",
        input=value,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise ValueError(f"gh secret set {name} failed with exit code {result.returncode}")


def run_value_preflights(*, require_openssl: bool, python_executable: str = sys.executable) -> None:
    platform_command = [
        python_executable,
        str(SCRIPT_DIR / "check-platform-signing-secrets-preflight.py"),
    ]
    if require_openssl:
        platform_command.append("--require-openssl")

    preflights: list[tuple[str, list[str]]] = [
        (
            "platform signing secret value preflight",
            platform_command,
        ),
        (
            "Linux signing secret preflight",
            [
                python_executable,
                str(SCRIPT_DIR / "check-linux-signing-secrets-preflight.py"),
            ],
        ),
    ]
    for name, command in preflights:
        result = subprocess.run(
            command,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if result.returncode != 0:
            raise ValueError(f"{name} failed with exit code {result.returncode}")


def print_secret_names(label: str, names: tuple[str, ...], stream) -> None:
    print(label, file=stream)
    for name in names:
        print(f"- {name}", file=stream)


def configure_release_secrets(
    repo: str,
    gh: str,
    values: dict[str, str],
    dry_run: bool,
) -> tuple[str, ...]:
    missing = tuple(name for name in REQUIRED_RELEASE_SECRETS if name not in values)
    if missing:
        raise ValueError("missing local environment values: " + ", ".join(missing))

    names = tuple(name for name in REQUIRED_RELEASE_SECRETS if name in values)
    if dry_run:
        return names

    for name in names:
        set_secret(gh, repo, name, values[name])
    return names


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo",
        default="",
        help="GitHub repository in owner/name form; defaults to GH_REPO or gh repo view",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate local environment values and print secret names without writing them",
    )
    parser.add_argument(
        "--preflight-values",
        action="store_true",
        help="run local signing secret value preflights before dry-run output or GitHub writes",
    )
    parser.add_argument(
        "--require-openssl",
        action="store_true",
        help="require OpenSSL-backed Windows/macOS PKCS#12 parsing when --preflight-values is used",
    )
    parser.add_argument(
        "--gh",
        default="",
        help=argparse.SUPPRESS,
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        repo_root = Path(__file__).resolve().parents[1]
        os.chdir(repo_root)
        if args.require_openssl and not args.preflight_values:
            raise ValueError("--require-openssl requires --preflight-values")

        values, missing = collect_env_values(REQUIRED_RELEASE_SECRETS)
        if missing:
            print_secret_names(
                "GitHub release secret setup failed: missing local environment values:",
                missing,
                sys.stderr,
            )
            return 1

        if args.preflight_values:
            run_value_preflights(require_openssl=args.require_openssl)

        gh = args.gh or find_gh()
        repo = args.repo.strip() or infer_repo(gh)
        configured = configure_release_secrets(repo, gh, values, args.dry_run)
    except (OSError, ValueError) as exc:
        print(f"GitHub release secret setup failed: {exc}", file=sys.stderr)
        return 1

    action = "would configure" if args.dry_run else "configured"
    print(
        f"GitHub release secret setup {action} {len(configured)} "
        f"required secret names for {repo}"
    )
    for name in configured:
        print(f"{action}: {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
