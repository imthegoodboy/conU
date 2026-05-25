#!/usr/bin/env python3
"""Configure required GitHub Actions release secrets from local environment values."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Mapping

from github_release_secrets import REQUIRED_RELEASE_SECRETS, find_gh, infer_repo


SCRIPT_DIR = Path(__file__).resolve().parent


def render_env_template(names: tuple[str, ...]) -> str:
    lines = [
        "# conU release secret values",
        "# Fill these values locally, keep this file ignored, then run:",
        "# python scripts/set-github-release-secrets.py --env-file .env.release --check-env-file",
        "# python scripts/set-github-release-secrets.py --repo <owner/name> --env-file .env.release --env-file-only --dry-run --preflight-values --require-openssl",
        "",
    ]
    lines.extend(f"{name}=" for name in names)
    return "\n".join(lines) + "\n"


def write_env_template(path: Path, names: tuple[str, ...]) -> None:
    if path.exists():
        raise ValueError(f"env template file already exists: {path}")
    if path.parent and not path.parent.exists():
        raise ValueError(f"env template parent directory does not exist: {path.parent}")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise ValueError(f"could not create env template file: {path}") from exc
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(render_env_template(names))


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


def load_env_file_values(path: Path, names: tuple[str, ...]) -> dict[str, str]:
    allowed = set(names)
    values: dict[str, str] = {}
    try:
        stat = path.stat()
    except OSError as exc:
        raise ValueError(f"env file is not readable: {path}") from exc
    if not path.is_file():
        raise ValueError(f"env file is not a regular file: {path}")
    if stat.st_size > 128 * 1024:
        raise ValueError(f"env file is too large: {path}")

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError(f"env file must be UTF-8 text: {path}") from exc
    except OSError as exc:
        raise ValueError(f"env file is not readable: {path}") from exc

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            raise ValueError(f"env file line {line_number} is not KEY=VALUE")
        key, value = line.split("=", 1)
        key = key.strip()
        if key not in allowed:
            raise ValueError(f"env file line {line_number} uses an unsupported key")
        if key in values:
            raise ValueError(f"env file line {line_number} duplicates key: {key}")
        value = value.strip()
        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in ("'", '"')
        ):
            value = value[1:-1]
        values[key] = value
    return values


def missing_required_values(values: Mapping[str, str], names: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(name for name in names if not values.get(name))


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


def run_value_preflights(
    *,
    require_openssl: bool,
    values: Mapping[str, str] | None = None,
    python_executable: str = sys.executable,
) -> None:
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
    env = None
    if values is not None:
        env = os.environ.copy()
        env.update(values)
    for name, command in preflights:
        result = subprocess.run(
            command,
            check=False,
            env=env,
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
    missing = missing_required_values(values, REQUIRED_RELEASE_SECRETS)
    if missing:
        raise ValueError("missing local release secret values: " + ", ".join(missing))

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
        "--env-file",
        default="",
        help=(
            "optional UTF-8 KEY=VALUE file containing release secret values; "
            "supported keys are the required release secret names only"
        ),
    )
    parser.add_argument(
        "--env-file-only",
        action="store_true",
        help="require all release secret values to come from --env-file, ignoring local environment values",
    )
    parser.add_argument(
        "--check-env-file",
        action="store_true",
        help=(
            "validate --env-file contains every required release secret name with "
            "a non-empty value, then exit without GitHub CLI access"
        ),
    )
    parser.add_argument(
        "--print-env-template",
        action="store_true",
        help="print an empty release-secret env-file template and exit",
    )
    parser.add_argument(
        "--write-env-template",
        default="",
        help="write an empty release-secret env-file template; refuses to overwrite",
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
        if args.print_env_template and args.write_env_template:
            raise ValueError("--print-env-template and --write-env-template are mutually exclusive")
        if (args.print_env_template or args.write_env_template) and (
            args.dry_run
            or args.env_file
            or args.env_file_only
            or args.check_env_file
            or args.preflight_values
            or args.require_openssl
        ):
            raise ValueError("env template generation cannot be combined with setup options")
        if args.check_env_file:
            if not args.env_file:
                raise ValueError("--check-env-file requires --env-file")
            if args.dry_run or args.env_file_only or args.preflight_values or args.require_openssl:
                raise ValueError("--check-env-file cannot be combined with setup options")
        if args.require_openssl and not args.preflight_values:
            raise ValueError("--require-openssl requires --preflight-values")
        if args.env_file_only and not args.env_file:
            raise ValueError("--env-file-only requires --env-file")
        if args.print_env_template:
            print(render_env_template(REQUIRED_RELEASE_SECRETS), end="")
            return 0
        if args.write_env_template:
            write_env_template(Path(args.write_env_template).expanduser(), REQUIRED_RELEASE_SECRETS)
            print(f"GitHub release secret env template written: {args.write_env_template}")
            return 0
        if args.check_env_file:
            values = load_env_file_values(
                Path(args.env_file).expanduser(), REQUIRED_RELEASE_SECRETS
            )
            missing = missing_required_values(values, REQUIRED_RELEASE_SECRETS)
            if missing:
                print_secret_names(
                    "GitHub release secret env file check failed: missing required env-file values:",
                    missing,
                    sys.stderr,
                )
                return 1
            print(
                "GitHub release secret env file check passed: "
                f"{len(REQUIRED_RELEASE_SECRETS)} required secret names have non-empty values"
            )
            for name in REQUIRED_RELEASE_SECRETS:
                print(f"present: {name}")
            return 0

        if args.env_file_only:
            values = {}
        else:
            values, _missing = collect_env_values(REQUIRED_RELEASE_SECRETS)
        if args.env_file:
            values.update(
                load_env_file_values(Path(args.env_file).expanduser(), REQUIRED_RELEASE_SECRETS)
            )
        missing = missing_required_values(values, REQUIRED_RELEASE_SECRETS)
        if missing:
            print_secret_names(
                "GitHub release secret setup failed: missing local release secret values:",
                missing,
                sys.stderr,
            )
            return 1

        if args.preflight_values:
            run_value_preflights(require_openssl=args.require_openssl, values=values)

        gh = args.gh or find_gh()
        repo = args.repo.strip() or infer_repo(gh)
        configured = configure_release_secrets(repo, gh, values, args.dry_run)
    except (OSError, ValueError) as exc:
        action = (
            "GitHub release secret env file check failed"
            if getattr(args, "check_env_file", False)
            else "GitHub release secret setup failed"
        )
        print(f"{action}: {exc}", file=sys.stderr)
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
