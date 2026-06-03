#!/usr/bin/env python3
"""Configure required GitHub Actions release secrets from local environment values."""

from __future__ import annotations

import argparse
import errno
import os
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Mapping

from github_release_secrets import (
    NPM_TOKEN_ROTATION_MARKER_VAR,
    NPM_TOKEN_ROTATION_REQUIRED_AFTER,
    NPM_TOKEN_SECRET_NAME,
    REQUIRED_RELEASE_SECRETS,
    find_gh,
    infer_repo,
    load_secret_metadata,
    normalize_repo,
)


SCRIPT_DIR = Path(__file__).resolve().parent
MAX_ENV_FILE_BYTES = 128 * 1024
OPEN_BINARY = getattr(os, "O_BINARY", 0)
OPEN_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
POSIX_ENV_FILE_FORBIDDEN_MODE = stat.S_IRWXG | stat.S_IRWXO
DRY_RUN_NPM_TOKEN_ROTATION_MARKER_FROM_UPDATED_AT = (
    "from NPM_TOKEN updatedAt after upload"
)


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
        env_text = read_env_file(path)
    except UnicodeDecodeError as exc:
        raise ValueError(f"env file must be UTF-8 text: {path}") from exc
    except OSError as exc:
        raise ValueError(f"env file is not readable: {path}") from exc

    lines = env_text.splitlines()
    for line_number, raw_line in enumerate(lines, start=1):
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        line = raw_line.lstrip()
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        if "=" not in line:
            raise ValueError(f"env file line {line_number} is not KEY=VALUE")
        key, value = line.split("=", 1)
        key = key.strip()
        if key not in allowed:
            raise ValueError(f"env file line {line_number} uses an unsupported key")
        if key in values:
            raise ValueError(f"env file line {line_number} duplicates key: {key}")
        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in ("'", '"')
        ):
            value = value[1:-1]
        values[key] = value
    return values


def read_env_file(path: Path) -> str:
    handle, _size = open_env_file(path)
    with handle:
        data = handle.read(MAX_ENV_FILE_BYTES + 1)
        if len(data) > MAX_ENV_FILE_BYTES:
            raise ValueError(f"env file is too large: {path}")
        validate_open_env_file(handle, path)
    return data.decode("utf-8")


def open_env_file(path: Path) -> tuple[BinaryIO, int]:
    if path.is_symlink():
        raise ValueError(f"env file must not be a symlink: {path}")
    if not path.exists():
        raise ValueError(f"env file is not readable: {path}")
    flags = os.O_RDONLY | OPEN_BINARY | OPEN_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(f"env file must not be a symlink: {path}") from exc
        if not path.exists():
            raise ValueError(f"env file is not readable: {path}") from exc
        if not path.is_file():
            raise ValueError(f"env file is not a regular file: {path}") from exc
        raise
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"env file is not a regular file: {path}")
        validate_env_file_permissions(metadata.st_mode, path)
        size = metadata.st_size
        if size > MAX_ENV_FILE_BYTES:
            raise ValueError(f"env file is too large: {path}")
        return os.fdopen(fd, "rb"), size
    except BaseException:
        os.close(fd)
        raise


def validate_open_env_file(handle: BinaryIO, path: Path) -> int:
    metadata = os.fstat(handle.fileno())
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"env file is not a regular file: {path}")
    validate_env_file_permissions(metadata.st_mode, path)
    size = metadata.st_size
    if size > MAX_ENV_FILE_BYTES:
        raise ValueError(f"env file is too large: {path}")
    return size


def validate_env_file_permissions(mode: int, path: Path) -> None:
    if os.name != "posix":
        return
    if mode & POSIX_ENV_FILE_FORBIDDEN_MODE:
        raise ValueError(
            "env file permissions must not allow group or other access: "
            f"{path}"
        )


def missing_required_values(values: Mapping[str, str], names: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(
        name
        for name in names
        if (value := values.get(name)) is None or value.strip() == ""
    )


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


def set_variable(gh: str, repo: str, name: str, value: str) -> None:
    result = subprocess.run(
        [gh, "variable", "set", name, "--repo", repo, "--body", value],
        check=False,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise ValueError(f"gh variable set {name} failed with exit code {result.returncode}")


def parse_utc_timestamp(value: str, label: str) -> datetime:
    raw = value.strip()
    if not raw:
        raise ValueError(f"{label} timestamp must not be empty")
    if raw.endswith("Z"):
        raw = f"{raw[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise ValueError(f"{label} timestamp must be ISO-8601 with a timezone") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def render_utc_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_npm_rotation_marker_timestamp(value: str) -> str:
    observed = parse_utc_timestamp(value, NPM_TOKEN_ROTATION_MARKER_VAR)
    required = parse_utc_timestamp(
        NPM_TOKEN_ROTATION_REQUIRED_AFTER,
        f"{NPM_TOKEN_ROTATION_MARKER_VAR} minimum",
    )
    if observed <= required:
        raise ValueError(
            f"{NPM_TOKEN_ROTATION_MARKER_VAR} timestamp must be after "
            f"{render_utc_timestamp(required)}"
        )
    return render_utc_timestamp(observed)


def load_npm_rotation_marker_timestamp_from_secret_metadata(repo: str, gh: str) -> str:
    records = load_secret_metadata(repo, gh)
    record = records.get(NPM_TOKEN_SECRET_NAME)
    if record is None or not record.updated_at:
        raise ValueError(
            f"{NPM_TOKEN_SECRET_NAME} secret metadata is missing; "
            f"rotate and upload {NPM_TOKEN_SECRET_NAME} before setting "
            f"{NPM_TOKEN_ROTATION_MARKER_VAR}"
        )
    return normalize_npm_rotation_marker_timestamp(record.updated_at)


def configure_npm_rotation_marker(
    repo: str,
    gh: str,
    timestamp: str,
    confirm_rotated: bool,
    dry_run: bool,
) -> str:
    if not confirm_rotated:
        raise ValueError(
            "--set-npm-token-rotation-marker requires --confirm-npm-token-rotated"
        )
    normalized = normalize_npm_rotation_marker_timestamp(timestamp)
    if not dry_run:
        set_variable(gh, repo, NPM_TOKEN_ROTATION_MARKER_VAR, normalized)
    return normalized


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
        (
            "npm token authentication preflight",
            [
                python_executable,
                str(SCRIPT_DIR / "check-npm-publish-preflight.py"),
                "--require-token-env",
                "NPM_TOKEN",
                "--token-auth-check",
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


def require_npm_rotation_marker_for_token_write(
    *,
    values: Mapping[str, str],
    marker_requested: bool,
    dry_run: bool,
) -> None:
    # Dry-run must fail like the real write so setup checks cannot bless a stale token.
    if marker_requested:
        return
    if (value := values.get(NPM_TOKEN_SECRET_NAME)) is None or value.strip() == "":
        return
    raise ValueError(
        f"{NPM_TOKEN_SECRET_NAME} setup requires "
        f"{NPM_TOKEN_ROTATION_MARKER_VAR}; add "
        "--set-npm-token-rotation-marker-from-secret-updated-at "
        "--confirm-npm-token-rotated after rotating the token"
    )


def should_defer_npm_rotation_marker_updated_at(
    *,
    dry_run: bool,
    derive_from_secret_updated_at: bool,
    secret_setup_requested: bool,
    values: Mapping[str, str],
) -> bool:
    if not (dry_run and derive_from_secret_updated_at and secret_setup_requested):
        return False
    return values.get(NPM_TOKEN_SECRET_NAME, "").strip() != ""


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
        "--set-npm-token-rotation-marker",
        default="",
        metavar="ISO-8601_TIMESTAMP",
        help=(
            "set non-secret GitHub variable "
            f"{NPM_TOKEN_ROTATION_MARKER_VAR} after NPM_TOKEN has been rotated; "
            f"timestamp must be after {NPM_TOKEN_ROTATION_REQUIRED_AFTER}"
        ),
    )
    parser.add_argument(
        "--allow-unverified-npm-token-rotation-marker",
        action="store_true",
        help=(
            "allow manual NPM rotation marker timestamps without checking GitHub "
            f"{NPM_TOKEN_SECRET_NAME} updatedAt metadata; prefer "
            "--set-npm-token-rotation-marker-from-secret-updated-at"
        ),
    )
    parser.add_argument(
        "--confirm-npm-token-rotated",
        action="store_true",
        help=(
            "confirm NPM_TOKEN was rotated before setting the non-secret "
            f"{NPM_TOKEN_ROTATION_MARKER_VAR} variable"
        ),
    )
    parser.add_argument(
        "--set-npm-token-rotation-marker-from-secret-updated-at",
        action="store_true",
        help=(
            "set non-secret GitHub variable "
            f"{NPM_TOKEN_ROTATION_MARKER_VAR} from GitHub's "
            f"{NPM_TOKEN_SECRET_NAME} updatedAt metadata after confirmed rotation"
        ),
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
            or args.set_npm_token_rotation_marker
            or args.allow_unverified_npm_token_rotation_marker
            or args.confirm_npm_token_rotated
            or args.set_npm_token_rotation_marker_from_secret_updated_at
        ):
            raise ValueError("env template generation cannot be combined with setup options")
        if args.check_env_file:
            if not args.env_file:
                raise ValueError("--check-env-file requires --env-file")
            if (
                args.dry_run
                or args.env_file_only
                or args.preflight_values
                or args.require_openssl
                or args.set_npm_token_rotation_marker
                or args.allow_unverified_npm_token_rotation_marker
                or args.confirm_npm_token_rotated
                or args.set_npm_token_rotation_marker_from_secret_updated_at
            ):
                raise ValueError("--check-env-file cannot be combined with setup options")
        if args.require_openssl and not args.preflight_values:
            raise ValueError("--require-openssl requires --preflight-values")
        if args.env_file_only and not args.env_file:
            raise ValueError("--env-file-only requires --env-file")
        if (
            args.set_npm_token_rotation_marker
            and args.set_npm_token_rotation_marker_from_secret_updated_at
        ):
            raise ValueError(
                "--set-npm-token-rotation-marker and "
                "--set-npm-token-rotation-marker-from-secret-updated-at are mutually exclusive"
            )
        if (
            args.allow_unverified_npm_token_rotation_marker
            and not args.set_npm_token_rotation_marker
        ):
            raise ValueError(
                "--allow-unverified-npm-token-rotation-marker requires "
                "--set-npm-token-rotation-marker"
            )
        if (
            args.set_npm_token_rotation_marker
            and not args.allow_unverified_npm_token_rotation_marker
        ):
            raise ValueError(
                "--set-npm-token-rotation-marker requires "
                "--allow-unverified-npm-token-rotation-marker; prefer "
                "--set-npm-token-rotation-marker-from-secret-updated-at"
            )
        marker_option_requested = bool(
            args.set_npm_token_rotation_marker
            or args.set_npm_token_rotation_marker_from_secret_updated_at
        )
        if args.confirm_npm_token_rotated and not marker_option_requested:
            raise ValueError(
                "--confirm-npm-token-rotated requires a NPM token rotation marker setup option"
            )
        if marker_option_requested and not args.confirm_npm_token_rotated:
            raise ValueError(
                "NPM token rotation marker setup requires --confirm-npm-token-rotated"
            )
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

        marker_requested = marker_option_requested
        secret_setup_requested = (
            not marker_requested
            or bool(args.env_file)
            or args.env_file_only
            or args.preflight_values
        )
        marker_timestamp = ""
        if args.set_npm_token_rotation_marker:
            marker_timestamp = normalize_npm_rotation_marker_timestamp(
                args.set_npm_token_rotation_marker
            )

        configured: tuple[str, ...] = ()
        if secret_setup_requested:
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
            require_npm_rotation_marker_for_token_write(
                values=values,
                marker_requested=marker_requested,
                dry_run=args.dry_run,
            )

            if args.preflight_values:
                run_value_preflights(require_openssl=args.require_openssl, values=values)
        else:
            values = {}

        gh = args.gh or find_gh()
        repo = normalize_repo(args.repo.strip() or infer_repo(gh))
        if secret_setup_requested:
            configured = configure_release_secrets(repo, gh, values, args.dry_run)
        if marker_requested:
            if args.set_npm_token_rotation_marker_from_secret_updated_at:
                if should_defer_npm_rotation_marker_updated_at(
                    dry_run=args.dry_run,
                    derive_from_secret_updated_at=True,
                    secret_setup_requested=secret_setup_requested,
                    values=values,
                ):
                    marker_timestamp = DRY_RUN_NPM_TOKEN_ROTATION_MARKER_FROM_UPDATED_AT
                else:
                    marker_timestamp = load_npm_rotation_marker_timestamp_from_secret_metadata(
                        repo,
                        gh,
                    )
            if marker_timestamp == DRY_RUN_NPM_TOKEN_ROTATION_MARKER_FROM_UPDATED_AT:
                if not args.dry_run:
                    raise ValueError("internal error: deferred npm rotation marker requires --dry-run")
            else:
                marker_timestamp = configure_npm_rotation_marker(
                    repo,
                    gh,
                    marker_timestamp or args.set_npm_token_rotation_marker,
                    args.confirm_npm_token_rotated,
                    args.dry_run,
                )
    except (OSError, ValueError) as exc:
        action = (
            "GitHub release secret env file check failed"
            if getattr(args, "check_env_file", False)
            else "GitHub release secret setup failed"
        )
        print(f"{action}: {exc}", file=sys.stderr)
        return 1

    action = "would configure" if args.dry_run else "configured"
    if configured:
        print(
            f"GitHub release secret setup {action} {len(configured)} "
            f"required secret names for {repo}"
        )
        for name in configured:
            print(f"{action}: {name}")
    if marker_timestamp:
        print(
            f"GitHub release variable setup {action} "
            f"{NPM_TOKEN_ROTATION_MARKER_VAR}={marker_timestamp} for {repo}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
