#!/usr/bin/env python3
"""Smoke test the @conu/cli npm launcher download installer path."""

from __future__ import annotations

import argparse
import functools
import http.server
import importlib.util
import os
import socketserver
import sys
import tempfile
import threading
from pathlib import Path

from json_safety import load_json_object


DEFAULT_PACKAGE_DIR = Path("packaging/npm/conu-cli")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist", type=Path, help="directory containing release archives")
    parser.add_argument(
        "--package-dir",
        type=Path,
        default=DEFAULT_PACKAGE_DIR,
        help="path to the @conu/cli package directory",
    )
    args = parser.parse_args()

    local_smoke = load_local_smoke_helpers()
    dist = local_smoke.validate_input_directory(args.dist, "release dist directory")
    package_dir = local_smoke.validate_package_directory(
        args.package_dir,
        "@conu/cli package directory",
    )

    node = local_smoke.require_tool("node")
    npm = local_smoke.require_tool("npm", "npm.cmd")
    expected_asset_name = npm_asset_name(package_dir, local_smoke)

    archives = sorted(dist.glob("*.zip")) + sorted(dist.glob("*.tar.gz"))
    if not archives:
        raise SystemExit(f"no release archives found in {dist}")
    validate_served_dist_assets(dist)

    smoked = 0
    skipped = 0
    with LocalArtifactServer(dist) as release_base:
        with tempfile.TemporaryDirectory(prefix="conu-npm-download-smoke-") as temp_dir:
            temp_root = Path(temp_dir)
            for archive in archives:
                target = local_smoke.read_manifest_target(archive)
                if not local_smoke.target_is_current_platform(target):
                    skipped += 1
                    print(f"skipping {archive.name}: target {target!r} is not this runner")
                    continue

                if archive.name != expected_asset_name:
                    expected_archive = dist / expected_asset_name
                    expected_checksum = expected_archive.with_name(f"{expected_archive.name}.sha256")
                    if (
                        target.lower() == "host"
                        and expected_archive.exists()
                        and expected_checksum.exists()
                    ):
                        skipped += 1
                        print(
                            f"skipping {archive.name}: host archive alias; "
                            f"npm downloads {expected_asset_name}"
                        )
                        continue
                    raise SystemExit(
                        f"{archive.name} targets this runner, but the npm installer downloads "
                        f"{expected_asset_name}; provide that platform-named archive and checksum"
                    )

                checksum = archive.with_name(f"{archive.name}.sha256")
                if not checksum.exists():
                    raise SystemExit(f"{archive.name} missing sibling checksum file {checksum.name}")

                prefix = temp_root / f"{local_smoke.archive_stem(archive)}-npm-download"
                install_npm_package_from_release_base(
                    archive,
                    npm,
                    package_dir,
                    prefix,
                    release_base,
                    local_smoke,
                )
                local_smoke.smoke_installed_launcher(archive, node, prefix, temp_root)
                print(f"smoked {archive.name}: npm launcher download install verified checksum")
                smoked += 1

    if smoked == 0:
        raise SystemExit("no current-platform release archives were npm-download-smoke tested")

    print(f"smoked {smoked} conU npm launcher download install(s); skipped {skipped}")
    return 0


def load_local_smoke_helpers():
    helper_path = Path(__file__).with_name("smoke-npm-launcher-local.py")
    spec = importlib.util.spec_from_file_location("conu_npm_launcher_local_smoke", helper_path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"could not load helper script {helper_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def npm_asset_name(package_dir: Path, local_smoke) -> str:
    manifest = load_json_object(package_dir.joinpath("package.json"), encoding="utf-8")
    version = manifest.get("version")
    if not isinstance(version, str) or not version:
        raise SystemExit(f"{package_dir / 'package.json'} missing package version")

    platform_key = local_smoke.npm_platform_key()
    extension = ".tar.gz" if platform_key.startswith("linux-") else ".zip"
    return f"conu-{version}-{platform_key}{extension}"


def validate_served_dist_assets(dist: Path) -> None:
    for root, dir_names, file_names in os.walk(dist, followlinks=False):
        root_path = Path(root)
        for name in sorted([*dir_names, *file_names]):
            path = root_path / name
            relative = path.relative_to(dist).as_posix()
            if path.is_symlink():
                raise SystemExit(
                    f"npm download smoke served asset must not be a symlink: {relative}"
                )
            if not path.is_dir() and not path.is_file():
                raise SystemExit(
                    "npm download smoke served asset must be a regular file or directory: "
                    f"{relative}"
                )


def install_npm_package_from_release_base(
    archive: Path,
    npm: str,
    package_dir: Path,
    prefix: Path,
    release_base: str,
    local_smoke,
) -> None:
    env = os.environ.copy()
    env["CONU_NPM_DIST_BASE"] = release_base
    for name in ("CONU_NPM_BINARY_DIR", "CONU_NPM_SKIP_DOWNLOAD", "CONU_NPM_ALLOW_UNVERIFIED"):
        env.pop(name, None)

    output = local_smoke.run_command(
        archive,
        [
            npm,
            "install",
            "--prefix",
            str(prefix),
            "--foreground-scripts",
            "--no-audit",
            "--no-fund",
            str(package_dir),
        ],
        env,
    )

    install_output = f"{output.stdout}\n{output.stderr}"
    expected = f"installed conU native binaries for {archive.name}"
    if expected not in install_output:
        raise SystemExit(
            f"{archive.name} npm install did not report download-backed native install\n"
            f"stdout:\n{local_smoke.safe_snippet(output.stdout)}\n"
            f"stderr:\n{local_smoke.safe_snippet(output.stderr)}"
        )


class QuietArtifactHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return


class ThreadingArtifactServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


class LocalArtifactServer:
    def __init__(self, directory: Path):
        handler = functools.partial(QuietArtifactHandler, directory=str(directory))
        self.server = ThreadingArtifactServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> str:
        self.thread.start()
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


if __name__ == "__main__":
    sys.exit(main())
