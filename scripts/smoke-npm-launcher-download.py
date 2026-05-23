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

    dist = args.dist.resolve()
    package_dir = args.package_dir.resolve()
    if not package_dir.joinpath("package.json").exists():
        raise SystemExit(f"missing npm package manifest in {package_dir}")

    local_smoke = load_local_smoke_helpers()
    node = local_smoke.require_tool("node")
    npm = local_smoke.require_tool("npm", "npm.cmd")

    archives = sorted(dist.glob("*.zip")) + sorted(dist.glob("*.tar.gz"))
    if not archives:
        raise SystemExit(f"no release archives found in {dist}")

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
