#!/usr/bin/env python3
"""Regression checks for package-manager manifest generation."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = ROOT / "scripts" / "generate-package-manager-manifests.py"
VERSION = "0.1.0"
TARGETS = {
    "macos-arm64": f"conu-{VERSION}-macos-arm64.zip",
    "macos-x64": f"conu-{VERSION}-macos-x64.zip",
    "linux-arm64": f"conu-{VERSION}-linux-arm64.tar.gz",
    "linux-x64": f"conu-{VERSION}-linux-x64.tar.gz",
    "windows-x64": f"conu-{VERSION}-windows-x64.zip",
}
WINDOWS_BINARIES = ("conu", "conud", "conu-relay", "conu-mcp")
HOMEBREW_FILENAME = "conu.rb"
SCOOP_FILENAME = "conu.json"


def load_generator():
    spec = importlib.util.spec_from_file_location(
        "generate_package_manager_manifests",
        GENERATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load package-manager manifest generator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_checksum(path: Path, archive_name: str | None = None) -> str:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    path.with_name(f"{path.name}.sha256").write_text(
        f"{digest}  {archive_name or path.name}\n",
        encoding="ascii",
    )
    return digest


def write_windows_zip(path: Path, *, rooted: bool) -> str:
    root = f"conu-{VERSION}-windows-x64/" if rooted else ""
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as package:
        for binary in WINDOWS_BINARIES:
            package.writestr(f"{root}bin/{binary}.exe", f"{binary}\n")
    return write_checksum(path)


def write_dist(root: Path, *, rooted_windows: bool = False) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for target, filename in TARGETS.items():
        archive = root / filename
        if target == "windows-x64":
            hashes[target] = write_windows_zip(archive, rooted=rooted_windows)
        else:
            archive.write_bytes(f"{target}\n".encode("ascii"))
            hashes[target] = write_checksum(archive)
    return hashes


def generate(generator, dist: Path, output: Path) -> None:
    assets = generator.load_release_assets(
        dist,
        VERSION,
        "imthegoodboy/conU",
        f"v{VERSION}",
    )
    windows_extract_dir = generator.detect_windows_extract_dir(
        dist / assets["windows-x64"].filename,
        VERSION,
    )
    output.mkdir(parents=True, exist_ok=True)
    homebrew = generator.render_homebrew_formula(VERSION, "imthegoodboy/conU", assets)
    scoop = generator.render_scoop_manifest(
        VERSION,
        "imthegoodboy/conU",
        assets["windows-x64"],
        windows_extract_dir,
    )
    generator.assert_output_safe(homebrew + "\n" + scoop, dist)
    (output / HOMEBREW_FILENAME).write_text(homebrew, encoding="ascii", newline="\n")
    (output / SCOOP_FILENAME).write_text(scoop, encoding="ascii", newline="\n")


def expect_failure(description: str, action, expected: str) -> None:
    try:
        action()
    except SystemExit as exc:
        message = str(exc)
        if expected not in message:
            raise AssertionError(
                f"{description} failed with {message!r}, expected {expected!r}"
            ) from exc
        return
    raise AssertionError(f"{description} unexpectedly passed")


def assert_no_forbidden_output(path: Path, temp: Path) -> None:
    text = path.read_text(encoding="ascii")
    forbidden = [
        str(temp).replace("\\", "/"),
        "NPM_TOKEN",
        "CONU_RELAY_TOKEN",
        "token_sha256_hex",
        "payloadHex",
        "BEGIN PRIVATE KEY",
    ]
    normalized = text.replace("\\", "/")
    for literal in forbidden:
        if literal and literal in normalized:
            raise AssertionError(f"{path.name} contained forbidden literal {literal!r}")


def main() -> int:
    generator = load_generator()
    if generator.validate_version("1.2.3-rc.1+build.5") != "1.2.3-rc.1+build.5":
        raise AssertionError("package-manager generator rejected semver prerelease plus build metadata")
    with tempfile.TemporaryDirectory(prefix="conu-package-manifest-") as temp_text:
        temp = Path(temp_text)

        rootless_dist = temp / "rootless-dist"
        rootless_out = temp / "rootless-out"
        rootless_dist.mkdir()
        hashes = write_dist(rootless_dist, rooted_windows=False)
        generate(generator, rootless_dist, rootless_out)

        homebrew = (rootless_out / HOMEBREW_FILENAME).read_text(encoding="ascii")
        if "class Conu < Formula" not in homebrew:
            raise AssertionError("homebrew formula class was missing")
        if "license :cannot_represent" not in homebrew:
            raise AssertionError("homebrew formula did not use a Homebrew-compatible license")
        if 'pipe_output("#{bin}/conu-mcp", "", 0)' not in homebrew or "conu-mcp\", \"--help\"" in homebrew:
            raise AssertionError("homebrew formula did not close stdin for the conu-mcp smoke test")
        if TARGETS["macos-arm64"] not in homebrew or hashes["macos-arm64"] not in homebrew:
            raise AssertionError("homebrew formula did not include macOS arm64 asset and hash")
        if TARGETS["linux-x64"] not in homebrew or hashes["linux-x64"] not in homebrew:
            raise AssertionError("homebrew formula did not include Linux x64 asset and hash")
        assert_no_forbidden_output(rootless_out / HOMEBREW_FILENAME, temp)

        scoop = json.loads((rootless_out / SCOOP_FILENAME).read_text(encoding="ascii"))
        if scoop["architecture"]["64bit"]["hash"] != hashes["windows-x64"]:
            raise AssertionError("scoop manifest did not use the Windows release hash")
        if "extract_dir" in scoop:
            raise AssertionError("rootless Windows archive should not set extract_dir")
        if ["bin\\conu.exe", "conu"] not in scoop["bin"]:
            raise AssertionError("scoop manifest did not expose conu")
        assert_no_forbidden_output(rootless_out / SCOOP_FILENAME, temp)

        rooted_dist = temp / "rooted-dist"
        rooted_out = temp / "rooted-out"
        rooted_dist.mkdir()
        write_dist(rooted_dist, rooted_windows=True)
        generate(generator, rooted_dist, rooted_out)
        rooted_scoop = json.loads((rooted_out / SCOOP_FILENAME).read_text(encoding="ascii"))
        if rooted_scoop.get("extract_dir") != f"conu-{VERSION}-windows-x64":
            raise AssertionError("rooted Windows archive should set extract_dir")

        missing_checksum = temp / "missing-checksum"
        missing_checksum.mkdir()
        write_dist(missing_checksum)
        (missing_checksum / f"{TARGETS['linux-x64']}.sha256").unlink()
        expect_failure(
            "missing checksum",
            lambda: generator.load_release_assets(
                missing_checksum,
                VERSION,
                "imthegoodboy/conU",
                f"v{VERSION}",
            ),
            "missing checksum file",
        )

        wrong_name = temp / "wrong-name"
        wrong_name.mkdir()
        write_dist(wrong_name)
        windows_archive = wrong_name / TARGETS["windows-x64"]
        write_checksum(windows_archive, archive_name="other.zip")
        expect_failure(
            "checksum names wrong archive",
            lambda: generator.load_release_assets(
                wrong_name,
                VERSION,
                "imthegoodboy/conU",
                f"v{VERSION}",
            ),
            "names wrong archive",
        )

        wrong_digest = temp / "wrong-digest"
        wrong_digest.mkdir()
        write_dist(wrong_digest)
        linux_archive = wrong_digest / TARGETS["linux-x64"]
        linux_archive.with_name(f"{linux_archive.name}.sha256").write_text(
            f"{'0' * 64}  {linux_archive.name}\n",
            encoding="ascii",
        )
        expect_failure(
            "checksum mismatch",
            lambda: generator.load_release_assets(
                wrong_digest,
                VERSION,
                "imthegoodboy/conU",
                f"v{VERSION}",
            ),
            "checksum mismatch",
        )

    print("package-manager manifest generation regressions passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
