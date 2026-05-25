#!/usr/bin/env python3
"""Regression checks for release artifact smoke binary preflight."""

from __future__ import annotations

import importlib.util
import stat
import tempfile
import zipfile
from pathlib import Path


def main() -> int:
    smoke = load_smoke_helpers()

    with fixture_dir() as root:
        bin_dir = root / "bin"
        write_binaries(bin_dir, smoke)
        smoke.verify_archive_binaries(Path("fixture.zip"), bin_dir)

    with fixture_dir() as root:
        expect_failure(
            smoke,
            root / "missing-bin",
            "missing binary directory",
            "missing binary directory",
        )

    with fixture_dir() as root:
        bin_dir = root / "bin"
        write_binaries(bin_dir, smoke, skip="conud")
        expect_failure(smoke, bin_dir, "missing executable(s): conud", "missing binary")

    with fixture_dir() as root:
        bin_dir = root / "bin"
        write_binaries(bin_dir, smoke, skip="conu-relay")
        bin_dir.joinpath(f"conu-relay{smoke.binary_suffix()}").mkdir()
        expect_failure(
            smoke,
            bin_dir,
            "not a regular file: conu-relay",
            "directory named as binary",
        )

    with fixture_dir() as root:
        archive = root / "conu-0.1.0-test.zip"
        write_zip(archive, {"conu-0.1.0-test/manifest.toml": 'target = "host"\n'})
        target = smoke.read_manifest_target(archive)
        if target != "host":
            raise SystemExit(f"rooted manifest target: expected host, got {target}")

    with fixture_dir() as root:
        archive = root / "conu-0.1.0-test.zip"
        write_zip(archive, {"conu-9.9.9-test/manifest.toml": 'target = "host"\n'})
        expect_action_failure(
            lambda: smoke.read_manifest_target(archive),
            "unexpected archive root",
            "unexpected manifest root",
        )

    with fixture_dir() as root:
        archive = root / "conu-0.1.0-mixed.zip"
        write_zip(
            archive,
            {
                "manifest.toml": 'target = "host"\n',
                "conu-0.1.0-mixed/bin/conu": "placeholder",
            },
        )
        expect_action_failure(
            lambda: smoke.read_manifest_target(archive),
            "mixes rooted and rootless",
            "mixed manifest root style",
        )

    with fixture_dir() as root:
        archive = Path("conu-0.1.0-test.zip")
        expected_root = root / "conu-0.1.0-test"
        expected_root.mkdir()
        expected_root.joinpath("manifest.toml").write_text('target = "host"\n', encoding="utf-8")
        resolved = smoke.find_package_root(archive, root)
        if resolved != expected_root:
            raise SystemExit(f"rooted package root: expected {expected_root}, got {resolved}")

    with fixture_dir() as root:
        wrong_root = root / "conu-9.9.9-test"
        wrong_root.mkdir()
        wrong_root.joinpath("manifest.toml").write_text('target = "host"\n', encoding="utf-8")
        expect_action_failure(
            lambda: smoke.find_package_root(Path("conu-0.1.0-test.zip"), root),
            "unexpected archive root",
            "unexpected extracted root",
        )

    with fixture_dir() as root:
        archive = root / "conu-0.1.0-duplicate.zip"
        write_zip_entries(
            archive,
            [
                ("bin/conu", "first"),
                ("bin/./conu", "second"),
            ],
        )
        expect_action_failure(
            lambda: smoke.extract_archive(archive, root / "extract-duplicate"),
            "duplicate archive path",
            "duplicate extracted path",
        )

    with fixture_dir() as root:
        archive = root / "conu-0.1.0-too-large.zip"
        write_zip(archive, {"bin/conu": "too large"})
        original_limit = smoke.MAX_MEMBER_BYTES
        smoke.MAX_MEMBER_BYTES = 1
        try:
            expect_action_failure(
                lambda: smoke.extract_archive(archive, root / "extract-large"),
                "member is too large",
                "oversized extracted member",
            )
        finally:
            smoke.MAX_MEMBER_BYTES = original_limit

    with fixture_dir() as root:
        archive = root / "conu-0.1.0-too-many.zip"
        write_zip_entries(archive, [("one", "1"), ("two", "2")])
        original_limit = smoke.MAX_MEMBER_COUNT
        smoke.MAX_MEMBER_COUNT = 1
        try:
            expect_action_failure(
                lambda: smoke.extract_archive(archive, root / "extract-many"),
                "contains more than",
                "extracted entry count bound",
            )
        finally:
            smoke.MAX_MEMBER_COUNT = original_limit

    with fixture_dir() as root:
        archive = root / "conu-0.1.0-total.zip"
        write_zip_entries(archive, [("one", "1"), ("two", "2")])
        original_limit = smoke.MAX_TOTAL_UNCOMPRESSED_BYTES
        smoke.MAX_TOTAL_UNCOMPRESSED_BYTES = 1
        try:
            expect_action_failure(
                lambda: smoke.extract_archive(archive, root / "extract-total"),
                "uncompressed contents exceed",
                "extracted total size bound",
            )
        finally:
            smoke.MAX_TOTAL_UNCOMPRESSED_BYTES = original_limit

    with fixture_dir() as root:
        archive = root / "conu-0.1.0-unsupported.zip"
        info = zipfile.ZipInfo("device")
        info.external_attr = (stat.S_IFCHR | 0o644) << 16
        write_zip_infos(archive, [(info, b"device")])
        expect_action_failure(
            lambda: smoke.extract_archive(archive, root / "extract-unsupported"),
            "unsupported zip member",
            "unsupported zip member type",
        )

    print("release artifact smoke preflight check passed")
    return 0


def load_smoke_helpers():
    helper_path = Path(__file__).with_name("smoke-release-artifacts.py")
    spec = importlib.util.spec_from_file_location("conu_release_artifact_smoke", helper_path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"could not load helper script {helper_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class fixture_dir:
    def __enter__(self) -> Path:
        self.temp = tempfile.TemporaryDirectory(prefix="conu-release-smoke-preflight-")
        return Path(self.temp.name)

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.temp.cleanup()


def write_binaries(bin_dir: Path, smoke, skip: str | None = None) -> None:
    bin_dir.mkdir(parents=True, exist_ok=True)
    suffix = smoke.binary_suffix()
    for name in smoke.REQUIRED_BINARIES:
        if name == skip:
            continue
        bin_dir.joinpath(f"{name}{suffix}").write_text(name, encoding="utf-8")


def write_zip(path: Path, members: dict[str, bytes | str]) -> None:
    write_zip_entries(path, list(members.items()))


def write_zip_entries(path: Path, entries: list[tuple[str, bytes | str]]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as package:
        for name, content in entries:
            if isinstance(content, str):
                content = content.encode("utf-8")
            package.writestr(name, content)


def write_zip_infos(path: Path, entries: list[tuple[zipfile.ZipInfo, bytes]]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as package:
        for info, content in entries:
            package.writestr(info, content)


def expect_failure(smoke, bin_dir: Path, expected: str, label: str) -> None:
    expect_action_failure(
        lambda: smoke.verify_archive_binaries(Path("fixture.zip"), bin_dir),
        expected,
        label,
    )


def expect_action_failure(action, expected: str, label: str) -> None:
    try:
        action()
    except SystemExit as exc:
        message = str(exc)
        if expected in message:
            return
        raise SystemExit(f"{label}: expected {expected}, got: {message}") from exc
    raise SystemExit(f"{label}: expected smoke preflight failure")


if __name__ == "__main__":
    raise SystemExit(main())
