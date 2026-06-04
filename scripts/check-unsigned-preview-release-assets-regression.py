#!/usr/bin/env python3
"""Regression checks for unsigned preview release asset readiness."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-unsigned-preview-release-assets.py")
VERSION = "0.1.0"
TAG = "preview-12345"


def load_module():
    spec = importlib.util.spec_from_file_location("check_unsigned_preview_release_assets", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load unsigned preview release asset module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_preview_dist(path: Path, module, *, omit: str = "", extra: str = "") -> None:
    path.mkdir(parents=True, exist_ok=True)
    for name in module.expected_preview_asset_names(VERSION):
        if name == omit:
            continue
        (path / name).write_bytes(b"public preview artifact bytes")
    if extra:
        (path / extra).write_bytes(b"unexpected public preview artifact bytes")


def assert_safe_report(report) -> dict:
    payload = report.as_json()
    rendered = json.dumps(payload)
    forbidden = (
        "do-not-print-this-token-or-payload",
        "BEGIN PGP PRIVATE KEY BLOCK",
        "private message contents",
    )
    for value in forbidden:
        if value in rendered:
            raise AssertionError(f"readiness report leaked forbidden value: {value}")
    return payload


def github_asset(name: str, index: int) -> dict[str, object]:
    return {
        "name": name,
        "size": 12 + index,
        "state": "uploaded",
        "digest": f"sha256:{index:064x}",
    }


def assert_issue(report, expected: str, label: str) -> None:
    if report.ready:
        raise AssertionError(f"{label} should fail")
    rendered = json.dumps(assert_safe_report(report))
    if expected not in rendered:
        raise AssertionError(f"{label} did not report expected issue: {expected}")


def run_dist_tests(module) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        dist = Path(tmp) / "dist"
        write_preview_dist(dist, module)
        payload = module.load_dist_metadata(TAG, dist)
        report = module.audit_preview_assets("local/dist", TAG, payload)
        if not report.ready:
            raise AssertionError(f"ready preview dist should pass: {report.as_json()}")
        if report.required_assets != module.expected_preview_asset_names(VERSION):
            raise AssertionError("preview dist required asset list changed unexpectedly")

    with tempfile.TemporaryDirectory() as tmp:
        dist = Path(tmp) / "dist"
        missing = f"conu-{VERSION}-linux-arm64.tar.gz.sha256"
        write_preview_dist(dist, module, omit=missing)
        payload = module.load_dist_metadata(TAG, dist)
        report = module.audit_preview_assets("local/dist", TAG, payload)
        assert_issue(report, "missing required platform assets", "missing preview checksum")

    with tempfile.TemporaryDirectory() as tmp:
        dist = Path(tmp) / "dist"
        write_preview_dist(dist, module, extra=f"conu-{VERSION}-linux-x64.tar.gz.asc")
        payload = module.load_dist_metadata(TAG, dist)
        report = module.audit_preview_assets("local/dist", TAG, payload)
        assert_issue(report, "contains forbidden asset names", "preview signature asset")
        assert_issue(report, "contains unexpected assets", "preview unexpected signature asset")

    with tempfile.TemporaryDirectory() as tmp:
        dist = Path(tmp) / "dist"
        write_preview_dist(dist, module, extra=f"conu-{VERSION}-update-policy.json")
        payload = module.load_dist_metadata(TAG, dist)
        report = module.audit_preview_assets("local/dist", TAG, payload)
        assert_issue(report, "contains forbidden asset names", "preview update policy asset")


def run_metadata_tests(module) -> None:
    names = module.expected_preview_asset_names(VERSION)
    payload = {
        "tag_name": TAG,
        "draft": False,
        "prerelease": True,
        "assets": [github_asset(name, index) for index, name in enumerate(names)],
    }
    report = module.audit_preview_assets("local/release", TAG, payload)
    if not report.ready:
        raise AssertionError("ready preview release metadata should pass")

    draft_payload = dict(payload)
    draft_payload["draft"] = True
    report = module.audit_preview_assets("local/release", TAG, draft_payload)
    assert_issue(report, "must not be a draft", "draft preview release")

    release_payload = dict(payload)
    release_payload["prerelease"] = False
    report = module.audit_preview_assets("local/release", TAG, release_payload)
    assert_issue(report, "must be marked prerelease", "non-prerelease preview release")

    duplicate_payload = dict(payload)
    duplicate_payload["assets"] = list(payload["assets"]) + [payload["assets"][0]]
    report = module.audit_preview_assets("local/release", TAG, duplicate_payload)
    assert_issue(report, "duplicate asset names", "duplicate preview release asset")

    bad_tag_payload = dict(payload)
    bad_tag_payload["tag_name"] = "v0.1.0"
    try:
        module.audit_preview_assets("local/release", TAG, bad_tag_payload)
    except ValueError as exc:
        if "tag mismatch" not in str(exc):
            raise AssertionError("unexpected bad tag error") from exc
    else:
        raise AssertionError("tag mismatch should fail")

    missing_digest_payload = dict(payload)
    missing_digest_payload["assets"] = [dict(asset) for asset in payload["assets"]]
    del missing_digest_payload["assets"][0]["digest"]
    report = module.audit_preview_assets("local/release", TAG, missing_digest_payload)
    assert_issue(report, "digest must be sha256 metadata", "missing preview asset digest")

    bad_digest_payload = dict(payload)
    bad_digest_payload["assets"] = [dict(asset) for asset in payload["assets"]]
    bad_digest_payload["assets"][0]["digest"] = "do-not-print-this-token-or-payload"
    report = module.audit_preview_assets("local/release", TAG, bad_digest_payload)
    assert_issue(report, "digest must be sha256 metadata", "invalid preview asset digest")


def main() -> int:
    module = load_module()
    run_dist_tests(module)
    run_metadata_tests(module)
    print("Unsigned preview release asset regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
