#!/usr/bin/env python3
"""Regression checks for GitHub Release asset publication preflight."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-github-release-assets-published.py")
SENSITIVE_SENTINEL = "do-not-print-this-secret-value"
TEST_TAG = "v0.1.0"
TEST_VERSION = "0.1.0"


def load_module():
    spec = importlib.util.spec_from_file_location("check_github_release_assets_published", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load GitHub Release asset preflight module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def ready_payload(
    module,
    *,
    tag: str = TEST_TAG,
    version: str = TEST_VERSION,
    prerelease: bool = False,
) -> dict[str, object]:
    assets = [
        {
            "name": name,
            "size": 128 + index,
            "state": "uploaded",
            "digest": f"sha256:{index:064x}",
            "browser_download_url": f"https://example.invalid/{SENSITIVE_SENTINEL}/{name}",
        }
        for index, name in enumerate(module.expected_release_asset_names(version))
    ]
    return {
        "id": 12345,
        "tag_name": tag,
        "draft": False,
        "prerelease": prerelease,
        "assets": assets,
        "body": SENSITIVE_SENTINEL,
    }


def assert_raises(func, pattern: str) -> None:
    try:
        func()
    except ValueError as exc:
        if SENSITIVE_SENTINEL in str(exc):
            raise AssertionError("error message leaked a sensitive fixture value") from exc
        if pattern not in str(exc):
            raise AssertionError(f"expected {pattern!r} in {exc!r}") from exc
        return
    raise AssertionError(f"expected ValueError containing {pattern!r}")


def assert_not_ready(report, pattern: str) -> None:
    if report.ready:
        raise AssertionError("expected release asset report to fail")
    rendered = json.dumps(report.as_json())
    if SENSITIVE_SENTINEL in rendered:
        raise AssertionError("release asset report leaked a sensitive fixture value")
    if pattern not in rendered:
        raise AssertionError(f"expected {pattern!r} in report: {rendered}")


def run_expected_name_tests(module) -> None:
    names = module.expected_release_asset_names(TEST_VERSION)
    if len(names) != len(set(names)):
        raise AssertionError("expected release asset list contains duplicate names")
    required = {
        "conu-0.1.0-windows-x64.zip",
        "conu-0.1.0-linux-x64.tar.gz.asc",
        "conu_0.1.0_amd64.deb.asc",
        "conu-0.1.0-1.x86_64.rpm.asc",
        "conu-0.1.0-apt-repository-metadata.zip.asc",
        "conu-linux-gpg-key.asc.sha256",
        "conu-0.1.0-hosted-linux-repositories.zip.asc",
        "conu-0.1.0-hosted-linux-repository-site.zip.asc",
        "conu-0.1.0-update-policy.json",
        "conu-0.1.0-update-policy.json.sha256",
        "conu-0.1.0-update-policy.json.asc",
        "conu-0.1.0-package-manager-submissions.zip",
        "conu-0.1.0-package-manager-submissions.zip.sha256",
        "conu-0.1.0-package-manager-submissions.zip.asc",
        "conu.rb",
        "conu.json",
        "imthegoodboy.conU.yaml",
        "conu.0.1.0.nupkg",
    }
    missing = sorted(required - set(names))
    if missing:
        raise AssertionError(f"expected release asset list missed required names: {missing!r}")


def run_audit_tests(module) -> None:
    payload = ready_payload(module)
    report = module.audit_release_assets("owner/repo", TEST_TAG, payload)
    if not report.ready:
        raise AssertionError(f"expected ready report, got {report.issues!r}")
    rendered = json.dumps(report.as_json())
    if SENSITIVE_SENTINEL in rendered:
        raise AssertionError("release readiness report included an unrelated release field")

    missing_payload = ready_payload(module)
    missing_payload["assets"] = missing_payload["assets"][:-1]
    assert_not_ready(
        module.audit_release_assets("owner/repo", TEST_TAG, missing_payload),
        "missingAssets",
    )

    duplicate_payload = ready_payload(module)
    duplicate_payload["assets"] = [
        *duplicate_payload["assets"],
        dict(duplicate_payload["assets"][0]),
    ]
    assert_not_ready(
        module.audit_release_assets("owner/repo", TEST_TAG, duplicate_payload),
        "duplicateAssets",
    )

    draft_payload = ready_payload(module)
    draft_payload["draft"] = True
    assert_not_ready(
        module.audit_release_assets("owner/repo", TEST_TAG, draft_payload),
        "release is still a draft",
    )

    stable_prerelease_payload = ready_payload(module, prerelease=True)
    assert_not_ready(
        module.audit_release_assets("owner/repo", TEST_TAG, stable_prerelease_payload),
        "stable tags",
    )

    prerelease_tag = "v0.1.0-rc.1"
    prerelease_version = "0.1.0-rc.1"
    prerelease_flag_payload = ready_payload(
        module,
        tag=prerelease_tag,
        version=prerelease_version,
        prerelease=False,
    )
    assert_not_ready(
        module.audit_release_assets("owner/repo", prerelease_tag, prerelease_flag_payload),
        "semver prerelease tags",
    )
    prerelease_ready_payload = ready_payload(
        module,
        tag=prerelease_tag,
        version=prerelease_version,
        prerelease=True,
    )
    prerelease_report = module.audit_release_assets(
        "owner/repo",
        prerelease_tag,
        prerelease_ready_payload,
    )
    if not prerelease_report.ready:
        raise AssertionError(f"expected prerelease report to pass, got {prerelease_report.issues!r}")

    mismatch_payload = ready_payload(module)
    mismatch_payload["tag_name"] = "v0.2.0"
    assert_not_ready(
        module.audit_release_assets("owner/repo", TEST_TAG, mismatch_payload),
        "expected v0.1.0",
    )

    zero_size_payload = ready_payload(module)
    zero_size_payload["assets"][0]["size"] = 0
    assert_not_ready(
        module.audit_release_assets("owner/repo", TEST_TAG, zero_size_payload),
        "size must be greater than zero",
    )

    bad_state_payload = ready_payload(module)
    bad_state_payload["assets"][0]["state"] = "new"
    assert_not_ready(
        module.audit_release_assets("owner/repo", TEST_TAG, bad_state_payload),
        "state must be uploaded",
    )

    missing_digest_payload = ready_payload(module)
    del missing_digest_payload["assets"][0]["digest"]
    assert_not_ready(
        module.audit_release_assets("owner/repo", TEST_TAG, missing_digest_payload),
        "digest must be sha256 metadata",
    )

    bad_digest_payload = ready_payload(module)
    bad_digest_payload["assets"][0]["digest"] = SENSITIVE_SENTINEL
    assert_not_ready(
        module.audit_release_assets("owner/repo", TEST_TAG, bad_digest_payload),
        "digest must be sha256 metadata",
    )

    forbidden_payload = ready_payload(module)
    forbidden_payload["assets"].append(
        {
            "name": "conu-0.1.0-runtime-secret.zip",
            "size": 100,
            "state": "uploaded",
            "digest": f"sha256:{999:064x}",
        }
    )
    assert_not_ready(
        module.audit_release_assets("owner/repo", TEST_TAG, forbidden_payload),
        "forbiddenAssets",
    )

    whitespace_payload = ready_payload(module)
    whitespace_payload["assets"][0]["name"] = f"{whitespace_payload['assets'][0]['name']} "
    assert_raises(
        lambda: module.audit_release_assets("owner/repo", TEST_TAG, whitespace_payload),
        "whitespace or control",
    )

    unexpected_payload = ready_payload(module)
    unexpected_payload["assets"].append(
        {
            "name": "conu-0.1.0-extra-notes.txt",
            "size": 100,
            "state": "uploaded",
            "digest": f"sha256:{1000:064x}",
        }
    )
    assert_not_ready(
        module.audit_release_assets("owner/repo", TEST_TAG, unexpected_payload),
        "unexpectedAssets",
    )

    assert_raises(lambda: module.validate_tag("0.1.0"), "must start with")
    assert_raises(lambda: module.validate_tag("vlatest"), "semver")


def run_dist_tests(module) -> None:
    with tempfile.TemporaryDirectory(prefix="conu-release-dist-assets-") as temp_dir:
        dist = Path(temp_dir) / "dist"
        dist.mkdir()
        for name in module.expected_release_asset_names(TEST_VERSION):
            (dist / name).write_bytes(b"asset\n")

        payload = module.load_dist_metadata(TEST_TAG, dist)
        report = module.audit_release_assets("local/dist", TEST_TAG, payload)
        if not report.ready:
            raise AssertionError(f"expected local dist report to pass, got {report.issues!r}")

        unexpected = dist / "conu-0.1.0-extra.txt"
        unexpected.write_text(SENSITIVE_SENTINEL, encoding="utf-8")
        unexpected_report = module.audit_release_assets(
            "local/dist",
            TEST_TAG,
            module.load_dist_metadata(TEST_TAG, dist),
        )
        assert_not_ready(unexpected_report, "unexpectedAssets")
        rendered = json.dumps(unexpected_report.as_json())
        if SENSITIVE_SENTINEL in rendered:
            raise AssertionError("local dist report leaked unexpected file contents")
        unexpected.unlink()

        empty_asset = dist / "conu.rb"
        empty_asset.write_bytes(b"")
        assert_not_ready(
            module.audit_release_assets(
                "local/dist",
                TEST_TAG,
                module.load_dist_metadata(TEST_TAG, dist),
            ),
            "size must be greater than zero",
        )
        empty_asset.write_bytes(b"asset\n")

        package_asset = dist / "conu.json"
        package_asset.unlink()
        package_asset.mkdir()
        assert_not_ready(
            module.audit_release_assets(
                "local/dist",
                TEST_TAG,
                module.load_dist_metadata(TEST_TAG, dist),
            ),
            "local asset must be a regular file",
        )
        package_asset.rmdir()
        package_asset.write_bytes(b"asset\n")

        symlink_asset = dist / "conu.spec"
        symlink_asset.unlink()
        try:
            symlink_asset.symlink_to(dist / "conu.rb")
        except OSError:
            symlink_asset.write_bytes(b"asset\n")
        else:
            assert_not_ready(
                module.audit_release_assets(
                    "local/dist",
                    TEST_TAG,
                    module.load_dist_metadata(TEST_TAG, dist),
                ),
                "local asset must not be a symlink",
            )


def run_loader_tests(module) -> None:
    original_run_gh_json = module.run_gh_json

    def fake_run_gh_json(gh, args, description):
        if gh != "gh":
            raise AssertionError(f"unexpected gh executable: {gh!r}")
        if args == ["api", "repos/owner/repo/releases/tags/v0.1.0"]:
            if "Release" not in description:
                raise AssertionError(f"unexpected description: {description!r}")
            payload = ready_payload(module)
            payload["assets"] = []
            return payload
        if args == [
            "api",
            "--paginate",
            "--slurp",
            "repos/owner/repo/releases/12345/assets?per_page=100",
        ]:
            if "assets" not in description:
                raise AssertionError(f"unexpected description: {description!r}")
            assets = ready_payload(module)["assets"]
            return [assets[:10], assets[10:]]
        raise AssertionError(f"unexpected gh args: {args!r}")

    module.run_gh_json = fake_run_gh_json
    try:
        payload = module.load_release_metadata("owner/repo", TEST_TAG, "gh")
    finally:
        module.run_gh_json = original_run_gh_json

    with tempfile.TemporaryDirectory(prefix="conu-release-json-guard-") as temp_dir:
        release_json = Path(temp_dir) / "release.json"
        release_json.write_text(
            (
                '{"tag_name":"v0.1.0",'
                f'"tag_name":"{SENSITIVE_SENTINEL}",'
                '"assets":[]}\n'
            ),
            encoding="utf-8",
        )
        assert_raises(
            lambda: module.load_release_json(release_json),
            "duplicate JSON key",
        )
    if payload.get("tag_name") != TEST_TAG:
        raise AssertionError("loader did not return fixture release metadata")
    if len(payload.get("assets", [])) != len(module.expected_release_asset_names(TEST_VERSION)):
        raise AssertionError("loader did not return paginated release assets")

    module.run_gh_json = lambda *_args, **_kwargs: []
    try:
        assert_raises(
            lambda: module.load_release_metadata("owner/repo", TEST_TAG, "gh"),
            "unexpected payload",
        )
    finally:
        module.run_gh_json = original_run_gh_json


def run_main_tests(module) -> None:
    with tempfile.TemporaryDirectory(prefix="conu-release-assets-") as temp_dir:
        release_json = Path(temp_dir) / "release.json"
        release_json.write_text(json.dumps(ready_payload(module)), encoding="utf-8")

        original_argv = sys.argv
        stdout = io.StringIO()
        stderr = io.StringIO()
        sys.argv = [
            "check-github-release-assets-published.py",
            "--repo",
            "owner/repo",
            "--tag",
            TEST_TAG,
            "--release-json",
            str(release_json),
            "--gh",
            "gh",
        ]
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = module.main()
        finally:
            sys.argv = original_argv

    if exit_code != 0:
        raise AssertionError(f"expected main() to pass, got {exit_code}: {stderr.getvalue()}")
    rendered = stdout.getvalue() + stderr.getvalue()
    if SENSITIVE_SENTINEL in rendered:
        raise AssertionError("main() output leaked unrelated release metadata")

    with tempfile.TemporaryDirectory(prefix="conu-release-dist-main-") as temp_dir:
        dist = Path(temp_dir) / "dist"
        dist.mkdir()
        for name in module.expected_release_asset_names(TEST_VERSION):
            (dist / name).write_bytes(b"asset\n")

        original_argv = sys.argv
        stdout = io.StringIO()
        stderr = io.StringIO()
        sys.argv = [
            "check-github-release-assets-published.py",
            "--tag",
            TEST_TAG,
            "--dist-dir",
            str(dist),
        ]
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = module.main()
        finally:
            sys.argv = original_argv

    if exit_code != 0:
        raise AssertionError(f"expected dist main() to pass, got {exit_code}: {stderr.getvalue()}")


def main() -> int:
    module = load_module()
    run_expected_name_tests(module)
    run_audit_tests(module)
    run_dist_tests(module)
    run_loader_tests(module)
    run_main_tests(module)
    print("GitHub Release asset publication preflight regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
