#!/usr/bin/env python3
"""Regression checks for custom hosted Linux repository S3 publication."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SITE_CHECKER = ROOT / "scripts" / "check-hosted-linux-repository-site.py"
PAGES_PREPARER = ROOT / "scripts" / "prepare-hosted-linux-repository-pages.py"
PUBLISHER = ROOT / "scripts" / "publish-hosted-linux-repository-s3.py"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
VERSION = "0.1.0"
BASE_URL = "https://packages.example.com/conu"
BUCKET = "conu-packages-fixture"
PREFIX = "public/conu"
HOSTED_BUNDLE = f"conu-{VERSION}-hosted-linux-repositories.zip"
SITE_BUNDLE = f"conu-{VERSION}-hosted-linux-repository-site.zip"


def main() -> int:
    site_checker = load_site_checker()
    bundle_checker = site_checker.load_bundle_checker()
    with tempfile.TemporaryDirectory(prefix="conu-hosted-linux-s3-") as temp_text:
        temp = Path(temp_text)
        dist = temp / "dist"
        site_dir = temp / "site"
        dist.mkdir()
        site_dir.mkdir()

        bundle_checker.write_signed_dist(dist)
        bundle_checker.run_generator(dist, dist)
        hosted_bundle = dist / HOSTED_BUNDLE
        site_checker.write_signature(hosted_bundle)
        site_checker.run_generator(dist, dist, BASE_URL)
        site = dist / SITE_BUNDLE
        site_checker.write_signature(site)
        run_preparer(dist, site_dir)

        dry_run = run_publisher(
            site_dir,
            "--dry-run",
            "--json",
        )
        report = json.loads(dry_run)
        assert_publication_report(report, published=False)

        fake_aws = write_fake_aws(temp)
        fake_log = temp / "fake-aws-log.jsonl"
        confirm = run_publisher(
            site_dir,
            "--confirm",
            "--json",
            "--aws-cli",
            str(fake_aws),
            env={"CONU_FAKE_AWS_LOG": str(fake_log)},
        )
        confirm_report = json.loads(confirm)
        assert_publication_report(confirm_report, published=True)
        assert_fake_aws_log(fake_log, confirm_report["fileCount"])

        missing_bucket = run_publisher_raw(site_dir, "--dry-run", "--bucket", "")
        assert_failure("missing bucket", missing_bucket, "S3 bucket is required")

        mismatch = run_publisher_raw(
            site_dir,
            "--dry-run",
            "--base-url",
            "https://packages.example.com/other",
        )
        assert_failure("base URL mismatch", mismatch, "repository.json baseUrl does not match")

        forbidden = temp / "forbidden-site"
        shutil.copytree(site_dir, forbidden)
        (forbidden / "README.txt").write_text("NPM_TOKEN\n", encoding="ascii")
        forbidden_result = run_publisher_raw(forbidden, "--dry-run")
        assert_failure("forbidden text", forbidden_result, "forbidden repository publication text")

        uncovered = temp / "uncovered-site"
        shutil.copytree(site_dir, uncovered)
        (uncovered / "extra.txt").write_text("public extra\n", encoding="ascii")
        uncovered_result = run_publisher_raw(uncovered, "--dry-run")
        assert_failure("uncovered cache rule", uncovered_result, "not covered by cache-policy.json")

        bad_endpoint = run_publisher_raw(
            site_dir,
            "--dry-run",
            "--endpoint-url",
            "http://s3.example.com",
        )
        assert_failure("bad endpoint URL", bad_endpoint, "S3 endpoint URL must use HTTPS")

    assert_workflow_wiring()
    print("Hosted Linux repository S3 publication regression checks passed")
    return 0


def load_site_checker():
    import importlib.util

    spec = importlib.util.spec_from_file_location("check_hosted_linux_repository_site", SITE_CHECKER)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load hosted Linux repository site checker")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def run_preparer(site: Path, output_dir: Path) -> str:
    return subprocess.run(
        [
            sys.executable,
            str(PAGES_PREPARER),
            str(site),
            "--output-dir",
            str(output_dir),
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    ).stdout


def run_publisher(site_dir: Path, *extra_args: str, env: dict[str, str] | None = None) -> str:
    result = run_publisher_raw(site_dir, *extra_args, env=env)
    if result.returncode != 0:
        raise AssertionError(f"publisher failed unexpectedly: {result.stdout!r}")
    return result.stdout


def run_publisher_raw(
    site_dir: Path,
    *extra_args: str,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    run_env = os.environ.copy()
    if env:
        run_env.update(env)
    return subprocess.run(
        [
            sys.executable,
            str(PUBLISHER),
            str(site_dir),
            "--bucket",
            BUCKET,
            "--prefix",
            PREFIX,
            "--base-url",
            BASE_URL,
            "--expected-version",
            VERSION,
            *extra_args,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=run_env,
    )


def assert_publication_report(report: dict, *, published: bool) -> None:
    if report["schema"] != "conu.hostedLinuxRepository.s3Publication.v1":
        raise AssertionError("publication report schema was wrong")
    if report["published"] is not published:
        raise AssertionError("publication report published flag was wrong")
    if report["baseUrl"] != BASE_URL:
        raise AssertionError("publication report base URL was wrong")
    if report["version"] != VERSION:
        raise AssertionError("publication report version was wrong")
    if report["bucket"] != BUCKET or report["prefix"] != PREFIX:
        raise AssertionError("publication report target metadata was wrong")
    if report["fileCount"] < 20:
        raise AssertionError("publication report file count was too low")
    if report["totalBytes"] <= 0:
        raise AssertionError("publication report total bytes was empty")
    for guard in ("payloadDisplayed", "tokenDisplayed", "keyMaterialDisplayed"):
        if report[guard] is not False:
            raise AssertionError(f"publication report expected {guard}=false")
    cache_classes = set(report["cacheClasses"])
    expected_classes = {
        "no-cache",
        "public, max-age=300, must-revalidate",
        "public, max-age=31536000, immutable",
    }
    if cache_classes != expected_classes:
        raise AssertionError(f"publication report cache classes were {cache_classes!r}")


def write_fake_aws(temp: Path) -> Path:
    fake_py = temp / "fake_aws.py"
    fake_py.write_text(
        "\n".join(
            [
                "import json, os, pathlib, sys",
                "args = sys.argv[1:]",
                "if 's3' not in args or 'cp' not in args:",
                "    print('expected s3 cp command', file=sys.stderr)",
                "    sys.exit(2)",
                "if '--cache-control' not in args or '--content-type' not in args:",
                "    print('missing cache metadata', file=sys.stderr)",
                "    sys.exit(3)",
                "cp_index = args.index('cp')",
                "source = pathlib.Path(args[cp_index + 1])",
                "target = args[cp_index + 2]",
                "if not source.is_file() or not target.startswith('s3://conu-packages-fixture/public/conu/'):",
                "    print('bad source or target', file=sys.stderr)",
                "    sys.exit(4)",
                "log = os.environ['CONU_FAKE_AWS_LOG']",
                "with open(log, 'a', encoding='utf-8') as handle:",
                "    handle.write(json.dumps(args, sort_keys=True) + '\\n')",
            ]
        )
        + "\n",
        encoding="ascii",
        newline="\n",
    )
    if os.name == "nt":
        fake_cmd = temp / "fake-aws.cmd"
        fake_cmd.write_text(
            f"@echo off\r\n\"{sys.executable}\" \"{fake_py}\" %*\r\n",
            encoding="ascii",
            newline="\r\n",
        )
        return fake_cmd
    fake_sh = temp / "fake-aws"
    fake_sh.write_text(
        f"#!/bin/sh\nexec \"{sys.executable}\" \"{fake_py}\" \"$@\"\n",
        encoding="ascii",
        newline="\n",
    )
    fake_sh.chmod(0o755)
    return fake_sh


def assert_fake_aws_log(log: Path, expected_count: int) -> None:
    if not log.exists():
        raise AssertionError("fake AWS log was not written")
    rows = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line]
    if len(rows) != expected_count:
        raise AssertionError(f"fake AWS saw {len(rows)} uploads, expected {expected_count}")
    targets = set()
    for args in rows:
        if args.count("s3") != 1 or args.count("cp") != 1:
            raise AssertionError(f"unexpected AWS command args: {args!r}")
        target = args[args.index("cp") + 2]
        if target in targets:
            raise AssertionError(f"duplicate S3 target: {target}")
        targets.add(target)
        cache_control = args[args.index("--cache-control") + 1]
        if cache_control not in {
            "no-cache",
            "public, max-age=300, must-revalidate",
            "public, max-age=31536000, immutable",
        }:
            raise AssertionError(f"unexpected cache-control value: {cache_control}")
        joined = " ".join(args)
        for forbidden in ("NPM_TOKEN", "CONU_RELAY_TOKEN", "payloadHex", "token_sha256_hex"):
            if forbidden in joined:
                raise AssertionError(f"AWS command exposed forbidden text: {forbidden}")


def assert_failure(description: str, result: subprocess.CompletedProcess[str], expected: str) -> None:
    if result.returncode == 0 or expected not in result.stdout:
        raise AssertionError(f"{description} failed with {result.stdout!r}, expected {expected!r}")


def assert_workflow_wiring() -> None:
    ci = CI_WORKFLOW.read_text(encoding="utf-8")
    release = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    for label, text in (("CI", ci), ("release", release)):
        if "Hosted Linux repository S3 publication regression" not in text:
            raise AssertionError(f"{label} workflow is missing S3 publication regression")
    required_release_snippets = (
        "Publish Custom Linux Repository S3 Site",
        "Linux Repository Publication Gate",
        "CONU_LINUX_REPOSITORY_S3_BUCKET",
        "python scripts/publish-hosted-linux-repository-s3.py",
        "needs: [github-release, linux-repository-pages, custom-linux-repository-publish]",
        "needs: [github-release, linux-repository-publication]",
    )
    for snippet in required_release_snippets:
        if snippet not in release:
            raise AssertionError(f"release workflow missed {snippet!r}")


if __name__ == "__main__":
    sys.exit(main())
