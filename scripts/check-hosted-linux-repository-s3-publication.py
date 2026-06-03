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
PREFLIGHT = ROOT / "scripts" / "check-custom-linux-repository-publication-preflight.py"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
VERSION = "0.1.0"
BASE_URL = "https://packages.example.com/conu"
BUCKET = "conu-packages-fixture"
PREFIX = "public/conu"
HOSTED_BUNDLE = f"conu-{VERSION}-hosted-linux-repositories.zip"
SITE_BUNDLE = f"conu-{VERSION}-hosted-linux-repository-site.zip"
SENSITIVE_SENTINEL = "do-not-print-this-secret-value"
PUBLISHER_TIMEOUT_SECONDS = 300
PREPARER_TIMEOUT_SECONDS = 60
PREFLIGHT_TIMEOUT_SECONDS = 60


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

        encoded_base_result = run_publisher_raw(
            site_dir,
            "--dry-run",
            "--base-url",
            f"{BASE_URL}/%2e%2e%2fother",
        )
        assert_failure(
            "encoded base URL",
            encoded_base_result,
            "repository base URL path must not contain encoded separators",
        )

        for bad_url in (
            "https://packages.example.com:bad/conu",
            "https://packages.example.com:/conu",
            "https://:443/conu",
            "https://packages.example.com:443x/conu",
        ):
            malformed_base = run_publisher_raw(
                site_dir,
                "--dry-run",
                "--base-url",
                bad_url,
            )
            assert_failure(
                "malformed repository base URL authority",
                malformed_base,
                "repository base URL authority",
            )

        query_download_url = temp / "query-download-url-site"
        shutil.copytree(site_dir, query_download_url)
        repository_path = query_download_url / "repository.json"
        repository = json.loads(repository_path.read_text(encoding="ascii"))
        repository["downloads"]["hostedBundleUrl"] += "?token=value"
        repository_path.write_text(
            json.dumps(repository, indent=2, sort_keys=True) + "\n",
            encoding="ascii",
            newline="\n",
        )
        query_download_result = run_publisher_raw(query_download_url, "--dry-run")
        assert_failure(
            "query download URL",
            query_download_result,
            "must not include params, query, or fragment",
        )

        escaped_dot_download_url = temp / "escaped-dot-download-url-site"
        shutil.copytree(site_dir, escaped_dot_download_url)
        repository_path = escaped_dot_download_url / "repository.json"
        repository = json.loads(repository_path.read_text(encoding="ascii"))
        repository["downloads"]["hostedBundleUrl"] = repository["downloads"][
            "hostedBundleUrl"
        ].replace("/downloads/", "/downloads/%2e%2e/")
        repository_path.write_text(
            json.dumps(repository, indent=2, sort_keys=True) + "\n",
            encoding="ascii",
            newline="\n",
        )
        escaped_dot_result = run_publisher_raw(escaped_dot_download_url, "--dry-run")
        assert_failure(
            "escaped dot download URL",
            escaped_dot_result,
            "path must not contain dot segments",
        )

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

        loopback_endpoint = run_publisher_raw(
            site_dir,
            "--dry-run",
            "--endpoint-url",
            "http://127.0.0.1:9000",
        )
        assert_failure(
            "loopback endpoint URL",
            loopback_endpoint,
            "S3 endpoint URL must use HTTPS",
        )
        publisher = load_publisher()
        normalized_loopback_endpoint = publisher.validate_endpoint_url(
            "http://127.0.0.1:9000",
            allow_loopback_http=True,
        )
        if normalized_loopback_endpoint != "http://127.0.0.1:9000":
            raise AssertionError("explicit loopback endpoint allowance should normalize URL")

        raw_dot_endpoint = run_publisher_raw(
            site_dir,
            "--dry-run",
            "--endpoint-url",
            "https://s3.example.com/api/../v1",
        )
        assert_failure(
            "raw dot endpoint URL",
            raw_dot_endpoint,
            "S3 endpoint URL path must not contain dot segments",
        )

        encoded_dot_endpoint = run_publisher_raw(
            site_dir,
            "--dry-run",
            "--endpoint-url",
            "https://s3.example.com/api/%2e%2e/v1",
        )
        assert_failure(
            "encoded dot endpoint URL",
            encoded_dot_endpoint,
            "S3 endpoint URL path must not contain dot segments",
        )

        encoded_separator_endpoint = run_publisher_raw(
            site_dir,
            "--dry-run",
            "--endpoint-url",
            "https://s3.example.com/api%2fv1",
        )
        assert_failure(
            "encoded separator endpoint URL",
            encoded_separator_endpoint,
            "S3 endpoint URL path must not contain encoded separators",
        )

        for bad_url in (
            "https://s3.example.com:bad/api",
            "https://s3.example.com:/api",
            "https://:443/api",
            "https://s3.example.com:443x/api",
        ):
            malformed_endpoint = run_publisher_raw(
                site_dir,
                "--dry-run",
                "--endpoint-url",
                bad_url,
            )
            assert_failure(
                "malformed endpoint URL authority",
                malformed_endpoint,
                "S3 endpoint URL authority",
            )

        oversized_metadata = temp / "oversized-metadata-site"
        shutil.copytree(site_dir, oversized_metadata)
        (oversized_metadata / "repository.json").write_text(
            '{"padding":"' + ("x" * (1024 * 1024 + 1)) + '"}\n',
            encoding="ascii",
            newline="\n",
        )
        oversized_result = run_publisher_raw(oversized_metadata, "--dry-run")
        assert_failure("oversized metadata", oversized_result, "repository.json is larger")

        bad_cache_control = temp / "bad-cache-control-site"
        shutil.copytree(site_dir, bad_cache_control)
        cache_policy_path = bad_cache_control / "cache-policy.json"
        cache_policy = json.loads(cache_policy_path.read_text(encoding="ascii"))
        cache_policy["rules"][0]["cacheControl"] = "public, max-age=300\nx-bad: 1"
        cache_policy_path.write_text(
            json.dumps(cache_policy, indent=2, sort_keys=True) + "\n",
            encoding="ascii",
            newline="\n",
        )
        bad_cache_result = run_publisher_raw(bad_cache_control, "--dry-run")
        assert_failure("bad Cache-Control", bad_cache_result, "Cache-Control")

        bad_headers = temp / "bad-headers-site"
        shutil.copytree(site_dir, bad_headers)
        (bad_headers / "_headers").write_text(
            "/repository.json\n  Cache-Control: public, max-age=31536000, immutable\n",
            encoding="ascii",
            newline="\n",
        )
        bad_headers_result = run_publisher_raw(bad_headers, "--dry-run")
        assert_failure(
            "bad _headers cache policy",
            bad_headers_result,
            "_headers Cache-Control rules",
        )

        unsafe_cache_path = temp / "unsafe-cache-path-site"
        shutil.copytree(site_dir, unsafe_cache_path)
        cache_policy_path = unsafe_cache_path / "cache-policy.json"
        cache_policy = json.loads(cache_policy_path.read_text(encoding="ascii"))
        cache_policy["rules"][0]["paths"].append("/.git/config")
        cache_policy_path.write_text(
            json.dumps(cache_policy, indent=2, sort_keys=True) + "\n",
            encoding="ascii",
            newline="\n",
        )
        unsafe_cache_result = run_publisher_raw(unsafe_cache_path, "--dry-run")
        assert_failure(
            "unsafe cache path",
            unsafe_cache_result,
            "forbidden local-state segment",
        )

        symlink_site_target = temp / "symlink-site-target"
        shutil.copytree(site_dir, symlink_site_target)
        symlink_site_root = temp / "symlink-site-root"
        if try_symlink(symlink_site_target, symlink_site_root, target_is_directory=True):
            symlink_site_result = run_publisher_raw(symlink_site_root, "--dry-run")
            assert_failure(
                "symlinked site directory",
                symlink_site_result,
                "site directory must not be a symlink",
            )

        symlink_metadata = temp / "symlink-metadata-site"
        shutil.copytree(site_dir, symlink_metadata)
        metadata_target = temp / "repository-target.json"
        metadata_target.write_text(
            (site_dir / "repository.json").read_text(encoding="ascii"),
            encoding="ascii",
            newline="\n",
        )
        metadata_link = symlink_metadata / "repository.json"
        metadata_link.unlink()
        if try_symlink(metadata_target, metadata_link):
            symlink_result = run_publisher_raw(symlink_metadata, "--dry-run")
            assert_failure(
                "symlinked metadata",
                symlink_result,
                "repository.json must not be a symlink",
            )

        symlink_entry = temp / "symlink-entry-site"
        shutil.copytree(site_dir, symlink_entry)
        external_dir = temp / "external-dir"
        external_dir.mkdir()
        if try_symlink(external_dir, symlink_entry / "linked-dir", target_is_directory=True):
            symlink_entry_result = run_publisher_raw(symlink_entry, "--dry-run")
            assert_failure("symlinked site entry", symlink_entry_result, "site entry must not be a symlink")

    assert_preflight()
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


def load_publisher():
    import importlib.util

    spec = importlib.util.spec_from_file_location("publish_hosted_linux_repository_s3", PUBLISHER)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load hosted Linux repository S3 publisher")
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
        timeout=PREPARER_TIMEOUT_SECONDS,
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
        timeout=PUBLISHER_TIMEOUT_SECONDS,
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


def write_fake_aws(temp: Path) -> str:
    fake_py = temp / "fake aws.py"
    fake_py.write_text(
        "\n".join(
            [
                "import json, os, sys",
                "args = sys.argv[1:]",
                "if 's3' not in args or 'cp' not in args:",
                "    print('expected s3 cp command', file=sys.stderr)",
                "    sys.exit(2)",
                "if '--cache-control' not in args or '--content-type' not in args:",
                "    print('missing cache metadata', file=sys.stderr)",
                "    sys.exit(3)",
                "cp_index = args.index('cp')",
                "source = args[cp_index + 1]",
                "target = args[cp_index + 2]",
                "if source != '-' or not target.startswith('s3://conu-packages-fixture/public/conu/'):",
                "    print('bad source or target', file=sys.stderr)",
                "    sys.exit(4)",
                "if '--expected-size' not in args:",
                "    print('missing expected upload size', file=sys.stderr)",
                "    sys.exit(5)",
                "body = sys.stdin.buffer.read()",
                "expected_size = int(args[args.index('--expected-size') + 1])",
                "if len(body) != expected_size:",
                "    print('stdin size did not match expected upload size', file=sys.stderr)",
                "    sys.exit(6)",
                "log = os.environ['CONU_FAKE_AWS_LOG']",
                "with open(log, 'a', encoding='utf-8') as handle:",
                "    handle.write(json.dumps({'args': args, 'stdinBytes': len(body)}, sort_keys=True) + '\\n')",
            ]
        )
        + "\n",
        encoding="ascii",
        newline="\n",
    )
    return subprocess.list2cmdline([sys.executable, str(fake_py)])


def assert_fake_aws_log(log: Path, expected_count: int) -> None:
    if not log.exists():
        raise AssertionError("fake AWS log was not written")
    rows = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line]
    if len(rows) != expected_count:
        raise AssertionError(f"fake AWS saw {len(rows)} uploads, expected {expected_count}")
    targets = set()
    for row in rows:
        args = row["args"]
        if args.count("s3") != 1 or args.count("cp") != 1:
            raise AssertionError(f"unexpected AWS command args: {args!r}")
        source = args[args.index("cp") + 1]
        if source != "-":
            raise AssertionError(f"upload source was not stdin: {args!r}")
        target = args[args.index("cp") + 2]
        if target in targets:
            raise AssertionError(f"duplicate S3 target: {target}")
        targets.add(target)
        expected_size = int(args[args.index("--expected-size") + 1])
        if row["stdinBytes"] != expected_size:
            raise AssertionError(f"upload body size did not match --expected-size: {args!r}")
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


def assert_preflight() -> None:
    valid = run_preflight_raw(preflight_env())
    if valid.returncode != 0:
        raise AssertionError(f"custom repository preflight failed unexpectedly: {valid.stdout!r}")
    valid_report = json.loads(valid.stdout)
    assert_safe_preflight_report(valid_report)
    if not valid_report["ready"]:
        raise AssertionError(f"custom repository preflight should be ready: {valid_report!r}")

    missing_env = preflight_env()
    missing_env.pop("CONU_LINUX_REPOSITORY_S3_BUCKET")
    missing_env["CONU_LINUX_REPOSITORY_AWS_SECRET_ACCESS_KEY"] = "   "
    missing = run_preflight_raw(missing_env)
    if missing.returncode == 0:
        raise AssertionError("missing custom repository preflight config unexpectedly passed")
    missing_report = json.loads(missing.stdout)
    assert_safe_preflight_report(missing_report)
    for name in (
        "CONU_LINUX_REPOSITORY_S3_BUCKET",
        "CONU_LINUX_REPOSITORY_AWS_SECRET_ACCESS_KEY",
    ):
        if name not in missing_report["missing"]:
            raise AssertionError(f"custom repository preflight did not report missing {name}")

    invalid_env = preflight_env()
    invalid_env["CONU_LINUX_REPOSITORY_BASE_URL"] = (
        f"https://user:{SENSITIVE_SENTINEL}@packages.example.com/conu"
    )
    invalid_env["CONU_LINUX_REPOSITORY_S3_PREFIX"] = "bad//prefix"
    invalid_env["CONU_LINUX_REPOSITORY_S3_ENDPOINT_URL"] = (
        f"https://user:{SENSITIVE_SENTINEL}@s3.example.com"
    )
    invalid_env["CONU_LINUX_REPOSITORY_AWS_REGION"] = "us east 1"
    invalid_env["CONU_LINUX_REPOSITORY_AWS_ACCESS_KEY_ID"] = (
        f"access-key\n{SENSITIVE_SENTINEL}"
    )
    invalid = run_preflight_raw(invalid_env)
    if invalid.returncode == 0:
        raise AssertionError("invalid custom repository preflight config unexpectedly passed")
    invalid_report = json.loads(invalid.stdout)
    assert_safe_preflight_report(invalid_report)
    rendered = json.dumps(invalid_report)
    for expected in (
        "custom repository base URL must not include credentials",
        "custom repository S3 prefix must not contain empty path segments",
        "custom repository S3 endpoint URL must not include credentials",
        "custom repository AWS region must not contain whitespace",
        "single-line secret value",
    ):
        if expected not in rendered:
            raise AssertionError(f"custom repository preflight missed {expected!r}")


def preflight_env() -> dict[str, str]:
    return {
        "CONU_LINUX_REPOSITORY_BASE_URL": BASE_URL,
        "CONU_LINUX_REPOSITORY_S3_BUCKET": BUCKET,
        "CONU_LINUX_REPOSITORY_S3_PREFIX": PREFIX,
        "CONU_LINUX_REPOSITORY_S3_ENDPOINT_URL": "https://s3.example.com",
        "CONU_LINUX_REPOSITORY_AWS_REGION": "us-east-1",
        "CONU_LINUX_REPOSITORY_AWS_ACCESS_KEY_ID": "AKIAEXAMPLEKEY",
        "CONU_LINUX_REPOSITORY_AWS_SECRET_ACCESS_KEY": "secret/access+key=example",
        "CONU_LINUX_REPOSITORY_AWS_SESSION_TOKEN": "optional-session-token",
    }


def run_preflight_raw(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    run_env = os.environ.copy()
    for name in preflight_env():
        run_env.pop(name, None)
    run_env.update(env)
    return subprocess.run(
        [sys.executable, str(PREFLIGHT), "--json"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=run_env,
        timeout=PREFLIGHT_TIMEOUT_SECONDS,
    )


def assert_safe_preflight_report(report: dict[str, object]) -> None:
    rendered = json.dumps(report)
    if SENSITIVE_SENTINEL in rendered:
        raise AssertionError("custom repository preflight leaked a secret value")
    for flag in (
        "payloadDisplayed",
        "contentsDisplayed",
        "tokenDisplayed",
        "tokenHashDisplayed",
        "keyMaterialDisplayed",
        "secretValuesDisplayed",
    ):
        if report.get(flag) is not False:
            raise AssertionError(f"custom repository preflight report did not set {flag}=false")


def try_symlink(target: Path, link: Path, *, target_is_directory: bool = False) -> bool:
    try:
        os.symlink(target, link, target_is_directory=target_is_directory)
    except (OSError, NotImplementedError):
        return False
    return True


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
        "python scripts/check-custom-linux-repository-publication-preflight.py",
        "python scripts/publish-hosted-linux-repository-s3.py",
        "needs: [github-release, linux-repository-pages, custom-linux-repository-publish]",
        "needs: [github-release, linux-repository-publication]",
    )
    for snippet in required_release_snippets:
        if snippet not in release:
            raise AssertionError(f"release workflow missed {snippet!r}")


if __name__ == "__main__":
    sys.exit(main())
