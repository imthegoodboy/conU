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
        publisher = load_publisher()
        assert_aws_cli_wrapper_guard(publisher, fake_aws)
        failing_aws = write_failing_fake_aws(temp)
        failed_confirm = run_publisher_raw(
            site_dir,
            "--confirm",
            "--json",
            "--aws-cli",
            failing_aws,
        )
        assert_failed_publication_redacts(failed_confirm, failing_aws)

        missing_bucket = run_publisher_raw(site_dir, "--dry-run", "--bucket", "")
        assert_failure("missing bucket", missing_bucket, "S3 bucket is required")

        for bucket, expected in (
            ("Conu-Packages", "S3 bucket contains unsupported characters"),
            ("conu_packages", "S3 bucket contains unsupported characters"),
            ("192.168.0.1", "S3 bucket must not be formatted as an IPv4 address"),
            ("bad..bucket", "S3 bucket must not contain adjacent dots"),
            ("bad.-bucket", "S3 bucket must not contain dot-hyphen boundaries"),
            ("bad-.bucket", "S3 bucket must not contain dot-hyphen boundaries"),
        ):
            invalid_bucket = run_publisher_raw(site_dir, "--dry-run", "--bucket", bucket)
            assert_failure(f"invalid bucket {bucket}", invalid_bucket, expected)

        mismatch = run_publisher_raw(
            site_dir,
            "--dry-run",
            "--base-url",
            "https://packages.example.com/other",
        )
        assert_failure("base URL mismatch", mismatch, "repository.json baseUrl does not match")

        duplicate_repository = temp / "duplicate-repository-json-site"
        shutil.copytree(site_dir, duplicate_repository)
        (duplicate_repository / "repository.json").write_text(
            '{"schema":"conu.hostedLinuxRepository.site.v1",'
            f'"version":"{VERSION}","version":"{SENSITIVE_SENTINEL}"}}\n',
            encoding="ascii",
            newline="\n",
        )
        duplicate_repository_result = run_publisher_raw(duplicate_repository, "--dry-run")
        assert_failure(
            "duplicate repository JSON",
            duplicate_repository_result,
            "repository.json is not valid JSON",
        )
        assert_no_sentinel(duplicate_repository_result.stdout, "duplicate repository JSON output")

        duplicate_cache_policy = temp / "duplicate-cache-policy-json-site"
        shutil.copytree(site_dir, duplicate_cache_policy)
        (duplicate_cache_policy / "cache-policy.json").write_text(
            '{"schema":"conu.hostedLinuxRepository.cachePolicy.v1",'
            f'"version":"{VERSION}","version":"{SENSITIVE_SENTINEL}"}}\n',
            encoding="ascii",
            newline="\n",
        )
        duplicate_cache_policy_result = run_publisher_raw(duplicate_cache_policy, "--dry-run")
        assert_failure(
            "duplicate cache policy JSON",
            duplicate_cache_policy_result,
            "cache-policy.json is not valid JSON",
        )
        assert_no_sentinel(duplicate_cache_policy_result.stdout, "duplicate cache policy JSON output")

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

        for bad_url in (
            "https://packages.example.com%20.evil/conu",
            "https://packages.example.com%40evil.test/conu",
            "https://packages.example.com\\evil.test/conu",
        ):
            unsafe_base_authority = run_publisher_raw(
                site_dir,
                "--dry-run",
                "--base-url",
                bad_url,
            )
            assert_failure(
                "unsafe repository base URL authority",
                unsafe_base_authority,
                "repository base URL authority",
            )

        control_base_path = run_publisher_raw(
            site_dir,
            "--dry-run",
            "--base-url",
            f"{BASE_URL}/%00",
        )
        assert_failure(
            "control repository base URL path",
            control_base_path,
            "whitespace or control characters",
        )

        for bad_url in (
            "https://127.0.0.1/conu",
            "https://10.0.0.1/conu",
            "https://[fc00::1]/conu",
            "https://[2001:db8:1::1]/conu",
            "https://[3fff::1]/conu",
            "https://[5f00::1]/conu",
            "https://[64:ff9b:1::1]/conu",
            "https://[64:ff9b::a00:1]/conu",
            "https://[100:0:0:1::1]/conu",
            "https://packages.local/conu",
        ):
            non_public_base = run_publisher_raw(
                site_dir,
                "--dry-run",
                "--base-url",
                bad_url,
            )
            assert_failure(
                "non-public repository base URL",
                non_public_base,
                "repository base URL host must be public",
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

        for bad_url in (
            "https://s3.example.com%20.evil/api",
            "https://s3.example.com%40evil.test/api",
            "https://s3.example.com\\evil.test/api",
        ):
            unsafe_endpoint_authority = run_publisher_raw(
                site_dir,
                "--dry-run",
                "--endpoint-url",
                bad_url,
            )
            assert_failure(
                "unsafe endpoint URL authority",
                unsafe_endpoint_authority,
                "S3 endpoint URL authority",
            )

        control_endpoint_path = run_publisher_raw(
            site_dir,
            "--dry-run",
            "--endpoint-url",
            "https://s3.example.com/api/%00/v1",
        )
        assert_failure(
            "control endpoint URL path",
            control_endpoint_path,
            "whitespace or control characters",
        )

        unsafe_region = run_publisher_raw(
            site_dir,
            "--dry-run",
            "--region",
            "us-east-1;rm",
        )
        assert_failure("unsafe AWS region", unsafe_region, "AWS region contains unsupported characters")
        for region, expected in (
            ("US-EAST-1", "AWS region contains unsupported characters"),
            ("us_east_1", "AWS region contains unsupported characters"),
            ("us.east.1", "AWS region contains unsupported characters"),
            ("us-east-", "AWS region contains unsupported characters"),
            ("us--east-1", "AWS region must not contain consecutive hyphens"),
        ):
            invalid_region = run_publisher_raw(site_dir, "--dry-run", "--region", region)
            assert_failure(f"invalid AWS region {region}", invalid_region, expected)

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


def write_failing_fake_aws(temp: Path) -> str:
    fake_py = temp / "failing fake aws.py"
    fake_py.write_text(
        "\n".join(
            [
                "import sys",
                f"print('NODE_AUTH_TOKEN={SENSITIVE_SENTINEL}', file=sys.stderr)",
                f"print('Authorization: Bearer {SENSITIVE_SENTINEL}', file=sys.stderr)",
                f"print('https://user:{SENSITIVE_SENTINEL}@example.invalid/conu', file=sys.stderr)",
                "print('https://s3.example.invalid/conu?"
                f"X-Amz-Signature={SENSITIVE_SENTINEL}&"
                f"X-Amz-Credential={SENSITIVE_SENTINEL}&"
                f"X-Amz-Security-Token={SENSITIVE_SENTINEL}', file=sys.stderr)",
                "sys.exit(7)",
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


def assert_no_sentinel(output: str, label: str) -> None:
    if SENSITIVE_SENTINEL in output:
        raise AssertionError(f"{label} leaked duplicate-key shadow value")


def assert_failed_publication_redacts(
    result: subprocess.CompletedProcess[str],
    fake_aws: str,
) -> None:
    if result.returncode == 0:
        raise AssertionError("failing fake AWS publication unexpectedly passed")
    if SENSITIVE_SENTINEL in result.stdout:
        raise AssertionError("failing fake AWS publication leaked a sensitive value")
    if Path(fake_aws).name in result.stdout or "failing fake aws" in result.stdout:
        raise AssertionError("failing fake AWS publication leaked the wrapper command path")
    report = json.loads(result.stdout)
    if report["published"] is not False or report["endpointChecked"] is not False:
        raise AssertionError("failed publication report claimed work completed")
    for guard in ("payloadDisplayed", "tokenDisplayed", "keyMaterialDisplayed"):
        if report[guard] is not False:
            raise AssertionError(f"failed publication report expected {guard}=false")
    if "[redacted]" not in json.dumps(report):
        raise AssertionError("failed publication report did not include redacted command output")


def assert_aws_cli_wrapper_guard(publisher, fake_aws: str) -> None:
    if publisher.parse_aws_cli("aws") != ["aws"]:
        raise AssertionError("plain aws CLI wrapper did not parse")
    if len(publisher.parse_aws_cli(fake_aws)) < 2:
        raise AssertionError("fake AWS CLI wrapper with a script path did not parse")

    for raw, expected in (
        ("aws s3 rm s3://victim --recursive", "S3 service or upload subcommands"),
        ("aws s3api delete-object --bucket victim --key release", "S3 service or upload subcommands"),
        ("aws s3://victim", "S3 targets"),
        ("aws --endpoint-url https://evil.example", "publication-owned or unsafe options"),
        ("aws --region us-east-1", "publication-owned or unsafe options"),
        ("aws --cache-control public", "publication-owned or unsafe options"),
        ("aws --debug", "publication-owned or unsafe options"),
        ("aws --no-verify-ssl", "publication-owned or unsafe options"),
        (
            f"env AWS_SECRET_ACCESS_KEY={SENSITIVE_SENTINEL} aws",
            "inline credentials or secrets",
        ),
        (f"aws --password {SENSITIVE_SENTINEL}", "inline credentials or secrets"),
        (
            f"aws https://user:{SENSITIVE_SENTINEL}@example.invalid",
            "inline credentials or secrets",
        ),
        ("--profile release", "executable must not be an option"),
    ):
        try:
            publisher.parse_aws_cli(raw)
        except publisher.PublicationError as exc:
            if expected not in str(exc):
                raise AssertionError(f"unexpected AWS CLI wrapper failure for {raw!r}: {exc}")
        else:
            raise AssertionError(f"unsafe AWS CLI wrapper unexpectedly parsed: {raw}")

    try:
        publisher.validate_aws_cli_wrapper(["aws", "bad\narg"])
    except publisher.PublicationError as exc:
        if "control arguments" not in str(exc):
            raise AssertionError(f"unexpected AWS CLI control argument failure: {exc}")
    else:
        raise AssertionError("AWS CLI wrapper with a control character unexpectedly parsed")


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

    for prefix, expected in (
        ("bad prefix", "custom repository S3 prefix must not contain whitespace or control characters"),
        ("bad/%00/prefix", "custom repository S3 prefix must not contain whitespace or control characters"),
        ("bad/%2f/prefix", "custom repository S3 prefix must not contain encoded separators"),
        ("bad/%2e%2e/prefix", "custom repository S3 prefix must not contain dot segments"),
    ):
        prefix_env = preflight_env()
        prefix_env["CONU_LINUX_REPOSITORY_S3_PREFIX"] = prefix
        prefix_result = run_preflight_raw(prefix_env)
        if prefix_result.returncode == 0:
            raise AssertionError(f"unsafe custom repository prefix unexpectedly passed: {prefix}")
        prefix_report = json.loads(prefix_result.stdout)
        assert_safe_preflight_report(prefix_report)
        if expected not in json.dumps(prefix_report):
            raise AssertionError(f"custom repository preflight missed prefix failure {expected!r}")

    for bucket, expected in (
        ("Conu-Packages", "custom repository S3 bucket contains unsupported characters"),
        ("conu_packages", "custom repository S3 bucket contains unsupported characters"),
        ("192.168.0.1", "custom repository S3 bucket must not be formatted as an IPv4 address"),
        ("bad..bucket", "custom repository S3 bucket must not contain adjacent dots"),
        ("bad.-bucket", "custom repository S3 bucket must not contain dot-hyphen boundaries"),
        ("bad-.bucket", "custom repository S3 bucket must not contain dot-hyphen boundaries"),
    ):
        bucket_env = preflight_env()
        bucket_env["CONU_LINUX_REPOSITORY_S3_BUCKET"] = bucket
        bucket_result = run_preflight_raw(bucket_env)
        if bucket_result.returncode == 0:
            raise AssertionError(f"unsafe custom repository bucket unexpectedly passed: {bucket}")
        bucket_report = json.loads(bucket_result.stdout)
        assert_safe_preflight_report(bucket_report)
        if expected not in json.dumps(bucket_report):
            raise AssertionError(f"custom repository preflight missed bucket failure {expected!r}")

    for region, expected in (
        ("US-EAST-1", "custom repository AWS region contains unsupported characters"),
        ("us_east_1", "custom repository AWS region contains unsupported characters"),
        ("us.east.1", "custom repository AWS region contains unsupported characters"),
        ("us-east-", "custom repository AWS region contains unsupported characters"),
        ("us--east-1", "custom repository AWS region must not contain consecutive hyphens"),
    ):
        region_env = preflight_env()
        region_env["CONU_LINUX_REPOSITORY_AWS_REGION"] = region
        region_result = run_preflight_raw(region_env)
        if region_result.returncode == 0:
            raise AssertionError(f"unsafe custom repository AWS region unexpectedly passed: {region}")
        region_report = json.loads(region_result.stdout)
        assert_safe_preflight_report(region_report)
        if expected not in json.dumps(region_report):
            raise AssertionError(f"custom repository preflight missed region failure {expected!r}")

    unsafe_env = preflight_env()
    unsafe_env["CONU_LINUX_REPOSITORY_BASE_URL"] = (
        "https://packages.example.com%40evil.test/conu"
    )
    unsafe_env["CONU_LINUX_REPOSITORY_S3_ENDPOINT_URL"] = (
        "https://s3.example.com%20.evil/api"
    )
    unsafe_env["CONU_LINUX_REPOSITORY_AWS_REGION"] = "us-east-1;rm"
    unsafe = run_preflight_raw(unsafe_env)
    if unsafe.returncode == 0:
        raise AssertionError("unsafe custom repository preflight config unexpectedly passed")
    unsafe_report = json.loads(unsafe.stdout)
    assert_safe_preflight_report(unsafe_report)
    unsafe_rendered = json.dumps(unsafe_report)
    for expected in (
        "custom repository base URL authority is invalid",
        "custom repository S3 endpoint URL authority is invalid",
        "custom repository AWS region contains unsupported characters",
    ):
        if expected not in unsafe_rendered:
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
