#!/usr/bin/env python3
"""Regression checks for hosted Linux repository endpoint readiness auditing."""

from __future__ import annotations

import functools
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import threading
import zipfile
from fnmatch import fnmatchcase
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse


ROOT = Path(__file__).resolve().parents[1]
ENDPOINT_CHECKER = ROOT / "scripts" / "check-hosted-linux-repository-endpoint.py"
SITE_CHECKER = ROOT / "scripts" / "check-hosted-linux-repository-site.py"
VERSION = "0.1.0"
PLACEHOLDER_BASE_URL = "https://packages.example.com/conu"
PUBLIC_KEY = "conu-linux-gpg-key.asc"
HOSTED_BUNDLE = f"conu-{VERSION}-hosted-linux-repositories.zip"
SITE_BUNDLE = f"conu-{VERSION}-hosted-linux-repository-site.zip"


def main() -> int:
    site_checker = load_site_checker()
    bundle_checker = site_checker.load_bundle_checker()
    with tempfile.TemporaryDirectory(prefix="conu-hosted-linux-endpoint-") as temp_text:
        temp = Path(temp_text)
        site_root = temp / "site"
        dist = temp / "dist"
        dist.mkdir()
        site_root.mkdir()

        bundle_checker.write_signed_dist(dist)
        bundle_checker.run_generator(dist, dist)
        hosted_bundle = dist / HOSTED_BUNDLE
        site_checker.write_signature(hosted_bundle)
        site_checker.run_generator(dist, dist, PLACEHOLDER_BASE_URL)
        extract_site(dist / SITE_BUNDLE, site_root)

        good_site = temp / "good-site"
        shutil.copytree(site_root, good_site)
        with serve_site(good_site, mode="good") as base_url:
            rewrite_base_url(good_site, PLACEHOLDER_BASE_URL, base_url)

            report = run_checker(base_url, "--expected-version", VERSION, "--json")
            parsed = json.loads(report)
            if parsed["ready"] is not True:
                raise AssertionError(f"expected ready endpoint report, got {parsed!r}")
            if parsed["baseUrl"] != base_url:
                raise AssertionError("endpoint report baseUrl was wrong")
            if parsed["version"] != VERSION:
                raise AssertionError("endpoint report version was wrong")
            if any("payload" in key.lower() for key in parsed):
                raise AssertionError("endpoint report included an unrelated payload field")

            run_checker_expect_failure(
                base_url,
                "HTTPS URL",
                "--expected-version",
                VERSION,
                allow_loopback_http=False,
            )

        missing_cache_header = temp / "missing-cache-header"
        shutil.copytree(site_root, missing_cache_header)
        with serve_site(missing_cache_header, mode="missing-cache-header") as base_url:
            rewrite_base_url(missing_cache_header, PLACEHOLDER_BASE_URL, base_url)
            run_checker_expect_failure(base_url, "Cache-Control", "--expected-version", VERSION)

        wrong_cache_header = temp / "wrong-cache-header"
        shutil.copytree(site_root, wrong_cache_header)
        with serve_site(wrong_cache_header, mode="wrong-cache-header") as base_url:
            rewrite_base_url(wrong_cache_header, PLACEHOLDER_BASE_URL, base_url)
            run_checker_expect_failure(base_url, "Cache-Control", "--expected-version", VERSION)

        bad_headers_file = temp / "bad-headers-file"
        shutil.copytree(site_root, bad_headers_file)
        (bad_headers_file / "_headers").write_text(
            "/repository.json\n  Cache-Control: public, max-age=31536000, immutable\n",
            encoding="ascii",
            newline="\n",
        )
        with serve_site(bad_headers_file, mode="good") as base_url:
            rewrite_base_url(bad_headers_file, PLACEHOLDER_BASE_URL, base_url)
            run_checker_expect_failure(base_url, "_headers Cache-Control rules", "--expected-version", VERSION)

        bad_cache_policy = temp / "bad-cache-policy"
        shutil.copytree(site_root, bad_cache_policy)
        cache_policy_path = bad_cache_policy / "cache-policy.json"
        cache_policy = json.loads(cache_policy_path.read_text(encoding="ascii"))
        cache_policy["tokenDisplayed"] = True
        cache_policy_path.write_text(
            json.dumps(cache_policy, indent=2, sort_keys=True) + "\n",
            encoding="ascii",
            newline="\n",
        )
        with serve_site(bad_cache_policy, mode="good") as base_url:
            rewrite_base_url(bad_cache_policy, PLACEHOLDER_BASE_URL, base_url)
            run_checker_expect_failure(base_url, "tokenDisplayed=false", "--expected-version", VERSION)

        unsafe_cache_path = temp / "unsafe-cache-path"
        shutil.copytree(site_root, unsafe_cache_path)
        cache_policy_path = unsafe_cache_path / "cache-policy.json"
        cache_policy = json.loads(cache_policy_path.read_text(encoding="ascii"))
        cache_policy["rules"][0]["paths"].append("/.git/config")
        cache_policy_path.write_text(
            json.dumps(cache_policy, indent=2, sort_keys=True) + "\n",
            encoding="ascii",
            newline="\n",
        )
        headers_path = unsafe_cache_path / "_headers"
        headers_path.write_text(
            headers_path.read_text(encoding="ascii")
            + "\n/.git/config\n  Cache-Control: no-cache\n",
            encoding="ascii",
            newline="\n",
        )
        with serve_site(unsafe_cache_path, mode="good") as base_url:
            rewrite_base_url(unsafe_cache_path, PLACEHOLDER_BASE_URL, base_url)
            run_checker_expect_failure(
                base_url,
                "forbidden local-state segment",
                "--expected-version",
                VERSION,
            )

        bad_base_url = temp / "bad-base-url"
        shutil.copytree(site_root, bad_base_url)
        with serve_site(bad_base_url, mode="good") as base_url:
            rewrite_base_url(bad_base_url, PLACEHOLDER_BASE_URL, base_url)
            repository_path = bad_base_url / "repository.json"
            repository = json.loads(repository_path.read_text(encoding="ascii"))
            repository["baseUrl"] = "https://wrong.example.com/conu"
            repository_path.write_text(
                json.dumps(repository, indent=2, sort_keys=True) + "\n",
                encoding="ascii",
                newline="\n",
            )
            run_checker_expect_failure(base_url, "repository.json baseUrl", "--expected-version", VERSION)

        query_download_url = temp / "query-download-url"
        shutil.copytree(site_root, query_download_url)
        with serve_site(query_download_url, mode="good") as base_url:
            rewrite_base_url(query_download_url, PLACEHOLDER_BASE_URL, base_url)
            repository_path = query_download_url / "repository.json"
            repository = json.loads(repository_path.read_text(encoding="ascii"))
            repository["downloads"]["hostedBundleUrl"] += "?token=value"
            repository_path.write_text(
                json.dumps(repository, indent=2, sort_keys=True) + "\n",
                encoding="ascii",
                newline="\n",
            )
            run_checker_expect_failure(
                base_url,
                "must not include params, query, or fragment",
                "--expected-version",
                VERSION,
            )

    print("Hosted Linux repository endpoint regression checks passed")
    return 0


def load_site_checker():
    spec = importlib.util.spec_from_file_location(
        "check_hosted_linux_repository_site",
        SITE_CHECKER,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load hosted Linux repository site checker")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def extract_site(site: Path, output_dir: Path) -> None:
    with zipfile.ZipFile(site) as archive:
        for name in archive.namelist():
            path = (output_dir / name).resolve()
            if not path.is_relative_to(output_dir.resolve()):
                raise AssertionError(f"site member escaped output dir: {name}")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(archive.read(name))


def rewrite_base_url(site_root: Path, old: str, new: str) -> None:
    for path in site_root.rglob("*"):
        if not path.is_file():
            continue
        if path.name == "_headers" or path.suffix.lower() not in {
            ".txt",
            ".json",
            ".html",
            ".list",
            ".repo",
        }:
            continue
        text = path.read_text(encoding="ascii")
        if old in text:
            path.write_text(text.replace(old, new), encoding="ascii", newline="\n")


class CachePolicyHandler(SimpleHTTPRequestHandler):
    server_version = "conu-fixture/1"

    def __init__(self, *args, directory: str, mode: str, **kwargs):
        self.mode = mode
        super().__init__(*args, directory=directory, **kwargs)

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    def end_headers(self) -> None:
        parsed = urlparse(self.path)
        request_path = unquote(parsed.path)
        if request_path == "/":
            request_path = "/index.html"
        cache_control = self.cache_control_for(request_path)
        if cache_control is not None:
            if self.mode == "wrong-cache-header" and request_path.startswith("/downloads/"):
                cache_control = "no-cache"
            self.send_header("Cache-Control", cache_control)
        super().end_headers()

    def cache_control_for(self, request_path: str) -> str | None:
        if self.mode == "missing-cache-header" and request_path == "/repository.json":
            return None
        headers_path = Path(self.directory) / "_headers"
        if not headers_path.exists():
            return None
        entries = parse_headers_file(headers_path.read_text(encoding="ascii"))
        for pattern, cache_control in entries:
            if fnmatchcase(request_path, pattern):
                return cache_control
        return None


class serve_site:
    def __init__(self, site_root: Path, *, mode: str):
        self.site_root = site_root
        self.mode = mode
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None

    def __enter__(self) -> str:
        handler = functools.partial(
            CachePolicyHandler,
            directory=str(self.site_root),
            mode=self.mode,
        )
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        if self.thread is not None:
            self.thread.join(timeout=5)


def parse_headers_file(text: str) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    current_path: str | None = None
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if line.startswith(" ") or line.startswith("\t"):
            stripped = line.strip()
            if current_path is None or ":" not in stripped:
                continue
            name, value = stripped.split(":", 1)
            if name.strip().lower() == "cache-control":
                entries.append((current_path, value.strip()))
            continue
        current_path = line.strip()
    return entries


def run_checker(base_url: str, *extra_args: str) -> str:
    completed = subprocess.run(
        [
            sys.executable,
            str(ENDPOINT_CHECKER),
            "--base-url",
            base_url,
            "--allow-loopback-http",
            *extra_args,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return completed.stdout


def run_checker_expect_failure(
    base_url: str,
    expected: str,
    *extra_args: str,
    allow_loopback_http: bool = True,
) -> str:
    args = [sys.executable, str(ENDPOINT_CHECKER), "--base-url", base_url, *extra_args]
    if allow_loopback_http:
        args.append("--allow-loopback-http")
    completed = subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode == 0 or expected not in completed.stdout:
        raise AssertionError(
            f"endpoint check failed with {completed.stdout!r}, expected {expected!r}"
        )
    return completed.stdout


if __name__ == "__main__":
    raise SystemExit(main())
