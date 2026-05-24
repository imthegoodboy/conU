#!/usr/bin/env python3
"""Audit GitHub Actions release secret names before creating a release tag."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from github_release_secrets import (
    REQUIRED_RELEASE_SECRETS,
    SecretReadiness,
    audit_secret_names,
    find_gh,
    infer_repo,
    load_secret_names,
)


def print_text_report(report: SecretReadiness) -> None:
    if report.ready:
        print(
            "GitHub release secret readiness passed: "
            f"{len(report.present)}/{len(report.required)} required secret names configured "
            f"for {report.repo}"
        )
        return

    print(
        "GitHub release secret readiness failed: "
        f"{len(report.missing)}/{len(report.required)} required secret names missing "
        f"for {report.repo}",
        file=sys.stderr,
    )
    for name in report.missing:
        print(f"missing: {name}", file=sys.stderr)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo",
        default="",
        help="GitHub repository in owner/name form; defaults to GH_REPO or gh repo view",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print a machine-readable report containing secret names only",
    )
    parser.add_argument(
        "--gh",
        default="",
        help=argparse.SUPPRESS,
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        repo_root = Path(__file__).resolve().parents[1]
        os.chdir(repo_root)

        gh = args.gh or find_gh()
        repo = args.repo.strip() or infer_repo(gh)
        report = audit_secret_names(repo, load_secret_names(repo, gh))
    except (OSError, ValueError) as exc:
        print(f"GitHub release secret readiness failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report.as_json(), indent=2, sort_keys=True))
    else:
        print_text_report(report)
    return 0 if report.ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
