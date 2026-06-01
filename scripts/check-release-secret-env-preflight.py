#!/usr/bin/env python3
"""Validate injected release secret environment values before a tagged release."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Mapping

from github_release_secrets import REQUIRED_RELEASE_SECRETS


def main() -> int:
    args = parse_args()
    report = audit_environment(os.environ)

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    elif report["ready"]:
        print("Tagged release secret environment preflight passed.")
    else:
        print("Tagged release secret environment preflight failed.", file=sys.stderr)
        for name in report["missing"]:
            print(f"missing: {name}", file=sys.stderr)

    return 0 if report["ready"] else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json",
        action="store_true",
        help="print a machine-readable report containing secret names only",
    )
    return parser.parse_args()


def audit_environment(env: Mapping[str, str]) -> dict[str, object]:
    missing = tuple(
        name
        for name in REQUIRED_RELEASE_SECRETS
        if (value := env.get(name)) is None or value.strip() == ""
    )
    present = tuple(name for name in REQUIRED_RELEASE_SECRETS if name not in missing)
    return {
        "schema": "conu.releaseSecretEnvPreflight.v1",
        "ready": not missing,
        "required": REQUIRED_RELEASE_SECRETS,
        "present": present,
        "missing": missing,
        "payloadDisplayed": False,
        "contentsDisplayed": False,
        "tokenDisplayed": False,
        "tokenHashDisplayed": False,
        "keyMaterialDisplayed": False,
        "secretValuesDisplayed": False,
    }


if __name__ == "__main__":
    raise SystemExit(main())
