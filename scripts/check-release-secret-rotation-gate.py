#!/usr/bin/env python3
"""Fail release preflight when a required secret rotation marker is stale."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from github_release_secrets import REQUIRED_RELEASE_SECRETS


@dataclass(frozen=True)
class RotationGateReport:
    secret_name: str
    marker_env: str
    required_after: str
    rotated_after: str
    ready: bool
    issues: tuple[str, ...]

    def as_json(self) -> dict[str, Any]:
        return {
            "schema": "conu.releaseSecretRotationGate.v1",
            "checked": True,
            "ready": self.ready,
            "secretName": self.secret_name,
            "markerEnv": self.marker_env,
            "requiredAfter": self.required_after,
            "rotatedAfter": self.rotated_after,
            "issues": list(self.issues),
            "payloadDisplayed": False,
            "tokenDisplayed": False,
            "tokenHashDisplayed": False,
            "keyMaterialDisplayed": False,
            "contentsDisplayed": False,
            "secretValuesDisplayed": False,
        }


def parse_utc_timestamp(value: str, label: str) -> datetime:
    raw = value.strip()
    if not raw:
        raise ValueError(f"{label} timestamp must not be empty")
    if raw.endswith("Z"):
        raw = f"{raw[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise ValueError(f"{label} timestamp must be ISO-8601 with a timezone") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def render_utc_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def audit_rotation_marker(
    *,
    secret_name: str,
    marker_env: str,
    required_after: str,
    rotated_after: str,
) -> RotationGateReport:
    normalized_secret = secret_name.strip()
    if normalized_secret not in REQUIRED_RELEASE_SECRETS:
        raise ValueError(
            f"release secret rotation gate uses an unknown required secret: {normalized_secret}"
        )
    normalized_marker = marker_env.strip()
    if not normalized_marker:
        raise ValueError("release secret rotation marker env name is required")

    required = parse_utc_timestamp(required_after, f"{normalized_secret} required rotation")
    rendered_required = render_utc_timestamp(required)
    observed_raw = rotated_after.strip()
    if not observed_raw:
        return RotationGateReport(
            secret_name=normalized_secret,
            marker_env=normalized_marker,
            required_after=rendered_required,
            rotated_after="",
            ready=False,
            issues=(f"{normalized_secret} rotation marker {normalized_marker} is missing",),
        )

    try:
        observed = parse_utc_timestamp(observed_raw, f"{normalized_secret} rotation marker")
    except ValueError:
        return RotationGateReport(
            secret_name=normalized_secret,
            marker_env=normalized_marker,
            required_after=rendered_required,
            rotated_after="",
            ready=False,
            issues=(f"{normalized_secret} rotation marker timestamp is invalid",),
        )

    rendered_observed = render_utc_timestamp(observed)
    if observed <= required:
        return RotationGateReport(
            secret_name=normalized_secret,
            marker_env=normalized_marker,
            required_after=rendered_required,
            rotated_after=rendered_observed,
            ready=False,
            issues=(f"{normalized_secret} rotation marker is not after required timestamp",),
        )

    return RotationGateReport(
        secret_name=normalized_secret,
        marker_env=normalized_marker,
        required_after=rendered_required,
        rotated_after=rendered_observed,
        ready=True,
        issues=(),
    )


def print_text_report(report: RotationGateReport) -> None:
    if report.ready:
        print(
            "Release secret rotation gate passed: "
            f"{report.secret_name} marker {report.marker_env} is after {report.required_after}"
        )
        return
    print("Release secret rotation gate failed", file=sys.stderr)
    for issue in report.issues:
        print(f"issue: {issue}", file=sys.stderr)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--secret-name", required=True, help="required release secret name")
    parser.add_argument(
        "--rotated-after-env",
        required=True,
        help="environment variable containing a non-secret rotation timestamp marker",
    )
    parser.add_argument(
        "--required-after",
        required=True,
        help="minimum required rotation timestamp, as ISO-8601 with timezone",
    )
    parser.add_argument("--json", action="store_true", help="print a machine-readable report")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        marker_value = os.environ.get(args.rotated_after_env, "")
        report = audit_rotation_marker(
            secret_name=args.secret_name,
            marker_env=args.rotated_after_env,
            required_after=args.required_after,
            rotated_after=marker_value,
        )
    except ValueError as exc:
        print(f"Release secret rotation gate failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report.as_json(), indent=2, sort_keys=True))
    else:
        print_text_report(report)
    return 0 if report.ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
