#!/usr/bin/env python3
"""Regression check for tagged release update-download/apply verification gate."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
GATE_NAME = "Verify published release update policy and artifact with CLI"


def main() -> int:
    text = WORKFLOW.read_text(encoding="utf-8")
    publish_index = require_after(text, "- name: Publish release assets", 0)
    gate_index = require_after(text, f"- name: {GATE_NAME}", publish_index)
    next_job_index = require_after(text, "\n  linux-repository-pages:", gate_index)
    gate = text[gate_index:next_job_index]

    required_fragments = (
        'gh release download "$TAG_NAME" --repo "$GH_REPO" --pattern conu-linux-gpg-key.asc',
        'export GNUPGHOME="$GNUPG_HOME"',
        'gpg --batch --yes --import "$KEY_DIR/conu-linux-gpg-key.asc"',
        'CONU_LINUX_GPG_KEY_FINGERPRINT',
        'Published Linux GPG public key fingerprint mismatch',
        'APPLY_INSTALL_DIR="$RUNNER_TEMP/conu-update-apply-bin"',
        'rm -rf "$KEY_DIR" "$GNUPG_HOME" "$DOWNLOAD_DIR" "$APPLY_INSTALL_DIR"',
        'rm -rf "$DOWNLOAD_DIR" "$APPLY_INSTALL_DIR"',
        'cargo run -p conu-cli -- update check --policy-url "$POLICY_URL" --gpg-verify --json',
        'cargo run -p conu-cli -- update download --policy-url "$POLICY_URL" --output-dir "$DOWNLOAD_DIR" --target linux-x64 --gpg-verify --json',
        'cargo run -p conu-cli -- update apply --policy-url "$POLICY_URL" --artifact-file "$DOWNLOAD_DIR/conu-${VERSION}-linux-x64.tar.gz" --install-dir "$APPLY_INSTALL_DIR" --target linux-x64 --gpg-verify --dry-run --json',
        "for attempt in 1 2 3 4 5 6; do",
        "Published release update policy, linux-x64 artifact, and dry-run apply verified.",
    )
    for fragment in required_fragments:
        if fragment not in gate:
            raise AssertionError(f"{GATE_NAME} gate is missing {fragment!r}")

    release_notes_index = text.find("Installed clients can", publish_index)
    if release_notes_index == -1:
        raise AssertionError("release notes are missing installed-client update text")
    release_notes = text[release_notes_index:gate_index]
    for fragment in ("conu update download", "conu update apply"):
        if fragment not in release_notes:
            raise AssertionError(f"release notes do not mention {fragment}")

    print("release update download/apply gate regression check passed")
    return 0


def require_after(text: str, needle: str, start: int) -> int:
    index = text.find(needle, start)
    if index == -1:
        raise AssertionError(f"release workflow is missing {needle!r}")
    return index


if __name__ == "__main__":
    raise SystemExit(main())
