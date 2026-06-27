#!/usr/bin/env python3
"""Validate conU deployment and static site scaffolding."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def require(path: str) -> str:
    target = ROOT / path
    if not target.exists():
        raise SystemExit(f"missing required file: {path}")
    return target.read_text(encoding="utf-8")


def require_contains(path: str, needles: list[str]) -> None:
    text = require(path)
    missing = [needle for needle in needles if needle not in text]
    if missing:
        joined = ", ".join(repr(item) for item in missing)
        raise SystemExit(f"{path} is missing {joined}")


def main() -> None:
    require_contains(
        "packaging/docker/relay-entrypoint.sh",
        ["${PORT:-8787}", 'conu-relay --serve "0.0.0.0:${port}"'],
    )
    require_contains(
        "packaging/docker/relay.Dockerfile",
        ["conu-relay-entrypoint", "ENTRYPOINT"],
    )
    require_contains(
        "render.yaml",
        [
            "type: web",
            "runtime: docker",
            "dockerfilePath: ./packaging/docker/relay.Dockerfile",
            "mountPath: /var/lib/conu-relay",
            "CONU_RELAY_TOKEN",
            "generateValue: true",
            "healthCheckPath: /healthz",
        ],
    )
    require_contains(
        "docs/render-relay-hosting.md",
        [
            "wss://<service>.onrender.com/conu",
            "/healthz",
            "conu-relay --issue-credential",
            "conu peers policy",
            "metadata-only",
        ],
    )
    require_contains(
        "site/index.html",
        [
            "npm install -g @conu/cli",
            "Agent communication CLI",
            "Download",
        ],
    )
    require_contains(
        "site/vercel.json",
        ["cleanUrls", "Cache-Control", "styles.css"],
    )
    require_contains(
        "README.md",
        ["Fast Path", "render.yaml", ".agents/skills/conu-agent-user/SKILL.md"],
    )
    require_contains(
        ".agents/skills/conu-agent-user/SKILL.md",
        [
            "conu agents register",
            "conu messages send",
            "conu relay credential set --stdin",
            "Privacy Rules",
        ],
    )
    print("deployment assets check passed")


if __name__ == "__main__":
    main()
