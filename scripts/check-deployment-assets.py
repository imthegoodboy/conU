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
    if (ROOT / "Dockerfile").read_text(encoding="utf-8") != (
        ROOT / "packaging/docker/relay.Dockerfile"
    ).read_text(encoding="utf-8"):
        raise SystemExit("Dockerfile must match packaging/docker/relay.Dockerfile")
    require_contains(
        "Dockerfile",
        [
            "FROM rust:1.88-bookworm AS build",
            "cargo build --release -p conu-relay",
            "conu-relay-entrypoint",
        ],
    )
    require_contains("Cargo.toml", ['rust-version = "1.88"'])
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
            "plan: free",
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
            "free plan",
            "persistent disk",
            "/healthz",
            "conu-relay --issue-credential",
            "conu peers policy",
            "metadata-only",
        ],
    )
    require_contains(
        "site/index.html",
        [
            "npm install -g conu",
            "<h1 id=\"title\">conU</h1>",
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
