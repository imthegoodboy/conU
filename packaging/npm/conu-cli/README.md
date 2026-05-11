# @conu/cli

This npm package is a thin launcher for the native Rust conU binaries:

- `conu`
- `conud`
- `conu-relay`
- `conu-mcp`

The package does not reimplement conU in JavaScript. On install, it downloads the matching native release archive from GitHub Releases, verifies the `.sha256` file, and places the binaries under the package-local `vendor/` directory.

## Install

```sh
npm install -g @conu/cli
conu doctor
```

The expected release asset names are:

```txt
conu-0.1.0-windows-x64.zip
conu-0.1.0-linux-x64.tar.gz
conu-0.1.0-linux-arm64.tar.gz
conu-0.1.0-macos-x64.tar.gz
conu-0.1.0-macos-arm64.tar.gz
```

Each archive must have a sibling checksum file named `<asset>.sha256`.

## Environment

```txt
CONU_NPM_DIST_BASE        Override the release base URL.
CONU_NPM_BINARY_DIR       Copy binaries from a local directory instead of downloading.
CONU_NPM_SKIP_DOWNLOAD    Skip install download for package publishing checks.
CONU_NPM_ALLOW_UNVERIFIED Allow install when a checksum file is unavailable.
```

The default download base is:

```txt
https://github.com/imthegoodboy/conU/releases/download/v0.1.0
```

## Current Product Limit

The npm package only solves distribution. It does not turn the current relay into a managed public network. Users still run `conu-relay` themselves, configure trusted peer cards, and use reachable `ws://` relay endpoints until hosted auth/TLS and persistent sessions are implemented.
