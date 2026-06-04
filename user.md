# Simple Launch Setup For Now

Do not paste tokens, passwords, certificates, private keys, or secret values into chat. Put secrets only in a GitHub secret prompt, a local ignored file, or the GitHub repository settings UI.

## What Is Required Right Now

For simple testing and launch prep, you do not need paid Windows or Apple signing certificates.

The only release/publish value needed right now is already set:

```txt
REQUIRED  NPM_TOKEN  GitHub Actions secret
```

You already ran:

```powershell
gh secret set NPM_TOKEN --repo imthegoodboy/conU
```

The npm token rotation marker is also already set, so there is nothing else you need to paste or configure for npm right now.

## What You Can Skip For Now

Skip all paid signing values for now:

```txt
SKIP_FOR_NOW  CONU_WINDOWS_SIGN_CERT_PFX_BASE64
SKIP_FOR_NOW  CONU_WINDOWS_SIGN_CERT_PASSWORD
SKIP_FOR_NOW  CONU_MACOS_DEVELOPER_ID_APPLICATION_P12_BASE64
SKIP_FOR_NOW  CONU_MACOS_DEVELOPER_ID_APPLICATION_PASSWORD
SKIP_FOR_NOW  CONU_MACOS_CODESIGN_IDENTITY
SKIP_FOR_NOW  CONU_MACOS_NOTARY_APPLE_ID
SKIP_FOR_NOW  CONU_MACOS_NOTARY_TEAM_ID
SKIP_FOR_NOW  CONU_MACOS_NOTARY_PASSWORD
```

Do not create fake values for these. They are only needed later for a fully signed public Windows/macOS release.

You can also skip Linux GPG signing for now unless you specifically want signed Linux release artifacts:

```txt
OPTIONAL_FOR_NOW  CONU_LINUX_GPG_PRIVATE_KEY_BASE64
OPTIONAL_FOR_NOW  CONU_LINUX_GPG_PASSPHRASE
OPTIONAL_FOR_NOW  CONU_LINUX_GPG_KEY_ID
OPTIONAL_FOR_NOW  CONU_LINUX_GPG_KEY_FINGERPRINT
```

## What This Means

For now, conU can keep moving through:

```txt
local app testing
CI hardening
npm package checks
release artifact verification
unsigned local/manual builds
production-readiness fixes that do not require paid certificates
```

The only thing that will still be blocked is the final fully signed public tagged release gate. That is expected until real Windows/macOS signing credentials exist.

## How To Test Locally Now

From the repo root:

```powershell
cargo fmt --check
cargo check --workspace --all-targets
npm run check --prefix packaging/npm/conu-cli
python scripts\check-production-readiness-toolchain.py
python scripts\verify-release-versions.py
python scripts\check-release-artifact-verifier.py
python scripts\check-release-artifact-smoke-preflight.py
python scripts\check-npm-launcher-local-smoke-preflight.py
```

If local Rust checks fail on Windows because `dlltool.exe` or `link.exe` is missing, tell me only that tool name. Do not paste secrets.

## How To Let Me Continue

Reply with:

```txt
continue without paid signing secrets
```

Then I will continue production-readiness work without waiting for Windows/macOS certificates.

## Later Only: Fully Signed Public Release

Only when you want a fully signed public release, you will need real signing credentials:

```txt
Windows: code-signing certificate from a certificate authority
macOS: Apple Developer Program Developer ID certificate and notarization credentials
Linux: GPG release-signing key
```

Those are not needed for the simple launch/testing path right now.
