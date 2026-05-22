# conU Platform Code Signing And Notarization

This document defines the release-signing path for issue #58. It covers the
native archives produced by `.github/workflows/release.yml`; it does not add
auto-update or OS package-manager publishing.

## Release Policy

- Windows release ZIPs contain Authenticode-signed `conu.exe`, `conud.exe`,
  `conu-relay.exe`, and `conu-mcp.exe` before checksums and attestations are
  generated.
- macOS release ZIPs contain Developer ID-signed `conu`, `conud`,
  `conu-relay`, and `conu-mcp` binaries and are submitted to Apple notarization
  before checksums and attestations are generated.
- Linux release tarballs use SHA-256 checksum files plus GitHub artifact
  attestations for archive provenance. Detached GPG/minisign signatures and
  distro-specific package signatures should be added when conU publishes native
  `.deb`, `.rpm`, Homebrew, or similar packages.
- Signing secrets are maintainer-owned repository secrets. The workflow never
  prints certificates, private keys, signing passwords, npm tokens, relay
  tokens, local conU state, or payload contents.

## Required GitHub Secrets

Windows:

```txt
CONU_WINDOWS_SIGN_CERT_PFX_BASE64
CONU_WINDOWS_SIGN_CERT_PASSWORD
CONU_WINDOWS_TIMESTAMP_URL          optional, defaults to http://timestamp.digicert.com
```

macOS:

```txt
CONU_MACOS_DEVELOPER_ID_APPLICATION_P12_BASE64
CONU_MACOS_DEVELOPER_ID_APPLICATION_PASSWORD
CONU_MACOS_CODESIGN_IDENTITY
CONU_MACOS_NOTARY_APPLE_ID
CONU_MACOS_NOTARY_TEAM_ID
CONU_MACOS_NOTARY_PASSWORD
```

Publication:

```txt
NPM_TOKEN
```

`CONU_MACOS_NOTARY_PASSWORD` should be an Apple app-specific password or other
Apple-supported notary credential material. Do not store raw certificate files
or passwords in the repo.

## Workflow Behavior

On tag builds matching `v*`, the release workflow runs a preflight before
package checks and platform builds. The preflight fails closed unless all
Windows signing, macOS signing/notarization, and `NPM_TOKEN` publication secrets
are configured. `CONU_SIGNING_REQUIRED=1` is also set for the release matrix so
the platform build scripts keep their local fail-closed signing checks.

Manual `workflow_dispatch` builds can still run unsigned when secrets are
absent, which keeps smoke packaging available for maintainers. Those non-tag
runs do not publish GitHub Releases or npm packages.

The build scripts write signing status into `manifest.toml`:

```toml
windows_authenticode_signed = true
macos_codesigned = true
macos_notarized = true
linux_signature_policy = "sha256-checksum-and-github-artifact-attestation"
```

Local unsigned builds keep the booleans false.

## Verification Commands

Windows, after extracting a release ZIP:

```powershell
Get-AuthenticodeSignature .\bin\conu.exe
Get-AuthenticodeSignature .\bin\conud.exe
Get-AuthenticodeSignature .\bin\conu-relay.exe
Get-AuthenticodeSignature .\bin\conu-mcp.exe
```

Each command should report `Status` as `Valid`.

macOS, after extracting a release ZIP:

```sh
codesign --verify --strict --verbose=2 bin/conu
codesign --verify --strict --verbose=2 bin/conud
codesign --verify --strict --verbose=2 bin/conu-relay
codesign --verify --strict --verbose=2 bin/conu-mcp
spctl -a -vv -t exec bin/conu
```

The release workflow submits the ZIP with `xcrun notarytool submit --wait`; if a
submission fails, use `xcrun notarytool log <submission-id>` from the macOS
release job to inspect Apple validation output.

Linux, before extracting a release tarball:

```sh
sha256sum -c conu-0.1.0-linux-x64.tar.gz.sha256
gh attestation verify ./conu-0.1.0-linux-x64.tar.gz -R imthegoodboy/conU
```

Use the matching asset name for `linux-arm64`.

## References

- Apple documents that notarization uses Developer ID signing and accepts ZIP,
  PKG, and DMG distribution containers with `notarytool`:
  https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution
- Apple `notarytool` custom workflow:
  https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution/customizing_the_notarization_workflow
- Microsoft `Set-AuthenticodeSignature`:
  https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature
- GitHub artifact attestations:
  https://docs.github.com/en/actions/concepts/security/artifact-attestations
