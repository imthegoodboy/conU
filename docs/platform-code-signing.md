# conU Platform Code Signing And Notarization

This document defines the release-signing path for issue #58. It covers the
native archives and generated package assets produced by
`.github/workflows/release.yml`; it does not add auto-update or OS
package-manager publishing.

## Release Policy

- Windows release ZIPs contain Authenticode-signed `conu.exe`, `conud.exe`,
  `conu-relay.exe`, and `conu-mcp.exe` before checksums and attestations are
  generated.
- macOS release ZIPs contain Developer ID-signed `conu`, `conud`,
  `conu-relay`, and `conu-mcp` binaries and are submitted to Apple notarization
  before checksums and attestations are generated.
- Linux release tarballs use SHA-256 checksum files, GitHub artifact
  attestations for archive provenance, and armored detached GPG `.asc`
  signatures. Generated Debian packages use SHA-256 sidecars plus detached
  `.asc` signatures. Generated RPM packages use native RPM package signatures,
  refreshed SHA-256 sidecars, and detached `.asc` signatures. Generated APT
  metadata ZIP bundles add native `InRelease` and `Release.gpg` signatures over
  `Release`; generated RPM metadata ZIP bundles are generated from signed RPM
  packages and add `repodata/repomd.xml.asc` over `repodata/repomd.xml`. Both
  metadata ZIPs refresh their `.sha256` sidecars before detached `.asc`
  signatures are created over the final ZIPs.
  Tagged releases also publish `conu-linux-gpg-key.asc` plus its `.sha256`
  sidecar so users can verify those Linux signatures from release assets. The
  release workflow pins the imported Linux GPG private key to the configured
  full maintainer fingerprint before any Linux public key, RPM package,
  repository metadata, or detached signature asset is produced.
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

Linux GPG signatures:

```txt
CONU_LINUX_GPG_PRIVATE_KEY_BASE64
CONU_LINUX_GPG_PASSPHRASE
CONU_LINUX_GPG_KEY_ID
CONU_LINUX_GPG_KEY_FINGERPRINT
```

`CONU_LINUX_GPG_KEY_FINGERPRINT` must be the full 40-hex-character primary
maintainer key fingerprint. `CONU_LINUX_GPG_KEY_ID` should be the same full
fingerprint or another non-ambiguous key id that resolves to that one primary
secret key after import.

`CONU_MACOS_NOTARY_PASSWORD` should be an Apple app-specific password or other
Apple-supported notary credential material. Do not store raw certificate files
or passwords in the repo.

Before storing or tagging with these values, export the local environment and
run:

```sh
python scripts/check-platform-signing-secrets-preflight.py --require-openssl --json
```

The preflight decodes the Windows PFX and macOS P12 as strict base64, validates
the macOS notary identity fields, rejects timestamp URLs with credentials,
queries, or fragments, and uses OpenSSL to confirm each PKCS#12 blob parses
with the configured password and contains both a certificate and a private key.
Its text and JSON reports include only environment variable names, booleans, and
sanitized failure categories; they do not print certificates, private keys,
passwords, tokens, or signing material.

To run the same value checks during GitHub secret setup, export all required
release secret values and run:

```sh
python scripts/set-github-release-secrets.py --repo <owner/name> --dry-run --preflight-values --require-openssl
```

Instead of exporting values into the shell, maintainers may place the required
`KEY=VALUE` pairs in an ignored local file such as `.env.release` and run:

```sh
python scripts/set-github-release-secrets.py --repo <owner/name> --env-file .env.release --dry-run --preflight-values --require-openssl
```

The env-file parser accepts only the required release secret names, rejects
malformed, duplicate, or unsupported keys, and reports only names plus line
numbers. It must not be committed; the repository ignores `.env` and `.env.*`
files by default.

That helper also runs the Linux GPG signing-secret preflight, suppresses
preflight stdout/stderr to avoid leaking secret material from subprocesses, and
sends values to `gh secret set` through stdin when rerun without `--dry-run`.
Run the standalone preflight scripts directly when a setup failure needs a
sanitized diagnostic report.

## Workflow Behavior

On tag builds matching `v*`, the release workflow runs a preflight before
package checks and platform builds. The preflight fails closed unless all
Windows signing, macOS signing/notarization, Linux GPG signing, and
`NPM_TOKEN` publication secrets are configured. It also validates the configured
Windows PFX and macOS P12 values with OpenSSL before platform matrix jobs start,
imports the configured Linux GPG private key into a temporary keyring, verifies that
`CONU_LINUX_GPG_KEY_ID` resolves to `CONU_LINUX_GPG_KEY_FINGERPRINT`, and
probe-signs a temporary file with `CONU_LINUX_GPG_PASSPHRASE` so malformed
keys, mismatched fingerprints, and wrong passphrases fail before builds.
`CONU_SIGNING_REQUIRED=1` is also set for the release matrix so the platform
build scripts keep their local fail-closed signing checks.

Manual `workflow_dispatch` builds can still run unsigned when secrets are
absent, which keeps smoke packaging available for maintainers. Those non-tag
runs do not publish GitHub Releases or npm packages.

Tagged GitHub Release publication imports the Linux GPG private key into a
temporary `GNUPGHOME`, verifies the imported primary secret-key fingerprint
against `CONU_LINUX_GPG_KEY_FINGERPRINT`, signs generated RPM package payloads
first, refreshes their `.rpm.sha256` sidecars, generates RPM repository metadata
from those signed RPM packages, then adds and verifies native signatures inside
the generated APT/RPM repository metadata ZIPs and refreshes their `.sha256`
sidecars. It then signs only the Linux archives, generated Debian/RPM packages,
and final APT/RPM repository metadata ZIPs with detached `.asc` signatures.
Every signature is verified before upload, and the temporary keyring is removed
when the job exits. A missing or mismatched fingerprint fails closed during tag
preflight and again before any Linux signing artifact is written.

The same temporary import path exports only the armored Linux GPG public key as
`conu-linux-gpg-key.asc` with a strict `.sha256` sidecar. The workflow refuses
to write private-key material as that public-key asset.

The build scripts write signing status into `manifest.toml`:

```toml
windows_authenticode_signed = true
macos_codesigned = true
macos_notarized = true
linux_signature_policy = "sha256-checksum-and-github-artifact-attestation"
```

Local unsigned builds keep the booleans false. Linux detached signatures are
created later during tagged GitHub Release publication, so they are represented
by adjacent `.asc` release assets rather than by fields inside the archive
manifest.

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
sha256sum -c conu-linux-gpg-key.asc.sha256
EXPECTED_CONU_LINUX_GPG_FINGERPRINT=<published-40-hex-maintainer-fingerprint>
gpg --show-keys --with-colons conu-linux-gpg-key.asc | awk -F: '/^fpr:/ {print $10; exit}' | grep -Fx "$EXPECTED_CONU_LINUX_GPG_FINGERPRINT"
gpg --import conu-linux-gpg-key.asc
sha256sum -c conu-0.1.0-linux-x64.tar.gz.sha256
gh attestation verify ./conu-0.1.0-linux-x64.tar.gz -R imthegoodboy/conU
gpg --verify conu-0.1.0-linux-x64.tar.gz.asc conu-0.1.0-linux-x64.tar.gz
```

Use the matching asset name for `linux-arm64`. Generated Debian/RPM package and
repository metadata assets use the same detached verification form:

```sh
gpg --verify conu_0.1.0_amd64.deb.asc conu_0.1.0_amd64.deb
gpg --verify conu-0.1.0-1.x86_64.rpm.asc conu-0.1.0-1.x86_64.rpm
gpg --verify conu-0.1.0-apt-repository-metadata.zip.asc conu-0.1.0-apt-repository-metadata.zip
gpg --verify conu-0.1.0-rpm-repository-metadata.zip.asc conu-0.1.0-rpm-repository-metadata.zip
```

Generated repository metadata ZIPs also carry native repository signatures:

```sh
unzip -q conu-0.1.0-apt-repository-metadata.zip -d apt-metadata
gpg --verify apt-metadata/InRelease
gpg --verify apt-metadata/Release.gpg apt-metadata/Release

unzip -q conu-0.1.0-rpm-repository-metadata.zip -d rpm-metadata
gpg --verify rpm-metadata/repodata/repomd.xml.asc rpm-metadata/repodata/repomd.xml
```

Generated RPM packages also carry native RPM package signatures. Import the
release public key into a throwaway RPM database when checking manually:

```sh
mkdir -p rpmdb
rpm --define "_dbpath $(pwd)/rpmdb" --import conu-linux-gpg-key.asc
rpmkeys --define "_dbpath $(pwd)/rpmdb" --checksig --verbose conu-0.1.0-1.x86_64.rpm
```

Use the matching RPM asset name for `aarch64`.

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
- RPM `rpmsign` manual:
  https://rpm.org/docs/4.20.x/man/rpmsign.8
