# conU Package-Manager Manifests

conU does not hand-maintain package-manager hashes. Generate them from the
verified release assets for a tag:

```sh
python scripts/generate-package-manager-manifests.py dist --output-dir dist --version 0.1.0 --tag v0.1.0
```

The generator requires the platform archives and strict sibling `.sha256` files
for:

```txt
conu-<version>-macos-arm64.zip
conu-<version>-macos-x64.zip
conu-<version>-linux-arm64.tar.gz
conu-<version>-linux-x64.tar.gz
conu-<version>-windows-x64.zip
```

It writes:

```txt
conu.rb
conu.json
imthegoodboy.conU.yaml
conu.<version>.nupkg
conu_<version>_amd64.deb
conu_<version>_amd64.deb.sha256
conu_<version>_arm64.deb
conu_<version>_arm64.deb.sha256
conu.spec
```

The release workflow uploads those files beside the native archives on `v*`
tagged releases. Homebrew tap, Scoop bucket, winget-pkgs, Chocolatey package,
Debian repository, and RPM package maintainers can copy, unpack, or build from
the generated files after reviewing the release.

`conu.<version>.nupkg` is a deterministic Chocolatey package containing
`conu.nuspec`, `tools/chocolateyInstall.ps1`, and
`tools/chocolateyUninstall.ps1`; it intentionally references the verified
Windows release ZIP and checksum instead of embedding the binaries.

The generated Debian packages are deterministic `.deb` archives for `amd64` and
`arm64`. They embed only the four verified Linux release binaries plus small
package metadata/docs, and each `.deb` has its own strict `.sha256` sidecar. The
generated `conu.spec` references the verified Linux release archives and static
SHA-256 values for RPM builds on `x86_64` and `aarch64`; it does not submit to or
configure any RPM repository.

The generated manifest/spec files contain only public GitHub Release URLs,
static SHA-256 hashes, package metadata, install helper code, and binary
mappings. Generated Debian packages may embed the verified Linux release
binaries and minimal package metadata only. Generated package-manager outputs
must not contain signing secrets, npm tokens, relay tokens, local paths, conU
state, private payloads, or package-manager repository credentials.
