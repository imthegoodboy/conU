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
```

The release workflow uploads those files beside the native archives on `v*`
tagged releases. Homebrew tap, Scoop bucket, winget-pkgs, and Chocolatey package
maintainers can copy or unpack the generated files into their package
repositories after reviewing the release.

`conu.<version>.nupkg` is a deterministic Chocolatey package containing
`conu.nuspec`, `tools/chocolateyInstall.ps1`, and
`tools/chocolateyUninstall.ps1`; it intentionally references the verified
Windows release ZIP and checksum instead of embedding the binaries.

The generated files contain only public GitHub Release URLs, static SHA-256
hashes, package metadata, install helper code, and binary mappings. They must
not contain signing secrets, npm tokens, relay tokens, local paths, conU state,
payloads, or generated release artifact contents.
