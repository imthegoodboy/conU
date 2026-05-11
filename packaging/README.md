# conU Packaging

These files package the current conU app for local developer and early-user installs.

Phase 15 makes installation, startup, service registration, and release validation repeatable. It does not claim the unfinished public internet data plane is complete.

## Release Artifacts

Build a release directory from the repository root:

Windows:

```powershell
.\scripts\build-release.ps1
# If MSVC Build Tools are not installed:
.\scripts\build-release.ps1 -Toolchain stable-x86_64-pc-windows-gnu
```

macOS/Linux:

```sh
./scripts/build-release.sh
```

The artifact contains:

```txt
bin/conu
bin/conud
bin/conu-relay
bin/conu-mcp
docs/
packaging/
manifest.toml
```

`manifest.toml` records `payload_contents_included = false`; release archives must not contain local conU state, private keys, logs, inboxes, or message payload files.

## Windows Current-User Install

From an unpacked artifact:

```powershell
.\packaging\windows\install.ps1 -SourceBin .\bin
```

This copies binaries to:

```txt
%LOCALAPPDATA%\Programs\conU\bin
```

Add `-InstallService` from an elevated PowerShell session to create a Windows service named `conud`:

```powershell
.\packaging\windows\install.ps1 -SourceBin .\bin -InstallService
```

Uninstall:

```powershell
.\packaging\windows\uninstall.ps1 -RemoveService
```

## Linux systemd

Install binaries into `/usr/local/bin`, then copy `linux/conud.service` to `/etc/systemd/system/conud.service` and edit the `User`, `Group`, and `Environment=CONU_HOME=...` lines.

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now conud
systemctl status conud
```

## macOS launchd

Install binaries into `/usr/local/bin`, then edit `macos/com.conu.conud.plist` and replace `/Users/YOU` with the target user's absolute home path before copying it to `~/Library/LaunchAgents/`.

```sh
launchctl load ~/Library/LaunchAgents/com.conu.conud.plist
launchctl start com.conu.conud
```

## Verification

After install:

```sh
conu init
conu security audit
conu doctor
conu start
conu status
```

`conu doctor` should report `ready_for_local_use` once local state, security controls, companion binaries, and payload-safe logs are in place.
