# What You Need To Set So I Can Continue

Do not paste any secret values or tokens into chat. Put values only in your local terminal, local `.env.release` file, GitHub secret prompt, or the GitHub repository settings UI. After you finish, tell me only `done`.

## Current Blocker

The app is passing CI and production checks except public release signing. These 12 GitHub Actions secrets are still missing:

```txt
REQUIRED  CONU_WINDOWS_SIGN_CERT_PFX_BASE64
REQUIRED  CONU_WINDOWS_SIGN_CERT_PASSWORD
REQUIRED  CONU_MACOS_DEVELOPER_ID_APPLICATION_P12_BASE64
REQUIRED  CONU_MACOS_DEVELOPER_ID_APPLICATION_PASSWORD
REQUIRED  CONU_MACOS_CODESIGN_IDENTITY
REQUIRED  CONU_MACOS_NOTARY_APPLE_ID
REQUIRED  CONU_MACOS_NOTARY_TEAM_ID
REQUIRED  CONU_MACOS_NOTARY_PASSWORD
REQUIRED  CONU_LINUX_GPG_PRIVATE_KEY_BASE64
REQUIRED  CONU_LINUX_GPG_PASSPHRASE
REQUIRED  CONU_LINUX_GPG_KEY_ID
REQUIRED  CONU_LINUX_GPG_KEY_FINGERPRINT
```

`NPM_TOKEN` is already configured. The rotation marker is also set.

Optional release values that are not part of the current blocker:

```txt
OPTIONAL  CONU_WINDOWS_TIMESTAMP_URL
OPTIONAL  CONU_LINUX_REPOSITORY_BASE_URL
OPTIONAL  CONU_LINUX_REPOSITORY_S3_BUCKET
OPTIONAL  CONU_LINUX_REPOSITORY_S3_PREFIX
OPTIONAL  CONU_LINUX_REPOSITORY_S3_ENDPOINT_URL
OPTIONAL  CONU_LINUX_REPOSITORY_AWS_REGION
OPTIONAL  CONU_LINUX_REPOSITORY_AWS_ACCESS_KEY_ID
OPTIONAL  CONU_LINUX_REPOSITORY_AWS_SECRET_ACCESS_KEY
```

Do not set optional values unless you specifically want a custom timestamp server or a custom S3-compatible Linux repository host. The default release path uses the built-in timestamp default and GitHub Pages.

## If You Do Not Want Paid Certs Right Now

This is okay. Do not create fake secrets.

For now, you can skip:

```txt
CONU_WINDOWS_SIGN_CERT_PFX_BASE64
CONU_WINDOWS_SIGN_CERT_PASSWORD
CONU_MACOS_DEVELOPER_ID_APPLICATION_P12_BASE64
CONU_MACOS_DEVELOPER_ID_APPLICATION_PASSWORD
CONU_MACOS_CODESIGN_IDENTITY
CONU_MACOS_NOTARY_APPLE_ID
CONU_MACOS_NOTARY_TEAM_ID
CONU_MACOS_NOTARY_PASSWORD
```

Why: Windows Authenticode and Apple Developer ID/notarization require paid or identity-verified accounts/certificates. Without them, a fully signed public production release cannot pass the live tagged-release gate.

You can still continue without paid certs. The project can keep moving on:

```txt
code hardening
CI fixes
npm package readiness
release artifact verification
unsigned local/manual release builds
Linux GPG setup if you want a free signing step
```

If you want the free signing step only, set just the Linux GPG values:

```txt
CONU_LINUX_GPG_PRIVATE_KEY_BASE64
CONU_LINUX_GPG_PASSPHRASE
CONU_LINUX_GPG_KEY_ID
CONU_LINUX_GPG_KEY_FINGERPRINT
```

That improves Linux release-signature readiness, but the full tagged public release will still fail until the paid Windows and macOS signing/notary secrets are also set.

If you want me to continue without paid certs, reply:

```txt
continue without paid signing secrets
```

## Where You Get These Values

Some of these are paid identity/signing credentials. Linux GPG is the only one you can create locally for free.

### Windows Code Signing Secrets

Source: a public code-signing certificate authority that issues Windows Authenticode code-signing certificates.

Microsoft Authenticode uses a code-signing certificate issued by a certificate authority after the authority verifies the software publisher identity:

```txt
https://learn.microsoft.com/windows-hardware/drivers/install/authenticode
```

What you need to do:

1. Buy an OV or EV code-signing certificate from a certificate authority that supports Windows Authenticode signing.
2. Complete their identity verification.
3. Ask for/export the certificate as a `.pfx` file with a private key and password.
4. If the provider gives only a USB token, HSM, or cloud signing key that cannot export a `.pfx`, stop and tell me. The current workflow expects a `.pfx`, and I will need to adapt the workflow for cloud/HSM signing.

Values you get from this:

```txt
REQUIRED  CONU_WINDOWS_SIGN_CERT_PFX_BASE64      = base64 of the .pfx file
REQUIRED  CONU_WINDOWS_SIGN_CERT_PASSWORD        = password for the .pfx file
OPTIONAL  CONU_WINDOWS_TIMESTAMP_URL             = custom timestamp URL; omit for default
```

### macOS Signing And Notarization Secrets

Source: Apple Developer Program account.

Apple Developer ID certificates are used for Mac software distributed outside the Mac App Store:

```txt
https://developer.apple.com/help/account/create-certificates/create-developer-id-certificates/
https://developer.apple.com/developer-id/
```

Apple notarization uses `notarytool`; Apple documents using Apple ID/app-specific-password credentials with a Team ID:

```txt
https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution/customizing_the_notarization_workflow
https://support.apple.com/en-us/102654
```

What you need to do:

1. Enroll in the Apple Developer Program if you are not already enrolled.
2. On a Mac, open Keychain Access and create a Certificate Signing Request.
3. In the Apple Developer account, create a `Developer ID Application` certificate using that CSR.
4. Download and install the certificate on the same Mac where the private key exists.
5. Export the certificate plus private key from Keychain Access as a `.p12` file and set a strong password.
6. Get the codesign identity on that Mac:

```sh
security find-identity -v -p codesigning
```

The identity usually looks like:

```txt
Developer ID Application: Your Name (TEAMID)
```

7. Get your Apple Team ID from Apple Developer account membership details.
8. Create an Apple app-specific password for notarization from your Apple Account security settings.

Values you get from this:

```txt
REQUIRED  CONU_MACOS_DEVELOPER_ID_APPLICATION_P12_BASE64 = base64 of the .p12 file
REQUIRED  CONU_MACOS_DEVELOPER_ID_APPLICATION_PASSWORD   = password for the .p12 file
REQUIRED  CONU_MACOS_CODESIGN_IDENTITY                   = Developer ID Application identity string
REQUIRED  CONU_MACOS_NOTARY_APPLE_ID                     = Apple developer account email
REQUIRED  CONU_MACOS_NOTARY_TEAM_ID                      = Apple Team ID
REQUIRED  CONU_MACOS_NOTARY_PASSWORD                     = app-specific password or notary credential
```

### Linux GPG Signing Secrets

Source: generate a local GPG/OpenPGP signing key.

GnuPG is the tool used for OpenPGP signing. Official manual:

```txt
https://gnupg.org/documentation/manuals/gnupg/
```

On Windows, install Gpg4win if `gpg` is not available:

```txt
https://www.gpg4win.org/download.html
```

What you need to do:

1. Generate a release-signing key:

```powershell
gpg --full-generate-key
```

Recommended choices:

```txt
Kind: RSA and RSA, or ECC signing-capable key if you know what you are doing
Size: 4096 for RSA
Expiry: 1 year or 2 years
Name: conU Release Signing
Email: your maintainer email
Passphrase: strong unique passphrase
```

2. List the key and fingerprint:

```powershell
gpg --list-secret-keys --keyid-format LONG --with-fingerprint
```

Use the full 40-character fingerprint for `CONU_LINUX_GPG_KEY_FINGERPRINT`. You can also use the same full fingerprint for `CONU_LINUX_GPG_KEY_ID`.

3. Export the private key:

```powershell
gpg --armor --export-secret-keys <FULL_FINGERPRINT> > conu-release-private.asc
```

4. Base64 the exported private key:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("conu-release-private.asc")) | Set-Clipboard
```

Values you get from this:

```txt
REQUIRED  CONU_LINUX_GPG_PRIVATE_KEY_BASE64      = copied base64 private key
REQUIRED  CONU_LINUX_GPG_PASSPHRASE              = passphrase used for the GPG key
REQUIRED  CONU_LINUX_GPG_KEY_ID                  = full fingerprint or unambiguous key id
REQUIRED  CONU_LINUX_GPG_KEY_FINGERPRINT         = full 40-character fingerprint
```

## Step 1: Create The Local Template

Run this from the repo root:

```powershell
python scripts\set-github-release-secrets.py --write-env-template .env.release
```

This creates `.env.release`. It is ignored by the repo. Do not commit it.

## Step 2: Fill `.env.release`

Open the file:

```powershell
notepad .env.release
```

Fill every empty value.

Windows values:

```txt
CONU_WINDOWS_SIGN_CERT_PFX_BASE64=<base64 of your Windows code-signing .pfx>
CONU_WINDOWS_SIGN_CERT_PASSWORD=<password for that .pfx>
```

To base64 a `.pfx` in PowerShell:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\path\to\windows-signing-cert.pfx")) | Set-Clipboard
```

macOS values:

```txt
CONU_MACOS_DEVELOPER_ID_APPLICATION_P12_BASE64=<base64 of your Developer ID Application .p12>
CONU_MACOS_DEVELOPER_ID_APPLICATION_PASSWORD=<password for that .p12>
CONU_MACOS_CODESIGN_IDENTITY=<Developer ID Application: Your Name (TEAMID)>
CONU_MACOS_NOTARY_APPLE_ID=<your Apple developer email>
CONU_MACOS_NOTARY_TEAM_ID=<your Apple Team ID>
CONU_MACOS_NOTARY_PASSWORD=<Apple app-specific password or notary credential>
```

To base64 a `.p12` in PowerShell:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\path\to\developer-id-application.p12")) | Set-Clipboard
```

Linux GPG values:

```txt
CONU_LINUX_GPG_PRIVATE_KEY_BASE64=<base64 of exported private signing key>
CONU_LINUX_GPG_PASSPHRASE=<GPG private key passphrase>
CONU_LINUX_GPG_KEY_ID=<full key id or fingerprint>
CONU_LINUX_GPG_KEY_FINGERPRINT=<full 40-hex fingerprint>
```

Useful GPG commands:

```powershell
gpg --list-secret-keys --keyid-format LONG
gpg --armor --export-secret-keys <KEY_ID_OR_FINGERPRINT> > conu-release-private.asc
[Convert]::ToBase64String([IO.File]::ReadAllBytes("conu-release-private.asc")) | Set-Clipboard
```

Put the copied base64 into `CONU_LINUX_GPG_PRIVATE_KEY_BASE64`.

## Step 3: Check The File Is Complete

```powershell
python scripts\set-github-release-secrets.py --env-file .env.release --check-env-file
```

This should say all 12 required secret names have non-empty values.

## Step 4: Dry-Run The Signing Secret Preflight

```powershell
python scripts\set-github-release-secrets.py --repo imthegoodboy/conU --env-file .env.release --env-file-only --dry-run --preflight-values --require-openssl
```

If this fails because OpenSSL is missing, install OpenSSL or tell me the exact non-secret error text. Do not send certificate/private-key/password values.

## Step 5: Upload The Secrets To GitHub

Only run this after Step 4 passes:

```powershell
python scripts\set-github-release-secrets.py --repo imthegoodboy/conU --env-file .env.release --env-file-only --preflight-values --require-openssl
```

The helper sends secrets to GitHub through stdin and should not print secret values.

## Step 6: Verify Readiness

Run:

```powershell
python scripts\check-github-release-secret-readiness.py --repo imthegoodboy/conU
python scripts\check-tagged-release-readiness.py --repo imthegoodboy/conU --tag v0.1.0 --require-ci --require-default-branch-head
```

If both pass, tell me `done` and I will continue with the next production-readiness step.

If a command fails, tell me only the missing secret names or sanitized error category. Do not paste any secret values.
