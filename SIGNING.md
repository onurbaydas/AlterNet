# Code Signing for AlterNet

This document explains the GitHub secrets required for signed release builds and how to prepare each certificate or key.

Unsigned builds still work — signing is entirely optional for local development and testing. The secrets listed here are only needed when publishing official releases via GitHub Actions.

---

## Required GitHub Secrets

Set these in your repository under Settings > Secrets and variables > Actions.

### Tauri Update Signing (all platforms)

| Secret | Description |
|--------|-------------|
| `TAURI_SIGNING_PRIVATE_KEY` | Ed25519 private key used to sign Tauri update manifests |
| `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | Password protecting the private key (leave empty string if none) |

These two secrets enable Tauri's built-in updater signing so that auto-update payloads can be verified by clients before installation.

### Apple / macOS Signing and Notarization

| Secret | Description |
|--------|-------------|
| `APPLE_CERTIFICATE` | Base64-encoded `.p12` Developer ID certificate |
| `APPLE_CERTIFICATE_PASSWORD` | Password used when exporting the `.p12` |
| `APPLE_SIGNING_IDENTITY` | The exact identity string, e.g. `Developer ID Application: Your Name (TEAMID)` |
| `APPLE_ID` | Apple ID email address used for notarization |
| `APPLE_PASSWORD` | App-specific password for the Apple ID (not your login password) |
| `APPLE_TEAM_ID` | Your 10-character Apple Developer Team ID |

### Windows Code Signing

| Secret | Description |
|--------|-------------|
| `WINDOWS_CERTIFICATE` | Base64-encoded `.pfx` code-signing certificate |
| `WINDOWS_CERTIFICATE_PASSWORD` | Password protecting the `.pfx` |

---

## How to Generate the Tauri Signing Keypair

Run the following command once and store the output securely:

```
tauri signer generate -w ~/.tauri/alternet.key
```

This creates a private key file at `~/.tauri/alternet.key` and prints the corresponding public key to stdout.

- Paste the **private key file contents** as the `TAURI_SIGNING_PRIVATE_KEY` secret.
- Add the **public key** to `tauri.conf.json` under `plugins.updater.pubkey` so clients can verify updates.

---

## How to Prepare the Apple Certificate

1. In Xcode or Keychain Access, export your Developer ID Application certificate as a `.p12` file and set a strong export password.
2. Base64-encode the file:

```bash
base64 -i DeveloperID.p12 | pbcopy
```

3. Paste the result as the `APPLE_CERTIFICATE` secret.
4. Store the export password as `APPLE_CERTIFICATE_PASSWORD`.
5. Create an app-specific password at appleid.apple.com and store it as `APPLE_PASSWORD`.

---

## How to Prepare the Windows Certificate

1. Obtain a code-signing certificate as a `.pfx` file from a trusted CA (e.g. DigiCert, Sectigo) or export one from the Windows Certificate Store.
2. Base64-encode the file:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("certificate.pfx")) | Set-Clipboard
```

Or on macOS/Linux:

```bash
base64 -i certificate.pfx | pbcopy
```

3. Paste the result as the `WINDOWS_CERTIFICATE` secret.
4. Store the certificate password as `WINDOWS_CERTIFICATE_PASSWORD`.

---

## Local / Unsigned Builds

If any of the secrets above are absent the corresponding signing step is skipped (the Apple and Windows import steps are conditional on `matrix.platform`). The Tauri build will still succeed and produce installable artifacts — they simply will not carry a verified signature or pass Gatekeeper/SmartScreen automatically.
