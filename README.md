# 🔐 FileKey

Encrypt and share files using passkeys, right in your browser. No accounts, no tracking, no servers. Everything happens on your device.

**Live at [filekey.app](https://filekey.app)** · Open source (GPLv3)

---

## Features

- **Passkey-based encryption** — your files lock and unlock with a passkey you already have (iCloud Keychain, a password manager, or a hardware security key). Nothing else to remember.
- **End-to-end** — files are sealed with AES-256 on your device. Nothing is ever uploaded.
- **No account, no tracking, no servers** — a fully static site that runs entirely in your browser, online or offline (installable as a PWA).
- **Secure sharing** — encrypt a file to someone else's share key so only they can open it, or send a link that lets anyone send *you* an encrypted file.
- **Recovery codes** — a one-time recovery code plus a self-contained offline recovery tool, so you are never locked out, even if you lose your passkey or FileKey disappears.
- **Folders and big files** — encrypt whole folders, and large files stream straight to disk without freezing the page.

---

## How it works

FileKey derives an encryption identity from your passkey's WebAuthn PRF extension, then uses HPKE (RFC 9180: DHKEM-P256 + HKDF-SHA-256 + AES-256-GCM) to encrypt your files — entirely in the browser.

## Build and run

FileKey uses [Bun](https://bun.sh).

```bash
cd reference
bun install
bun test            # crypto-core tests
bun run build:web   # build the app
bun run serve       # serve it locally
```

## Older files

Files locked with the original FileKey still open at **[v1.filekey.app](https://v1.filekey.app)** with the same passkey (the app links you there automatically).

## License

[GPLv3](LICENSE).
