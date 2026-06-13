# 🔐 FileKey

FileKey is an offline web app that lets you quickly encrypt and share files using passkeys. No accounts, no tracking, no cloud.

> 🛡️ **FileKey is free, open source, and privacy-first.** Live at **[filekey.app](https://filekey.app)**.

---

### 🚀 Features

- ✅ **Free & Open Source** – Licensed under GPLv3.
- ✅ **Accountless** – No logins, no tracking.
- ✅ **Passkey-Based Encryption** – Uses your existing passkey, password manager, or hardware security key.
- ✅ **No Cloud** – Files are sealed with AES-256 on your device. Nothing is ever uploaded.
- ✅ **Secure Sharing** – Encrypt a file to someone's Share Key, or post a "send me a file" link.
- ✅ **Recovery Codes** – Optional offline recovery codes so you're never locked out.
- ✅ **Folders & Large Files** – Encrypt whole folders, and stream multi-gigabyte files easily.
- ✅ **Offline** – Runs 100% in your browser, online or offline. Installable as a PWA.

---

### 🗣️ What People Say 

- French cybersecurity blogger Korben wrote a nice [breakdown of FileKey](https://korben.info/filekey-chiffrement-fichiers-passkeys-local-opensource.html).
- Tom Dörr's [X thread](https://x.com/tom_doerr/status/1921957643444273491?s=20). (40k+ views)
- Launch Post on [Reddit](https://www.reddit.com/r/yubikey/comments/1iiptny/introducing_filekey_encrypt_decrypt_files_using/). (100k+ views)
- Sharing Feature Launch on [Reddit](https://www.reddit.com/r/yubikey/comments/1jbbvwd/update_filekey_encrypt_share_files_using/) (45k+ views)
- PrivacyGuide [Discussion](https://discuss.privacyguides.net/t/filekey-passkey-file-encryption/26326/3)

---

### 👨‍💻 How to Use FileKey

1. **Create your FileKey**<br>
   Create a passkey stored in your password manager or security key (iCloud Keychain, Google Password Manager, 1Password, a YubiKey, etc.).

2. **Encrypt files**<br>
   Drop any file (or a whole folder) into FileKey. It's encrypted instantly with AES-256 and saved as `name.filekey`.

3. **Decrypt files**<br>
   Drop the encrypted file back in. Your passkey unlocks it, locally and securely.

4. **Share privately**<br>
   Encrypt a file to someone's Share Key (only they can open it), or share a "send me a file" link to receive encrypted files from anyone.

5. **Save a recovery code**<br>
   Optionally save a one-time recovery code so you can get back into your files even if you lose your passkey.

---

### 💾 Supported Systems

FileKey needs a passkey provider that supports the WebAuthn **PRF extension**: a compatible password manager (Apple Passwords, Google Password Manager, 1Password, etc.) or a FIDO2 hardware security key (YubiKey 5 / Bio Series). Your browser and OS must also support WebAuthn + PRF. A non-exhaustive compatibility table:

| Platform | Passkey providers | Notes |
|----------|-------------------|-------|
| **macOS** | Apple Passwords, 1Password, YubiKey | Safari ≥ 17 or Chrome ≥ 112. YubiKeys may not work in Safari. |
| **iOS / iPadOS** | Apple Passwords, 1Password | Safari ≥ 17 or Chrome ≥ 112. |
| **Windows** | 1Password, YubiKey | Edge ≥ 112 or Chrome ≥ 112. Requires Windows 11. |
| **Android** | Google Password Manager, 1Password, YubiKey | Chrome ≥ 112. |
| **Linux** | YubiKey (via browser) | Recent Chrome / Chromium browsers. |

> ⚠️ **Notes:**
> - The provider must implement the WebAuthn PRF extension; support varies by app and version, so if a manager doesn't work yet, it likely hasn't shipped PRF.
> - Chromium-based browsers (Brave, Vivaldi, Opera) generally work.
> - Windows 10 and earlier don't support PRF.

---

### 🛠️ How the Encryption Works

FileKey derives your encryption identity from a passkey. When you create your FileKey, a passkey is registered against the app's domain (`filekey.app`) as the relying party. Authenticating runs the passkey's PRF extension over a fixed input, producing a deterministic secret that never leaves your device. That secret is run through HKDF-SHA-256 to derive your long-term identity key pair, so the same passkey always reproduces the same identity, and nothing has to be stored beyond the passkey itself.

Files are encrypted with HPKE (Hybrid Public Key Encryption, [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html)) in Auth mode, using the DHKEM-P256 + HKDF-SHA-256 suite. HPKE derives fresh per-file keys, and the file body is sealed with AES-256-GCM in a streaming, chunked construction so files of any size encrypt and decrypt without being held entirely in memory. Encrypting to yourself uses your own public key; sharing uses the recipient's. Every operation runs entirely on your device through audited crypto libraries.

> 🛡️ Your passkey is the only credential. There's nothing else to store, and nothing ever leaves your device.

---

### 🔁 Sharing

Every FileKey user has a unique Share Key, a long public string you'll find in the menu under "Your Share Key." It's safe to share openly; it's a public address, not a secret.

#### 📤 Sharing a file

1. Choose Share when encrypting (or send to a saved contact).
2. Enter the recipient's Share Key.
3. FileKey produces a file only that recipient can open, named `name.shared.filekey`. Send it by any method: email, messaging, file transfer.

#### 📥 Receiving a shared file

1. Open FileKey and authenticate.
2. Drop the `.shared.filekey` file in.
3. FileKey recognizes it and decrypts it with your key.

#### 📨 "Send me a file"

Share a "send me a file" link (it embeds your Share Key). Anyone (no account, no passkey) can use it to encrypt a file *to you* right in their browser, then send you the result. Only you can open it.

#### 🔐 Security details

- Your private keys never leave your device.
- Shared files are locked to a specific recipient (public-key, end-to-end).
- All encryption and decryption happen on your device, with no servers involved.
- Files are sealed with AES-256.
- Your Share Key is public and can be shared openly.

---

### 🔑 Recovery Codes

Because your identity comes from your passkey, losing that passkey would normally mean losing access. FileKey offers an optional recovery code, a 24-word phrase (BIP39) that backs up your identity. Save it once, keep it somewhere safe, and you can restore access later.

FileKey also ships a self-contained offline recovery tool (`recover.html`): a single HTML file you can keep on disk. With your recovery code it decrypts your `.filekey` files entirely offline, even if the FileKey website ever disappears.

---

### 🫥 What Happens if FileKey Disappears?

Two safety nets:

1. **The offline recovery tool** (above) opens your files with just your recovery code, no website required.
2. **Install FileKey as an app** so it keeps working offline:

#### 💻 Desktop (Chrome / Edge / Brave)
Open FileKey, click the Install icon in the address bar, and confirm. It opens as a standalone offline app.

#### 📱 iOS / iPadOS (Safari)
Open FileKey in Safari → tap Share → Add to Home Screen → Add.

#### 🤖 Android (Chrome / Edge / Brave / Samsung Internet)
Open FileKey → tap Add to Home screen (banner or ⋮ menu) → confirm.

Because FileKey is a static site with no backend, you can also self-host it (see below).

---

### 🛠️ Build & Self-Host

FileKey is a static site built with [Bun](https://bun.sh):

```bash
cd reference
bun install
bun test            # crypto-core tests
bun run build:web   # build the app
bun run serve       # serve it locally
```

The build output is plain static files. Host them on any static host or your own server.

---

### 📦 Older Files

FileKey 1.1 uses a new, standards-based format and cannot open files made by the original FileKey. Old files still open at **[v1.filekey.app](https://v1.filekey.app)** with the same passkey, and FileKey links you there automatically when it detects one. The original v1 source lives on the [`v1` branch](../../tree/v1).

---

### 🔗 Links

> 🔒 **[filekey.app](https://filekey.app)** – the app
>
> 📜 **[Substack](https://filekey.substack.com/)** – our blog
>
> 💬 **[Signal Group](https://signal.group/#CjQKIDpdakX0nr1V00ciNv3dsWCFZgUwm_NylulFJz4VOUJ_EhBtY-bq759RNExzcCWMUGIB)** – chat with us

---

### 📜 License

[GPLv3](LICENSE).
