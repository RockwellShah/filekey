---
title: What happens if you lose your passkey?
description: If your encryption identity comes from a passkey, what happens when you lose it? FileKey's answer: passkeys sync, and a 24-word recovery code opens your files even with an offline tool.
date: 2026-06-12
category: Guide
author: FileKey.app
---

If FileKey derives your encryption from a passkey, the obvious worry is: lose the passkey, lose your files? You don't. Passkeys sync across your devices, and a 24-word recovery code can re-derive your identity and open your files, with an offline tool that keeps working even if FileKey itself disappears.

## Do passkeys vanish if you lose your phone?

No. Passkeys sync through your platform: iCloud Keychain across Apple devices, Google Password Manager across Android and Chrome. Lose a phone and the same passkey is still on your other devices, so your FileKey identity comes right back when you unlock. The one exception is a hardware security key, which is a single physical object, and that is exactly why FileKey also gives you a recovery code.

## What is the FileKey recovery code?

It's a 24-word phrase, in the same standard format (BIP-39) that crypto wallets use. Those 24 words are the master backstop: from them, FileKey can re-derive your identity and open anything that was encrypted to you, with no passkey involved. It isn't shown at signup. You reveal it on demand from the **Your FileKey** menu (the sliders icon, top right) → **Recovery Code** → **Show it**, after a quick passkey check. Save it somewhere safe and offline. Anyone who has it can open your files, so treat it like the key it is.

## How do you open your files without the passkey?

FileKey ships an **offline recovery tool**: a single self-contained page you download, with nothing to install. You give it your 24 words and your FileKey domain, drop in your `.filekey` files, and it decrypts them locally. It makes zero network requests, by its own design, so nothing about your recovery touches a server, an account, or us.

## What if FileKey itself goes away?

That's the whole point of the offline tool. It's one HTML file that runs entirely on its own, so paired with your recovery code, your files stay openable even if filekey.app went dark tomorrow. The client is also open source and self-hostable, so the file format isn't locked to us. Your access doesn't depend on our staying online.

That's the trade FileKey makes: no password to phish, no account to lock you out of, and a recovery path you fully control. New to the model? Start with [passkeys vs passwords](/blog/passkeys-vs-passwords/), or read [how a passkey becomes an encryption key](/blog/passkey-to-encryption-key/) for the full chain.
