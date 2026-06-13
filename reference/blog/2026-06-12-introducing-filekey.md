---
title: Introducing FileKey
description: Why we built a file encryption tool with no accounts, no passwords, and no server, and why it's a static page on purpose.
date: 2026-06-12
category: News
author: Rockwell Shah
---

Most of us send sensitive files the same way we send everything else: as an email or chat attachment. The trouble is that those files can be read by every server and backup they pass through. FileKey is a free, open source tool that fixes this. It encrypts a file so that only one specific person can open it, using the passkey you already have.

## The idea

Passkeys solved signing in. FileKey uses the same hardware to solve encryption. When you authenticate, your passkey can return a secret that never leaves your device (the WebAuthn PRF extension). FileKey turns that secret into an encryption identity. The result is strong, modern encryption with nothing new to remember and no password that can leak.

## How sending works

Your recipient opens FileKey and taps **Send me a file**, which gives them a personal link. You open their link, choose a file, and approve with Face ID or Touch ID. FileKey encrypts the file to them, on your device, and hands you back a `.filekey` file. You send that file over any channel you already use: email, chat, a USB stick. Only your recipient can open it. There is no relay reading your data, because there is no relay at all.

## What makes it different

- **No accounts, no passwords.** Your passkey is your identity.
- **No server.** The site is a static page, and all the cryptography runs in your browser. Nothing you encrypt is ever uploaded.
- **No tracking.** No analytics, no cookies.
- **Open source.** The exact client source is published, auditable, and self-hostable.
- **Works offline.** FileKey installs as an app and encrypts and decrypts with the network off.

## Boring cryptography, on purpose

Under the hood, FileKey uses HPKE from RFC 9180: a P-256 key agreement, HKDF-SHA-256, and AES-256-GCM, streamed in chunks so that large files don't exhaust memory. Boring is a compliment in cryptography. The genuinely new part is the keys you never have to manage, because your device already manages your passkey.

## What's next

Version 1.1 added Safari and iPhone support, along with smooth handling of large files. Next, we're designing shareable links: a zero-knowledge relay so you can send a link instead of a file, without giving up end-to-end encryption. The encryption will always be free.

If you have something sensitive to send, you can [open FileKey](/) right now. And if you want to take it apart, the [source](/source.txt) is right there.
