---
title: How to send tax documents securely
description: Your accountant wants your W-2. Email is the worst way to send it. Three safer options, ranked by effort and by what they actually protect you from.
date: 2026-02-07
category: Guide
author: FileKey.app
---

It's tax season. Your accountant needs your W-2, a few 1099s, maybe a passport scan. The default move is to attach them to an email, and it's the worst option available. Here's why, and three safer ways ranked by effort.

## Why email is the wrong tool

Email was designed for delivery, not secrecy. An attachment sits in readable form on your machine, your provider's servers, your accountant's inbox, and every backup of all three, indefinitely. You're not trusting one company with your Social Security number; you're trusting an unknown number of them, forever.

## The options, ranked

| Method | Who can read it | Effort |
| --- | --- | --- |
| Email attachment | You, them, and every server and backup in between | None |
| Password PDF | Anyone who intercepts the password, which usually travels in the same inbox | Low |
| Client portal | You, them, and the portal vendor | Medium |
| FileKey | You and your accountant. That's the whole list. | Low |

A portal is a fine answer if your accountant already pays for one. The password-protected PDF is the trap: old PDF encryption is weak, and the password almost always travels over the same channel as the file, which defeats the point.

## Sending your W-2 with FileKey

1. Ask your accountant to open [filekey.app](/), create or unlock their filekey (Face ID, about 30 seconds), then open the **Your FileKey** menu (the sliders icon, top right) and choose **Receive a file**. It's free. They copy the link it gives them and send it to you.
2. Open that link and choose your documents. FileKey encrypts everything in your browser into a single `.shared.filekey` file locked to your accountant alone. You don't need an account or a passkey of your own to send, so there's no Face ID step on your end.
3. Send that file however you like, even regular email. Only your accountant can open it.

> **Why this works over plain email:** the attachment everyone's servers can see is unreadable ciphertext. Email becomes a courier that can't peek inside the envelope.

Nothing uploads to FileKey, there's no account to create, and the encryption is the same public-key cryptography (HPKE with AES-256) used by modern secure messengers. If you're curious how a fingerprint becomes an encryption key, we wrote up [the full technical path](/blog/passkey-to-encryption-key/).
