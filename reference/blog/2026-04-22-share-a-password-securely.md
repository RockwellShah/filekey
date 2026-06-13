---
title: How to share a password securely
description: Sometimes you have to send a login. Here's how to share a password so it doesn't sit readable in a chat forever.
date: 2026-04-22
category: Guide
author: FileKey.app
---

Sharing a password is something you should rarely do, but sometimes must: a Wi-Fi code, a shared account, a one-time login for a contractor. Texting or emailing it leaves it readable in a thread forever. Here's how to hand off a password so it doesn't linger.

## Why a texted password is a problem

A password in a chat or email stays there, on both devices and both providers' servers, long after it's needed. If either account is ever compromised, so is the password, and anything it unlocks. People also reuse passwords, so one leaked credential often opens more than one door.

## The better ways

- **A password manager's share feature** (like Bitwarden Send) is purpose-built for this: encrypted, with an expiry.
- **FileKey** works when you'd rather not involve an account. Put the credential in a file, encrypt it to the recipient, and send it. Only they can open it, and there's no plaintext sitting in a thread.

## With FileKey

1. The recipient opens [filekey.app](/), taps **Send me a file**, and sends you the link.
2. Put the password in a text file, open the link, add it, and approve with Face ID or Touch ID.
3. Send the `.filekey` file. Only they can read it.

> Whatever method you use, change the password afterward if it protected anything important, and never reuse it elsewhere.

For the comparison, see [FileKey vs a password-protected PDF](/blog/filekey-vs-password-protected-pdf/). The deeper fix for passwords altogether is [passkeys](/blog/passkeys-vs-passwords/).
