---
title: FileKey vs a password-protected PDF
description: Locking a PDF with a password feels secure. Here's why it's weaker than you think, and when it's actually fine.
date: 2026-09-01
category: Comparison
author: FileKey.app
---

When someone needs to send a sensitive document "securely," the instinct is to slap a password on the PDF and email it. It feels responsible. But a password-protected PDF has two weak points that quietly undo most of the protection. Here's the honest comparison.

## Weak point one: the encryption is often weak

PDF password protection is only as strong as the tool that made it and the password you chose. Older PDF encryption, and many quick "lock this PDF" tools, use schemes that off-the-shelf software cracks in minutes, and a short or guessable password falls to a dictionary attack no matter how good the scheme is. Modern PDF software with AES-256 and a long random password is genuinely strong, but most people never get there.

## Weak point two: the password travels with the file

This is the one that gets everyone. The password almost always goes through the same channel as the file. You email the locked PDF, then email or text the password. Anyone who can read one inbox can read both. You've locked the door and taped the key to it.

## How FileKey is different

FileKey doesn't use a password you have to transmit. The file is encrypted to your recipient's passkey, so the key is something only their device holds. You never send it at all, which means there's nothing to intercept.

| | Password-protected PDF | FileKey |
| --- | --- | --- |
| Strength | Depends on the tool and password | AES-256, always |
| The key | A password you must send separately | Your recipient's passkey; never transmitted |
| Common failure | Password sent over the same channel | Nothing to send |
| Works for | PDFs | Any file |

## When a password PDF is fine

If you use modern software with AES-256, pick a long random password, and deliver that password through a genuinely different channel (the file by email, the password by a phone call), a password-protected PDF is reasonable. The trouble is that's a lot of "ifs," and most people skip them. FileKey removes the ifs.

See also [FileKey vs WeTransfer](/blog/filekey-vs-wetransfer/) for the hosted-link comparison.
