---
title: FileKey vs Bitwarden Send
description: Both send encrypted files and text. Here's how they differ, and when each is the right tool.
date: 2026-05-20
category: Comparison
author: FileKey.app
---

Bitwarden Send and FileKey both let you send something encrypted, a file or a snippet of text, without emailing it in the clear. They take different routes to get there. Here's an honest comparison.

## What does Bitwarden Send do?

If you use Bitwarden (a well-regarded open-source password manager), Send lets you share encrypted text or a file via a link, with an expiry date and an optional password. It's hosted by Bitwarden, convenient, and good at quick one-off shares.

## How is FileKey different from Bitwarden Send?

FileKey encrypts a file to a specific person's passkey, with no account and no server. The file is encrypted on your device, and only that recipient can open it. Bitwarden Send mints a link that anyone holding the link (and password, if set) can open; FileKey locks the file to one identity.

| | Bitwarden Send | FileKey |
| --- | --- | --- |
| Model | Encrypted link, optional password | Encrypted to a person's passkey |
| Account | Bitwarden account to send | None, ever |
| Where it lives | Bitwarden's servers | Nowhere; you send the file |
| Expiry | Yes, built in | You control the file |
| Best for | Quick shares, text snippets | Locking a file to one person |

## When should you use FileKey vs Bitwarden Send?

If you already live in Bitwarden and want a quick expiring link, Send is great. If you want the file locked to one specific person, with no account and no server in the middle, that's FileKey. They're more complementary than competing.

For the hosted-link comparison generally, see [FileKey vs WeTransfer](/blog/filekey-vs-wetransfer/).
