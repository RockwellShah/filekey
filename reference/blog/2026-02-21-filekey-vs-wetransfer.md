---
title: FileKey vs WeTransfer: what secure file sharing actually means
description: Both move files from A to B. Only one of them can't read what you're sending. An honest comparison.
date: 2026-02-21
category: Comparison
author: FileKey.app
---

WeTransfer is the default for sending a file that's too big for email. It's fast and frictionless. But "we transferred your file" and "no one but your recipient can read your file" are different promises, and only one of these tools makes the second one. Here's an honest comparison.

## What does WeTransfer do well?

Let's be fair: WeTransfer is genuinely good at its job. Drop a file, get a link, the recipient downloads it, no account needed for basic use. For a non-sensitive file, a design mockup, a video, a slide deck, it's hard to beat for convenience, and your file is encrypted in transit and at rest on their servers.

## What's the difference between FileKey and WeTransfer?

"Encrypted at rest" means WeTransfer encrypts your file on their servers with **their** keys, which means they can also decrypt it. Your file passes through, and is readable by, WeTransfer's systems. That's fine for a portfolio. It is not fine for a passport, a contract, or your tax return.

FileKey is **end-to-end** encrypted. The file is encrypted on your device, to your recipient's key, before it goes anywhere, and only your recipient can decrypt it. There is no server in the middle that can read it, because with FileKey there's no server at all: the app is a static page, and the file never leaves your device until you hand it over already encrypted.

## Side by side

| | WeTransfer | FileKey |
| --- | --- | --- |
| Who can read the file | You, your recipient, and WeTransfer | You and your recipient only |
| Encryption | In transit and at rest, their keys | End-to-end, your recipient's key |
| Account needed | No, on the free tier | No, ever |
| Where files live | WeTransfer's servers | Nowhere; you send the encrypted file yourself |
| Large files | Yes, with size and tier limits | Yes |
| Cost | Free tier plus paid Pro | Free and open source |

## When should you use FileKey vs WeTransfer?

Use WeTransfer (or anything like it) when the file isn't sensitive and you just want a quick download link. Use FileKey when the contents matter, a legal document, anything with an ID number, financial records, medical records, when "the company that runs the service can read this" is not an acceptable answer.

One honest note: FileKey today sends an encrypted **file**, not a hosted download **link**. If you specifically need a link the recipient clicks, that's a feature we're building, a zero-knowledge relay where even the relay can't read the file. Until then, FileKey is the tool for when privacy matters more than a link.

Curious how the encryption actually works? We explain [how FileKey turns a passkey into an encryption key](/blog/passkey-to-encryption-key/).
