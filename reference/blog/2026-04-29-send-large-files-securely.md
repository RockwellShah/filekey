---
title: How to send large files securely without the cloud
description: Email caps out around 25 MB. Here's how to send big files privately, without uploading them to a service that can read them.
date: 2026-04-29
category: Guide
author: FileKey.app
---

Email attachments cap out around 25 MB, so for anything bigger, a video, a design archive, a database export, people reach for a cloud link. But most cloud transfer services can read what you upload. Here's how to send a large file privately, without handing it to a server that holds the keys.

## The usual trade-off

The convenient options, cloud drives and transfer links, store your file on their servers, encrypted with their keys, which means they can read it. That's fine for a non-sensitive video, and not fine for anything confidential. Free tiers also come with size limits and expiry you don't control.

## Encrypt first, then send

FileKey encrypts the file on your device before it goes anywhere, so the size of the file doesn't change who can read it: only your recipient, ever.

1. The recipient opens [filekey.app](/), creates or unlocks their filekey, then opens the **Your FileKey** menu (the sliders icon, top right), chooses **Receive a file**, and sends you the link.
2. Open that link and add the large file. FileKey encrypts it in your browser, handling big files without freezing the page. You don't need an account or a passkey of your own to send.
3. You get an encrypted `.shared.filekey` file. Send it however you normally move large files, and only your recipient can open it, with their own passkey.

> Because the file is already encrypted, you can use any large-file transfer you like to actually move it, even a regular cloud link. The service carrying it can't read it.

See [FileKey vs WeTransfer](/blog/filekey-vs-wetransfer/) for how this compares to the usual big-file services.
