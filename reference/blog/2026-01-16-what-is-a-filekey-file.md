---
title: What is a .filekey file?
description: A .filekey file is an end-to-end encrypted file made with FileKey. Open it free in your browser with a passkey. No account, nothing to install.
date: 2026-01-16
category: Guide
author: FileKey.app
---

A `.filekey` file is an encrypted file made with FileKey. If someone sent you one, they chose you: it is locked so that only you can open it. Opening it is free, takes about a minute, and happens entirely on your device. A file ending in `.shared.filekey` is the same thing, encrypted for sharing.

## How to open a .filekey file

1. Go to **filekey.app** in your browser, on your phone or computer.
2. Add the `.filekey` file by dragging it in or tapping to choose it.
3. Approve with Face ID, Touch ID, or your device PIN when asked.

If the file was encrypted to you, you get the original back instantly, exactly as it was sent. The unlocking happens in your browser; the file is never uploaded anywhere. First time here? FileKey sets you up with a passkey first, the same Face ID or fingerprint sign-in you already use elsewhere. It takes about 30 seconds, with no account and no password.

## Why won't a .filekey file open?

A `.filekey` file is locked to one person's key, so the usual reason it won't open is that it was not encrypted to you:

- **The sender made it before you had FileKey.** Set up at filekey.app, then open the **Your FileKey** menu (the sliders icon, top right) and choose **Receive a file** to get your personal link, and pass it to the sender. When they send a file through your link, the new file is locked to you and will open.
- **You encrypted it yourself.** Open it on a device signed in with the same passkey you used to create it, or recover access with your recovery code.
- **You have a recovery code.** FileKey's offline recovery tool can unlock your own files with just the code, no passkey needed.

## Is it safe?

- The contents are end-to-end encrypted with AES-256. Anyone else holding the file, including an email provider or cloud drive, sees only scrambled data.
- It is safe to store or forward a `.filekey` file anywhere. Without the right key, no one can open it, including us.
- Decryption never uploads your file. FileKey is a page that runs in your browser; your data stays on your device.
- A `.filekey` file is data, not a program, so it cannot run anything on its own. Once decrypted, treat the file inside like any other attachment from that person.

## Common questions

**Can I open it without FileKey?** No other app reads the format yet, and there is no password to guess or crack. For your own files, FileKey's offline recovery tool plus your recovery code works even without filekey.app.

**Does it work on iPhone and Android?** Yes. FileKey runs in the browser on phones, tablets, and computers, including Safari on a recent iPhone (iOS 18 or later).

**Do I get the original file back?** Yes, exactly. A PDF comes back as the same PDF, byte for byte.

**Why would someone send a file this way?** Because email and chat attachments can be read by the services that carry them. A `.filekey` file can be read by exactly one person: you.

Someone sent you a file? [Open it at filekey.app](/). Want to send something sensitive back? Same tool, same price: free.
