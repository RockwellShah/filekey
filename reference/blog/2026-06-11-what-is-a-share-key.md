---
title: What is a share key?
description: Your FileKey share key is a public key you can hand out freely. Anyone can use it to encrypt a file that only you can open. Here's how it works and how to send with one.
date: 2026-06-11
category: Guide
author: FileKey.app
---

A FileKey share key is your public key, a short `fkey1…` string you can post anywhere. Hand it to someone and they can encrypt a file that only you can open. It's safe to share publicly because it can only lock files to you, never unlock them.

## What is a share key?

It's the public half of your FileKey identity. Public-key encryption splits your key in two: a public key that locks files *to you*, and a private key, held behind your passkey and never leaving your device, that unlocks them. Your share key is that public half. You give it out so people can send you files only you can read.

## Where do you find your share key?

Open the **Your FileKey** menu (the sliders icon, top right) and choose **Your Share Key**. Copy the `fkey1…` string and share it however you like: a message, your email signature, a profile page. Because it's a public key, there's no risk in it being seen.

## How do you send a file to another FileKey user?

If your recipient already uses FileKey and has given you their share key:

1. Drop your file into [filekey.app](/) (it encrypts a copy to you first).
2. On the result, tap **Share** and paste their share key, or pick them from **Contacts** if you've sent to them before.
3. You get a `.shared.filekey` file locked to them. Send it any way you like; only they can open it.

After the first send, FileKey offers to remember that person as a contact, with a nickname you choose, stored encrypted on your own device. Next time you just pick them from the list instead of pasting a key.

## Is it safe to share your share key publicly?

Yes. A share key only lets people *encrypt to you*. It can't decrypt anything, it isn't a login, and it isn't your identity. The worst anyone can do with it is send you a file. Your private key never leaves your device, and it's the only thing that can open what's encrypted to you.

## Share key or Receive-a-file link, which do you use?

- **Share key:** best when the other person also uses FileKey. They keep your key and can send to you anytime.
- **[Receive-a-file link](/blog/receive-documents-from-clients-securely/):** best when the sender doesn't use FileKey. They open your link and send without an account.

Both produce a file only you can open.

Under the hood, your share key is a P-256 public key and the encryption is HPKE, the same standard used in TLS. We walk through [how a passkey becomes an encryption key](/blog/passkey-to-encryption-key/) if you want the full chain. New to the format? Here's [what a .filekey file is](/blog/what-is-a-filekey-file/).
