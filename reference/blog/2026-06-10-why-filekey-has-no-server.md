---
title: Why FileKey has no server, and why that's safer
description: FileKey is a static page with no backend. Here's why a security tool with no server to break is more trustworthy, not less.
date: 2026-06-10
category: Deep dive
author: FileKey.app
---

Most "secure" apps ask you to trust their servers. FileKey doesn't have any. It's a static web page: all the cryptography runs in your browser, and nothing you encrypt is ever uploaded. That sounds like a limitation. For a security tool, it's the opposite. Here's why.

## What does "no server" actually mean?

When you use FileKey, your browser downloads a set of static files (HTML, a script, a font) and runs them. There's no backend that receives your files, no database of users, and no API your data passes through. Encryption and decryption happen entirely on your device. The only thing the host does is serve the same static files to everyone.

## Why is having no server safer?

- **Nothing to breach.** A server that holds user files or keys is a target, and a breach exposes everyone on it. FileKey has no such server, so there's no central pile of data to steal.
- **Nothing to subpoena or leak.** A company can only hand over what it has. FileKey's host never receives your files or keys, so there's nothing to produce.
- **A smaller trust surface.** You're trusting a small set of static files you can read, not an opaque backend you can't. The exact client source is published at [/source.txt](/source.txt).
- **It can't quietly change per user.** Everyone gets the same static files; there's no server logic that could treat one user differently.

## What are the trade-offs of having no server?

A static, client-side design has real limits. It depends on the browser and your passkey, so very old setups are out. And because the site is web-served, you're trusting that the files you receive are the real ones, which is why FileKey publishes its source, is self-hostable, and caches its code for repeat visits. The point isn't that "no server" is magic. It's that for encrypting your own files, removing the server removes the biggest thing that can betray you.

For how the encryption itself works, see [how a passkey becomes an encryption key](/blog/passkey-to-encryption-key/) and [what HPKE is](/blog/what-is-hpke/).
