---
title: Passkeys vs passwords: why your face is a better key
description: Passwords get phished, reused, and breached. Passkeys can't be any of those. Here's what a passkey actually is and why it's a real upgrade.
date: 2026-03-18
category: Deep dive
author: FileKey.app
---

Passwords have been the worst part of the internet for thirty years. Passkeys are the replacement that's finally good enough to win, and they're the foundation FileKey is built on. Here's what a passkey actually is, in plain terms, and why it beats a password on every axis that matters.

## What a password really is

A password is a shared secret: you know it, the website stores a hash of it, and you both have to keep it safe. That model has three fatal flaws. You reuse it, so one breach unlocks many accounts. You can be tricked into typing it on a fake site, which is phishing. And the site can leak its whole database, which is a breach. None of these is user error you can fully train away; they're built into the design.

## What a passkey is

A passkey is a public and private key pair created on your device. The private key never leaves your device's secure hardware; the website only ever stores your public key. To sign in, your device proves it holds the private key by signing a challenge, unlocked by your Face ID, Touch ID, or PIN.

That one change removes all three flaws at once:

- **Nothing to reuse.** Each passkey is unique to one site, generated automatically.
- **Nothing to phish.** The signature is bound to the real site's domain, so a fake site can't trigger a valid one.
- **Nothing to breach.** The site stores only public keys, and a stolen database of public keys is worthless to an attacker.

## "But what if I lose my device?"

Passkeys sync through your platform: iCloud Keychain across Apple devices, Google Password Manager across Android and Chrome. Lose a phone and your passkeys are still on your other devices. A hardware security key is the exception, since it's a single physical object, which is why any tool that leans on one should give you a recovery path.

## Why FileKey builds on passkeys

FileKey takes this a step further: it uses your passkey not just to sign in but to *encrypt*. The same secure-hardware key that proves who you are also derives your encryption identity, so you get real public-key encryption with nothing to remember. We wrote up the exact mechanism in [how FileKey turns a passkey into an encryption key](/blog/passkey-to-encryption-key/).

The short version: a password is something you know and can lose; a passkey is something your device holds and proves. For both signing in and encrypting, that's simply a better key.
