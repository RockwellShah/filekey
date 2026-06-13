---
title: How FileKey turns a passkey into an encryption key
description: From Face ID to AES-256 with nothing to remember. WebAuthn's PRF extension, HKDF, and HPKE, explained from the spec up.
date: 2026-02-28
category: Deep dive
author: FileKey.app
---

FileKey has no passwords and no key files, yet it does real public-key encryption. The trick is a young piece of the WebAuthn standard that lets your passkey hand the page a secret only it can produce. Here is the whole chain, from a Face ID tap to an AES-256-encrypted file.

## The problem with encryption keys

Encryption is easy. Key management is the hard part. Passwords get reused and phished. Key files get lost or copied. PGP has decades of evidence that people cannot be asked to manage long-lived keypairs by hand. So the question for FileKey was: where do we get a strong, stable, secret key that the user never has to see or store?

The answer turned out to be the passkey they already have.

## Step 1: the passkey and the PRF extension

A passkey is a public and private keypair held in your device's secure hardware, or synced through iCloud Keychain or Google Password Manager. You normally use it to sign in. But WebAuthn has an extension called **PRF** (a pseudo-random function, built on the authenticator's `hmac-secret`). When you authenticate, you can hand the authenticator a label, and it returns a secret derived from that label and a key that never leaves the authenticator.

Two things make this useful. The same label always produces the same secret on the same passkey, and that secret is never stored anywhere. It is recomputed on demand, gated behind your Face ID, Touch ID, or PIN.

## Step 2: from a PRF secret to an identity (HKDF)

The raw PRF output is not used directly. FileKey runs it through **HKDF** (HMAC-based key derivation, with a FileKey-specific namespace) to derive a stable **P-256** keypair: your FileKey identity. Your public key is your share key, the thing you hand to people so they can send you files. The private key is what decrypts them.

Because the identity is derived from the PRF secret, it is reproducible: the same passkey always derives the same identity, on any device the passkey syncs to. Nothing is stored; it is re-derived each session, and the private key is imported **non-extractable**, so even the page that uses it cannot read the raw bytes back out.

## Step 3: encrypting to someone (HPKE)

To send a file, FileKey uses **HPKE** (Hybrid Public Key Encryption, RFC 9180), the modern standard also used by MLS and TLS Encrypted Client Hello. The exact suite is **DHKEM(P-256, HKDF-SHA-256)** for the key agreement and **AES-256-GCM** for the bulk encryption, streamed in chunks so a multi-gigabyte file never has to fit in memory.

In plain terms: your browser performs a Diffie-Hellman key agreement between your identity and the recipient's public key, derives a fresh symmetric key, and encrypts the file with AES-256. Only the recipient's private key, sitting behind their passkey, can complete the other half of that agreement and decrypt.

## Why this is a good trade

- **Nothing to manage.** The key is your passkey. There is no password to phish and no key file to lose.
- **Nothing stored.** The identity is recomputed from the PRF secret each session, and the private key is non-extractable.
- **Boring, audited primitives.** HKDF, P-256, AES-256-GCM, HPKE: standard building blocks, not homemade crypto.
- **Recoverable.** A one-time recovery code lets you re-derive your identity if you ever lose the passkey, so "the key is your passkey" does not mean "lose the passkey, lose everything."

The whole client is open source: you can read [the exact source](/source.txt) that runs in your browser, or start with [what a .filekey file is](/blog/what-is-a-filekey-file/).

> One limitation worth stating plainly: this is classical elliptic-curve cryptography (P-256), so it carries the same harvest-now-decrypt-later exposure as almost everything else online today. FileKey's file format versions both the format and the ciphersuite, so a post-quantum HPKE suite can roll out later without breaking existing files.
