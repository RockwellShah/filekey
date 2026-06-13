---
title: What is HPKE, and why FileKey uses it
description: HPKE is the modern standard for public-key encryption (RFC 9180). Here's what it is, in plain terms, and why FileKey encrypts your files with it.
date: 2026-06-03
category: Deep dive
author: FileKey.app
---

FileKey encrypts files with HPKE, a relatively new internet standard for public-key encryption. If you've heard of it from TLS or MLS and wondered what it actually does, here's a plain explanation, and why it's the right tool for encrypting a file to a person.

## The problem HPKE solves

Public-key encryption sounds simple: encrypt to someone's public key, only their private key decrypts. But doing it correctly, combining the public-key step with fast symmetric encryption, picking safe algorithms, and binding it all together, has historically been a minefield of subtle mistakes. HPKE (Hybrid Public Key Encryption, RFC 9180, published 2022) is the IETF's answer: one vetted, standard construction so nobody has to reinvent it.

## How it works, briefly

HPKE has three parts, named in its suite:

- **A KEM** (key encapsulation): a Diffie-Hellman exchange that lets sender and recipient agree on a shared secret using the recipient's public key. FileKey uses **DHKEM with P-256**.
- **A KDF** (key derivation): turns that shared secret into a proper encryption key. FileKey uses **HKDF-SHA-256**.
- **An AEAD** (the actual encryption): encrypts the data with built-in authentication, so tampering is detectable. FileKey uses **AES-256-GCM**.

Put together: the sender's browser does a key agreement with the recipient's public key, derives a key, and encrypts the file with AES-256. Only the recipient's private key can complete the agreement and decrypt.

## Why FileKey uses it

- **It's standard and vetted**, not homemade crypto. The same construction is used in TLS Encrypted Client Hello and the Messaging Layer Security (MLS) protocol.
- **It fits the model exactly**: encrypt to a public key (your recipient's passkey-derived identity), with no shared password needed.
- **It streams**: FileKey encrypts in chunks, so a huge file never has to fit in memory.

For the full chain from your passkey to the encrypted file, see [how FileKey turns a passkey into an encryption key](/blog/passkey-to-encryption-key/).
