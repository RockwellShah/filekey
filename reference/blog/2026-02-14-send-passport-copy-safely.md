---
title: How to send a passport copy safely
description: Visa applications, landlords, and banks all ask for a passport scan. Here's how to send one without losing control of it.
date: 2026-02-14
category: Guide
author: FileKey.app
---

Someone has asked you to send a copy of your passport: a visa service, a landlord, a bank, a new employer. It's one of the most sensitive documents you own, and the ways most people send it are the least safe. Here's how to do it without leaving a copy on every server in between.

## Why a passport scan is risky to send

A passport copy is a near-complete identity kit: your photo, full name, date and place of birth, passport number, and signature. That is more than enough for identity theft. When you email or message it, the file sits in readable form on your device, your provider's servers, the recipient's inbox, and every backup of all three, often for years. Once it's out, you can't pull it back.

## The safer options, ranked

| Method | Who can read it | Effort |
| --- | --- | --- |
| Email or chat attachment | You, them, and every server and backup in between | None |
| Password-protected PDF | Anyone who intercepts the password (usually sent the same way) | Low |
| The requester's own upload portal | You, them, and the portal vendor | Medium |
| FileKey | You and the person you sent it to. That's the list. | Low |

If the company that needs your passport offers a secure upload portal, use it. Otherwise the most private option is to encrypt the file so that only that one recipient can open it.

## Send a passport copy with FileKey

1. Ask the recipient to open [filekey.app](/), create or unlock their filekey (Face ID, about 30 seconds), then open the **Your FileKey** menu (the sliders icon, top right) and choose **Receive a file**. They copy the link it generates and send it to you.
2. Open that link and add your passport scan. FileKey encrypts it in your browser into a single `.shared.filekey` file locked to that recipient. You don't need an account or a passkey of your own to send, so there's no Face ID step on your end.
3. Send the `.shared.filekey` file any way you like, even regular email. Only they can open it, with their own passkey.

> **Why this is different:** the attachment that travels through everyone's servers is unreadable ciphertext. Even if your email is breached later, your passport isn't sitting in it in any usable form.

## Two extra precautions

- **Add a watermark.** Before sending, write the purpose across the image, like "For [company] visa application only, July 2026." It won't stop a determined thief, but it makes a stolen copy much harder to reuse elsewhere.
- **Send only what's asked.** If they need the photo page, send the photo page, not your whole passport.

Sending other sensitive documents? The same approach works for [tax documents](/blog/send-tax-documents-securely/) and anything else you'd rather not leave lying in an inbox. New to the format? Here's [what a .filekey file is](/blog/what-is-a-filekey-file/).
