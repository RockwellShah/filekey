---
title: How to encrypt a file on iPhone (no app to install)
description: You don't need an app to encrypt a file on iPhone. Here's how to do it in Safari with Face ID, in about a minute.
date: 2026-05-06
category: Guide
author: FileKey.app
---

You don't need to install anything to encrypt a file on an iPhone. As of FileKey 1.1, the whole thing works in Safari, using the same Face ID you already use to unlock your phone. Here's how.

## What you need

An iPhone running iOS 18 or later (so Safari supports passkey-based encryption), and the file you want to encrypt, in Files, Photos, or anywhere you can share from. That's it. No App Store download, no account.

## How do you encrypt a file on iPhone?

1. Open [filekey.app](/) in Safari. The first time, it sets you up with a passkey using Face ID, about 30 seconds.
2. Add the file by tapping to choose from Files or Photos.
3. Approve with Face ID. FileKey encrypts the file on your device into a `.filekey` file locked to you, and hands it back to save in Files. Only your passkey can open it.

To open it again later, reopen [filekey.app](/), add the `.filekey` file, and approve with Face ID; you get the original back. To send a file *to someone else* instead, tap **Share** on the encrypted result and paste their share key (or open the **Receive a file** link they send you), which locks it to them as a `.shared.filekey` file.

> Everything happens on your phone. The file is never uploaded and there's no account; the encryption runs locally, in Safari.

New to the format? See [what a .filekey file is](/blog/what-is-a-filekey-file/). FileKey 1.1 added this iPhone support, [here's what else changed](/blog/filekey-1-1/).
