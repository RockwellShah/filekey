---
title: The best Firefox Send alternatives
description: Mozilla shut down Firefox Send in 2020. Here are the closest private, encrypted alternatives, and which one fits which job.
date: 2026-03-11
category: Comparison
author: FileKey.app
---

Firefox Send was a favorite: drop a file, get an encrypted link, and it expired on its own. Mozilla shut it down in 2020 after abuse problems, and nothing has cleanly replaced it. Here's an honest rundown of the closest options today, and where FileKey fits.

## What made Firefox Send good?

Send's appeal was three things: end-to-end encryption (the link held the key, so Mozilla couldn't read your file), a self-destruct timer, and zero friction (no account). A real replacement has to keep the encryption; the link and the timer are conveniences on top.

## The options

- **Self-hosted Send (timvisee/send).** A community fork of the original that you run yourself. Closest to the real thing: link-based and ephemeral. The catch is you host and maintain it. Best if you already run a server.
- **Bitwarden Send.** Part of the Bitwarden password manager. Sends encrypted text or a file with an expiry and optional password. Solid and hosted, but you and the recipient live in Bitwarden's world, and it can see metadata.
- **Wormhole.** Slick, link-based, end-to-end encrypted, with files that expire. Good for one-off transfers, if you're happy trusting a hosted service to stay online.
- **FileKey.** End-to-end encrypted to a specific person via their passkey, with no account and no server. A different model: you encrypt a file *to a recipient* rather than minting a public link.

## Which Firefox Send alternative should you pick?

| You want | Pick |
| --- | --- |
| The original, self-hosted | timvisee/send |
| A hosted link with a timer | Wormhole or Bitwarden Send |
| Strongest privacy to a known person, no account | FileKey |
| To run nothing and trust no server with your file | FileKey |

One honest caveat: FileKey today encrypts a *file to a person*, not a click-to-download *link*. A link-based, self-expiring transfer (a true Send replacement, where even the relay can't read the file) is on our roadmap as a zero-knowledge relay. If you need the link model right now, one of the others above will serve you better. If you want the strongest "only this person can ever read it," that's FileKey.

Curious how FileKey's per-person encryption works? See [how a passkey becomes an encryption key](/blog/passkey-to-encryption-key/).
