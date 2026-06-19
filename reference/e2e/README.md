# FileKey E2E differential test suite

Headless, fully automated end-to-end tests that drive the **real deployed** apps
(go.filekey.app and filekey.app) with a CDP **virtual passkey**, so there are no
fingerprints to provide. They run the suite-0x02 self-encryption change through the
actual UI + WebCrypto + WebAuthn, and diff behaviour across staging (new code) and
prod (old code).

## Run

```
cd reference/e2e
npm install            # installs playwright-core (browsers are reused from the local cache)
node run.mjs           # full suite; prints a pass/fail matrix, exit 0 if all critical cells pass
```

Standalone de-risk scripts (subsets, faster to iterate on):
`derisk-identity.mjs`, `derisk-roundtrip.mjs`, `derisk-large.mjs`, `derisk-share.mjs`.

Cross-engine crypto portability (Chromium + WebKit/Safari + Firefox), no WebAuthn needed:

```
npx playwright install webkit firefox            # one-time: the non-Chromium engines
bun build e2e/cross-engine-entry.js --target browser --format iife --outfile e2e/cross-engine-bundle.js
node cross-engine.mjs                             # runs suite-0x02 encrypt/decrypt + identity on all 3
```

It serves the real reference core over `http://localhost` (a secure context, so `crypto.subtle`
works) and asserts the deterministic 0x02 output + derived identity are byte-identical on every engine.
The virtual-passkey UI harness (`run.mjs`) is Chromium-only because the CDP virtual authenticator is a
Chrome feature; this script covers the crypto on the other engines instead.

## Browser

Uses a local Playwright "Google Chrome for Testing" (Chromium) build via `executablePath`.
Override with `FILEKEY_E2E_CHROME=/path/to/chromium`. If you don't have one cached, run
`npx playwright install chromium` and point the env var at it.

## What it covers (`run.mjs`)

- Staging self round-trips (suite 0x02): small, empty, unicode/long filename, 65 MiB (worker path), folder bundle.
- Same passkey == same identity on both sites (shared RP-ID `filekey.app`).
- Prod self-encryption is suite 0x01 (baseline, old code).
- **Backward compat**: staging opens a prod-made 0x01 file.
- **Forward fail-closed**: prod rejects a staging 0x02 file with a clear error, no plaintext.
- Wrong identity cannot decrypt a 0x02 self file.
- Sharing: Alice → Bob round-trip (suite 0x01 HPKE, unchanged).

## How the virtual passkey works

The CDP virtual authenticator needs `hasPrf: true` + `ctap2Version: "ctap2_1"` to do the
WebAuthn PRF extension FileKey relies on (see `lib.mjs`). One authenticator + the shared
`filekey.app` RP-ID means a single credential is the same identity on both deployments,
which is what makes the cross-version (differential) cells meaningful.

> Note: this exercises the app with a *virtual* authenticator, not the real platform
> Touch ID path. That ceremony is unchanged by the suite-0x02 release, so it's low-risk,
> but a one-off manual unlock with a real passkey is the belt-and-suspenders check.
