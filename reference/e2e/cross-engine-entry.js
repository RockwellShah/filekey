// Browser entry for the cross-engine crypto test: exposes the REAL reference suite-0x02 core on
// window.FK so it can run on Chromium / WebKit (Safari) / Firefox without WebAuthn (master_prk is
// supplied directly). Bundled with: bun build e2e/cross-engine-entry.js --target browser --outfile ...
import { Namespace, NamespaceSet, deriveIdentityFromPrf, encryptToSelf, decrypt } from "../src/index.js";
import { selfEncryptWithSaltForTest } from "../src/cipher.js";
globalThis.FK = { Namespace, NamespaceSet, deriveIdentityFromPrf, encryptToSelf, decrypt, selfEncryptWithSaltForTest };
