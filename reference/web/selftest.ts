// In-browser self-test: runs the full crypto pipeline under the browser's WebCrypto,
// using a fixed prf_secret (no passkey needed). Proves the same code path the Node tests
// cover also works in a real browser. Writes a JSON verdict to #result.
import {
  Namespace,
  NamespaceSet,
  masterPrkFromPrfSecret,
  deriveIdentity,
  encodeShareKey,
  decodeShareKey,
  encodeRecoveryBip39,
  decodeRecoveryBip39,
  encodeRecoveryBech32m,
  decodeRecoveryBech32m,
  encryptToSelf,
  encryptToShareKey,
  decrypt,
  toHex,
} from "../src/index.js";

// crypto.getRandomValues() caps at 65536 bytes per call; fill large buffers in chunks.
function randBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let off = 0; off < n; off += 65536) {
    crypto.getRandomValues(out.subarray(off, Math.min(off + 65536, n)));
  }
  return out;
}

async function run() {
  const results: Array<{ name: string; pass: boolean; detail?: string }> = [];
  const check = (name: string, cond: boolean, detail = "") => results.push({ name, pass: cond, detail });

  const RP = "localhost";
  const NS = new Namespace(RP);
  const SET = new NamespaceSet([RP]);
  const senderPrf = new Uint8Array(32).fill(0x11);
  const recipPrf = new Uint8Array(32).fill(0x22);

  try {
    const sender = await deriveIdentity(masterPrkFromPrfSecret(senderPrf), NS);
    const recipient = await deriveIdentity(masterPrkFromPrfSecret(recipPrf), NS);
    check("derive identity (HPKE DeriveKeyPair)", sender.staticPkRaw.length === 65 && sender.staticPkRaw[0] === 0x04);

    // Share key round trip.
    const sk = encodeShareKey(recipient.staticPkRaw, NS);
    const dec = decodeShareKey(sk, SET);
    check("share key round trip", toHex(dec.recipientPkRaw) === toHex(recipient.staticPkRaw), sk);

    // Self-encrypt round trip across sizes.
    for (const size of [0, 1, 65536, 65537, 130000]) {
      const pt = randBytes(size);
      const file = await encryptToSelf({ identity: sender, plaintext: pt, metadata: { filename: `t${size}.bin`, mimeType: "application/octet-stream", createdAtUnixMs: 0, extras: new Map() } });
      const res = await decrypt({ file, namespaces: SET, resolveIdentity: async () => sender });
      check(`self round trip ${size}B`, toHex(res.plaintext) === toHex(pt) && res.selfEncrypted);
    }

    // Shared encrypt → recipient decrypts.
    const msg = new TextEncoder().encode("browser shared payload");
    const shared = await encryptToShareKey({ senderIdentity: sender, recipientShareKey: sk, namespaces: SET, plaintext: msg, metadata: { filename: "m.txt", mimeType: "text/plain", createdAtUnixMs: 0, extras: new Map() } });
    const sharedRes = await decrypt({ file: shared, namespaces: SET, resolveIdentity: async () => recipient });
    check("shared encrypt → recipient decrypt", new TextDecoder().decode(sharedRes.plaintext) === "browser shared payload" && !sharedRes.selfEncrypted);

    // Tamper detection.
    const tampered = shared.slice();
    tampered[tampered.length - 1]! ^= 0x01;
    let rejected = false;
    try {
      await decrypt({ file: tampered, namespaces: SET, resolveIdentity: async () => recipient });
    } catch {
      rejected = true;
    }
    check("tamper detection (fails closed)", rejected);

    // Recovery codes.
    const mprk = masterPrkFromPrfSecret(senderPrf);
    check("BIP39 recovery round trip", toHex(decodeRecoveryBip39(encodeRecoveryBip39(mprk))) === toHex(mprk));
    check("Bech32m recovery round trip", toHex(decodeRecoveryBech32m(encodeRecoveryBech32m(mprk, NS), SET).masterPrk) === toHex(mprk));
  } catch (e) {
    check("UNCAUGHT", false, (e as Error).message);
  }

  const allPass = results.every((r) => r.pass);
  const el = document.getElementById("result")!;
  el.textContent = JSON.stringify({ allPass, count: results.length, results }, null, 2);
  el.setAttribute("data-pass", String(allPass));
}

run();
