// Conformance: re-derive identities and re-decrypt the committed KAT vectors (§11.1).
// Guards against the implementation drifting away from the published vectors.
import { describe, test, expect } from "bun:test";
import vectors from "./vectors.json" with { type: "json" };
import {
  Namespace,
  NamespaceSet,
  masterPrkFromPrfSecret,
  deriveIdentity,
  encodeShareKey,
  encodeRecoveryBip39,
  encodeRecoveryBech32m,
  decrypt,
  fromHex,
  toHex,
} from "../src/index.js";

const RP = vectors.identity.canonical_rp_id;
const NS = new Namespace(RP);
const SET = new NamespaceSet([RP]);

describe("KAT vectors — identity (§11.1)", () => {
  test("namespace tag matches", () => {
    expect(toHex(NS.tag)).toBe(vectors.identity.namespace_tag);
  });

  test("sender identity, share key, recovery codes reproduce", async () => {
    const mprk = masterPrkFromPrfSecret(fromHex(vectors.identity.sender.prf_secret));
    expect(toHex(mprk)).toBe(vectors.identity.sender.master_prk);
    const id = await deriveIdentity(mprk, NS);
    expect(toHex(id.staticPkRaw)).toBe(vectors.identity.sender.static_pk);
    expect(encodeShareKey(id.staticPkRaw, NS)).toBe(vectors.identity.sender.share_key);
    expect(encodeRecoveryBip39(mprk)).toBe(vectors.identity.sender.recovery_bip39);
    expect(encodeRecoveryBech32m(mprk, NS)).toBe(vectors.identity.sender.recovery_bech32m);
  });

  test("recipient identity reproduces", async () => {
    const id = await deriveIdentity(masterPrkFromPrfSecret(fromHex(vectors.identity.recipient.prf_secret)), NS);
    expect(toHex(id.staticPkRaw)).toBe(vectors.identity.recipient.static_pk);
    expect(encodeShareKey(id.staticPkRaw, NS)).toBe(vectors.identity.recipient.share_key);
  });
});

describe("KAT vectors — files (§11.1)", () => {
  for (const v of vectors.files) {
    if (!v.file_hex) continue; // only small cases carry full bytes
    test(`decrypts ${v.name} (${v.plaintext_size} bytes)`, async () => {
      const prf = v.self_encrypted ? vectors.identity.sender.prf_secret : vectors.identity.recipient.prf_secret;
      const id = await deriveIdentity(masterPrkFromPrfSecret(fromHex(prf)), NS);
      const file = fromHex(v.file_hex);
      const res = await decrypt({ file, namespaces: SET, resolveIdentity: async () => id });
      expect(res.metadata.originalSize).toBe(v.plaintext_size);
      expect(res.plaintext.length).toBe(v.plaintext_size);
      expect(res.selfEncrypted).toBe(v.self_encrypted);
    });
  }
});
