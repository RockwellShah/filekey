// Suite 0x02 — symmetric, post-quantum-safe self-encryption (§5.6, §6.5).
import { describe, test, expect } from "bun:test";
import {
  Namespace,
  NamespaceSet,
  FileKeyError,
  deriveIdentityFromPrf,
  encrypt,
  decrypt,
  encryptToSelf,
  FORMAT_VERSION,
  SUITE_ID,
  SUITE_SELF,
  MAGIC,
  type Identity,
  type Metadata,
} from "../src/index.js";
import { selfEncryptWithSaltForTest } from "../src/cipher.js";

const RP = "filekey.app";
const NS = new Namespace(RP);
const SET = new NamespaceSet([RP]);

const prf = (fill: number) => new Uint8Array(32).fill(fill);
const identity = (fill: number) => deriveIdentityFromPrf(prf(fill), NS);
const meta = (over: Partial<Omit<Metadata, "originalSize">> = {}): Omit<Metadata, "originalSize"> => ({
  filename: "report.pdf",
  mimeType: "application/pdf",
  createdAtUnixMs: 1_700_000_000_000,
  extras: new Map(),
  ...over,
});
const resolveTo = (id: Identity) => async () => id;
const hx = (b: Uint8Array) => Buffer.from(b).toString("hex");

function randomBytes(n: number): Uint8Array {
  const a = new Uint8Array(n);
  for (let o = 0; o < n; o += 65536) crypto.getRandomValues(a.subarray(o, Math.min(o + 65536, n)));
  return a;
}

/** True if `needle`'s exact byte sequence appears anywhere in `haystack`. */
function contains(haystack: Uint8Array, needle: Uint8Array): boolean {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) continue outer;
    return true;
  }
  return false;
}

describe("suite 0x02 — quantum-safe self-encryption (§5.6/§6.5)", () => {
  test("round-trips and is tagged FKEY / v1 / suite 0x02", async () => {
    const id = await identity(0x01);
    const pt = randomBytes(5000);
    const file = await encryptToSelf({ identity: id, plaintext: pt, metadata: meta() });

    expect([...file.subarray(0, 4)]).toEqual([...MAGIC]); // "FKEY"
    expect(file[4]).toBe(FORMAT_VERSION); // 0x01
    expect(file[5]).toBe(SUITE_SELF); // 0x02

    const res = await decrypt({ file, namespaces: SET, resolveIdentity: resolveTo(id) });
    expect(res.plaintext).toEqual(pt);
    expect(res.suiteId).toBe(SUITE_SELF);
    expect(res.selfEncrypted).toBe(true);
    expect(res.metadata.filename).toBe("report.pdf");
  });

  test("the file carries NO public key — nothing for Shor (the whole point)", async () => {
    const id = await identity(0x02);
    const file = await encryptToSelf({ identity: id, plaintext: randomBytes(3000), metadata: meta() });
    expect(contains(file, id.staticPkRaw)).toBe(false); // static_pk is absent

    // Contrast: a suite 0x01 (HPKE) self-encrypted file DOES carry static_pk in cleartext.
    const hpkeSelf = await encrypt({
      senderIdentity: id,
      recipientPkRaw: id.staticPkRaw,
      namespace: id.namespace,
      plaintext: randomBytes(100),
      metadata: meta(),
    });
    expect(hpkeSelf[5]).toBe(SUITE_ID);
    expect(contains(hpkeSelf, id.staticPkRaw)).toBe(true);
  });

  test("two self-encryptions of the same plaintext differ (per-file salt) yet both decrypt", async () => {
    const id = await identity(0x03);
    const pt = new Uint8Array([1, 2, 3, 4, 5]);
    const f1 = await encryptToSelf({ identity: id, plaintext: pt, metadata: meta() });
    const f2 = await encryptToSelf({ identity: id, plaintext: pt, metadata: meta() });
    expect(hx(f1)).not.toBe(hx(f2));
    expect((await decrypt({ file: f1, namespaces: SET, resolveIdentity: resolveTo(id) })).plaintext).toEqual(pt);
    expect((await decrypt({ file: f2, namespaces: SET, resolveIdentity: resolveTo(id) })).plaintext).toEqual(pt);
  });

  test("deterministic for a fixed salt, different for a different salt (test-only API)", async () => {
    const id = await identity(0x04);
    const pt = new Uint8Array([9, 8, 7]);
    const inp = { masterPrk: id.masterPrk!, namespace: id.namespace, plaintext: pt, metadata: meta() };
    const saltA = new Uint8Array(32).fill(0xaa);
    const saltB = new Uint8Array(32).fill(0xbb);
    expect(hx(await selfEncryptWithSaltForTest(inp, saltA))).toBe(hx(await selfEncryptWithSaltForTest(inp, saltA)));
    expect(hx(await selfEncryptWithSaltForTest(inp, saltA))).not.toBe(hx(await selfEncryptWithSaltForTest(inp, saltB)));
  });

  test("payload tamper and truncation are rejected", async () => {
    const id = await identity(0x05);
    const file = await encryptToSelf({ identity: id, plaintext: randomBytes(2000), metadata: meta() });

    const tampered = file.slice();
    const ti = tampered.length - 5;
    tampered[ti] = tampered[ti]! ^ 0x01;
    await expect(decrypt({ file: tampered, namespaces: SET, resolveIdentity: resolveTo(id) })).rejects.toThrow(FileKeyError);

    const truncated = file.slice(0, file.length - 1);
    await expect(decrypt({ file: truncated, namespaces: SET, resolveIdentity: resolveTo(id) })).rejects.toThrow(FileKeyError);
  });

  test("a different identity (different master_prk) cannot decrypt", async () => {
    const id = await identity(0x06);
    const other = await identity(0x76);
    const file = await encryptToSelf({ identity: id, plaintext: randomBytes(500), metadata: meta() });
    await expect(decrypt({ file, namespaces: SET, resolveIdentity: resolveTo(other) })).rejects.toThrow(FileKeyError);
  });

  test("empty and multi-chunk plaintexts round-trip", async () => {
    const id = await identity(0x07);
    for (const n of [0, 1, 65536, 200000]) {
      const pt = randomBytes(n);
      const file = await encryptToSelf({ identity: id, plaintext: pt, metadata: meta() });
      const res = await decrypt({ file, namespaces: SET, resolveIdentity: resolveTo(id) });
      expect(res.plaintext).toEqual(pt);
      expect(res.metadata.originalSize).toBe(n);
      expect(res.suiteId).toBe(SUITE_SELF);
    }
  });

  test("existing suite 0x01 self-encrypted files still decrypt (backward compat)", async () => {
    const id = await identity(0x08);
    const pt = randomBytes(1234);
    const hpkeSelf = await encrypt({
      senderIdentity: id,
      recipientPkRaw: id.staticPkRaw,
      namespace: id.namespace,
      plaintext: pt,
      metadata: meta(),
    });
    expect(hpkeSelf[5]).toBe(SUITE_ID);
    const res = await decrypt({ file: hpkeSelf, namespaces: SET, resolveIdentity: resolveTo(id) });
    expect(res.plaintext).toEqual(pt);
    expect(res.suiteId).toBe(SUITE_ID);
    expect(res.selfEncrypted).toBe(true);
  });

  test("an unknown suite is still rejected (strict-reject gate intact)", async () => {
    const id = await identity(0x09);
    const file = await encryptToSelf({ identity: id, plaintext: randomBytes(10), metadata: meta() });
    const munged = file.slice();
    munged[5] = 0x03; // neither 0x01 nor 0x02
    await expect(decrypt({ file: munged, namespaces: SET, resolveIdentity: resolveTo(id) })).rejects.toThrow(/suite_id|unsupported/i);
  });

  // The worker (web/worker.ts) rebuilds an Identity from cloned key material + master_prk, not via
  // deriveIdentityFromPrf. These two tests pin that exact shape: with master_prk it decrypts suite 0x02;
  // without it (the pre-plumbing worker) it fails closed with a clear error rather than crashing.
  test("worker-style reconstructed identity (with master_prk) decrypts suite 0x02", async () => {
    const id = await identity(0x0b);
    const pt = randomBytes(150_000); // multi-chunk, like a large-file worker job
    const file = await encryptToSelf({ identity: id, plaintext: pt, metadata: meta() });
    const reconstructed: Identity = { namespace: id.namespace, keyPair: id.keyPair, staticPkRaw: id.staticPkRaw, masterPrk: id.masterPrk };
    const res = await decrypt({ file, namespaces: SET, resolveIdentity: async () => reconstructed });
    expect(res.plaintext).toEqual(pt);
    expect(res.suiteId).toBe(SUITE_SELF);
  });

  test("worker-style reconstructed identity WITHOUT master_prk fails closed on suite 0x02", async () => {
    const id = await identity(0x0c);
    const file = await encryptToSelf({ identity: id, plaintext: randomBytes(100), metadata: meta() });
    const noPrk: Identity = { namespace: id.namespace, keyPair: id.keyPair, staticPkRaw: id.staticPkRaw }; // master_prk absent
    await expect(decrypt({ file, namespaces: SET, resolveIdentity: async () => noPrk })).rejects.toThrow(/master_prk/i);
  });

  test("suite 0x02 header tamper (flags or reserved byte) is rejected at parse", async () => {
    const id = await identity(0x0d);
    const file = await encryptToSelf({ identity: id, plaintext: randomBytes(50), metadata: meta() });
    for (const off of [6 /* flags */, 7 /* reserved */]) {
      const t = file.slice();
      t[off] = 0x01;
      await expect(decrypt({ file: t, namespaces: SET, resolveIdentity: resolveTo(id) })).rejects.toThrow(/flags|reserved/i);
    }
  });

  test("a wrong-length file_salt is rejected by the key schedule", async () => {
    const id = await identity(0x0e);
    const inp = { masterPrk: id.masterPrk!, namespace: id.namespace, plaintext: new Uint8Array([1]), metadata: meta() };
    await expect(selfEncryptWithSaltForTest(inp, new Uint8Array(31))).rejects.toThrow(/file_salt|self_salt/i);
  });

  test("a suite 0x02 file for an unconfigured namespace is rejected by tag", async () => {
    const id = await identity(0x0f);
    const file = await encryptToSelf({ identity: id, plaintext: randomBytes(40), metadata: meta() });
    const otherSet = new NamespaceSet(["other.example"]);
    await expect(decrypt({ file, namespaces: otherSet, resolveIdentity: resolveTo(id) })).rejects.toThrow(/namespace/i);
  });
});
