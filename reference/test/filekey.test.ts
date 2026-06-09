import { describe, test, expect } from "bun:test";
import {
  Namespace,
  NamespaceSet,
  namespaceTag,
  validateCanonicalRpId,
  FileKeyError,
  masterPrkFromPrfSecret,
  deriveIdentity,
  deriveIdentityFromPrf,
  identityFingerprint,
  encodeShareKey,
  decodeShareKey,
  encodeRecoveryBip39,
  decodeRecoveryBip39,
  encodeRecoveryBech32m,
  decodeRecoveryBech32m,
  decodeRecoveryAuto,
  encrypt,
  decrypt,
  encryptToShareKey,
  encryptToSelf,
  encodeMetadata,
  decodeMetadata,
  type Identity,
  type Metadata,
} from "../src/index.js";
import { encryptWithEphemeralForTest } from "../src/cipher.js";

const RP = "filekey.app";
const NS = new Namespace(RP);
const SET = new NamespaceSet([RP]);

function prf(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill);
}
async function identity(fill: number, ns = NS): Promise<Identity> {
  return deriveIdentityFromPrf(prf(fill), ns);
}
const meta = (over: Partial<Omit<Metadata, "originalSize">> = {}): Omit<Metadata, "originalSize"> => ({
  filename: "report.pdf",
  mimeType: "application/pdf",
  createdAtUnixMs: 1_700_000_000_000,
  extras: new Map(),
  ...over,
});
const resolveTo = (id: Identity) => async () => id;

describe("identity derivation (§4)", () => {
  test("deterministic: same prf_secret + namespace → same static_pk", async () => {
    const a = await identity(0x11);
    const b = await identity(0x11);
    expect(Buffer.from(a.staticPkRaw).toString("hex")).toBe(Buffer.from(b.staticPkRaw).toString("hex"));
  });
  test("different namespace → different identity (RP-ID is part of identity)", async () => {
    const a = await identity(0x11, NS);
    const b = await identity(0x11, new Namespace("other.example"));
    expect(Buffer.from(a.staticPkRaw).toString("hex")).not.toBe(Buffer.from(b.staticPkRaw).toString("hex"));
  });
  test("master_prk requires 32-byte prf_secret", () => {
    expect(() => masterPrkFromPrfSecret(new Uint8Array(31))).toThrow(FileKeyError);
  });
  test("static_pk is 65-byte uncompressed", async () => {
    const a = await identity(0x22);
    expect(a.staticPkRaw.length).toBe(65);
    expect(a.staticPkRaw[0]).toBe(0x04);
  });
});

describe("identity fingerprint (§4.7)", () => {
  test("6 words, deterministic, namespace-scoped", async () => {
    const a = await identity(0x11);
    const fpA = identityFingerprint(a.staticPkRaw);
    expect(fpA.words.split(" ").length).toBe(6);
    expect(fpA.hex).toMatch(/^[0-9a-f]{8}$/);
    // deterministic
    expect(identityFingerprint(a.staticPkRaw).words).toBe(fpA.words);
    // different identity → different fingerprint
    const b = await identity(0x22);
    expect(identityFingerprint(b.staticPkRaw).words).not.toBe(fpA.words);
    // namespace-scoped: same passkey, different namespace → different fingerprint
    const aOther = await identity(0x11, new Namespace("other.example"));
    expect(identityFingerprint(aOther.staticPkRaw).words).not.toBe(fpA.words);
  });
  test("rejects malformed pk", () => {
    expect(() => identityFingerprint(new Uint8Array(33))).toThrow(FileKeyError);
  });
});

describe("namespace (§4.4, §8.5)", () => {
  test("tag is SHA-256(canonical_rp_id)[0:4]", () => {
    expect(namespaceTag(RP).length).toBe(4);
  });
  test("rejects bad canonical RP-IDs", () => {
    expect(() => validateCanonicalRpId("Filekey.App")).toThrow(); // uppercase
    expect(() => validateCanonicalRpId("filekey.app.")).toThrow(); // trailing dot
    expect(() => validateCanonicalRpId("_x.example.com")).toThrow(); // underscore
    expect(() => validateCanonicalRpId("-foo.com")).toThrow(); // leading hyphen
    expect(() => validateCanonicalRpId("ab--cd.com")).toThrow(); // reserved xx-- non-xn--
  });
  test("accepts filekey.app and xn-- labels", () => {
    expect(validateCanonicalRpId("filekey.app").length).toBe(11);
    expect(() => validateCanonicalRpId("xn--bcher-kva.example")).not.toThrow();
  });
  test("NamespaceSet rejects colliding tags only on true collision", () => {
    expect(() => new NamespaceSet([RP, RP])).not.toThrow(); // same id is idempotent
  });
});

describe("share keys (§4.4)", () => {
  test("encode/decode round trip", async () => {
    const a = await identity(0x33);
    const sk = encodeShareKey(a.staticPkRaw, NS);
    expect(sk.startsWith("fkey1")).toBe(true);
    const { recipientPkRaw, namespace } = decodeShareKey(sk, SET);
    expect(namespace.canonicalRpId).toBe(RP);
    expect(Buffer.from(recipientPkRaw).toString("hex")).toBe(Buffer.from(a.staticPkRaw).toString("hex"));
  });
  test("length is ~72 chars", async () => {
    const a = await identity(0x33);
    expect(encodeShareKey(a.staticPkRaw, NS).length).toBe(72);
  });
  test("rejects wrong namespace", async () => {
    const a = await identity(0x33, new Namespace("other.example"));
    const sk = encodeShareKey(a.staticPkRaw, new Namespace("other.example"));
    expect(() => decodeShareKey(sk, SET)).toThrow(/wrong_namespace|not configured/);
  });
  test("rejects corrupted checksum", async () => {
    const a = await identity(0x33);
    const sk = encodeShareKey(a.staticPkRaw, NS);
    const bad = sk.slice(0, -1) + (sk.endsWith("q") ? "p" : "q");
    expect(() => decodeShareKey(bad, SET)).toThrow(FileKeyError);
  });
});

describe("recovery codes (§4.6)", () => {
  test("BIP39 24-word round trip", () => {
    const mprk = masterPrkFromPrfSecret(prf(0x44));
    const phrase = encodeRecoveryBip39(mprk);
    expect(phrase.split(" ").length).toBe(24);
    expect(Buffer.from(decodeRecoveryBip39(phrase)).toString("hex")).toBe(Buffer.from(mprk).toString("hex"));
  });
  test("BIP39 rejects 12-word phrase", () => {
    const twelve = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    expect(() => decodeRecoveryBip39(twelve)).toThrow(/24 words/);
  });
  test("Bech32m round trip carries namespace", () => {
    const mprk = masterPrkFromPrfSecret(prf(0x44));
    const code = encodeRecoveryBech32m(mprk, NS);
    expect(code.startsWith("fkeyrec1")).toBe(true);
    const dec = decodeRecoveryBech32m(code, SET);
    expect(dec.namespace.canonicalRpId).toBe(RP);
    expect(Buffer.from(dec.masterPrk).toString("hex")).toBe(Buffer.from(mprk).toString("hex"));
  });
  test("auto-detect dispatches both formats", () => {
    const mprk = masterPrkFromPrfSecret(prf(0x44));
    expect(decodeRecoveryAuto(encodeRecoveryBip39(mprk), SET).namespace).toBeNull();
    expect(decodeRecoveryAuto(encodeRecoveryBech32m(mprk, NS), SET).namespace?.canonicalRpId).toBe(RP);
  });
  test("recovery code reconstructs a working identity", async () => {
    const orig = await identity(0x55);
    const sk = encodeShareKey(orig.staticPkRaw, NS);
    const mprk = masterPrkFromPrfSecret(prf(0x55));
    const restored = await deriveIdentity(mprk, NS);
    expect(encodeShareKey(restored.staticPkRaw, NS)).toBe(sk); // same identity
  });
});

describe("encrypt/decrypt round trips (§6, §7)", () => {
  const sizes = [0, 1, 100, 65535, 65536, 65537, 200_000];
  for (const size of sizes) {
    test(`self-encrypt round trip, ${size} bytes`, async () => {
      const id = await identity(0x66);
      const pt = crypto.getRandomValues(new Uint8Array(size));
      const file = await encryptToSelf({ identity: id, plaintext: pt, metadata: meta() });
      const res = await decrypt({ file, namespaces: SET, resolveIdentity: resolveTo(id) });
      expect(res.selfEncrypted).toBe(true);
      expect(Buffer.from(res.plaintext).toString("hex")).toBe(Buffer.from(pt).toString("hex"));
      expect(res.metadata.filename).toBe("report.pdf");
      expect(res.metadata.originalSize).toBe(size);
    });
  }

  test("shared encrypt: Alice → Bob (same namespace)", async () => {
    const alice = await identity(0xa1);
    const bob = await identity(0xb0);
    const bobShareKey = encodeShareKey(bob.staticPkRaw, NS);
    const pt = new TextEncoder().encode("for bob's eyes only");
    const file = await encryptToShareKey({
      senderIdentity: alice,
      recipientShareKey: bobShareKey,
      namespaces: SET,
      plaintext: pt,
      metadata: meta({ filename: "secret.txt" }),
    });
    const res = await decrypt({ file, namespaces: SET, resolveIdentity: resolveTo(bob) });
    expect(new TextDecoder().decode(res.plaintext)).toBe("for bob's eyes only");
    expect(res.selfEncrypted).toBe(false);
    expect(Buffer.from(res.senderPkRaw).toString("hex")).toBe(Buffer.from(alice.staticPkRaw).toString("hex"));
  });

  test("send-me-a-file link: throwaway anonymous sender → recipient decrypts", async () => {
    // Mirrors the web "#to=<key>" path: a sender with NO persistent identity mints a one-time random
    // keypair and encrypts to the recipient's share key. The recipient must decrypt it, and the sender
    // must read as anonymous (an unrecognized key, not self).
    const recipient = await identity(0xa1);
    const recipientShareKey = encodeShareKey(recipient.staticPkRaw, NS);
    const throwaway = await deriveIdentityFromPrf(crypto.getRandomValues(new Uint8Array(32)), NS); // one-time, no passkey
    const { recipientPkRaw, namespace } = decodeShareKey(recipientShareKey, SET);
    const pt = new TextEncoder().encode("an anonymous drop");
    const file = await encrypt({ senderIdentity: throwaway, recipientPkRaw, namespace, plaintext: pt, metadata: meta({ filename: "drop.txt" }) });
    const res = await decrypt({ file, namespaces: SET, resolveIdentity: async () => recipient });
    expect(new TextDecoder().decode(res.plaintext)).toBe("an anonymous drop");
    expect(res.selfEncrypted).toBe(false);
    // sender_pk is the throwaway key (decryptable, anonymous) — not the recipient's own key.
    expect(Buffer.from(res.senderPkRaw).toString("hex")).toBe(Buffer.from(throwaway.staticPkRaw).toString("hex"));
    expect(Buffer.from(res.senderPkRaw).toString("hex")).not.toBe(Buffer.from(recipient.staticPkRaw).toString("hex"));
  });

  test("extras round-trip and ordering preserved", async () => {
    const id = await identity(0x66);
    const extras = new Map<string, Uint8Array>([
      ["com.example.a", new Uint8Array([1, 2, 3])],
      ["com.example.b", new Uint8Array([4, 5])],
    ]);
    const file = await encryptToSelf({ identity: id, plaintext: new Uint8Array([9]), metadata: meta({ extras }) });
    const res = await decrypt({ file, namespaces: SET, resolveIdentity: resolveTo(id) });
    expect([...res.metadata.extras.keys()]).toEqual(["com.example.a", "com.example.b"]);
    expect(Buffer.from(res.metadata.extras.get("com.example.a")!).toString("hex")).toBe("010203");
  });
});

describe("deterministic ephemeral (§11.1 carveout)", () => {
  test("same ekm → identical ciphertext", async () => {
    const id = await identity(0x77);
    const ekm = new Uint8Array(32).fill(0xee).buffer;
    const selfInput = () => ({ senderIdentity: id, recipientPkRaw: id.staticPkRaw, namespace: id.namespace, plaintext: new Uint8Array([1, 2, 3]), metadata: meta() });
    const f1 = await encryptWithEphemeralForTest(selfInput(), ekm);
    const f2 = await encryptWithEphemeralForTest(selfInput(), structuredClone(ekm));
    expect(Buffer.from(f1).toString("hex")).toBe(Buffer.from(f2).toString("hex"));
  });
  test("no ekm → different ciphertext (fresh ephemeral)", async () => {
    const id = await identity(0x77);
    const f1 = await encryptToSelf({ identity: id, plaintext: new Uint8Array([1, 2, 3]), metadata: meta() });
    const f2 = await encryptToSelf({ identity: id, plaintext: new Uint8Array([1, 2, 3]), metadata: meta() });
    expect(Buffer.from(f1).toString("hex")).not.toBe(Buffer.from(f2).toString("hex"));
  });
});

describe("negative cases (tamper / truncation / wrong recipient)", () => {
  async function makeFile(): Promise<{ id: Identity; file: Uint8Array }> {
    const id = await identity(0x88);
    const file = await encryptToSelf({ identity: id, plaintext: crypto.getRandomValues(new Uint8Array(150_000)), metadata: meta() });
    return { id, file };
  }

  test("flip a byte in the payload → auth fails", async () => {
    const { id, file } = await makeFile();
    const tampered = file.slice();
    tampered[tampered.length - 100]! ^= 0x01;
    await expect(decrypt({ file: tampered, namespaces: SET, resolveIdentity: resolveTo(id) })).rejects.toThrow(FileKeyError);
  });

  test("flip a byte in the header → rejected", async () => {
    const { id, file } = await makeFile();
    const tampered = file.slice();
    tampered[8]! ^= 0xff; // namespace tag byte → wrong namespace
    await expect(decrypt({ file: tampered, namespaces: SET, resolveIdentity: resolveTo(id) })).rejects.toThrow(/wrong_namespace|namespace/);
  });

  test("truncate the last chunk → rejected", async () => {
    const { id, file } = await makeFile();
    const truncated = file.subarray(0, file.length - (65536 + 16)); // drop a full last chunk
    await expect(decrypt({ file: truncated, namespaces: SET, resolveIdentity: resolveTo(id) })).rejects.toThrow(FileKeyError);
  });

  test("append trailing bytes → rejected", async () => {
    const { id, file } = await makeFile();
    const extended = new Uint8Array(file.length + 10);
    extended.set(file);
    await expect(decrypt({ file: extended, namespaces: SET, resolveIdentity: resolveTo(id) })).rejects.toThrow(FileKeyError);
  });

  test("wrong recipient cannot decrypt", async () => {
    const alice = await identity(0xa1);
    const bob = await identity(0xb0);
    const carol = await identity(0xc0);
    const file = await encryptToShareKey({
      senderIdentity: alice,
      recipientShareKey: encodeShareKey(bob.staticPkRaw, NS),
      namespaces: SET,
      plaintext: new Uint8Array([1, 2, 3]),
      metadata: meta(),
    });
    await expect(decrypt({ file, namespaces: SET, resolveIdentity: resolveTo(carol) })).rejects.toThrow(FileKeyError);
  });

  test("sender not in recipient's namespace → encryption rejects", async () => {
    const alice = await identity(0xa1, new Namespace("other.example"));
    const bob = await identity(0xb0, NS);
    await expect(
      encryptToShareKey({
        senderIdentity: alice,
        recipientShareKey: encodeShareKey(bob.staticPkRaw, NS),
        namespaces: SET,
        plaintext: new Uint8Array([1]),
        metadata: meta(),
      }),
    ).rejects.toThrow(/sender_namespace_mismatch|namespace/);
  });
});

describe("metadata validation (§5.4.1)", () => {
  test("rejects path-traversal filename", () => {
    expect(() => encodeMetadata({ ...meta({ filename: ".." }), originalSize: 0 } as Metadata)).toThrow(/dotdot|traversal/);
  });
  test("rejects path separator", () => {
    expect(() => encodeMetadata({ ...meta({ filename: "a/b" }), originalSize: 0 } as Metadata)).toThrow(/separator/);
  });
  test("rejects control byte in filename", () => {
    expect(() => encodeMetadata({ ...meta({ filename: "ab" }), originalSize: 0 } as Metadata)).toThrow(/control/);
  });
  test("metadata round trip", () => {
    const m: Metadata = { ...meta({ filename: "x.bin", mimeType: "application/octet-stream" }), originalSize: 42 };
    const dec = decodeMetadata(encodeMetadata(m));
    expect(dec.filename).toBe("x.bin");
    expect(dec.originalSize).toBe(42);
  });
});
