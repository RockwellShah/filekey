// PRF → master_prk → identity KEM keypair (spec §4.1–§4.3).
import { CipherSuite, DhkemP256HkdfSha256, HkdfSha256, Aes256Gcm } from "@hpke/core";
import { sha256 } from "@noble/hashes/sha2.js";
import { extract, expand } from "@noble/hashes/hkdf.js";
import { p256 } from "@noble/curves/nist.js";
import { bytesToNumberBE } from "@noble/curves/utils.js";
import { base64urlnopad } from "@scure/base";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { ascii, concat, toHex } from "./bytes.js";
import { LABEL_MASTER_PRK, LABEL_IDENTITY_KEM, LABEL_PRF_INPUT, LABEL_FINGERPRINT, PK_LEN } from "./constants.js";
import { FileKeyError, Namespace } from "./namespace.js";

/** The one and only cipher suite: HPKE Auth, DHKEM(P-256, HKDF-SHA-256) + AES-256-GCM. */
export const suite = new CipherSuite({
  kem: new DhkemP256HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
});

/** The constant 32-byte WebAuthn PRF input salt (§4.1): SHA-256("FILEKEY-v1/prf-input/identity"). */
export const PRF_INPUT_SALT: Uint8Array = sha256(ascii(LABEL_PRF_INPUT));

/** master_prk = HKDF-Extract(salt="FILEKEY-v1/master-prk", IKM=prf_secret) (§4.2). */
export function masterPrkFromPrfSecret(prfSecret: Uint8Array): Uint8Array {
  if (prfSecret.length !== 32) {
    throw new FileKeyError(`prf_secret must be 32 bytes, got ${prfSecret.length}`, "prf_secret_length");
  }
  return extract(sha256, prfSecret, ascii(LABEL_MASTER_PRK));
}

export interface Identity {
  readonly namespace: Namespace;
  readonly keyPair: CryptoKeyPair;
  /** static_pk as 65-byte SEC1 uncompressed. */
  readonly staticPkRaw: Uint8Array;
}

// ---- DHKEM(P-256) DeriveKeyPair over @noble (Safari-compatible) ----
// @hpke/core's kem.deriveKeyPair() derives the private scalar, then relies on WebCrypto to synthesize
// the public key from a private-scalar-only key. Chrome/Bun do that; Safari/WebKit refuses with a
// DOMException ("Data provided to an operation does not meet requirements"), which broke identity
// derivation — and therefore *all* of FileKey — on every WebKit browser. We compute the point with
// @noble and import a COMPLETE JWK (x, y, d), which Safari accepts. This is RFC 9180 §7.1.3 DeriveKeyPair
// for DHKEM(P-256, HKDF-SHA-256) and is byte-identical to @hpke/core (verified by the test vectors), so
// existing keys, files, and fingerprints are unaffected. Only this deterministic derivation moves off
// @hpke/core; the rest of the suite (encap/seal/open) still runs through it.
const HPKE_V1 = ascii("HPKE-v1");
const KEM_SUITE_ID = Uint8Array.from([0x4b, 0x45, 0x4d, 0x00, 0x10]); // "KEM" || I2OSP(0x0010, 2)
const EMPTY = new Uint8Array(0);
function labeledExtractKem(salt: Uint8Array, label: string, ikm: Uint8Array): Uint8Array {
  return extract(sha256, concat(HPKE_V1, KEM_SUITE_ID, ascii(label), ikm), salt); // HKDF-Extract("HPKE-v1"||suite_id||label||ikm)
}
function labeledExpandKem(prk: Uint8Array, label: string, info: Uint8Array, len: number): Uint8Array {
  const li = concat(Uint8Array.from([(len >> 8) & 0xff, len & 0xff]), HPKE_V1, KEM_SUITE_ID, ascii(label), info);
  return expand(sha256, prk, li, len);
}
async function deriveP256KeyPair(ikm: Uint8Array): Promise<CryptoKeyPair> {
  const dkpPrk = labeledExtractKem(EMPTY, "dkp_prk", ikm);
  const order = p256.Point.Fn.ORDER;
  let sk: Uint8Array | undefined;
  for (let counter = 0; counter <= 255 && !sk; counter++) {
    const cand = labeledExpandKem(dkpPrk, "candidate", Uint8Array.from([counter]), 32);
    cand[0] = cand[0]! & 0xff; // P-256 bitmask per RFC 9180 (0xff ⇒ no-op; kept for fidelity)
    const v = bytesToNumberBE(cand);
    if (v !== 0n && v < order) sk = cand; // accept the first candidate with 0 < sk < n
  }
  if (!sk) throw new FileKeyError("failed to derive a P-256 key pair from IKM", "derive_keypair");
  const pub = p256.getPublicKey(sk, false); // 65-byte SEC1 uncompressed: 0x04 || x(32) || y(32)
  const alg = { name: "ECDH", namedCurve: "P-256" };
  // The private key MUST be imported extractable:true. Importing it non-extractable (to block raw-key
  // exfiltration by compromised in-page code) was tried and it broke HPKE decryption for a subset of
  // derived identities under @hpke/core 1.9 + the complete-JWK import we use for Safari (see the
  // DeriveKeyPair workaround above) — a "can't open my files" regression in exchange for only marginal
  // hardening (in-page code can decrypt in place without ever exporting the key). Do not flip this without
  // re-verifying that EVERY identity round-trips on Chrome AND Safari.
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", x: base64urlnopad.encode(pub.subarray(1, 33)), y: base64urlnopad.encode(pub.subarray(33, 65)), d: base64urlnopad.encode(sk) },
    alg, true, ["deriveBits"],
  );
  const publicKey = await crypto.subtle.importKey("raw", toArrayBuffer(pub), alg, true, []);
  // Best-effort scrub of the raw private scalar + KEM PRK. JS can't guarantee wiping (and the JWK `d`
  // string handed to importKey is an immutable copy we can't reach), but this clears the obvious live copies.
  sk.fill(0);
  dkpPrk.fill(0);
  return { privateKey, publicKey };
}

/**
 * Derive the full identity for a namespace from master_prk (§4.3):
 *   identity_ikm = HKDF-Expand(master_prk, "FILEKEY-v1/identity-kem" || canonical_rp_id, 32)
 *   (static_sk, static_pk) = HPKE.DeriveKeyPair(DHKEM-P256, identity_ikm)
 * The canonical RP-ID is bound so the identity is namespace-scoped regardless of how
 * master_prk was obtained (WebAuthn, recovery code, or test vector).
 */
export async function deriveIdentity(masterPrk: Uint8Array, namespace: Namespace): Promise<Identity> {
  if (masterPrk.length !== 32) {
    throw new FileKeyError(`master_prk must be 32 bytes, got ${masterPrk.length}`, "master_prk_length");
  }
  const info = new Uint8Array([...ascii(LABEL_IDENTITY_KEM), ...namespace.rpIdBytes]);
  const identityIkm = expand(sha256, masterPrk, info, 32);
  const keyPair = await deriveP256KeyPair(identityIkm);
  identityIkm.fill(0); // scrub the KEM seed once the keypair is derived (best-effort)
  const staticPkRaw = new Uint8Array(await suite.kem.serializePublicKey(keyPair.publicKey));
  if (staticPkRaw.length !== PK_LEN) {
    throw new FileKeyError(`derived static_pk length ${staticPkRaw.length} != ${PK_LEN}`, "derive_pk_length");
  }
  return { namespace, keyPair, staticPkRaw };
}

/** Convenience: PRF output → full identity for a namespace. */
export async function deriveIdentityFromPrf(prfSecret: Uint8Array, namespace: Namespace): Promise<Identity> {
  const masterPrk = masterPrkFromPrfSecret(prfSecret);
  try {
    return await deriveIdentity(masterPrk, namespace);
  } finally {
    masterPrk.fill(0); // scrub the derived master PRK; the caller owns (and scrubs) prfSecret
  }
}

export interface Fingerprint {
  /** Canonical 6-word fingerprint for out-of-band verification (§4.7). */
  words: string;
  /** Glanceable secondary form: first 4 bytes of the fingerprint hash, as hex. */
  hex: string;
}

/**
 * Identity fingerprint (§4.7): SHA-256("FILEKEY-v1/fingerprint" || static_pk), the
 * top 66 bits encoded as 6 BIP39 English words. Deterministic and identical across
 * conforming implementations, so two people can verify they hold the same key by eye.
 */
export function identityFingerprint(staticPkRaw: Uint8Array): Fingerprint {
  if (staticPkRaw.length !== PK_LEN) {
    throw new FileKeyError(`static_pk must be ${PK_LEN} bytes, got ${staticPkRaw.length}`, "pk_length");
  }
  const h = sha256(concat(ascii(LABEL_FINGERPRINT), staticPkRaw));
  // Top 66 bits of the first 9 bytes (72 bits) → 6 × 11-bit BIP39 indices.
  let acc = 0n;
  for (let i = 0; i < 9; i++) acc = (acc << 8n) | BigInt(h[i]!);
  acc >>= 6n; // drop the low 6 bits, keep the top 66
  const idx: number[] = new Array(6);
  for (let i = 5; i >= 0; i--) {
    idx[i] = Number(acc & 0x7ffn);
    acc >>= 11n;
  }
  const words = idx.map((i) => wordlist[i]!).join(" ");
  return { words, hex: toHex(h.subarray(0, 4)) };
}

export function toArrayBuffer(u: Uint8Array): ArrayBuffer {
  // Return a standalone (non-shared) ArrayBuffer copy; handles subarray views safely.
  const ab = new ArrayBuffer(u.length);
  new Uint8Array(ab).set(u);
  return ab;
}
