// Generate reproducible known-answer test vectors (spec §11.1).
// Uses fixed prf_secret and fixed HPKE ephemeral key material (the §11.1 deterministic
// carveout) so every run produces byte-identical output. Self-verifies before writing.
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  Namespace,
  NamespaceSet,
  masterPrkFromPrfSecret,
  deriveIdentity,
  identityFingerprint,
  encodeShareKey,
  encodeRecoveryBip39,
  encodeRecoveryBech32m,
  decrypt,
  toHex,
  fromHex,
  type Identity,
  type Metadata,
} from "../src/index.js";
import { encryptWithEphemeralForTest } from "../src/cipher.js";

const RP = "filekey.app";
const NS = new Namespace(RP);
const SET = new NamespaceSet([RP]);

// Fixed inputs (hex) — chosen constants for reproducibility, NOT secrets.
const SENDER_PRF = fromHex("11".repeat(32));
const RECIPIENT_PRF = fromHex("22".repeat(32));
const EKM = fromHex("ee".repeat(32)); // deterministic HPKE ephemeral key material

const baseMeta = (filename: string): Omit<Metadata, "originalSize"> => ({
  filename,
  mimeType: "application/octet-stream",
  createdAtUnixMs: 0,
  extras: new Map(),
});

// Deterministic pseudo-random plaintext (so vectors don't depend on a CSPRNG).
function detBytes(n: number, seed: number): Uint8Array {
  const out = new Uint8Array(n);
  let x = seed >>> 0;
  for (let i = 0; i < n; i++) {
    x = (x * 1664525 + 1013904223) >>> 0;
    out[i] = (x >>> 24) & 0xff;
  }
  return out;
}

async function main() {
  const sender = await deriveIdentity(masterPrkFromPrfSecret(SENDER_PRF), NS);
  const recipient = await deriveIdentity(masterPrkFromPrfSecret(RECIPIENT_PRF), NS);
  const senderMasterPrk = masterPrkFromPrfSecret(SENDER_PRF);

  const identityVectors = {
    canonical_rp_id: RP,
    namespace_tag: toHex(NS.tag),
    sender: {
      prf_secret: toHex(SENDER_PRF),
      master_prk: toHex(senderMasterPrk),
      static_pk: toHex(sender.staticPkRaw),
      share_key: encodeShareKey(sender.staticPkRaw, NS),
      fingerprint: identityFingerprint(sender.staticPkRaw).words,
      fingerprint_hex: identityFingerprint(sender.staticPkRaw).hex,
      recovery_bip39: encodeRecoveryBip39(senderMasterPrk),
      recovery_bech32m: encodeRecoveryBech32m(senderMasterPrk, NS),
    },
    recipient: {
      prf_secret: toHex(RECIPIENT_PRF),
      static_pk: toHex(recipient.staticPkRaw),
      share_key: encodeShareKey(recipient.staticPkRaw, NS),
      fingerprint: identityFingerprint(recipient.staticPkRaw).words,
    },
  };

  const cases: Array<{ name: string; size: number; self: boolean; ptSeed: number }> = [
    { name: "empty-self", size: 0, self: true, ptSeed: 1 },
    { name: "one-byte-self", size: 1, self: true, ptSeed: 2 },
    { name: "sub-chunk-self", size: 100, self: true, ptSeed: 3 },
    { name: "exact-64k-self", size: 65536, self: true, ptSeed: 4 },
    { name: "64k-plus-1-shared", size: 65537, self: false, ptSeed: 5 },
    { name: "multi-chunk-shared", size: 200000, self: false, ptSeed: 6 },
  ];

  const fileVectors = [];
  for (const c of cases) {
    const plaintext = detBytes(c.size, c.ptSeed);
    const recipientPkRaw = c.self ? sender.staticPkRaw : recipient.staticPkRaw;
    const file = await encryptWithEphemeralForTest({
      senderIdentity: sender,
      recipientPkRaw,
      namespace: NS,
      plaintext,
      metadata: baseMeta(`${c.name}.bin`),
    }, EKM.slice().buffer);

    // Self-verify: decrypt must reproduce the plaintext exactly.
    const id = c.self ? sender : recipient;
    const res = await decrypt({ file, namespaces: SET, resolveIdentity: async () => id });
    if (toHex(res.plaintext) !== toHex(plaintext)) {
      throw new Error(`vector ${c.name}: decrypt mismatch`);
    }
    if (res.metadata.originalSize !== c.size) throw new Error(`vector ${c.name}: size mismatch`);

    fileVectors.push({
      name: c.name,
      self_encrypted: c.self,
      plaintext_size: c.size,
      plaintext_sha256_prefix: toHex((await sha256(plaintext)).subarray(0, 8)),
      recipient_share_key: encodeShareKey(recipientPkRaw, NS),
      ekm: toHex(EKM),
      file_size: file.length,
      file_sha256: toHex(await sha256(file)),
      // Full file bytes for small cases; digest-only for large ones to keep the file readable.
      file_hex: c.size <= 1024 ? toHex(file) : null,
    });
  }

  const negative = [
    { name: "flip-payload-byte", expect: "auth_failed" },
    { name: "forge-namespace-tag", expect: "wrong_namespace" },
    { name: "drop-last-chunk", expect: "auth_failed-or-truncated" },
    { name: "append-trailing-bytes", expect: "rejected" },
    { name: "wrong-recipient", expect: "auth_failed" },
    { name: "bad-utf8-filename", expect: "filename_utf8 (rejected at encode)" },
    { name: "duplicate-extras-key", expect: "extras_duplicate" },
  ];

  const out = {
    spec_version: "0.4.7",
    suite: "FKEYv1-AUTH-P256-AES256GCM-STREAM64K",
    note: "Reproducible KAT vectors. Identity uses fixed prf_secret; files use the §11.1 deterministic-ephemeral carveout (fixed ekm). Regenerate with `bun run vectors`.",
    identity: identityVectors,
    files: fileVectors,
    negative_descriptors: negative,
  };

  const path = fileURLToPath(new URL("./vectors.json", import.meta.url));
  writeFileSync(path, JSON.stringify(out, null, 2) + "\n");
  console.log(`wrote ${fileVectors.length} file vectors + identity vectors to ${path}`);
  console.log(`sender share key: ${identityVectors.sender.share_key}`);
}

async function sha256(b: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", b.slice().buffer));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
