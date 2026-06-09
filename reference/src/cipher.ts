// Encryption (§6.4) and decryption (§7.2) procedures.
//
// Both directions are built on async generators so a caller can stream a large file
// without ever holding it whole in memory. The buffered `encrypt`/`decrypt` keep the
// original Uint8Array-in/Uint8Array-out signatures and are thin wrappers that drive the
// generators and collect the result. The wire format is byte-for-byte identical either way.
import { p256 } from "@noble/curves/nist.js";
import { ascii, concat, u32be, Reader, equalCT, bs, toHex, ByteSource, bytesSource } from "./bytes.js";
import {
  PK_LEN,
  ENC_LEN,
  HEADER_LEN,
  AAD_LEN,
  CHUNK_SIZE,
  GCM_TAG_LEN,
  MAX_CHUNK_INDEX,
  METADATA_CT_MAX,
  METADATA_CT_MIN,
  METADATA_NONCE,
  LABEL_PAYLOAD_KEY,
  LABEL_METADATA_KEY,
} from "./constants.js";
import { FileKeyError, Namespace, NamespaceSet } from "./namespace.js";
import { suite, Identity, toArrayBuffer } from "./identity.js";
import { Metadata, encodeMetadata, decodeMetadata } from "./metadata.js";
import { buildHeader, parseHeader, buildInfo, buildAad, chunkNonce } from "./wire.js";

/** Validate a 65-byte uncompressed SEC1 P-256 point (§5.3). Throws on any failure. */
export function validateUncompressedPk(raw: Uint8Array, what: string): void {
  if (raw.length !== PK_LEN) throw new FileKeyError(`${what} length ${raw.length} != 65`, "pk_length");
  if (raw[0] !== 0x04) throw new FileKeyError(`${what} leading byte != 0x04`, "pk_prefix");
  try {
    p256.Point.fromBytes(raw).assertValidity(); // range + on-curve + non-identity
  } catch (e) {
    throw new FileKeyError(`${what} is not a valid P-256 point: ${(e as Error).message}`, "pk_invalid");
  }
}

async function importAesKey(raw: ArrayBuffer): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function aesSeal(key: CryptoKey, nonce: Uint8Array, aad: Uint8Array, pt: Uint8Array): Promise<Uint8Array> {
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: bs(nonce), additionalData: bs(aad) }, key, bs(pt));
  return new Uint8Array(ct);
}

async function aesOpen(key: CryptoKey, nonce: Uint8Array, aad: Uint8Array, ct: Uint8Array): Promise<Uint8Array> {
  try {
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: bs(nonce), additionalData: bs(aad) }, key, bs(ct));
    return new Uint8Array(pt);
  } catch {
    throw new FileKeyError("AEAD authentication failed", "auth_failed");
  }
}

// ----------------------------------------------------------------------------
// Encryption (§6.4)
// ----------------------------------------------------------------------------

export interface EncryptInput {
  /** Sender's identity in the file's namespace (must equal `namespace`). */
  senderIdentity: Identity;
  /** Recipient's static_pk as 65-byte SEC1 uncompressed. */
  recipientPkRaw: Uint8Array;
  /** The file's namespace (recipient's; in v1 == sender's). */
  namespace: Namespace;
  plaintext: Uint8Array;
  /** Metadata sans originalSize (set internally to plaintext.length, the authoritative value). */
  metadata: Omit<Metadata, "originalSize">;
}

/** Streaming variant of {@link EncryptInput}: plaintext is read incrementally from a ByteSource. */
export interface EncryptStreamInput {
  senderIdentity: Identity;
  recipientPkRaw: Uint8Array;
  namespace: Namespace;
  /** The plaintext as a random-access byte source; `size` is the authoritative original_plaintext_size. */
  plaintext: ByteSource;
  metadata: Omit<Metadata, "originalSize">;
}

/**
 * Core streaming encryption (§6.4). Yields the .filekey file in order: first the fixed
 * head (header‖sender_pk‖hpke_enc‖u32(metaCtLen)‖metaCt), then each payload chunk. Concatenating
 * everything it yields produces exactly the bytes that the buffered `encrypt` returns.
 */
async function* sealStream(input: EncryptStreamInput, ekm?: ArrayBuffer | CryptoKeyPair): AsyncGenerator<Uint8Array> {
  const { senderIdentity, recipientPkRaw, namespace } = input;
  const M = input.plaintext.size;

  // §6.4 step 2: sender must be in the file's namespace.
  if (senderIdentity.namespace.canonicalRpId !== namespace.canonicalRpId) {
    throw new FileKeyError("sender identity is not in the recipient's namespace", "sender_namespace_mismatch");
  }
  validateUncompressedPk(recipientPkRaw, "recipient_pk");
  const senderPk = senderIdentity.staticPkRaw;

  // §6.4 steps 4–5: namespace tag + header.
  const header = buildHeader(namespace.tag);

  // §6.4 step 6: HPKE info transcript.
  const info = buildInfo(header, senderPk, recipientPkRaw, namespace.rpIdBytes);

  // §6.4 step 7: HPKE Auth SetupS (export-only usage).
  const recipientPublicKey = await suite.kem.deserializePublicKey(toArrayBuffer(recipientPkRaw));
  const sender = await suite.createSenderContext({
    recipientPublicKey,
    info,
    senderKey: senderIdentity.keyPair.privateKey,
    ...(ekm ? { ekm } : {}),
  });
  const hpkeEnc = new Uint8Array(sender.enc);
  if (hpkeEnc.length !== ENC_LEN) throw new FileKeyError(`hpke_enc length ${hpkeEnc.length} != 65`, "enc_length");

  // §6.4 steps 8–10: export keys, aad.
  const payloadKey = await importAesKey(await sender.export(ascii(LABEL_PAYLOAD_KEY), 32));
  const metadataKey = await importAesKey(await sender.export(ascii(LABEL_METADATA_KEY), 32));
  const aad = buildAad(header, senderPk, hpkeEnc);

  // §6.4 step 13: metadata chunk.
  const fullMeta: Metadata = { ...input.metadata, originalSize: M };
  const metaPt = encodeMetadata(fullMeta);
  const metaCt = await aesSeal(metadataKey, METADATA_NONCE, aad, metaPt);
  if (metaCt.length > METADATA_CT_MAX || metaCt.length < METADATA_CT_MIN) {
    throw new FileKeyError("metadata ciphertext length out of bounds", "metadata_ct_bounds");
  }

  // Emit the fixed head first, then payload chunks.
  yield concat(header, senderPk, hpkeEnc, u32be(metaCt.length), metaCt);

  // §6.4 step 14: payload chunks (STREAM).
  const totalChunks = M === 0 ? 1 : Math.ceil(M / CHUNK_SIZE);
  if (totalChunks > MAX_CHUNK_INDEX) throw new FileKeyError("payload exceeds 2^32 chunk cap", "chunk_overflow");
  for (let i = 0; i < totalChunks; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, M);
    const chunkPt = await input.plaintext.slice(start, end);
    // The buffered path gets exact-length chunks for free from a Uint8Array. A custom ByteSource that
    // under-reads would otherwise emit a file whose payload is shorter than the metadata's originalSize.
    if (chunkPt.length !== end - start) {
      throw new FileKeyError(`plaintext source returned ${chunkPt.length} bytes, expected ${end - start}`, "source_short_read");
    }
    const isLast = i === totalChunks - 1;
    yield await aesSeal(payloadKey, chunkNonce(i, isLast), aad, chunkPt);
  }
}

/**
 * Streaming encryption (§6.4). Yields the .filekey file bytes incrementally so a large
 * plaintext is never held whole in memory. Byte-identical to {@link encrypt}.
 */
export function encryptStream(input: EncryptStreamInput): AsyncGenerator<Uint8Array> {
  return sealStream(input);
}

/** Core encryption (§6.4). Returns the complete .filekey file bytes. */
export async function encrypt(input: EncryptInput): Promise<Uint8Array> {
  return collect(sealStream(toEncryptStreamInput(input)));
}

/**
 * TEST ONLY (§11.1 deterministic-ephemeral vectors): encrypt with caller-supplied HPKE ephemeral
 * key material instead of fresh randomness. Deliberately NOT re-exported from index.ts, so it is
 * unreachable through the public API. Reusing `ekm` for the same sender/recipient/namespace repeats
 * the HPKE enc and every nonce — catastrophic AES-GCM nonce reuse. Never call from a production path.
 */
export async function encryptWithEphemeralForTest(
  input: EncryptInput,
  ekm: ArrayBuffer | CryptoKeyPair,
): Promise<Uint8Array> {
  return collect(sealStream(toEncryptStreamInput(input), ekm));
}

function toEncryptStreamInput(input: EncryptInput): EncryptStreamInput {
  return {
    senderIdentity: input.senderIdentity,
    recipientPkRaw: input.recipientPkRaw,
    namespace: input.namespace,
    plaintext: bytesSource(input.plaintext),
    metadata: input.metadata,
  };
}

async function collect(gen: AsyncGenerator<Uint8Array>): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  for await (const piece of gen) parts.push(piece);
  return concat(...parts);
}

// ----------------------------------------------------------------------------
// Decryption (§7.2)
// ----------------------------------------------------------------------------

export interface DecryptResult {
  metadata: Metadata;
  plaintext: Uint8Array;
  /** The sender's static_pk (65-byte uncompressed) — for application identity resolution (§7.3). */
  senderPkRaw: Uint8Array;
  namespace: Namespace;
  /** True when sender_pk == the recipient's static_pk (self-encrypted file). */
  selfEncrypted: boolean;
}

export interface DecryptInput {
  file: Uint8Array;
  namespaces: NamespaceSet;
  /**
   * Resolve the recipient's identity for the file's namespace (§7.2 step 5). This is
   * where an interactive client triggers the WebAuthn PRF assertion. Called at most once.
   */
  resolveIdentity: (namespace: Namespace) => Promise<Identity>;
}

/** Streaming variant of {@link DecryptInput}: the file is read incrementally from a ByteSource. */
export interface DecryptStreamInput {
  file: ByteSource;
  namespaces: NamespaceSet;
  resolveIdentity: (namespace: Namespace) => Promise<Identity>;
}

export interface DecryptStreamResult {
  metadata: Metadata;
  senderPkRaw: Uint8Array;
  namespace: Namespace;
  selfEncrypted: boolean;
  /**
   * Yields plaintext chunks in order. Each chunk is individually AES-GCM authenticated BEFORE it is
   * yielded, but file-level integrity — that the final chunk was reached and the total decrypted size
   * matches `metadata.originalSize` — is only verified AFTER the last chunk, by throwing a FileKeyError
   * (auth failure, truncation, or size mismatch; §7.4).
   *
   * CONTRACT (load-bearing): a caller MUST NOT treat yielded chunks as trusted output until the
   * generator completes without throwing. For all-or-nothing release (never surfacing a valid prefix of
   * a file that turns out to be truncated), buffer every chunk and release only on normal completion —
   * which is exactly what the buffered {@link decrypt} does, so prefer it unless the file is too large to
   * hold. Streaming chunks straight to disk / a preview accepts that a truncated file can expose an
   * authenticated prefix before the final throw (Policy B); {@link decrypt} is the Policy-A path.
   */
  chunks: AsyncGenerator<Uint8Array>;
}

/**
 * Streaming decryption (§7.2). Reads the head + metadata (small, eager), triggers the
 * WebAuthn assertion via `resolveIdentity`, then returns the metadata together with a
 * generator that yields authenticated payload chunks. Output is never held whole in memory.
 */
export async function decryptStream(input: DecryptStreamInput): Promise<DecryptStreamResult> {
  const source = input.file;

  // §7.2 step 1: header (+ sender_pk, hpke_enc, metadata_ct_len — the fixed-size head).
  const headFixed = HEADER_LEN + PK_LEN + ENC_LEN + 4;
  const head = await source.slice(0, headFixed); // clamps near EOF; Reader throws "truncated" if short
  const r = new Reader(head);
  const header = r.take(HEADER_LEN).slice();
  const { namespaceTag } = parseHeader(header);

  // §7.2 step 2: dispatch by tag.
  const namespace = input.namespaces.matchTag(namespaceTag);
  if (!namespace) {
    throw new FileKeyError(`no configured namespace matches file tag 0x${toHex(namespaceTag)}`, "wrong_namespace");
  }

  // §7.2 steps 3–4: sender_pk, hpke_enc.
  const senderPk = r.take(PK_LEN).slice();
  validateUncompressedPk(senderPk, "sender_pk");
  const hpkeEnc = r.take(ENC_LEN).slice();
  validateUncompressedPk(hpkeEnc, "hpke_enc");

  // §7.2 step 5: recipient identity for this namespace (may trigger WebAuthn).
  const identity = await input.resolveIdentity(namespace);
  if (identity.namespace.canonicalRpId !== namespace.canonicalRpId) {
    throw new FileKeyError("resolved identity is not in the file's namespace", "identity_namespace_mismatch");
  }
  const recipientPk = identity.staticPkRaw;

  // §7.2 step 6–7: info + HPKE Auth SetupR.
  const info = buildInfo(header, senderPk, recipientPk, namespace.rpIdBytes);
  let recipient: Awaited<ReturnType<typeof suite.createRecipientContext>>;
  try {
    const senderPublicKey = await suite.kem.deserializePublicKey(toArrayBuffer(senderPk));
    recipient = await suite.createRecipientContext({
      recipientKey: identity.keyPair.privateKey,
      enc: toArrayBuffer(hpkeEnc),
      info,
      senderPublicKey,
    });
  } catch (e) {
    throw new FileKeyError(`HPKE SetupAuthR failed: ${(e as Error).message}`, "hpke_setup_failed");
  }

  // §7.2 steps 8–9: export keys, aad.
  const payloadKey = await importAesKey(await recipient.export(ascii(LABEL_PAYLOAD_KEY), 32));
  const metadataKey = await importAesKey(await recipient.export(ascii(LABEL_METADATA_KEY), 32));
  const aad = buildAad(header, senderPk, hpkeEnc);
  if (aad.length !== AAD_LEN) throw new FileKeyError("aad length invariant violated", "aad_length");

  // §7.2 steps 10–13: metadata length (bounded) + chunk.
  const metaCtLen = r.u32();
  if (metaCtLen > METADATA_CT_MAX || metaCtLen < METADATA_CT_MIN) {
    throw new FileKeyError(`metadata_ct_len ${metaCtLen} out of bounds`, "metadata_ct_bounds");
  }
  const metaCt = await source.slice(headFixed, headFixed + metaCtLen);
  if (metaCt.length !== metaCtLen) throw new FileKeyError("unexpected end of input (truncated file)", "truncated");
  const metaPt = await aesOpen(metadataKey, METADATA_NONCE, aad, metaCt);
  const metadata = decodeMetadata(metaPt);

  const payloadStart = headFixed + metaCtLen;
  const selfEncrypted = equalCT(senderPk, recipientPk);
  return {
    metadata,
    senderPkRaw: senderPk,
    namespace,
    selfEncrypted,
    chunks: openStream(source, payloadStart, payloadKey, aad, metadata.originalSize),
  };
}

/**
 * §7.2 steps 14–17: stream-decrypt the payload chunks. Yields each chunk's plaintext only
 * after it authenticates; enforces the same nonce/size/truncation invariants as the buffered
 * path, throwing (after the final chunk) on truncation or size mismatch.
 */
async function* openStream(
  source: ByteSource,
  payloadStart: number,
  payloadKey: CryptoKey,
  aad: Uint8Array,
  M: number,
): AsyncGenerator<Uint8Array> {
  const total = source.size;
  let off = payloadStart;
  let i = 0;
  let decryptedBytes = 0;
  let sawLast = false;
  for (;;) {
    const remaining = total - off;
    if (remaining === 0) throw new FileKeyError("no payload chunks (truncated before first chunk)", "no_chunks");
    if (remaining < GCM_TAG_LEN) throw new FileKeyError("incomplete final chunk (< 16 bytes)", "incomplete_chunk");
    if (i >= MAX_CHUNK_INDEX) throw new FileKeyError("chunk index exceeds 2^32 cap", "chunk_overflow");
    const toRead = Math.min(remaining, CHUNK_SIZE + GCM_TAG_LEN);
    const chunkCt = await source.slice(off, off + toRead);
    // toRead never exceeds remaining, so a correct source returns exactly toRead. A short read means a
    // truncated/unstable source — reject it rather than mis-derive isLast from the advanced offset.
    if (chunkCt.length !== toRead) {
      throw new FileKeyError("file source returned a short read (truncated or unstable source)", "truncated");
    }
    off += toRead;
    const isLast = off >= total;
    if (!isLast && chunkCt.length < GCM_TAG_LEN + 1) {
      throw new FileKeyError("non-final chunk has no plaintext", "empty_nonfinal_chunk");
    }
    const pt = await aesOpen(payloadKey, chunkNonce(i, isLast), aad, chunkCt);
    if (isLast && pt.length === 0 && M !== 0) {
      throw new FileKeyError("empty final chunk but original_plaintext_size != 0", "empty_final_mismatch");
    }
    decryptedBytes += pt.length;
    if (decryptedBytes > M) throw new FileKeyError("decrypted size overruns original_plaintext_size", "size_overrun");
    yield pt;
    if (isLast) {
      sawLast = true;
      break;
    }
    i++;
  }
  if (!sawLast) throw new FileKeyError("never saw last chunk (truncation)", "truncated");
  if (decryptedBytes !== M) {
    throw new FileKeyError(`decrypted ${decryptedBytes} != original_plaintext_size ${M}`, "size_mismatch");
  }
}

/** Core decryption (§7.2). Buffers output (Policy A, §7.4) and returns it only on full success. */
export async function decrypt(input: DecryptInput): Promise<DecryptResult> {
  const res = await decryptStream({
    file: bytesSource(input.file),
    namespaces: input.namespaces,
    resolveIdentity: input.resolveIdentity,
  });
  const out: Uint8Array[] = [];
  for await (const pt of res.chunks) out.push(pt);
  return {
    metadata: res.metadata,
    plaintext: concat(...out),
    senderPkRaw: res.senderPkRaw,
    namespace: res.namespace,
    selfEncrypted: res.selfEncrypted,
  };
}
