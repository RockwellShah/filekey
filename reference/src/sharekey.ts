// Share-key encoding/decoding (spec §4.4): Bech32m over sk_version || namespace_tag || compressed_pk.
import { p256 } from "@noble/curves/nist.js";
import { bech32m } from "@scure/base";
import { concat, toHex } from "./bytes.js";
import { SHARE_KEY_HRP, SK_VERSION, NS_TAG_LEN, COMPRESSED_PK_LEN, PK_LEN } from "./constants.js";
import { FileKeyError, NamespaceSet, Namespace } from "./namespace.js";

const BECH32_LIMIT = 1023;

/** Compress a 65-byte SEC1 uncompressed P-256 point to 33 bytes. Validates the point. */
export function compressPk(uncompressed: Uint8Array): Uint8Array {
  if (uncompressed.length !== PK_LEN || uncompressed[0] !== 0x04) {
    throw new FileKeyError("expected 65-byte uncompressed SEC1 point (0x04 prefix)", "pk_format");
  }
  try {
    return p256.Point.fromBytes(uncompressed).toBytes(true); // fromBytes throws if invalid/off-curve/identity
  } catch (e) {
    throw new FileKeyError(`point invalid: ${(e as Error).message}`, "point_invalid");
  }
}

/** Decompress a 33-byte SEC1 compressed P-256 point to 65 bytes. Validates the point. */
export function decompressPk(compressed: Uint8Array): Uint8Array {
  if (compressed.length !== COMPRESSED_PK_LEN || (compressed[0] !== 0x02 && compressed[0] !== 0x03)) {
    throw new FileKeyError("expected 33-byte compressed SEC1 point (0x02/0x03 prefix)", "pk_format");
  }
  try {
    const pt = p256.Point.fromBytes(compressed);
    pt.assertValidity(); // explicit on-curve + non-identity + range check
    return pt.toBytes(false);
  } catch (e) {
    throw new FileKeyError(`point invalid: ${(e as Error).message}`, "point_invalid");
  }
}

/** Encode a share key for a namespace identity. `staticPkRaw` is 65-byte uncompressed. */
export function encodeShareKey(staticPkRaw: Uint8Array, namespace: Namespace): string {
  const compressed = compressPk(staticPkRaw);
  const payload = concat(new Uint8Array([SK_VERSION]), namespace.tag, compressed);
  return bech32m.encode(SHARE_KEY_HRP, bech32m.toWords(payload), BECH32_LIMIT);
}

export interface DecodedShareKey {
  /** recipient_pk as 65-byte SEC1 uncompressed, ready for HPKE. */
  recipientPkRaw: Uint8Array;
  /** The matched configured namespace (the file's namespace). */
  namespace: Namespace;
}

/**
 * Decode + fully validate a share key against the configured namespaces.
 * Implements the ten §4.4 rejection checks; throws FileKeyError with a distinct
 * `code` per failure class (notably "wrong_namespace" for check 5).
 */
export function decodeShareKey(shareKey: string, namespaces: NamespaceSet): DecodedShareKey {
  // Checks 1–3: Bech32m decode (rejects bech32 non-m checksum, bad checksum, mixed case).
  let decoded: { prefix: string; words: number[] };
  try {
    decoded = bech32m.decode(shareKey as `${string}1${string}`, BECH32_LIMIT);
  } catch (e) {
    throw new FileKeyError(`share key is not valid Bech32m: ${(e as Error).message}`, "bech32m_decode");
  }
  if (decoded.prefix !== SHARE_KEY_HRP) {
    throw new FileKeyError(`share key HRP "${decoded.prefix}" != "${SHARE_KEY_HRP}"`, "wrong_hrp");
  }
  let payload: Uint8Array;
  try {
    payload = bech32m.fromWords(decoded.words);
  } catch (e) {
    throw new FileKeyError(`share-key payload is not valid Bech32m data: ${(e as Error).message}`, "bech32m_decode");
  }

  // Check 10: exact payload length before any further work.
  const expected = 1 + NS_TAG_LEN + COMPRESSED_PK_LEN; // 38
  if (payload.length !== expected) {
    throw new FileKeyError(`share-key payload length ${payload.length} != ${expected}`, "payload_length");
  }

  // Check 4: sk_version.
  const skVersion = payload[0]!;
  if (skVersion !== SK_VERSION) {
    throw new FileKeyError(`unsupported sk_version 0x${skVersion.toString(16)}`, "sk_version");
  }

  // Check 5: namespace tag must match a configured namespace.
  const tag = payload.subarray(1, 1 + NS_TAG_LEN);
  const namespace = namespaces.matchTag(tag);
  if (!namespace) {
    throw new FileKeyError(
      `share key is for a namespace not configured (tag 0x${toHex(tag)})`,
      "wrong_namespace",
    );
  }

  // Checks 6–9: point prefix, coordinate range, on-curve, non-identity (decompressPk enforces all).
  const compressed = payload.subarray(1 + NS_TAG_LEN);
  let recipientPkRaw: Uint8Array;
  try {
    recipientPkRaw = decompressPk(compressed);
  } catch (e) {
    if (e instanceof FileKeyError) throw e;
    throw new FileKeyError(`share-key point invalid: ${(e as Error).message}`, "point_invalid");
  }

  return { recipientPkRaw, namespace };
}
