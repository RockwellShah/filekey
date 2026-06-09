// Metadata chunk plaintext encode/decode (spec §5.4.1).
import { td, concat, u16be, u32be, u64be, Reader } from "./bytes.js";
import { METADATA_VERSION, METADATA_PLAINTEXT_MAX } from "./constants.js";
import { FileKeyError } from "./namespace.js";

export interface Metadata {
  filename: string;
  mimeType: string;
  /** original_plaintext_size — authoritative, enforced at decryption (§5.4.1 rule 4). */
  originalSize: number;
  /** created_at_unix_ms; 0 = unknown (§5.4.1 rule 5). */
  createdAtUnixMs: number;
  /** Ordered map of application-defined extras. */
  extras: Map<string, Uint8Array>;
}

const enc = new TextEncoder();

function validateFilenameBytes(bytes: Uint8Array): void {
  if (bytes.length === 0) return; // empty filename allowed only when filename_len == 0
  for (const b of bytes) {
    if (b <= 0x1f || b === 0x7f) throw new FileKeyError("filename contains a C0 control or DEL byte", "filename_control");
    if (b === 0x2f || b === 0x5c) throw new FileKeyError("filename contains a path separator", "filename_separator");
  }
  if (bytes[0] === 0x20 || bytes[bytes.length - 1] === 0x20) {
    throw new FileKeyError("filename begins or ends with SPACE", "filename_space");
  }
  let s: string;
  try {
    s = td.decode(bytes); // fatal UTF-8 validation
  } catch {
    throw new FileKeyError("filename is not valid UTF-8", "filename_utf8");
  }
  if (s === "." || s === "..") throw new FileKeyError(`filename "${s}" is a path-traversal form`, "filename_dotdot");
}

/** Encode metadata to its length-prefixed plaintext (§5.4.1). Validates as it builds. */
export function encodeMetadata(m: Metadata): Uint8Array {
  const filenameBytes = enc.encode(m.filename);
  if (filenameBytes.length > 65535) throw new FileKeyError("filename too long (> 65535 bytes)", "filename_length");
  validateFilenameBytes(filenameBytes);

  const mimeBytes = enc.encode(m.mimeType);
  if (mimeBytes.length > 256) throw new FileKeyError("mime_type too long (> 256 bytes)", "mime_length");

  if (m.originalSize < 0 || !Number.isSafeInteger(m.originalSize)) throw new FileKeyError("originalSize invalid", "size_invalid");
  if (m.createdAtUnixMs < 0 || !Number.isSafeInteger(m.createdAtUnixMs)) throw new FileKeyError("createdAtUnixMs invalid", "created_invalid");

  if (m.extras.size > 256) throw new FileKeyError("too many extras (> 256)", "extras_count");

  const parts: Uint8Array[] = [
    new Uint8Array([METADATA_VERSION]),
    u32be(filenameBytes.length),
    filenameBytes,
    u32be(mimeBytes.length),
    mimeBytes,
    u64be(BigInt(m.originalSize)),
    u64be(BigInt(m.createdAtUnixMs)),
    u16be(m.extras.size),
  ];
  for (const [key, value] of m.extras) {
    const keyBytes = enc.encode(key);
    if (keyBytes.length < 1 || keyBytes.length > 256) throw new FileKeyError(`extras key length ${keyBytes.length} not in 1..256`, "extras_key_length");
    if (value.length > 65536) throw new FileKeyError("extras value too long (> 65536)", "extras_value_length");
    parts.push(u16be(keyBytes.length), keyBytes, u32be(value.length), value);
  }

  const out = concat(...parts);
  if (out.length > METADATA_PLAINTEXT_MAX) throw new FileKeyError("metadata plaintext exceeds 1 MiB", "metadata_too_large");
  return out;
}

/** Decode + fully validate metadata plaintext (§5.4.1, all rules). */
export function decodeMetadata(plaintext: Uint8Array): Metadata {
  if (plaintext.length > METADATA_PLAINTEXT_MAX) {
    throw new FileKeyError("metadata plaintext exceeds 1 MiB", "metadata_too_large");
  }
  const r = new Reader(plaintext);

  const version = r.u8();
  if (version !== METADATA_VERSION) throw new FileKeyError(`metadata_version 0x${version.toString(16)} != 0x01`, "metadata_version");

  const filenameLen = r.u32();
  if (filenameLen > 65535) throw new FileKeyError("filename_len > 65535", "filename_length");
  const filenameBytes = r.take(filenameLen);
  validateFilenameBytes(filenameBytes);
  const filename = filenameLen === 0 ? "" : td.decode(filenameBytes);

  const mimeLen = r.u32();
  if (mimeLen > 256) throw new FileKeyError("mime_type_len > 256", "mime_length");
  const mimeBytes = r.take(mimeLen);
  let mimeType: string;
  try {
    mimeType = td.decode(mimeBytes);
  } catch {
    throw new FileKeyError("mime_type is not valid UTF-8", "mime_utf8");
  }

  const originalSize = r.u64();
  const createdAtUnixMs = r.u64();

  const extrasCount = r.u16();
  if (extrasCount > 256) throw new FileKeyError("extras_count > 256", "extras_count");
  const extras = new Map<string, Uint8Array>();
  const seen = new Set<string>();
  for (let i = 0; i < extrasCount; i++) {
    const keyLen = r.u16();
    if (keyLen < 1 || keyLen > 256) throw new FileKeyError(`extras key length ${keyLen} not in 1..256`, "extras_key_length");
    const keyBytes = r.take(keyLen);
    let key: string;
    try {
      key = td.decode(keyBytes);
    } catch {
      throw new FileKeyError("extras key is not valid UTF-8", "extras_key_utf8");
    }
    if (seen.has(key)) throw new FileKeyError(`duplicate extras key "${key}"`, "extras_duplicate"); // detect while parsing
    seen.add(key);
    const valueLen = r.u32();
    if (valueLen > 65536) throw new FileKeyError("extras value too long (> 65536)", "extras_value_length");
    const value = r.take(valueLen).slice();
    extras.set(key, value);
  }

  // Rule 8: no trailing bytes.
  if (r.remaining !== 0) throw new FileKeyError(`${r.remaining} trailing bytes after metadata`, "metadata_trailing");

  if (originalSize > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new FileKeyError("original_plaintext_size exceeds MAX_SAFE_INTEGER", "size_too_large");
  }
  if (createdAtUnixMs > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new FileKeyError("created_at_unix_ms exceeds MAX_SAFE_INTEGER", "created_too_large");
  }

  return {
    filename,
    mimeType,
    originalSize: Number(originalSize),
    createdAtUnixMs: Number(createdAtUnixMs),
    extras,
  };
}
