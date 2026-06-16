// Wire-format builders: header, HPKE info transcript, AAD, chunk nonces (spec §5, §6).
import { ascii, concat, i2osp } from "./bytes.js";
import {
  MAGIC,
  FORMAT_VERSION,
  SUITE_ID,
  SUITE_SELF,
  HEADER_LEN,
  NS_TAG_LEN,
  LABEL_HPKE_INFO,
  COUNTER_LEN,
} from "./constants.js";
import { FileKeyError } from "./namespace.js";

/** 12-byte file header (§5.2): magic||version||suite||flags||reserved||namespace_tag. */
export function buildHeader(namespaceTag: Uint8Array, suiteId: number = SUITE_ID): Uint8Array {
  if (namespaceTag.length !== NS_TAG_LEN) throw new FileKeyError("namespace_tag must be 4 bytes", "ns_tag_length");
  const header = new Uint8Array(HEADER_LEN);
  header.set(MAGIC, 0);
  header[4] = FORMAT_VERSION;
  header[5] = suiteId;
  header[6] = 0x00; // flags
  header[7] = 0x00; // reserved
  header.set(namespaceTag, 8);
  return header;
}

export interface ParsedHeader {
  /** Suite identifier: SUITE_ID (0x01, HPKE) or SUITE_SELF (0x02, symmetric self-encryption). */
  suiteId: number;
  namespaceTag: Uint8Array;
}

/** Validate + parse a 12-byte header (§7.2 step 1). Throws on any mismatch. */
export function parseHeader(header: Uint8Array): ParsedHeader {
  if (header.length !== HEADER_LEN) throw new FileKeyError(`header length ${header.length} != 12`, "header_length");
  for (let i = 0; i < 4; i++) {
    if (header[i] !== MAGIC[i]) throw new FileKeyError("bad magic (not an FKEY file)", "bad_magic");
  }
  if (header[4] !== FORMAT_VERSION) throw new FileKeyError(`unsupported format_version 0x${header[4]!.toString(16)}`, "format_version");
  const suiteId = header[5]!;
  if (suiteId !== SUITE_ID && suiteId !== SUITE_SELF) {
    throw new FileKeyError(`unsupported suite_id 0x${suiteId.toString(16)}`, "suite_id");
  }
  if (header[6] !== 0x00) throw new FileKeyError("non-zero flags byte (reserved in v1)", "flags_nonzero");
  if (header[7] !== 0x00) throw new FileKeyError("non-zero reserved byte", "reserved_nonzero");
  return { suiteId, namespaceTag: header.subarray(8, 12) };
}

/** HPKE info transcript (§6.2). */
export function buildInfo(
  header: Uint8Array,
  senderPk: Uint8Array,
  recipientPk: Uint8Array,
  rpIdBytes: Uint8Array,
): Uint8Array {
  if (rpIdBytes.length > 255) throw new FileKeyError("rp_id too long for u8 length prefix", "rpid_length");
  return concat(ascii(LABEL_HPKE_INFO), header, senderPk, recipientPk, new Uint8Array([rpIdBytes.length]), rpIdBytes);
}

/** AAD bound into every AEAD call (§5.4.2, §5.5): header||sender_pk||hpke_enc = 142 bytes. */
export function buildAad(header: Uint8Array, senderPk: Uint8Array, hpkeEnc: Uint8Array): Uint8Array {
  return concat(header, senderPk, hpkeEnc);
}

/** AAD for suite 0x02 symmetric self-encryption (§5.6): header||file_salt. Distinct from {@link buildAad};
 *  the HPKE 142-byte invariant does not apply because suite 0x02 carries no sender_pk/hpke_enc. */
export function buildSelfAad(header: Uint8Array, fileSalt: Uint8Array): Uint8Array {
  return concat(header, fileSalt);
}

/** chunk_nonce(i, is_last) = I2OSP(i, 11) || (0x01 if last else 0x00) (§5.5). */
export function chunkNonce(index: number, isLast: boolean): Uint8Array {
  return concat(i2osp(index, COUNTER_LEN), new Uint8Array([isLast ? 0x01 : 0x00]));
}
