// Optional recovery codes (spec §4.6): BIP39 24-word phrase and self-describing Bech32m.
import * as bip39 from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { bech32m } from "@scure/base";
import { concat, toHex } from "./bytes.js";
import { RECOVERY_HRP, REC_VERSION, NS_TAG_LEN } from "./constants.js";
import { FileKeyError, NamespaceSet, Namespace } from "./namespace.js";

const BECH32_LIMIT = 1023;

// ---- Format 1: BIP39 (24 words, 256-bit entropy + 8-bit checksum) — §4.6.2 ----

/** Encode master_prk (32 bytes) as a 24-word BIP39 English mnemonic. */
export function encodeRecoveryBip39(masterPrk: Uint8Array): string {
  if (masterPrk.length !== 32) {
    throw new FileKeyError(`master_prk must be 32 bytes, got ${masterPrk.length}`, "master_prk_length");
  }
  return bip39.entropyToMnemonic(masterPrk, wordlist);
}

/**
 * Decode a 24-word BIP39 phrase to master_prk. Rejects non-24-word phrases (§4.6.2 step 2),
 * unknown words, and checksum failures. Carries no namespace — caller supplies it (§4.6.2).
 */
export function decodeRecoveryBip39(mnemonic: string): Uint8Array {
  const words = mnemonic.trim().split(/\s+/);
  if (words.length !== 24) {
    throw new FileKeyError(`unsupported recovery phrase length ${words.length} (must be 24 words)`, "bip39_word_count");
  }
  const normalized = words.join(" ");
  let entropy: Uint8Array;
  try {
    entropy = bip39.mnemonicToEntropy(normalized, wordlist); // validates words + checksum
  } catch (e) {
    throw new FileKeyError(`invalid BIP39 recovery phrase: ${(e as Error).message}`, "bip39_invalid");
  }
  if (entropy.length !== 32) {
    throw new FileKeyError(`BIP39 entropy length ${entropy.length} != 32`, "bip39_entropy_length");
  }
  return entropy;
}

// ---- Format 2: Bech32m self-describing — §4.6.3 ----

/** Encode a self-describing recovery code: rec_version || namespace_tag || master_prk. */
export function encodeRecoveryBech32m(masterPrk: Uint8Array, namespace: Namespace): string {
  if (masterPrk.length !== 32) {
    throw new FileKeyError(`master_prk must be 32 bytes, got ${masterPrk.length}`, "master_prk_length");
  }
  const payload = concat(new Uint8Array([REC_VERSION]), namespace.tag, masterPrk);
  return bech32m.encode(RECOVERY_HRP, bech32m.toWords(payload), BECH32_LIMIT);
}

export interface DecodedRecoveryBech32m {
  masterPrk: Uint8Array;
  namespace: Namespace;
}

/** Decode + validate a Bech32m recovery code against configured namespaces (§4.6.3). */
export function decodeRecoveryBech32m(code: string, namespaces: NamespaceSet): DecodedRecoveryBech32m {
  let decoded: { prefix: string; words: number[] };
  try {
    decoded = bech32m.decode(code as `${string}1${string}`, BECH32_LIMIT);
  } catch (e) {
    throw new FileKeyError(`recovery code is not valid Bech32m: ${(e as Error).message}`, "bech32m_decode");
  }
  if (decoded.prefix !== RECOVERY_HRP) {
    throw new FileKeyError(`recovery HRP "${decoded.prefix}" != "${RECOVERY_HRP}"`, "wrong_hrp");
  }
  let payload: Uint8Array;
  try {
    payload = bech32m.fromWords(decoded.words);
  } catch (e) {
    throw new FileKeyError(`recovery payload is not valid Bech32m data: ${(e as Error).message}`, "bech32m_decode");
  }
  const expected = 1 + NS_TAG_LEN + 32; // 37
  if (payload.length !== expected) {
    throw new FileKeyError(`recovery payload length ${payload.length} != ${expected}`, "payload_length");
  }
  const recVersion = payload[0]!;
  if (recVersion !== REC_VERSION) {
    throw new FileKeyError(`unsupported rec_version 0x${recVersion.toString(16)}`, "rec_version");
  }
  const tag = payload.subarray(1, 1 + NS_TAG_LEN);
  const namespace = namespaces.matchTag(tag);
  if (!namespace) {
    throw new FileKeyError(
      `recovery code is for a namespace not configured (tag 0x${toHex(tag)})`,
      "wrong_namespace",
    );
  }
  const masterPrk = payload.subarray(1 + NS_TAG_LEN).slice();
  return { masterPrk, namespace };
}

/** Detect and decode either recovery-code format. BIP39 returns no namespace. */
export function decodeRecoveryAuto(
  input: string,
  namespaces: NamespaceSet,
): { masterPrk: Uint8Array; namespace: Namespace | null } {
  const trimmed = input.trim();
  if (/^fkeyrec1/i.test(trimmed)) {
    return decodeRecoveryBech32m(trimmed, namespaces);
  }
  const wordCount = trimmed.split(/\s+/).length;
  if (wordCount >= 12) {
    return { masterPrk: decodeRecoveryBip39(trimmed), namespace: null };
  }
  throw new FileKeyError("unsupported recovery code format (expected 24-word BIP39 or fkeyrec1… Bech32m)", "unknown_recovery_format");
}
