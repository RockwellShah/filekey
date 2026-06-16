// FileKey v0.4.7 reference implementation — public API.
//
// Layering:
//   - PRF-agnostic core: takes prf_secret (or master_prk) as input. Fully testable headless.
//   - WebAuthn PRF provider (web/) supplies prf_secret in a browser.
//
// This module re-exports the core and adds ergonomic share-key wrappers.

export * from "./bytes.js";
export * from "./constants.js";
export * from "./namespace.js";
export * from "./identity.js";
export * from "./sharekey.js";
export * from "./recovery.js";
export * from "./metadata.js";
export * from "./wire.js";
// cipher.ts: re-export the public surface explicitly so the test-only deterministic-ephemeral
// entry point (encryptWithEphemeralForTest) stays unreachable through the public API.
export { validateUncompressedPk, encrypt, decrypt, encryptStream, decryptStream, selfEncrypt, selfEncryptStream } from "./cipher.js";
export type {
  EncryptInput,
  DecryptInput,
  DecryptResult,
  EncryptStreamInput,
  DecryptStreamInput,
  DecryptStreamResult,
  SelfEncryptInput,
  SelfEncryptStreamInput,
} from "./cipher.js";

import { Identity } from "./identity.js";
import { Metadata } from "./metadata.js";
import { NamespaceSet, FileKeyError } from "./namespace.js";
import { decodeShareKey } from "./sharekey.js";
import { encrypt, selfEncrypt } from "./cipher.js";

export interface EncryptToShareKeyInput {
  senderIdentity: Identity;
  recipientShareKey: string;
  namespaces: NamespaceSet;
  plaintext: Uint8Array;
  metadata: Omit<Metadata, "originalSize">;
}

/** Encrypt to a recipient identified by their share key (the file's namespace comes from the share key). */
export async function encryptToShareKey(input: EncryptToShareKeyInput): Promise<Uint8Array> {
  const { recipientPkRaw, namespace } = decodeShareKey(input.recipientShareKey, input.namespaces);
  return encrypt({
    senderIdentity: input.senderIdentity,
    recipientPkRaw,
    namespace,
    plaintext: input.plaintext,
    metadata: input.metadata,
  });
}

export interface EncryptToSelfInput {
  identity: Identity;
  plaintext: Uint8Array;
  metadata: Omit<Metadata, "originalSize">;
}

/**
 * Self-encrypt (local protection). Uses suite 0x02 (symmetric, no KEM): file keys are derived straight
 * from the identity's master_prk, so the file carries no public key and is post-quantum-safe (only
 * AES-256 remains, which Grover cannot meaningfully dent). Existing suite 0x01 self-encrypted files
 * still decrypt unchanged — {@link decrypt} dispatches on the header's suite byte.
 */
export async function encryptToSelf(input: EncryptToSelfInput): Promise<Uint8Array> {
  const masterPrk = input.identity.masterPrk;
  if (!masterPrk) {
    throw new FileKeyError("identity is missing master_prk required for self-encryption", "master_prk_missing");
  }
  return selfEncrypt({
    masterPrk,
    namespace: input.identity.namespace,
    plaintext: input.plaintext,
    metadata: input.metadata,
  });
}
