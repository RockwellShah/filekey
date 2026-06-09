// Canonical RP-ID validation and namespace tags (spec §4.4, §8.5).
import { sha256 } from "@noble/hashes/sha2.js";
import { ascii, equalCT, toHex } from "./bytes.js";
import { NS_TAG_LEN } from "./constants.js";
import { FileKeyError } from "./errors.js";
export { FileKeyError };

const LABEL_RE = /^[a-z0-9-]{1,63}$/;

/**
 * Validate a canonical RP-ID against the normative §8.5 rules:
 * 1–253 bytes, only [a-z0-9.-], no trailing dot, each label 1–63 bytes,
 * no leading/trailing hyphen, and the reserved `xx--` prefix only when it is a
 * valid `xn--` Punycode A-label. (We accept `xn--` labels syntactically; full
 * Punycode decode verification is left to input canonicalization, §8.5.)
 * Returns the canonical bytes; throws FileKeyError on violation.
 */
export function validateCanonicalRpId(rpId: string): Uint8Array {
  const bytes = ascii(rpId);
  if (bytes.length < 1 || bytes.length > 253) {
    throw new FileKeyError(`canonical RP-ID length ${bytes.length} not in 1..253`, "rpid_length");
  }
  if (/[^a-z0-9.-]/.test(rpId)) {
    throw new FileKeyError("canonical RP-ID contains bytes outside [a-z0-9.-]", "rpid_charset");
  }
  if (rpId.endsWith(".")) {
    throw new FileKeyError("canonical RP-ID has a trailing dot", "rpid_trailing_dot");
  }
  const labels = rpId.split(".");
  for (const label of labels) {
    if (!LABEL_RE.test(label)) {
      throw new FileKeyError(`invalid label "${label}" (1–63 [a-z0-9-])`, "rpid_label");
    }
    if (label.startsWith("-") || label.endsWith("-")) {
      throw new FileKeyError(`label "${label}" starts/ends with hyphen`, "rpid_label_hyphen");
    }
    // Reserved xx-- prefix (hyphens in positions 3 AND 4): allowed only as xn-- A-labels.
    if (label.length >= 4 && label[2] === "-" && label[3] === "-") {
      if (!label.startsWith("xn--")) {
        throw new FileKeyError(`label "${label}" uses reserved xx-- prefix but is not xn--`, "rpid_reserved_prefix");
      }
    }
  }
  return bytes;
}

/** namespace_tag = first 4 bytes of SHA-256(canonical_rp_id) (§4.4). */
export function namespaceTag(canonicalRpId: string): Uint8Array {
  const bytes = validateCanonicalRpId(canonicalRpId);
  return sha256(bytes).subarray(0, NS_TAG_LEN);
}

/** A configured interop namespace: its canonical RP-ID and derived 4-byte tag. */
export class Namespace {
  readonly canonicalRpId: string;
  readonly rpIdBytes: Uint8Array;
  readonly tag: Uint8Array;

  constructor(canonicalRpId: string) {
    this.rpIdBytes = validateCanonicalRpId(canonicalRpId);
    this.canonicalRpId = canonicalRpId;
    this.tag = sha256(this.rpIdBytes).subarray(0, NS_TAG_LEN);
  }

  tagEquals(tag: Uint8Array): boolean {
    return equalCT(this.tag, tag);
  }
}

/**
 * A set of configured namespaces (single- or multi-namespace clients, §4.5).
 * Enforces the §4.4 rule 5(a) collision-rejection invariant.
 */
export class NamespaceSet {
  private readonly byTagHex = new Map<string, Namespace>();
  readonly namespaces: Namespace[] = [];

  constructor(canonicalRpIds: string[]) {
    for (const id of canonicalRpIds) this.add(id);
  }

  add(canonicalRpId: string): Namespace {
    const ns = new Namespace(canonicalRpId);
    const tagHex = toHex(ns.tag);
    const existing = this.byTagHex.get(tagHex);
    if (existing && existing.canonicalRpId !== ns.canonicalRpId) {
      throw new FileKeyError(
        `namespace tag collision: "${ns.canonicalRpId}" and "${existing.canonicalRpId}" share tag ${tagHex}`,
        "namespace_tag_collision",
      );
    }
    if (!existing) {
      this.byTagHex.set(tagHex, ns);
      this.namespaces.push(ns);
    }
    return ns;
  }

  /** Dispatch by the 4-byte file-header tag (§7.2 step 2). Null = no match. */
  matchTag(tag: Uint8Array): Namespace | null {
    return this.byTagHex.get(toHex(tag)) ?? null;
  }

  byRpId(canonicalRpId: string): Namespace | null {
    for (const ns of this.namespaces) if (ns.canonicalRpId === canonicalRpId) return ns;
    return null;
  }
}
