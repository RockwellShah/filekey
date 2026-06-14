// FileKey reference — local contacts (address book).
//
// A device-local list of recipients you've shared with: their PUBLIC share key
// plus an optional nickname you choose. This is explicitly allowed by the
// "no secrets stored" rule — share keys are public, and a nickname is your own
// local label (never sender-controlled, never written into any file).
//
// Stored ENCRYPTED-TO-SELF (reusing the core's encryptToSelf/decrypt) in
// localStorage, so the address book — a social-graph footprint — isn't readable
// at rest without the passkey, and is naturally scoped per identity. Loaded into
// memory on unlock. No DOM here; app.ts owns all rendering.
import {
  encryptToSelf,
  decrypt,
  type Identity,
  type NamespaceSet,
} from "../src/index.js";

export interface Contact {
  /** The recipient's share key (fkey1…). The unique id we dedupe on. */
  key: string;
  /** Your local display label. Optional; never leaves the device. */
  nickname?: string;
  /** Epoch ms, last time you shared to this key (drives recent-first order). */
  lastUsed: number;
  /** Epoch ms, when this contact was first saved. */
  addedAt: number;
}

export type NicknameResult = { ok: true } | { ok: false; conflict: Contact };

let contacts: Contact[] = [];
let ident: Identity | null = null;
let storageKey = "";

const td = new TextDecoder();
const te = new TextEncoder();
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

function b64encode(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s);
}
function b64decode(str: string): Uint8Array {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Load + decrypt the address book for this identity. Call once on unlock. */
export async function loadContacts(identity: Identity, namespaces: NamespaceSet): Promise<void> {
  ident = identity;
  contacts = [];
  // Per-identity storage key from the (public) static key, so different passkeys
  // never read or clobber each other's books.
  storageKey = "filekey.contacts." + hex(identity.staticPkRaw.subarray(1, 17));
  let raw: string | null = null;
  try { raw = localStorage.getItem(storageKey); } catch { return; } // storage blocked → session-only
  if (!raw) return;
  try {
    const res = await decrypt({ file: b64decode(raw), namespaces, resolveIdentity: async () => identity });
    const parsed = JSON.parse(td.decode(res.plaintext)) as unknown;
    if (Array.isArray(parsed)) {
      contacts = parsed
        .filter((c): c is Contact => !!c && typeof (c as Contact).key === "string")
        .map((c) => ({
          key: c.key,
          nickname: c.nickname?.trim() || undefined,
          lastUsed: typeof c.lastUsed === "number" ? c.lastUsed : 0,
          addedAt: typeof c.addedAt === "number" ? c.addedAt : 0,
        }));
    }
  } catch {
    // The stored blob exists but didn't decrypt/parse (corruption, or — astronomically unlikely — a
    // different passkey colliding on the 16-byte storage-key prefix). Don't silently discard it: the next
    // persist() would overwrite it for good. Stash the original once under a .bak key so it stays
    // recoverable, then start clean in memory.
    try {
      if (raw && !localStorage.getItem(storageKey + ".bak")) localStorage.setItem(storageKey + ".bak", raw);
    } catch { /* storage full/blocked → nothing more we can do */ }
    contacts = [];
  }
}

async function persist(): Promise<void> {
  if (!ident || !storageKey) return;
  try {
    const env = await encryptToSelf({
      identity: ident,
      plaintext: te.encode(JSON.stringify(contacts)),
      metadata: { filename: "filekey-contacts.json", mimeType: "application/json", createdAtUnixMs: Date.now(), extras: new Map() },
    });
    localStorage.setItem(storageKey, b64encode(env));
  } catch { /* storage unavailable → stays session-only */ }
}

/** Contacts, most-recently-used first (then alphabetical). */
export function listContacts(): Contact[] {
  return [...contacts].sort(
    (a, b) => b.lastUsed - a.lastUsed || (a.nickname || a.key).localeCompare(b.nickname || b.key),
  );
}
export function contactCount(): number { return contacts.length; }
export function findByKey(key: string): Contact | undefined { return contacts.find((c) => c.key === key); }

/** Record that we just shared to `key` (upsert + bump lastUsed). Reports whether it was newly added. */
export async function rememberUse(key: string): Promise<{ contact: Contact; isNew: boolean }> {
  const now = Date.now();
  let c = contacts.find((x) => x.key === key);
  const isNew = !c;
  if (c) c.lastUsed = now;
  else { c = { key, lastUsed: now, addedAt: now }; contacts.push(c); }
  await persist();
  return { contact: c, isNew };
}

export type AddResult = { ok: true; contact: Contact } | { ok: false; reason: "duplicate_key" | "duplicate_nickname"; conflict: Contact };
/** Manually add a contact (a share key + optional nickname). Rejects a duplicate key or nickname. */
export async function addContact(key: string, nickname?: string): Promise<AddResult> {
  const dupKey = contacts.find((c) => c.key === key);
  if (dupKey) return { ok: false, reason: "duplicate_key", conflict: dupKey };
  const n = nickname?.trim();
  if (n) {
    const dupNick = contacts.find((c) => c.nickname?.toLowerCase() === n.toLowerCase());
    if (dupNick) return { ok: false, reason: "duplicate_nickname", conflict: dupNick };
  }
  const now = Date.now();
  const contact: Contact = n ? { key, nickname: n, lastUsed: now, addedAt: now } : { key, lastUsed: now, addedAt: now };
  contacts.push(contact);
  await persist();
  return { ok: true, contact };
}

/** Set or clear a contact's nickname. Rejects (no change) if another contact already uses it. */
export async function setNickname(key: string, nickname: string): Promise<NicknameResult> {
  const c = contacts.find((x) => x.key === key);
  if (!c) return { ok: true };
  const n = nickname.trim();
  if (n) {
    const clash = contacts.find((x) => x.key !== key && x.nickname?.toLowerCase() === n.toLowerCase());
    if (clash) return { ok: false, conflict: clash };
    c.nickname = n;
  } else {
    delete c.nickname;
  }
  await persist();
  return { ok: true };
}

export async function removeContact(key: string): Promise<void> {
  contacts = contacts.filter((c) => c.key !== key);
  await persist();
}

export async function clearContacts(): Promise<void> {
  contacts = [];
  try { if (storageKey) localStorage.removeItem(storageKey); } catch { /* ignore */ }
}

// ---- import / export (plain JSON) ----
// Share keys are PUBLIC, so a plain-JSON export carries no secrets — and unlike an encrypted-to-self
// export, it can be imported into a different identity (a new passkey on another device). The file does
// reveal your contact list (names + their keys), so it's your data to guard, not a secret of the protocol.

export interface ImportResult {
  /** Newly saved contacts. */ added: number;
  /** Entries whose key was already in the book (left untouched). */ skipped: number;
  /** Entries with a missing/malformed/wrong-namespace share key. */ rejected: number;
}

/** Serialize the address book to a portable JSON string: {filekey_contacts, contacts:[{key, nickname?}]}. */
export function exportContactsJson(): string {
  const out = listContacts().map((c) => (c.nickname ? { key: c.key, nickname: c.nickname } : { key: c.key }));
  return JSON.stringify({ filekey_contacts: 1, contacts: out }, null, 2);
}

/**
 * Merge contacts from an exported JSON string. `isValidKey` is the caller's namespace-aware share-key
 * check, so this module stays decode-agnostic. Dedupes against existing keys; a nickname collision saves
 * the key without the clashing label. Returns counts. Throws only if the file isn't a recognizable export.
 */
export async function importContactsJson(json: string, isValidKey: (key: string) => boolean): Promise<ImportResult> {
  let data: unknown;
  try { data = JSON.parse(json); } catch { throw new Error("not valid JSON"); }
  const arr: unknown[] | null = Array.isArray(data)
    ? data
    : data && typeof data === "object" && Array.isArray((data as { contacts?: unknown }).contacts)
      ? (data as { contacts: unknown[] }).contacts
      : null;
  if (!arr) throw new Error("not a FileKey contacts export");

  let added = 0, skipped = 0, rejected = 0;
  for (const raw of arr) {
    const e = (raw ?? {}) as { key?: unknown; shareKey?: unknown; nickname?: unknown };
    const key = typeof e.key === "string" ? e.key : typeof e.shareKey === "string" ? e.shareKey : null;
    if (!key || !isValidKey(key)) { rejected++; continue; }
    const nickname = typeof e.nickname === "string" ? e.nickname : undefined;
    let res = await addContact(key, nickname);
    if (!res.ok && res.reason === "duplicate_nickname") res = await addContact(key); // save the key, drop the clashing label
    if (res.ok) added++;
    else skipped++; // remaining failure is duplicate_key
  }
  return { added, skipped, rejected };
}
