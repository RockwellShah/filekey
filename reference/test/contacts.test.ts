import { describe, test, expect } from "bun:test";
import { Namespace, NamespaceSet, deriveIdentityFromPrf, encodeShareKey, decodeShareKey } from "../src/index.js";
import * as Contacts from "../web/contacts.js";

const NS = new Namespace("filekey.app");
const SET = new NamespaceSet(["filekey.app"]);
const prf = (f: number) => new Uint8Array(32).fill(f);
const isValidKey = (k: string) => {
  try { decodeShareKey(k, SET); return true; } catch { return false; }
};
const shareKey = async (fill: number) => encodeShareKey((await deriveIdentityFromPrf(prf(fill), NS)).staticPkRaw, NS);

describe("contacts import/export (web/contacts.ts)", () => {
  test("export → clear → import round-trips, dedupes, and rejects invalid keys", async () => {
    await Contacts.loadContacts(await deriveIdentityFromPrf(prf(0x10), NS), SET);
    await Contacts.clearContacts();

    const keyA = await shareKey(0xa1);
    const keyB = await shareKey(0xb2);
    expect((await Contacts.addContact(keyA, "Alice")).ok).toBe(true);
    expect((await Contacts.addContact(keyB, "Bob")).ok).toBe(true);

    const json = Contacts.exportContactsJson();
    const parsed = JSON.parse(json) as { filekey_contacts: number; contacts: { key: string }[] };
    expect(parsed.filekey_contacts).toBe(1);
    expect(parsed.contacts.map((c) => c.key).sort()).toEqual([keyA, keyB].sort());

    await Contacts.clearContacts();
    expect(Contacts.contactCount()).toBe(0);

    const r1 = await Contacts.importContactsJson(json, isValidKey);
    expect(r1).toEqual({ added: 2, skipped: 0, rejected: 0 });
    expect(Contacts.findByKey(keyA)?.nickname).toBe("Alice");

    // re-import the same file → everything is a duplicate, nothing changes
    expect(await Contacts.importContactsJson(json, isValidKey)).toEqual({ added: 0, skipped: 2, rejected: 0 });

    // one bogus key + one valid → 1 added, 1 rejected
    const mixed = JSON.stringify({ contacts: [{ key: "not-a-key" }, { key: await shareKey(0xc3), nickname: "Carol" }] });
    expect(await Contacts.importContactsJson(mixed, isValidKey)).toEqual({ added: 1, skipped: 0, rejected: 1 });

    // bare-array form is accepted too
    const bare = JSON.stringify([{ key: await shareKey(0xd4), nickname: "Dave" }]);
    expect(await Contacts.importContactsJson(bare, isValidKey)).toEqual({ added: 1, skipped: 0, rejected: 0 });
    expect(Contacts.contactCount()).toBe(4);

    // unrecognizable files throw
    await expect(Contacts.importContactsJson("not json", isValidKey)).rejects.toThrow();
    await expect(Contacts.importContactsJson(JSON.stringify({ foo: 1 }), isValidKey)).rejects.toThrow();

    await Contacts.clearContacts();
  });

  test("a nickname collision saves the key without the clashing label", async () => {
    await Contacts.loadContacts(await deriveIdentityFromPrf(prf(0x11), NS), SET);
    await Contacts.clearContacts();
    const keyA = await shareKey(0xaa);
    const keyB = await shareKey(0xbb);
    await Contacts.addContact(keyA, "Sam");
    const r = await Contacts.importContactsJson(JSON.stringify({ contacts: [{ key: keyB, nickname: "Sam" }] }), isValidKey);
    expect(r).toEqual({ added: 1, skipped: 0, rejected: 0 });
    expect(Contacts.findByKey(keyB)?.nickname).toBeUndefined(); // saved, but the duplicate label was dropped
    await Contacts.clearContacts();
  });
});
