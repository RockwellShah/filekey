import { describe, test, expect } from "bun:test";
import { unzipSync } from "fflate";
import {
  Namespace,
  NamespaceSet,
  deriveIdentityFromPrf,
  encryptToSelf,
  encryptStream,
  decrypt,
  bytesSource,
  type Identity,
  type Metadata,
} from "../src/index.js";
import { zipBundleToBlob, type BundleItem } from "../web/bundle.js";

const NS = new Namespace("filekey.app");
const SET = new NamespaceSet(["filekey.app"]);
const meta: Omit<Metadata, "originalSize"> = { filename: "F.zip", mimeType: "application/zip", createdAtUnixMs: 1_700_000_000_000, extras: new Map() };

function items(): BundleItem[] {
  const big = new Uint8Array(300_000);
  for (let i = 0; i < big.length; i += 65536) crypto.getRandomValues(big.subarray(i, Math.min(i + 65536, big.length)));
  return [
    { path: "F/a.txt", file: new File([new Uint8Array([1, 2, 3, 4, 5])], "a.txt"), fromFolder: true },
    { path: "F/sub/b.bin", file: new File([big as unknown as BlobPart], "b.bin"), fromFolder: true },
    { path: "F/empty/", file: new File([], "empty"), fromFolder: true },
  ];
}
const entriesOf = (u: Uint8Array) => Object.keys(unzipSync(u)).sort();

async function collectGen(gen: AsyncGenerator<Uint8Array>): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  for await (const p of gen) parts.push(p);
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

describe("streaming zip bundle (web/bundle.ts)", () => {
  // Verify the streamed zip directly (don't call zipBundle here: its level-6 deflate runs in a Worker that
  // the bun test runtime can't host for larger entries — a test-env quirk, not a browser/app problem).
  test("zipBundleToBlob yields a valid zip with the expected entries + byte-exact contents", async () => {
    const its = items();
    const streamed = new Uint8Array(await (await zipBundleToBlob(its)).arrayBuffer());
    const names = entriesOf(streamed);
    expect(names).toContain("F/a.txt");
    expect(names).toContain("F/sub/b.bin");
    expect(names).toContain("F/empty/"); // preserved empty directory
    const u = unzipSync(streamed);
    expect(Array.from(u["F/a.txt"]!)).toEqual([1, 2, 3, 4, 5]);
    const original = new Uint8Array(await its[1]!.file.arrayBuffer());
    expect(Array.from(u["F/sub/b.bin"]!)).toEqual(Array.from(original)); // 300KB survives store round-trip byte-for-byte
  });

  test("zipBundleToBlob reports cumulative progress over every source byte", async () => {
    const its = items();
    let last = 0;
    await zipBundleToBlob(its, (b) => { last = b; });
    expect(last).toBe(its.reduce((n, it) => n + it.file.size, 0));
  });

  test("streamed bundle encrypts + decrypts back to the same archive (the large-folder path)", async () => {
    const id: Identity = await deriveIdentityFromPrf(new Uint8Array(32).fill(0x66), NS);
    const its = items();
    const zipBlob = await zipBundleToBlob(its);
    const file = await collectGen(
      encryptStream({ senderIdentity: id, recipientPkRaw: id.staticPkRaw, namespace: id.namespace, plaintext: bytesSource(new Uint8Array(await zipBlob.arrayBuffer())), metadata: meta }),
    );
    const res = await decrypt({ file, namespaces: SET, resolveIdentity: async () => id });
    expect(entriesOf(res.plaintext)).toEqual(entriesOf(new Uint8Array(await zipBlob.arrayBuffer())));
  });
});
