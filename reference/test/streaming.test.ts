import { describe, test, expect } from "bun:test";
import {
  Namespace,
  NamespaceSet,
  FileKeyError,
  deriveIdentityFromPrf,
  encrypt,
  decrypt,
  encryptStream,
  decryptStream,
  encryptToSelf,
  bytesSource,
  type ByteSource,
  type Identity,
  type Metadata,
} from "../src/index.js";

const RP = "filekey.app";
const NS = new Namespace(RP);
const SET = new NamespaceSet([RP]);

const prf = (fill: number) => new Uint8Array(32).fill(fill);
const identity = (fill: number, ns = NS): Promise<Identity> => deriveIdentityFromPrf(prf(fill), ns);
const meta = (over: Partial<Omit<Metadata, "originalSize">> = {}): Omit<Metadata, "originalSize"> => ({
  filename: "report.pdf",
  mimeType: "application/pdf",
  createdAtUnixMs: 1_700_000_000_000,
  extras: new Map(),
  ...over,
});
const resolveTo = (id: Identity) => async () => id;
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

/** getRandomValues caps at 65536 bytes per call in spec-strict runtimes; fill in blocks. */
function randomBytes(n: number): Uint8Array {
  const a = new Uint8Array(n);
  for (let o = 0; o < n; o += 65536) crypto.getRandomValues(a.subarray(o, Math.min(o + 65536, n)));
  return a;
}

async function collectGen(gen: AsyncGenerator<Uint8Array>): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  for await (const p of gen) parts.push(p);
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** A Blob-backed ByteSource — exactly the shape the web layer feeds the core. */
function blobSource(buf: Uint8Array): ByteSource {
  const blob = new Blob([buf as unknown as BlobPart]);
  return {
    size: blob.size,
    async slice(start: number, end: number): Promise<Uint8Array> {
      return new Uint8Array(await blob.slice(start, Math.min(end, blob.size)).arrayBuffer());
    },
  };
}

describe("streaming ↔ buffered equivalence (§7.4)", () => {
  test("decryptStream yields the same plaintext as buffered decrypt + surfaces metadata", async () => {
    const id = await identity(0x66);
    const pt = randomBytes(200_000); // ~4 chunks
    const file = await encryptToSelf({ identity: id, plaintext: pt, metadata: meta() });

    const buffered = await decrypt({ file, namespaces: SET, resolveIdentity: resolveTo(id) });
    const res = await decryptStream({ file: bytesSource(file), namespaces: SET, resolveIdentity: resolveTo(id) });
    const streamed = await collectGen(res.chunks);

    expect(hex(streamed)).toBe(hex(buffered.plaintext));
    expect(hex(streamed)).toBe(hex(pt));
    expect(res.selfEncrypted).toBe(true);
    expect(res.metadata.originalSize).toBe(200_000);
    expect(res.metadata.filename).toBe("report.pdf");
    expect(hex(res.senderPkRaw)).toBe(hex(id.staticPkRaw));
  });

  test("encryptStream output decrypts via both buffered and streaming paths", async () => {
    const id = await identity(0x66);
    const pt = randomBytes(130_000); // crosses a chunk boundary
    const file = await collectGen(
      encryptStream({ senderIdentity: id, recipientPkRaw: id.staticPkRaw, namespace: id.namespace, plaintext: bytesSource(pt), metadata: meta() }),
    );
    const a = await decrypt({ file, namespaces: SET, resolveIdentity: resolveTo(id) });
    expect(hex(a.plaintext)).toBe(hex(pt));
    const res = await decryptStream({ file: bytesSource(file), namespaces: SET, resolveIdentity: resolveTo(id) });
    expect(hex(await collectGen(res.chunks))).toBe(hex(pt));
  });

  // Chunk-boundary coverage mirrors the buffered suite to prove identical chunking.
  const sizes = [0, 1, 100, 65535, 65536, 65537, 200_000];
  for (const size of sizes) {
    test(`streaming self round trip, ${size} bytes`, async () => {
      const id = await identity(0x66);
      const pt = randomBytes(size);
      const file = await collectGen(
        encryptStream({ senderIdentity: id, recipientPkRaw: id.staticPkRaw, namespace: id.namespace, plaintext: bytesSource(pt), metadata: meta() }),
      );
      const res = await decryptStream({ file: bytesSource(file), namespaces: SET, resolveIdentity: resolveTo(id) });
      const out = await collectGen(res.chunks);
      expect(out.length).toBe(size);
      expect(hex(out)).toBe(hex(pt));
      expect(res.metadata.originalSize).toBe(size);
    });
  }
});

describe("streaming over a Blob-backed ByteSource (the web path)", () => {
  test("encryptStream reads plaintext from a Blob; decryptStream reads the file from a Blob", async () => {
    const id = await identity(0x66);
    const pt = randomBytes(200_000);
    const file = await collectGen(
      encryptStream({ senderIdentity: id, recipientPkRaw: id.staticPkRaw, namespace: id.namespace, plaintext: blobSource(pt), metadata: meta() }),
    );
    const res = await decryptStream({ file: blobSource(file), namespaces: SET, resolveIdentity: resolveTo(id) });
    expect(hex(await collectGen(res.chunks))).toBe(hex(pt));
  });

  test("shared encrypt streamed both ways: Alice → Bob", async () => {
    const alice = await identity(0xa1);
    const bob = await identity(0xb0);
    const pt = randomBytes(180_000);
    const file = await collectGen(
      encryptStream({ senderIdentity: alice, recipientPkRaw: bob.staticPkRaw, namespace: NS, plaintext: bytesSource(pt), metadata: meta({ filename: "v.bin" }) }),
    );
    const res = await decryptStream({ file: blobSource(file), namespaces: SET, resolveIdentity: resolveTo(bob) });
    expect(hex(await collectGen(res.chunks))).toBe(hex(pt));
    expect(res.selfEncrypted).toBe(false);
    expect(hex(res.senderPkRaw)).toBe(hex(alice.staticPkRaw));
    expect(res.metadata.filename).toBe("v.bin");
  });
});

describe("streaming decrypt preserves Policy A (throws before completing)", () => {
  async function selfFile(): Promise<{ id: Identity; file: Uint8Array }> {
    const id = await identity(0x88);
    const file = await encryptToSelf({ identity: id, plaintext: randomBytes(150_000), metadata: meta() });
    return { id, file };
  }

  test("generator throws on payload tamper", async () => {
    const { id, file } = await selfFile();
    const tampered = file.slice();
    tampered[tampered.length - 100]! ^= 0x01;
    const res = await decryptStream({ file: bytesSource(tampered), namespaces: SET, resolveIdentity: resolveTo(id) });
    await expect(collectGen(res.chunks)).rejects.toThrow(FileKeyError);
  });

  test("generator throws on truncation (dropped last chunk)", async () => {
    const { id, file } = await selfFile();
    const truncated = bytesSource(file.subarray(0, file.length - (65536 + 16)));
    const res = await decryptStream({ file: truncated, namespaces: SET, resolveIdentity: resolveTo(id) });
    await expect(collectGen(res.chunks)).rejects.toThrow(FileKeyError);
  });

  test("generator throws on appended trailing bytes", async () => {
    const { id, file } = await selfFile();
    const extended = new Uint8Array(file.length + 10);
    extended.set(file);
    const res = await decryptStream({ file: bytesSource(extended), namespaces: SET, resolveIdentity: resolveTo(id) });
    await expect(collectGen(res.chunks)).rejects.toThrow(FileKeyError);
  });

  test("a malformed header rejects before the chunks generator is created", async () => {
    const { id, file } = await selfFile();
    const tampered = file.slice();
    tampered[8]! ^= 0xff; // namespace tag → no matching namespace
    await expect(decryptStream({ file: bytesSource(tampered), namespaces: SET, resolveIdentity: resolveTo(id) })).rejects.toThrow(
      /wrong_namespace|namespace/,
    );
  });
});

describe("streaming hardens against misbehaving ByteSources (codex review)", () => {
  test("encryptStream rejects a plaintext source that under-reads (source_short_read)", async () => {
    const id = await identity(0x66);
    const real = randomBytes(200_000);
    let first = true;
    const lying: ByteSource = {
      size: real.length,
      async slice(s, e) {
        const stop = Math.min(e, real.length);
        if (first) {
          first = false;
          return real.subarray(s, stop - 1); // one byte short on a chunk
        }
        return real.subarray(s, stop);
      },
    };
    const err = await collectGen(
      encryptStream({ senderIdentity: id, recipientPkRaw: id.staticPkRaw, namespace: id.namespace, plaintext: lying, metadata: meta() }),
    ).then(() => null, (e) => e);
    expect(err).toBeInstanceOf(FileKeyError);
    expect((err as FileKeyError).code).toBe("source_short_read");
  });

  test("decryptStream rejects a file source that under-reads a payload chunk (truncated)", async () => {
    const id = await identity(0x66);
    const file = await encryptToSelf({ identity: id, plaintext: randomBytes(200_000), metadata: meta() });
    let firstBig = true;
    const lying: ByteSource = {
      size: file.length,
      async slice(s, e) {
        const stop = Math.min(e, file.length);
        if (e - s > 60_000 && firstBig) {
          firstBig = false;
          return file.subarray(s, stop - 1); // short a full payload chunk read
        }
        return file.subarray(s, stop);
      },
    };
    const res = await decryptStream({ file: lying, namespaces: SET, resolveIdentity: resolveTo(id) });
    await expect(collectGen(res.chunks)).rejects.toThrow(FileKeyError);
  });
});

describe("streaming supports early termination (the cancel path)", () => {
  test("abandoning the decrypt chunks generator early does not throw", async () => {
    const id = await identity(0x66);
    const file = await encryptToSelf({ identity: id, plaintext: randomBytes(200_000), metadata: meta() }); // ~4 chunks
    const res = await decryptStream({ file: bytesSource(file), namespaces: SET, resolveIdentity: resolveTo(id) });
    let count = 0;
    for await (const piece of res.chunks) {
      expect(piece).toBeInstanceOf(Uint8Array);
      count++;
      if (count === 1) break; // simulate Cancel after the first chunk
    }
    expect(count).toBe(1); // broke cleanly — the generator's return() ran without throwing
  });

  test("abandoning the encrypt generator early does not throw", async () => {
    const id = await identity(0x66);
    let count = 0;
    for await (const piece of encryptStream({ senderIdentity: id, recipientPkRaw: id.staticPkRaw, namespace: id.namespace, plaintext: bytesSource(randomBytes(200_000)), metadata: meta() })) {
      expect(piece).toBeInstanceOf(Uint8Array);
      count++;
      if (count === 2) break; // head + first chunk, then bail
    }
    expect(count).toBe(2);
  });
});
