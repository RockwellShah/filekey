// Off-main-thread encrypt / decrypt / zip (v1 dev review, point #1: keep the UI responsive during big
// operations). The whole crypto pipeline is already async-chunked and AES runs off-thread in Chrome, so
// this mainly moves the residual per-chunk JS (nonce/concat glue, the zip's CRC32, Blob assembly, GC
// churn) off the main thread for large files — small files stay on the main thread (see app.ts gating).
//
// WebAuthn/PRF MUST stay on the main thread (no `navigator.credentials` in a Worker), so this worker
// never derives identity. It receives the already-derived key material — a structured-cloned
// CryptoKeyPair (CryptoKey survives postMessage) plus the 65-byte static_pk and the canonical rpId — and
// rebuilds the Identity/Namespace here (both are class instances that do NOT survive structured clone).
// Cancellation is the client calling worker.terminate(), so there is no in-worker cancel flag.
import {
  encryptStream,
  decryptStream,
  Namespace,
  NamespaceSet,
  FileKeyError,
  type Identity,
  type Metadata,
  type ByteSource,
} from "../src/index.js";
import { zipBundleToBlob, type BundleItem } from "./bundle.js";

type EncryptJob = {
  kind: "encrypt";
  rpId: string;
  senderKeyPair: CryptoKeyPair;
  senderPk: Uint8Array;
  recipientPk: Uint8Array;
  blob: Blob;
  metadata: Omit<Metadata, "originalSize">;
};
type ZipEncryptJob = {
  kind: "zipEncrypt";
  rpId: string;
  senderKeyPair: CryptoKeyPair;
  senderPk: Uint8Array;
  recipientPk: Uint8Array;
  items: BundleItem[];
  totalBytes: number;
  metadata: Omit<Metadata, "originalSize">;
};
type DecryptJob = { kind: "decrypt"; rpId: string; rpIds: string[]; keyPair: CryptoKeyPair; staticPk: Uint8Array; file: Blob };
type Job = EncryptJob | ZipEncryptJob | DecryptJob;

// tsconfig uses the DOM lib (not WebWorker), so `self` is typed as Window; narrow to the bits we use.
const ctx = self as unknown as { onmessage: ((e: MessageEvent) => void) | null; postMessage: (m: unknown) => void };
const post = (m: unknown) => ctx.postMessage(m);
const progress = (done: number, total: number) => post({ kind: "progress", done, total });

// Read a Blob as a random-access ByteSource (same contract as app.ts's blobSource; Blob.slice works in workers).
function blobSource(blob: Blob, onRead?: (highWater: number) => void): ByteSource {
  return {
    size: blob.size,
    async slice(start: number, end: number): Promise<Uint8Array> {
      const stop = Math.min(end, blob.size);
      const u = new Uint8Array(await blob.slice(start, stop).arrayBuffer());
      onRead?.(stop);
      return u;
    },
  };
}

async function runEncrypt(job: EncryptJob | ZipEncryptJob): Promise<{ blob: Blob; shareSource?: Blob }> {
  const ns = new Namespace(job.rpId);
  const senderIdentity: Identity = { namespace: ns, keyPair: job.senderKeyPair, staticPkRaw: job.senderPk };
  let plaintext: ByteSource;
  let shareSource: Blob | undefined;
  if (job.kind === "zipEncrypt") {
    // Two phases mapped onto the byte total: zip read, then encrypt read (≈ 2x bytes), same as encryptBundle.
    let processed = 0;
    const report = () => progress(Math.round(processed / 2), job.totalBytes);
    const zipBlob = await zipBundleToBlob(job.items, (b) => { processed = b; report(); }, () => false);
    shareSource = zipBlob; // returned so Share can re-encrypt the archive without re-zipping
    plaintext = blobSource(zipBlob, (hw) => { processed = job.totalBytes + hw; report(); });
  } else {
    plaintext = blobSource(job.blob, (hw) => progress(hw, job.blob.size));
  }
  const parts: Blob[] = [];
  for await (const piece of encryptStream({ senderIdentity, recipientPkRaw: job.recipientPk, namespace: ns, plaintext, metadata: job.metadata })) {
    parts.push(new Blob([piece as unknown as BlobPart]));
  }
  return { blob: new Blob(parts, { type: "application/octet-stream" }), shareSource };
}

async function runDecrypt(job: DecryptJob): Promise<{ blob: Blob; metadata: Metadata }> {
  const identity: Identity = { namespace: new Namespace(job.rpId), keyPair: job.keyPair, staticPkRaw: job.staticPk };
  const res = await decryptStream({ file: blobSource(job.file), namespaces: new NamespaceSet(job.rpIds), resolveIdentity: async () => identity });
  const total = res.metadata.originalSize;
  const parts: Blob[] = [];
  let done = 0;
  for await (const pt of res.chunks) {
    parts.push(new Blob([pt as unknown as BlobPart])); // only assembled + returned after full authentication
    done += pt.length;
    progress(done, total);
  }
  return { blob: new Blob(parts, { type: res.metadata.mimeType || "application/octet-stream" }), metadata: res.metadata };
}

ctx.onmessage = (e: MessageEvent) => {
  const job = e.data as Job;
  void (async () => {
    try {
      if (job.kind === "decrypt") {
        const { blob, metadata } = await runDecrypt(job);
        post({ kind: "done", blob, metadata });
      } else {
        const { blob, shareSource } = await runEncrypt(job);
        post({ kind: "done", blob, shareSource });
      }
    } catch (err) {
      // Serialize the code (empty for non-FileKeyError, e.g. a storage-quota failure) so the client can
      // rebuild a real FileKeyError vs a plain Error — the catches discriminate on `instanceof FileKeyError`.
      const code = err instanceof FileKeyError ? err.code : "";
      post({ kind: "error", code, message: (err as Error)?.message ?? "worker error" });
    }
  })();
};
