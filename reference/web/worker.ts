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
  selfEncryptStream,
  decryptStream,
  Namespace,
  NamespaceSet,
  FileKeyError,
  type Identity,
  type Metadata,
  type ByteSource,
} from "../src/index.js";
import { zipBundleToBlob, type BundleItem } from "./bundle.js";

// `selfEncrypt: true` is the EXPLICIT self-encryption intent → the worker uses suite 0x02 (symmetric, no
// KEM, post-quantum-safe) with `senderMasterPrk` and REQUIRES it (a self job missing master_prk is a loud
// error, never a silent regression to suite 0x01). Without `selfEncrypt`, the recipient is someone else →
// HPKE suite 0x01 (sharing). master_prk is the session root; passing it into this same-origin, same-bundle
// worker is consistent with the worker already receiving `senderKeyPair` (the identity private key).
// master_prk is strictly more powerful in general (it is the root that derives that keypair), but in this
// single-namespace v1 app it compromises the same one identity, and there is no page↔worker trust boundary.
type EncryptJob = {
  kind: "encrypt";
  rpId: string;
  senderKeyPair: CryptoKeyPair;
  senderPk: Uint8Array;
  recipientPk: Uint8Array;
  blob: Blob;
  metadata: Omit<Metadata, "originalSize">;
  selfEncrypt?: boolean;
  senderMasterPrk?: Uint8Array;
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
  selfEncrypt?: boolean;
  senderMasterPrk?: Uint8Array;
};
// `masterPrk` lets the worker decrypt suite 0x02 self files (it derives the file keys from the file's
// salt). Absent it, only suite 0x01 (HPKE, via keyPair) decrypts. Same trust rationale as above.
type DecryptJob = { kind: "decrypt"; rpId: string; rpIds: string[]; keyPair: CryptoKeyPair; staticPk: Uint8Array; file: Blob; masterPrk?: Uint8Array };
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
  // Explicit `selfEncrypt` intent → suite 0x02 (no KEM, post-quantum-safe). The master_prk guard turns a
  // future refactor that forgets to pass it into a LOUD failure rather than a silent regression to suite
  // 0x01. Otherwise the recipient is someone else → HPKE suite 0x01 (sharing). Both reuse the src/ core.
  let stream: AsyncGenerator<Uint8Array>;
  if (job.selfEncrypt) {
    if (!job.senderMasterPrk) throw new FileKeyError("self-encryption requires master_prk (suite 0x02)", "master_prk_missing");
    stream = selfEncryptStream({ masterPrk: job.senderMasterPrk, namespace: ns, plaintext, metadata: job.metadata });
  } else {
    stream = encryptStream({
      senderIdentity: { namespace: ns, keyPair: job.senderKeyPair, staticPkRaw: job.senderPk },
      recipientPkRaw: job.recipientPk,
      namespace: ns,
      plaintext,
      metadata: job.metadata,
    });
  }
  const parts: Blob[] = [];
  for await (const piece of stream) parts.push(new Blob([piece as unknown as BlobPart]));
  return { blob: new Blob(parts, { type: "application/octet-stream" }), shareSource };
}

async function runDecrypt(job: DecryptJob): Promise<{ blob: Blob; metadata: Metadata }> {
  // master_prk is included so suite 0x02 self files decrypt (decryptSelfStream derives the file keys from
  // it); suite 0x01 ignores it and uses keyPair. Absent (older callers) → only 0x01 decrypts.
  const identity: Identity = { namespace: new Namespace(job.rpId), keyPair: job.keyPair, staticPkRaw: job.staticPk, masterPrk: job.masterPrk };
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
