// Byte utilities. All multi-byte integers are big-endian (spec §1.3).
import { FileKeyError } from "./errors.js";

export const te = new TextEncoder();
export const td = new TextDecoder("utf-8", { fatal: true }); // fatal: reject invalid UTF-8

// WebCrypto's BufferSource type wants an ArrayBuffer-backed view; our Uint8Arrays are
// always plain (never SharedArrayBuffer). This cast bridges the TS 5.7+ generic without copying.
export function bs(u: Uint8Array): BufferSource {
  return u as unknown as BufferSource;
}

export function ascii(s: string): Uint8Array {
  return te.encode(s);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
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

/**
 * A read-only, random-access byte source (DOM-free). The crypto core reads its
 * input through this so large files never need to live in one contiguous buffer.
 * `slice(start, end)` returns the bytes in [start, end); implementations MUST clamp
 * `end` to `size` (returning fewer bytes near EOF rather than throwing).
 */
export interface ByteSource {
  readonly size: number;
  slice(start: number, end: number): Promise<Uint8Array>;
}

/** Wrap an in-memory Uint8Array as a ByteSource (zero-copy subarray views). */
export function bytesSource(buf: Uint8Array): ByteSource {
  return {
    size: buf.length,
    slice(start: number, end: number): Promise<Uint8Array> {
      return Promise.resolve(buf.subarray(start, Math.min(end, buf.length)));
    },
  };
}

export function equalCT(a: Uint8Array, b: Uint8Array): boolean {
  // Length is public; compare contents in constant time.
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export function toHex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

export function fromHex(h: string): Uint8Array {
  if (h.length % 2 !== 0) throw new FileKeyError("odd-length hex string", "hex_decode");
  if (!/^[0-9a-fA-F]*$/.test(h)) throw new FileKeyError("hex string contains a non-hex character", "hex_decode");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// I2OSP(n, len) — big-endian, RFC 8017. Used for chunk counters.
export function i2osp(n: number | bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);
  let v = BigInt(n);
  if (v < 0n) throw new Error("i2osp: negative");
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new Error("i2osp: integer too large for length");
  return out;
}

// A minimal big-endian reader with bounds checking. Throws on overrun.
export class Reader {
  private off = 0;
  constructor(private readonly buf: Uint8Array) {}

  get remaining(): number {
    return this.buf.length - this.off;
  }
  get offset(): number {
    return this.off;
  }

  take(n: number): Uint8Array {
    if (n < 0) throw new Error("take: negative");
    if (this.off + n > this.buf.length) throw new FileKeyError("unexpected end of input (truncated file)", "truncated");
    const out = this.buf.subarray(this.off, this.off + n);
    this.off += n;
    return out;
  }
  u8(): number {
    return this.take(1)[0]!;
  }
  u16(): number {
    const b = this.take(2);
    return (b[0]! << 8) | b[1]!;
  }
  u32(): number {
    const b = this.take(4);
    // Avoid sign issues: use unsigned arithmetic.
    return b[0]! * 0x1000000 + ((b[1]! << 16) | (b[2]! << 8) | b[3]!);
  }
  u64(): bigint {
    const b = this.take(8);
    let v = 0n;
    for (const x of b) v = (v << 8n) | BigInt(x);
    return v;
  }
}

// Big-endian writers for fixed widths.
export function u16be(n: number): Uint8Array {
  if (n < 0 || n > 0xffff) throw new Error("u16 out of range");
  return new Uint8Array([(n >> 8) & 0xff, n & 0xff]);
}
export function u32be(n: number): Uint8Array {
  if (n < 0 || n > 0xffffffff) throw new Error("u32 out of range");
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}
export function u64be(n: bigint): Uint8Array {
  if (n < 0n || n > 0xffffffffffffffffn) throw new Error("u64 out of range");
  const out = new Uint8Array(8);
  let v = n;
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}
