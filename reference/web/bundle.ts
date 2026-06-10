// FileKey — input bundling for multi-file / folder encryption (web/ only; the crypto core
// is untouched). Collects dropped/picked files with their relative paths — recursing into
// folders via the drag-drop entry API — and zips them into one archive. app.ts then encrypts
// that archive as a single .filekey. Decryption is unchanged: it yields the .zip, which the
// user unpacks themselves. So this is an encrypt-side-only concern.
import { Zip, ZipPassThrough } from "fflate";

export interface BundleItem {
  /** Path inside the archive ("MyFolder/sub/file.txt"), or just the filename for a loose file. */
  path: string;
  file: File;
  /** True if this came from inside a dropped/picked folder (vs a loose top-level file). */
  fromFolder: boolean;
}

/** Collect items from a file <input> (honors webkitdirectory's relative paths). */
export function collectFromInput(files: FileList): BundleItem[] {
  return Array.from(files).map((file) => {
    const rel = file.webkitRelativePath; // "" for a plain multi-file pick; "Folder/…" for a directory pick
    return rel ? { path: rel, file, fromFolder: true } : { path: file.name, file, fromFolder: false };
  });
}

/** Collect items from a drop, recursing into folders via the (desktop) entry API. */
export async function collectFromDrop(dt: DataTransfer): Promise<BundleItem[]> {
  const roots: FileSystemEntry[] = [];
  for (const item of Array.from(dt.items)) {
    if (item.kind !== "file") continue;
    const entry = item.webkitGetAsEntry?.();
    if (entry) roots.push(entry);
  }
  if (!roots.length) {
    // No entry API available — fall back to the flat file list (loose files only).
    return Array.from(dt.files).map((file) => ({ path: file.name, file, fromFolder: false }));
  }
  const out: BundleItem[] = [];
  for (const e of roots) await walk(e, "", out);
  return out;
}

async function walk(entry: FileSystemEntry, prefix: string, out: BundleItem[]): Promise<void> {
  if (entry.isFile) {
    const file = await new Promise<File>((res, rej) => (entry as FileSystemFileEntry).file(res, rej));
    out.push({ path: prefix + entry.name, file, fromFolder: prefix !== "" });
  } else if (entry.isDirectory) {
    const children = await readAll((entry as FileSystemDirectoryEntry).createReader());
    if (children.length === 0) {
      // Preserve an empty directory: a zero-byte entry whose path ends in "/" becomes a real dir in the zip.
      out.push({ path: prefix + entry.name + "/", file: new File([], entry.name), fromFolder: true });
    } else {
      for (const c of children) await walk(c, prefix + entry.name + "/", out);
    }
  }
}

// readEntries returns results in batches; call until it yields an empty batch.
function readAll(reader: FileSystemDirectoryReader): Promise<FileSystemEntry[]> {
  return new Promise((resolve, reject) => {
    const all: FileSystemEntry[] = [];
    const next = () => reader.readEntries((batch) => {
      if (!batch.length) resolve(all);
      else { all.push(...batch); next(); }
    }, reject);
    next();
  });
}

/** Suggested archive base name: the common top-level folder, else a generic name. */
export function bundleName(items: BundleItem[]): string {
  const tops = new Set(items.map((i) => (i.path.includes("/") ? i.path.split("/")[0]! : "")));
  if (tops.size === 1) {
    const only = [...tops][0]!;
    if (only) return only;
  }
  return "filekey-bundle";
}

// Dedupe a path against already-used names: "a.txt" -> "a (2).txt".
function dedupePath(p: string, seen: Set<string>): string {
  if (!seen.has(p)) return p;
  const dot = p.lastIndexOf(".");
  const stem = dot > 0 ? p.slice(0, dot) : p;
  const ext = dot > 0 ? p.slice(dot) : "";
  let n = 2;
  while (seen.has(`${stem} (${n})${ext}`)) n++;
  return `${stem} (${n})${ext}`;
}

const ZIP_READ_CHUNK = 4 * 1024 * 1024; // read source files in 4MB slices when streaming them into the archive

/**
 * Stream the items into a zip Blob (Blob-of-Blobs, disk-backed) without ever holding the whole archive —
 * or any whole source file — in memory. Stored (no compression) so framing stays cheap and non-blocking;
 * the payload is encrypted afterward anyway, and bundles are usually already-compressed media. `onRead`
 * reports cumulative source bytes consumed (for progress). This is the large-folder counterpart to
 * {@link zipBundle}, which buffers the whole archive and is fine only for small bundles.
 */
export function zipBundleToBlob(
  items: BundleItem[],
  onRead?: (bytes: number) => void,
  isCancelled?: () => boolean,
): Promise<Blob> {
  return new Promise<Blob>((resolve, reject) => {
    const parts: Blob[] = [];
    const archive = new Zip((err, chunk, final) => {
      if (err) {
        reject(err);
        return;
      }
      if (chunk.length) parts.push(new Blob([chunk as unknown as BlobPart]));
      if (final) resolve(new Blob(parts, { type: "application/zip" }));
    });
    void (async () => {
      const seen = new Set<string>();
      let read = 0;
      for (const it of items) {
        if (isCancelled?.()) return resolve(new Blob([])); // caller polls the same flag and discards this
        const p = dedupePath(it.path, seen);
        seen.add(p);
        const entry = new ZipPassThrough(p);
        archive.add(entry);
        const size = it.file.size;
        if (size === 0) {
          entry.push(new Uint8Array(0), true); // empty file or preserved empty directory
          continue;
        }
        for (let off = 0; off < size; off += ZIP_READ_CHUNK) {
          if (isCancelled?.()) return resolve(new Blob([]));
          const end = Math.min(off + ZIP_READ_CHUNK, size);
          const slice = new Uint8Array(await it.file.slice(off, end).arrayBuffer());
          entry.push(slice, end >= size);
          read += slice.length;
          onRead?.(read);
        }
      }
      archive.end();
    })().catch(reject);
  });
}
