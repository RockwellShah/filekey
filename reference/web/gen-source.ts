// Generates web/source.txt — a single readable dump of the reference source,
// served at /source.txt (linked from the menu's "Source Code"), mirroring filekey.app.
// Wired into `build:web` so it stays current. Run: bun run web/gen-source.ts
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const webDir = dirname(fileURLToPath(import.meta.url));
const root = join(webDir, "..");
const APP_VERSION = JSON.parse(readFileSync(join(webDir, "version.json"), "utf8")).current;

// Human-readable source, in reading order. The built bundle (web/dist) is omitted.
const files = [
  "web/index.html",
  "web/app.ts",
  "web/contacts.ts",
  "web/recover.ts",
  "web/bundle.ts",
  "web/worker.ts",
  "web/webauthn.ts",
  "web/serve.ts",
  "web/sw.js",
  "web/manifest.json",
  "web/selftest.ts",
  "src/index.ts",
  "src/constants.ts",
  "src/bytes.ts",
  "src/namespace.ts",
  "src/identity.ts",
  "src/sharekey.ts",
  "src/recovery.ts",
  "src/metadata.ts",
  "src/cipher.ts",
  "src/wire.ts",
];

const bar = "=".repeat(78);
let out =
  "FileKey reference implementation, full source\n" +
  `v${APP_VERSION} · HPKE (DHKEM P-256 + HKDF-SHA-256 + AES-256-GCM, namespaced) · passkey (WebAuthn PRF)\n` +
  "Everything runs in the browser. No account, no server, nothing uploaded.\n";

for (const f of files) {
  let content: string;
  try {
    content = readFileSync(join(root, f), "utf8");
  } catch {
    continue; // skip any file that isn't present
  }
  out += `\n\n${bar}\n=== ${f} ===\n${bar}\n\n${content}`;
}

writeFileSync(join(webDir, "source.txt"), out);
console.log(`wrote web/source.txt (${out.length.toLocaleString()} bytes, ${files.length} files)`);
