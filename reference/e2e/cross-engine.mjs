// Cross-engine crypto portability test: runs the REAL reference suite-0x02 core (identity derivation +
// encrypt/decrypt) on Chromium, WebKit (Safari engine), and Firefox, with NO WebAuthn (master_prk is
// supplied directly). Asserts per-engine round-trip AND byte-identical deterministic output across
// engines. Served over http://localhost (a secure context, so crypto.subtle works without a cert).
import { chromium, webkit, firefox } from "playwright";
import http from "node:http";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dir = dirname(fileURLToPath(import.meta.url));
const bundle = readFileSync(join(__dir, "cross-engine-bundle.js"));
const html = `<!doctype html><html><head><meta charset="utf-8"></head><body><script src="/bundle.js"></script></body></html>`;
const CHROME = process.env.HOME + "/Library/Caches/ms-playwright/chromium-1208/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing";

const server = http.createServer((req, res) => {
  if (req.url === "/bundle.js") { res.writeHead(200, { "content-type": "text/javascript" }); res.end(bundle); }
  else { res.writeHead(200, { "content-type": "text/html" }); res.end(html); }
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const URL_ = `http://localhost:${server.address().port}/`;

// Runs in the page. Returns primitives/hex only (serializable across the Playwright boundary).
const PAGE_TEST = async () => {
  const enc = new TextEncoder();
  const hex = (u) => [...u].map((x) => x.toString(16).padStart(2, "0")).join("");
  const meta = () => ({ filename: "x.bin", mimeType: "application/octet-stream", createdAtUnixMs: 1700000000000, extras: new Map() });
  const ns = new FK.Namespace("filekey.app");
  const set = new FK.NamespaceSet(["filekey.app"]);

  // 1) identity derivation (the EC path; this is where WebKit/Safari WebCrypto JWK quirks would bite)
  const id = await FK.deriveIdentityFromPrf(new Uint8Array(32).fill(0x07), ns);
  const staticPkHex = hex(id.staticPkRaw);

  // 2) realistic round-trip via the real public API (random per-file salt)
  const pt = crypto.getRandomValues(new Uint8Array(5000));
  const file = await FK.encryptToSelf({ identity: id, plaintext: pt, metadata: meta() });
  const suite = file[5];
  const dec = await FK.decrypt({ file, namespaces: set, resolveIdentity: async () => id });
  const roundtrip = dec.plaintext.length === pt.length && dec.plaintext.every((b, i) => b === pt[i]);

  // 3) DETERMINISTIC suite-0x02 file (fixed master_prk + fixed salt) -> must be byte-identical across engines
  const masterPrk = new Uint8Array(32).fill(0x42);
  const salt = new Uint8Array(32).fill(0x99);
  const detPt = enc.encode("cross-engine-deterministic-plaintext");
  const detFile = await FK.selfEncryptWithSaltForTest({ masterPrk, namespace: ns, plaintext: detPt, metadata: meta() }, salt);
  const detRes = await FK.decrypt({ file: detFile, namespaces: set, resolveIdentity: async () => ({ namespace: ns, masterPrk }) });
  const detMatch = detRes.plaintext.length === detPt.length && detRes.plaintext.every((b, i) => b === detPt[i]);

  return { suite, roundtrip, staticPkHex, detHex: hex(detFile), detMatch };
};

const engines = [["chromium", chromium, { executablePath: CHROME }], ["webkit", webkit, {}], ["firefox", firefox, {}]];
const results = {};
for (const [name, eng, opts] of engines) {
  console.log(`[cross] running on ${name}...`);
  let browser;
  try {
    browser = await eng.launch({ headless: true, ...opts });
    const page = await browser.newPage();
    const errs = [];
    page.on("pageerror", (e) => errs.push(String(e.message)));
    await page.goto(URL_, { waitUntil: "load", timeout: 30000 });
    await page.waitForFunction(() => typeof window.FK === "object" && !!window.FK.encryptToSelf, { timeout: 20000 });
    const r = await page.evaluate(PAGE_TEST);
    results[name] = { ...r, errors: errs };
    console.log(`[cross] ${name}: suite 0x${r.suite.toString(16)}, roundtrip=${r.roundtrip}, detMatch=${r.detMatch}`);
  } catch (e) {
    results[name] = { error: String((e && e.message) || e) };
    console.log(`[cross] ${name}: ERROR ${results[name].error.slice(0, 160)}`);
  } finally {
    if (browser) await browser.close();
  }
}
server.close();

const names = engines.map((e) => e[0]);
const perEngineOk = names.every((n) => results[n] && results[n].suite === 2 && results[n].roundtrip && results[n].detMatch);
const detSet = new Set(names.map((n) => results[n] && results[n].detHex).filter(Boolean));
const idSet = new Set(names.map((n) => results[n] && results[n].staticPkHex).filter(Boolean));
const detConsistent = detSet.size === 1 && names.every((n) => results[n] && results[n].detHex);
const idConsistent = idSet.size === 1 && names.every((n) => results[n] && results[n].staticPkHex);

console.log("\n" + JSON.stringify(results, null, 2));
console.log("\nper-engine suite 0x02 + round-trip:        " + perEngineOk);
console.log("deterministic 0x02 file identical (3/3):   " + detConsistent);
console.log("identity (static_pk) identical (3/3):      " + idConsistent);
const pass = perEngineOk && detConsistent && idConsistent;
console.log("CROSS_ENGINE: " + (pass ? "PASS (suite 0x02 works identically on Chromium, WebKit/Safari, Firefox)" : "FAIL"));
process.exitCode = pass ? 0 : 1;
