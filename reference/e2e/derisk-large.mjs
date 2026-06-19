// De-risk #3 (codex): large-file (>=64 MiB) worker path. On staging, self-encrypt a 65 MiB file
// (routes to web/worker.ts, which uses selfEncryptStream with the plumbed master_prk), capture it,
// assert suite 0x02, decrypt it back (worker path with masterPrk), assert byte-identical.
import { launch, newSession, gotoAndAuth, dropAndSave, sha, suiteByte, STAGING } from "./lib.mjs";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomFillSync } from "node:crypto";

const log = (...a) => console.log("[large]", ...a);
const SIZE = 65 * 1024 * 1024; // just over the 64 MiB STREAM_THRESHOLD -> worker

(async () => {
  const dir = mkdtempSync(join(tmpdir(), "fk-large-"));
  log("generating", (SIZE / 1024 / 1024).toFixed(0), "MiB fixture...");
  const big = Buffer.allocUnsafe(SIZE);
  for (let o = 0; o < SIZE; o += 65536) randomFillSync(big, o, Math.min(65536, SIZE - o));
  const ptPath = join(dir, "bigfile.bin");
  writeFileSync(ptPath, big);
  const origHash = sha(big);
  log("original sha256:", origHash.slice(0, 16));

  const browser = await launch();
  try {
    const { page } = await newSession(browser, log);
    page.on("console", (m) => { const t = m.text(); if (/MB of|Saving|Encrypting|Decrypting/i.test(t)) log("ui:", t); });
    await gotoAndAuth(page, STAGING, { create: true });
    log("authed; uploading large file (worker encrypt)...");

    const enc = await dropAndSave(page, ptPath, { timeout: 240000 });
    const suite = suiteByte(enc.bytes);
    log("encrypted:", enc.name, (enc.bytes.length / 1024 / 1024).toFixed(1) + " MiB", "suite 0x" + suite.toString(16));
    const encPath = join(dir, enc.name);
    writeFileSync(encPath, enc.bytes);

    log("uploading .filekey (worker decrypt)...");
    const dec = await dropAndSave(page, encPath, { timeout: 240000 });
    const match = sha(dec.bytes) === origHash;
    log("decrypted:", dec.name, (dec.bytes.length / 1024 / 1024).toFixed(1) + " MiB", "match:", match);

    const result = { sizeMiB: SIZE / 1024 / 1024, suiteByte: "0x" + suite.toString(16), suiteIs0x02: suite === 0x02, decryptedMatchesOriginal: match };
    console.log(JSON.stringify(result, null, 2));
    const pass = suite === 0x02 && match;
    console.log("DERISK_LARGE: " + (pass ? "PASS (worker path: 65 MiB self-encrypt is suite 0x02 and round-trips)" : "FAIL"));
    process.exitCode = pass ? 0 : 1;
  } catch (e) {
    console.error("HARNESS_ERROR:", (e && e.stack) || e);
    process.exitCode = 2;
  } finally {
    await browser.close();
  }
})();
