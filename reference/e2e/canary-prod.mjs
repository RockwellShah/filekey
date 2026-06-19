// Post-deploy canary: poll filekey.app (prod) until it self-encrypts as suite 0x02 (the new code is
// live) and round-trips. Doubles as the deploy-readiness check (Vercel builds on push; the suite byte
// flips 0x01 -> 0x02 when the new bundle is serving).
import { launch, newSession, gotoAndAuth, dropAndSave, sha, suiteByte, PROD } from "./lib.mjs";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

const log = (...a) => console.log("[canary]", ...a);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function attempt() {
  const dir = mkdtempSync(join(tmpdir(), "fk-canary-"));
  const pt = randomBytes(3000);
  const ptPath = join(dir, "canary.txt");
  writeFileSync(ptPath, pt);
  const browser = await launch();
  try {
    const { page } = await newSession(browser);
    await gotoAndAuth(page, PROD, { create: true });
    const enc = await dropAndSave(page, ptPath);
    const suite = suiteByte(enc.bytes);
    const encPath = join(dir, enc.name); writeFileSync(encPath, enc.bytes);
    const dec = await dropAndSave(page, encPath);
    return { suite, roundtrip: sha(dec.bytes) === sha(pt) };
  } finally {
    await browser.close();
  }
}

(async () => {
  const MAX = 14, WAIT = 30000;
  for (let i = 1; i <= MAX; i++) {
    log(`attempt ${i}/${MAX} vs ${PROD}`);
    let r = null;
    try { r = await attempt(); } catch (e) { log("attempt error:", String((e && e.message) || e).slice(0, 140)); }
    if (r) {
      log(`prod self-encrypt suite 0x${r.suite.toString(16)}, round-trip ${r.roundtrip}`);
      if (r.suite === 0x02 && r.roundtrip) {
        console.log("CANARY: PASS — filekey.app now self-encrypts as suite 0x02 and round-trips.");
        process.exitCode = 0;
        return;
      }
      if (r.suite === 0x01) log("still serving old code (0x01); deploy not live yet.");
    }
    if (i < MAX) await sleep(WAIT);
  }
  console.log("CANARY: did NOT observe suite 0x02 on prod within the window — investigate the deploy.");
  process.exitCode = 1;
})();
