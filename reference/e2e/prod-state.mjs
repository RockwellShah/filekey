// One-shot: what is filekey.app serving RIGHT NOW? Self-encrypt once and report the suite byte
// (0x02 = new code live, 0x01 = old code still live).
import { launch, newSession, gotoAndAuth, dropAndSave, sha, suiteByte, PROD } from "./lib.mjs";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

(async () => {
  const dir = mkdtempSync(join(tmpdir(), "fk-prodstate-"));
  const pt = randomBytes(2000);
  const p = join(dir, "probe.txt");
  writeFileSync(p, pt);
  const browser = await launch();
  try {
    const { page } = await newSession(browser);
    await gotoAndAuth(page, PROD, { create: true });
    const enc = await dropAndSave(page, p);
    const suite = suiteByte(enc.bytes);
    const encPath = join(dir, enc.name); writeFileSync(encPath, enc.bytes);
    const dec = await dropAndSave(page, encPath);
    console.log(JSON.stringify({ site: PROD, selfEncryptSuite: "0x" + suite.toString(16), newCodeLive: suite === 0x02, roundTrip: sha(dec.bytes) === sha(pt) }, null, 2));
    console.log("PROD_SERVING: " + (suite === 0x02 ? "suite 0x02 (NEW code is live)" : "suite 0x01 (OLD code still live)"));
  } catch (e) {
    console.error("ERROR:", (e && e.stack) || e);
    process.exitCode = 2;
  } finally {
    await browser.close();
  }
})();
