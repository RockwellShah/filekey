// Post-deploy verifier: poll prod until the deploy is live and healthy. Every attempt checks:
//   1. deploy liveness: prod /version.json "current" equals the local working tree's version
//      (override with EXPECT_VERSION=x.y.z), so a ship that changes no crypto can never
//      green-light against the OLD deploy;
//   2. static assets: favicon/app icons + og.png resolve as images on prod;
//   3. crypto: self-encrypt -> suite 0x02 -> decrypt -> byte match (smoke; the deep
//      cross-session/large-file coverage lives in run.mjs);
//   4. optional copy gate for wording deploys:
//      EXPECT_COPY="must appear" FORBID_COPY="must be gone" node e2e/prod-verify.mjs
import { launch, newSession, dropAndSave, sha, suiteByte, PROD } from "./lib.mjs";
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";

const here = dirname(fileURLToPath(import.meta.url));
const EXPECT_VERSION = process.env.EXPECT_VERSION || JSON.parse(readFileSync(join(here, "..", "web", "version.json"), "utf8")).current;
const EXPECT_COPY = process.env.EXPECT_COPY || "";
const FORBID_COPY = process.env.FORBID_COPY || "";
const ATTEMPTS = 12;
const RETRY_MS = 25000;
const DEADLINE_MS = 20 * 60 * 1000; // hard wall-clock cap so a degraded prod can't hold the runner forever

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => console.log("[verify]", ...a);
const norm = (s) => s.replace(/\s+/g, " "); // innerText line breaks must not defeat a phrase match

async function liveVersion() {
  try {
    const r = await fetch(PROD + "/version.json", { signal: AbortSignal.timeout(15000) });
    return (await r.json()).current || "";
  } catch { return ""; }
}

async function assetsOk() {
  try {
    for (const p of ["/favicon.ico", "/apple-touch-icon.png", "/icon-192.png", "/icon-512.png", "/og.png"]) {
      const r = await fetch(PROD + p, { signal: AbortSignal.timeout(15000) });
      if (!(r.status === 200 && (r.headers.get("content-type") || "").startsWith("image/"))) return false;
    }
    return true;
  } catch { return false; }
}

async function attempt() {
  const dir = mkdtempSync(join(tmpdir(), "fk-verify-"));
  const pt = randomBytes(2000);
  const p = join(dir, "v.txt");
  writeFileSync(p, pt);
  const browser = await launch();
  try {
    return await checkApp(browser, dir, pt, p);
  } finally {
    await browser.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

async function checkApp(browser, dir, pt, p) {
    const { page } = await newSession(browser);
    await page.goto(PROD, { waitUntil: "domcontentloaded", timeout: 60000 });
    await page.waitForSelector('button:has-text("Unlock"), button:has-text("Create")', { timeout: 60000 });
    const body = norm(await page.locator("body").innerText());
    const copyOk = (!EXPECT_COPY || body.includes(norm(EXPECT_COPY))) && (!FORBID_COPY || !body.includes(norm(FORBID_COPY)));
    const copyStale = FORBID_COPY ? body.includes(norm(FORBID_COPY)) : false;
    // auth (inline so we read the intro copy before clicking)
    await page.locator('button:has-text("Create")').first().click();
    await page.waitForSelector('button:has-text("Unlock"), .msg_clickable', { timeout: 45000 });
    if (!(await page.locator("body.fk-authed").count())) {
      const u = page.locator('button:has-text("Unlock")');
      if (await u.count()) await u.first().click();
      else await page.locator(".msg_clickable").first().click();
    }
    await page.waitForSelector("body.fk-authed", { timeout: 45000 });
    const enc = await dropAndSave(page, p);
    const encP = join(dir, enc.name); writeFileSync(encP, enc.bytes);
    const dec = await dropAndSave(page, encP);
    return { copyOk, copyStale, suite: suiteByte(enc.bytes), roundtrip: sha(dec.bytes) === sha(pt) };
}

(async () => {
  const copyGate = EXPECT_COPY || FORBID_COPY ? " + expected copy" : "";
  const t0 = Date.now();
  for (let i = 1; i <= ATTEMPTS; i++) {
    if (Date.now() - t0 > DEADLINE_MS) { log("overall deadline reached, giving up"); break; }
    log(`attempt ${i}/${ATTEMPTS} vs ${PROD} (expect v${EXPECT_VERSION})`);
    const ver = await liveVersion();
    if (ver !== EXPECT_VERSION) {
      log(`live version is "${ver || "unknown"}", waiting for "${EXPECT_VERSION}"...`);
      if (i < ATTEMPTS) await sleep(RETRY_MS);
      continue;
    }
    const assets = await assetsOk();
    let r = null;
    try { r = await attempt(); } catch (e) { log("err:", String((e && e.message) || e).slice(0, 140)); }
    if (r) {
      log(`assets=${assets} copy ok=${r.copyOk} | crypto: suite 0x${r.suite.toString(16)} roundtrip=${r.roundtrip}`);
      if (assets && r.copyOk && r.suite === 2 && r.roundtrip) {
        console.log(`PROD_VERIFY: PASS (v${EXPECT_VERSION} live, assets healthy, suite 0x02 round-trip${copyGate}).`);
        process.exitCode = 0; return;
      }
      if (r.copyStale) log("old copy still served (build not live yet), waiting...");
    }
    if (i < ATTEMPTS) await sleep(RETRY_MS);
  }
  console.log("PROD_VERIFY: did not confirm a healthy deploy within the window.");
  process.exitCode = 1;
})();
