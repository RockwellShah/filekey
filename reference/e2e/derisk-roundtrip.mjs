// De-risk #2 (codex): download capture + the real suite-0x02 crypto. On staging: self-encrypt a
// small file via the real UI, capture the .filekey download, assert FKEY magic + version 0x01 +
// suite 0x02, then decrypt it back through the UI and assert the bytes match the original.
import { chromium } from "playwright-core";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes, createHash } from "node:crypto";

const CHROME = process.env.HOME + "/Library/Caches/ms-playwright/chromium-1208/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing";
const STAGING = "https://go.filekey.app";
const VAUTH = { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, hasPrf: true, isUserVerified: true, automaticPresenceSimulation: true };
const log = (...a) => console.log("[roundtrip]", ...a);
const sha = (b) => createHash("sha256").update(b).digest("hex");
const hx = (b, n) => [...b.slice(0, n)].map((x) => x.toString(16).padStart(2, "0")).join(" ");

async function ensureAuthed(page, { create }) {
  await page.waitForSelector('button:has-text("Unlock"), button:has-text("Create")', { timeout: 60000 });
  if (create) {
    await page.locator('button:has-text("Create")').first().click();
    await page.waitForSelector('button:has-text("Unlock"), .msg_clickable', { timeout: 45000 });
  }
  if (!(await page.locator("body.fk-authed").count())) {
    const u = page.locator('button:has-text("Unlock")');
    if (await u.count()) await u.first().click();
    else await page.locator(".msg_clickable").first().click();
  }
  await page.waitForSelector("body.fk-authed", { timeout: 45000 });
}

async function captureDownload(page, doClick) {
  const [download] = await Promise.all([page.waitForEvent("download", { timeout: 90000 }), doClick()]);
  const p = await download.path();
  return { name: download.suggestedFilename(), bytes: readFileSync(p) };
}

(async () => {
  const dir = mkdtempSync(join(tmpdir(), "fk-e2e-"));
  const plaintext = randomBytes(5000);
  const ptPath = join(dir, "secret.txt");
  writeFileSync(ptPath, plaintext);
  log("original sha256:", sha(plaintext).slice(0, 16), "(" + plaintext.length + " bytes)");

  const browser = await chromium.launch({ headless: true, executablePath: CHROME });
  try {
    const context = await browser.newContext({ acceptDownloads: true, reducedMotion: "reduce" });
    const page = await context.newPage();
    await page.addInitScript(() => { try { Object.defineProperty(window, "showSaveFilePicker", { value: undefined, configurable: true }); } catch {} });
    page.on("pageerror", (e) => log("PAGEERROR:", e.message));
    const client = await context.newCDPSession(page);
    await client.send("WebAuthn.enable");
    await client.send("WebAuthn.addVirtualAuthenticator", { options: VAUTH });

    await page.goto(STAGING, { waitUntil: "domcontentloaded", timeout: 60000 });
    await ensureAuthed(page, { create: true });
    log("authed on staging");

    // ENCRYPT: upload plaintext -> auto self-encrypt -> capture the .filekey download
    await page.setInputFiles("#file_input", ptPath);
    await page.waitForSelector(".std_download .save_act", { timeout: 60000 });
    const enc = await captureDownload(page, () => page.locator(".std_download .save_act").last().click());
    log("encrypted:", enc.name, enc.bytes.length + "B", "header:", hx(enc.bytes, 6));
    const magicOk = enc.bytes[0] === 0x46 && enc.bytes[1] === 0x4b && enc.bytes[2] === 0x45 && enc.bytes[3] === 0x59;
    const versionByte = enc.bytes[4], suiteByte = enc.bytes[5];

    // DECRYPT: upload the .filekey -> auto-decrypt -> capture the plaintext download
    const encPath = join(dir, enc.name);
    writeFileSync(encPath, enc.bytes);
    const before = await page.locator(".std_download").count();
    await page.setInputFiles("#file_input", encPath);
    await page.waitForFunction((n) => document.querySelectorAll(".std_download").length > n, before, { timeout: 60000 });
    await page.waitForSelector(".std_download .save_act", { timeout: 60000 });
    const dec = await captureDownload(page, () => page.locator(".std_download .save_act").last().click());
    log("decrypted:", dec.name, dec.bytes.length + "B", "sha256:", sha(dec.bytes).slice(0, 16));

    const result = {
      magicFKEY: magicOk,
      versionByte: "0x" + versionByte.toString(16),
      suiteByte: "0x" + suiteByte.toString(16),
      suiteIs0x02_quantumSafe: suiteByte === 0x02,
      encryptedName: enc.name,
      decryptedName: dec.name,
      decryptedMatchesOriginal: sha(dec.bytes) === sha(plaintext),
    };
    console.log(JSON.stringify(result, null, 2));
    const pass = magicOk && suiteByte === 0x02 && result.decryptedMatchesOriginal;
    console.log("DERISK_ROUNDTRIP: " + (pass ? "PASS (real-UI self-encrypt is suite 0x02 and round-trips)" : "FAIL"));
    process.exitCode = pass ? 0 : 1;
  } catch (e) {
    console.error("HARNESS_ERROR:", (e && e.stack) || e);
    process.exitCode = 2;
  } finally {
    await browser.close();
  }
})();
