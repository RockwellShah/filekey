// Shared helpers for the FileKey differential E2E harness (virtual-passkey driven, headless).
import { chromium } from "playwright-core";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

export const CHROME = process.env.FILEKEY_E2E_CHROME || (process.env.HOME + "/Library/Caches/ms-playwright/chromium-1208/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing");
export const STAGING = "https://go.filekey.app";
export const PROD = "https://filekey.app";
export const VAUTH = { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, hasPrf: true, isUserVerified: true, automaticPresenceSimulation: true };

export const sha = (b) => createHash("sha256").update(b).digest("hex");
export const suiteByte = (bytes) => bytes[5];
export const isFKEY = (b) => b[0] === 0x46 && b[1] === 0x4b && b[2] === 0x45 && b[3] === 0x59;

export async function launch() {
  return chromium.launch({ headless: true, executablePath: CHROME });
}

/** One context = one identity = one virtual authenticator (RP-ID filekey.app). */
export async function newSession(browser, onLog = () => {}) {
  const context = await browser.newContext({ acceptDownloads: true, reducedMotion: "reduce" });
  const page = await context.newPage();
  await page.addInitScript(() => { try { Object.defineProperty(window, "showSaveFilePicker", { value: undefined, configurable: true }); } catch {} });
  page.on("pageerror", (e) => onLog("PAGEERROR:", e.message));
  const client = await context.newCDPSession(page);
  await client.send("WebAuthn.enable");
  const { authenticatorId } = await client.send("WebAuthn.addVirtualAuthenticator", { options: VAUTH });
  return { context, page, client, authenticatorId };
}

/** Navigate to a FileKey site and authenticate. `create:true` enrolls (first visit); else discoverable unlock. */
export async function gotoAndAuth(page, url, { create }) {
  await page.goto(url, { waitUntil: "domcontentloaded", timeout: 60000 });
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

export async function fingerprint(page) {
  return (await page.locator("#acct_identity").innerText()).replace(/\s+/g, " ").trim();
}

/** Upload file(s) -> wait for the resulting download card -> click its Save -> capture the output bytes.
 *  Works for both encrypt (upload plaintext) and decrypt (upload .filekey): same UI mechanics. */
export async function dropAndSave(page, filePaths, { timeout = 120000 } = {}) {
  const before = await page.locator(".std_download").count();
  await page.setInputFiles("#file_input", Array.isArray(filePaths) ? filePaths : [filePaths]);
  await page.waitForFunction((n) => document.querySelectorAll(".std_download").length > n, before, { timeout });
  await page.waitForSelector(".std_download .save_act", { timeout });
  const [download] = await Promise.all([
    page.waitForEvent("download", { timeout }),
    page.locator(".std_download .save_act").last().click(),
  ]);
  return { name: download.suggestedFilename(), bytes: readFileSync(await download.path()) };
}

/** Upload a file that SHOULD fail to decrypt; assert fail-closed: no new output card, no plaintext download. */
export async function dropExpectFail(page, filePath, ms = 20000) {
  const before = await page.locator(".std_download").count();
  let downloaded = false;
  const onDl = () => { downloaded = true; };
  page.on("download", onDl);
  await page.setInputFiles("#file_input", filePath);
  const errorShown = await page.waitForSelector(".failed_dp", { timeout: ms }).then(() => true).catch(() => false);
  await page.waitForTimeout(2500); // allow any (erroneous) card/download to appear
  const after = await page.locator(".std_download").count();
  page.off("download", onDl);
  return { errorShown, newOutputCard: after > before, plaintextDownloaded: downloaded };
}
