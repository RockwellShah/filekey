// Shared helpers for the FileKey differential E2E harness (virtual-passkey driven, headless).
import { chromium } from "playwright-core";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

export const CHROME = process.env.FILEKEY_E2E_CHROME || (process.env.HOME + "/Library/Caches/ms-playwright/chromium-1208/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing");
export const STAGING = "https://go.filekey.app";
export const PROD = "https://filekey.app";
export const VAUTH = { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, hasPrf: true, isUserVerified: true, automaticPresenceSimulation: true };

export const sha = (b) => createHash("sha256").update(b).digest("hex");
export const isFKEY = (b) => b.length >= 4 && b[0] === 0x46 && b[1] === 0x4b && b[2] === 0x45 && b[3] === 0x59;

/** Validate the 12-byte FileKey header (magic + version) and return the suite byte. Throws on anything
 *  malformed, so a wrong/empty/truncated capture can never silently pass a suite-byte assertion. */
export function parseHeader(bytes) {
  if (!bytes || bytes.length < 12) throw new Error(`capture too short for a FileKey header (${bytes ? bytes.length : 0} bytes)`);
  if (!isFKEY(bytes)) throw new Error(`missing FKEY magic: ${[...bytes.slice(0, 4)].map((x) => x.toString(16)).join(" ")}`);
  if (bytes[4] !== 0x01) throw new Error(`unexpected format_version 0x${bytes[4].toString(16)}`);
  return { version: bytes[4], suite: bytes[5] };
}
export const suiteByte = (bytes) => parseHeader(bytes).suite;

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

/** Extract the real 8-hex identity fingerprint (e.g. "434D E5AB" -> "434DE5AB"). Throws if no
 *  fingerprint is rendered, so an empty/default header can't make an identity comparison vacuously equal. */
export async function fingerprint(page) {
  const txt = (await page.locator("#acct_identity").textContent()) || "";
  const m = txt.match(/([0-9A-Fa-f]{4})\s+([0-9A-Fa-f]{4})/);
  if (!m) throw new Error("no identity fingerprint rendered in #acct_identity: " + JSON.stringify(txt.replace(/\s+/g, " ").trim().slice(0, 60)));
  return (m[1] + m[2]).toUpperCase();
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

/** Upload a file that SHOULD fail to decrypt. Returns positive evidence so a silent no-op can't pass:
 *  `processed` (the file was actually ingested -> a new upload card) AND `rejected` (a visible failure
 *  message appeared), plus `newOutputCard`/`plaintextDownloaded` which MUST be false. A real fail-closed
 *  cell requires processed && rejected && !newOutputCard && !plaintextDownloaded. */
export async function dropExpectFail(page, filePath, ms = 20000) {
  const cardsBefore = await page.locator(".std_download").count();
  const uploadsBefore = await page.locator(".std_uploaded").count();
  let downloaded = false;
  const onDl = () => { downloaded = true; };
  page.on("download", onDl);
  await page.setInputFiles("#file_input", filePath);
  const processed = await page
    .waitForFunction((n) => document.querySelectorAll(".std_uploaded").length > n, uploadsBefore, { timeout: ms })
    .then(() => true).catch(() => false);
  const rejected = await page
    .waitForFunction(() => /unsupported|corrupt|couldn'?t|can'?t|failed to (unlock|open|decrypt)|different filekey site|with this key|wrong/i.test(document.body.innerText), null, { timeout: ms })
    .then(() => true).catch(() => false);
  await page.waitForTimeout(2000); // allow any (erroneous) output card/download to appear
  const newOutputCard = (await page.locator(".std_download").count()) > cardsBefore;
  page.off("download", onDl);
  return { processed, rejected, newOutputCard, plaintextDownloaded: downloaded };
}
