// De-risk #1 (codex's top risk): does ONE virtual passkey yield the SAME FileKey identity
// on both go.filekey.app and filekey.app (shared RP-ID), driving the REAL app headlessly?
// create+unlock on staging -> read fingerprint; navigate prod (same context) -> unlock -> read
// fingerprint; assert equal. Heavy diagnostics so failures are debuggable.
import { chromium } from "playwright-core";

const CHROME = process.env.HOME + "/Library/Caches/ms-playwright/chromium-1208/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing";
const STAGING = "https://go.filekey.app";
const PROD = "https://filekey.app";
const VAUTH = { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, hasPrf: true, isUserVerified: true, automaticPresenceSimulation: true };
const log = (...a) => console.log("[derisk]", ...a);

async function dumpButtons(page, label) {
  const txts = await page.$$eval("button", (bs) => bs.map((b) => (b.textContent || "").trim()).filter(Boolean));
  log(label, "buttons:", JSON.stringify(txts));
}

async function authedFingerprint(page, label, { create }) {
  await page.waitForLoadState("domcontentloaded");
  // auth buttons render after the intro; wait for either to appear
  await page.waitForSelector('button:has-text("Unlock"), button:has-text("Create")', { timeout: 60000 }).catch(() => {});
  await dumpButtons(page, label);
  if (create) {
    const createBtn = page.locator('button:has-text("Create")');
    if (await createBtn.count()) { log(label, "clicking Create"); await createBtn.first().click(); }
    // after create the app does NOT auto-auth; an Unlock affordance appears
    await page.waitForSelector('button:has-text("Unlock"), .msg_clickable', { timeout: 45000 }).catch(() => {});
  }
  if (!(await page.locator("body.fk-authed").count())) {
    const unlockBtn = page.locator('button:has-text("Unlock")');
    if (await unlockBtn.count()) { log(label, "clicking Unlock"); await unlockBtn.first().click(); }
    else { const mc = page.locator(".msg_clickable"); if (await mc.count()) { log(label, "clicking .msg_clickable"); await mc.first().click(); } }
  }
  await page.waitForSelector("body.fk-authed", { timeout: 45000 });
  const fp = (await page.locator("#acct_identity").innerText()).replace(/\s+/g, " ").trim();
  log(label, "authed, identity header:", JSON.stringify(fp));
  return fp;
}

(async () => {
  const browser = await chromium.launch({ headless: true, executablePath: CHROME });
  try {
    const context = await browser.newContext({ acceptDownloads: true, reducedMotion: "reduce" });
    const page = await context.newPage();
    page.on("pageerror", (e) => log("PAGEERROR:", e.message));
    page.on("console", (m) => { if (m.type() === "error") log("console.error:", m.text()); });

    const client = await context.newCDPSession(page);
    await client.send("WebAuthn.enable");
    const { authenticatorId } = await client.send("WebAuthn.addVirtualAuthenticator", { options: VAUTH });
    log("virtual authenticator:", authenticatorId);

    log("== STAGING ==", STAGING);
    await page.goto(STAGING, { waitUntil: "domcontentloaded", timeout: 60000 });
    const fpStaging = await authedFingerprint(page, "staging", { create: true });

    const creds1 = await client.send("WebAuthn.getCredentials", { authenticatorId });
    log("credentials on authenticator after staging enroll:", creds1.credentials.length);

    log("== PROD ==", PROD);
    await page.goto(PROD, { waitUntil: "domcontentloaded", timeout: 60000 });
    // does the authenticator survive cross-origin navigation?
    const creds2 = await client.send("WebAuthn.getCredentials", { authenticatorId }).catch((e) => ({ error: String(e.message || e) }));
    log("credentials visible after navigating to prod:", creds2.credentials ? creds2.credentials.length : creds2);
    const fpProd = await authedFingerprint(page, "prod", { create: false });

    const same = !!fpStaging && fpStaging === fpProd;
    console.log(JSON.stringify({ fpStaging, fpProd, identitiesMatch: same }, null, 2));
    console.log("DERISK_IDENTITY: " + (same ? "PASS (one passkey = same identity on both sites)" : "FAIL"));
    process.exitCode = same ? 0 : 1;
  } catch (e) {
    console.error("HARNESS_ERROR:", e && e.stack || e);
    process.exitCode = 2;
  } finally {
    await browser.close();
  }
})();
