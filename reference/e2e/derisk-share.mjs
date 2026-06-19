// Fix + verify the sharing flow (fast, no large file). Bob gets his share key; Alice shares a file
// to it (Confirm sets recipient + encrypts, THEN a "Save" .confirm_pub_key appears -> download);
// Bob decrypts. Shared files are suite 0x01 (HPKE), unchanged by this release.
import { launch, newSession, gotoAndAuth, dropAndSave, sha, suiteByte, STAGING } from "./lib.mjs";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

const log = (...a) => console.log("[share]", ...a);

(async () => {
  const dir = mkdtempSync(join(tmpdir(), "fk-share-"));
  const ptBytes = randomBytes(3000);
  const ptPath = join(dir, "for-bob.txt");
  writeFileSync(ptPath, ptBytes);
  const ptHash = sha(ptBytes);

  const browser = await launch();
  try {
    // Bob: identity + share key
    const B = await newSession(browser, log);
    await gotoAndAuth(B.page, STAGING, { create: true });
    await B.page.click("#acct_icon_container");
    await B.page.click("#chiz_get_public_key");
    await B.page.waitForFunction(() => /fkey1[a-z0-9]+/i.test(document.body.innerText), { timeout: 15000 });
    const bobKey = ((await B.page.locator("body").innerText()).match(/fkey1[a-z0-9]+/i) || [])[0];
    log("Bob share key:", bobKey ? bobKey.slice(0, 18) + "…" : null);
    if (!bobKey) throw new Error("no Bob key");

    // Alice: share `for-bob.txt` to Bob
    const A = await newSession(browser, log);
    await gotoAndAuth(A.page, STAGING, { create: true });
    const before = await A.page.locator(".std_download").count();
    await A.page.setInputFiles("#file_input", ptPath);
    await A.page.waitForFunction((n) => document.querySelectorAll(".std_download").length > n, before, { timeout: 30000 });
    await A.page.locator(".std_download .share_act").last().click();
    await A.page.waitForSelector(".pub_key_textarea", { timeout: 15000 });
    await A.page.locator(".pub_key_textarea").fill(bobKey);
    log("clicking recipient Confirm");
    await A.page.locator(".confirm_pub_key").filter({ hasText: "Confirm" }).first().click();
    // after confirm + encrypt, a "Save" .confirm_pub_key appears
    log("waiting for shared-file Save");
    const saveBtn = A.page.locator(".confirm_pub_key").filter({ hasText: "Save" });
    await saveBtn.first().waitFor({ timeout: 30000 });
    const [dl] = await Promise.all([
      A.page.waitForEvent("download", { timeout: 30000 }),
      saveBtn.first().click(),
    ]);
    const shared = readFileSync(await dl.path());
    log("shared file:", dl.suggestedFilename(), shared.length + "B", "suite 0x" + suiteByte(shared).toString(16));
    const sharedPath = join(dir, dl.suggestedFilename());
    writeFileSync(sharedPath, shared);

    // Bob: decrypt the shared file
    const dec = await dropAndSave(B.page, sharedPath);
    const match = sha(dec.bytes) === ptHash;
    log("Bob decrypted:", dec.name, "match:", match);

    const result = { sharedName: dl.suggestedFilename(), suiteByte: "0x" + suiteByte(shared).toString(16), suiteIs0x01: suiteByte(shared) === 0x01, bobDecryptMatches: match };
    console.log(JSON.stringify(result, null, 2));
    const pass = suiteByte(shared) === 0x01 && match;
    console.log("DERISK_SHARE: " + (pass ? "PASS (Alice->Bob HPKE 0x01 share round-trips)" : "FAIL"));
    process.exitCode = pass ? 0 : 1;
  } catch (e) {
    console.error("HARNESS_ERROR:", (e && e.stack) || e);
    process.exitCode = 2;
  } finally {
    await browser.close();
  }
})();
