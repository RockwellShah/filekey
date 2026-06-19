// Differential cells across PROD (filekey.app, old code) and STAGING (go.filekey.app, new code),
// one virtual passkey = same identity on both:
//   - identity_match: same fingerprint both sites
//   - prod_self_suite == 0x01 (old HPKE self), staging_self_suite == 0x02 (new symmetric self)
//   - backward_compat: a PROD-made 0x01 file decrypts on STAGING (new app opens old files)
//   - forward_fail_closed: a STAGING-made 0x02 file is rejected cleanly by PROD (old app), no plaintext
import { launch, newSession, gotoAndAuth, fingerprint, dropAndSave, dropExpectFail, sha, suiteByte, STAGING, PROD } from "./lib.mjs";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

const log = (...a) => console.log("[diff]", ...a);
const hex = (n) => "0x" + n.toString(16);

(async () => {
  const dir = mkdtempSync(join(tmpdir(), "fk-diff-"));
  const fileA = randomBytes(4096), fileApath = join(dir, "alpha.bin"); writeFileSync(fileApath, fileA);
  const fileB = randomBytes(4096), fileBpath = join(dir, "bravo.bin"); writeFileSync(fileBpath, fileB);
  const r = {};

  const browser = await launch();
  try {
    const { page } = await newSession(browser, log);

    await gotoAndAuth(page, STAGING, { create: true });
    const fpS = await fingerprint(page);
    log("staging identity:", fpS);

    // staging self-encrypt -> suite 0x02 (the new-format file, used for forward-fail-closed)
    const stagingEnc = await dropAndSave(page, fileApath);
    r.staging_self_suite = hex(suiteByte(stagingEnc.bytes));
    const stagingEncPath = join(dir, stagingEnc.name); writeFileSync(stagingEncPath, stagingEnc.bytes);
    log("staging self-encrypted:", stagingEnc.name, r.staging_self_suite);

    await gotoAndAuth(page, PROD, { create: false });
    const fpP = await fingerprint(page);
    r.identity_match = fpS === fpP;
    log("prod identity:", fpP, "| match:", r.identity_match);

    // prod self-encrypt -> suite 0x01 (old-format file, used for backward-compat)
    const prodEnc = await dropAndSave(page, fileBpath);
    r.prod_self_suite = hex(suiteByte(prodEnc.bytes));
    const prodEncPath = join(dir, prodEnc.name); writeFileSync(prodEncPath, prodEnc.bytes);
    log("prod self-encrypted:", prodEnc.name, r.prod_self_suite);

    // FORWARD FAIL-CLOSED: feed the 0x02 file to PROD (old code) -> must reject, no plaintext
    const fc = await dropExpectFail(page, stagingEncPath);
    r.forward_fail_closed = !fc.newOutputCard && !fc.plaintextDownloaded;
    r.forward_fail_detail = fc;
    log("prod fed 0x02 file:", JSON.stringify(fc));

    // BACKWARD COMPAT: STAGING (new code) decrypts the PROD-made 0x01 file
    await gotoAndAuth(page, STAGING, { create: false });
    const dec = await dropAndSave(page, prodEncPath);
    r.backward_compat = sha(dec.bytes) === sha(fileB);
    log("staging decrypted prod 0x01 file:", dec.name, "| match:", r.backward_compat);

    const pass = r.identity_match && r.prod_self_suite === "0x1" && r.staging_self_suite === "0x2" && r.backward_compat && r.forward_fail_closed;
    console.log("\n=== DIFFERENTIAL RESULTS ===");
    console.log(JSON.stringify(r, null, 2));
    console.log("DIFFERENTIAL: " + (pass ? "PASS" : "FAIL"));
    process.exitCode = pass ? 0 : 1;
  } catch (e) {
    console.error("HARNESS_ERROR:", (e && e.stack) || e);
    process.exitCode = 2;
  } finally {
    await browser.close();
  }
})();
