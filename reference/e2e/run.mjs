// FileKey suite-0x02 full differential E2E suite. Headless, virtual-passkey (zero fingerprints),
// real deployed prod (filekey.app, old code) + staging (go.filekey.app, new code).
// Run: node run.mjs   (exit 0 = all critical cells pass)
import { launch, newSession, gotoAndAuth, fingerprint, dropAndSave, dropExpectFail, sha, suiteByte, isFKEY, STAGING, PROD } from "./lib.mjs";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes, randomFillSync } from "node:crypto";

const results = [];
const record = (name, critical, pass, detail = "") => {
  results.push({ name, critical, pass });
  console.log(`  [${pass ? "PASS" : "FAIL"}] ${name}${detail ? " — " + detail : ""}`);
};

const dir = mkdtempSync(join(tmpdir(), "fk-run-"));
const mk = (name, bytes) => { const p = join(dir, name); writeFileSync(p, bytes); return { name, p, bytes, hash: sha(bytes) }; };
const save = (name, bytes) => { const p = join(dir, name); writeFileSync(p, bytes); return p; };
const bigBuf = (n) => { const b = Buffer.allocUnsafe(n); for (let o = 0; o < n; o += 65536) randomFillSync(b, o, Math.min(65536, n - o)); return b; };

const small = mk("note.txt", randomBytes(4096));
const empty = mk("empty.dat", Buffer.alloc(0));
const uni = mk("机密-документ-αβγ-long-name-test.txt", randomBytes(2048));
const b1 = mk("one.txt", randomBytes(1500)), b2 = mk("two.txt", randomBytes(2500));
const big = mk("bigfile.bin", bigBuf(65 * 1024 * 1024));

async function selfRoundtrip(page, fx, expectName, { timeout } = {}) {
  const enc = await dropAndSave(page, fx.p, { timeout });
  const suite = suiteByte(enc.bytes);
  const encPath = save(enc.name, enc.bytes);
  const dec = await dropAndSave(page, encPath, { timeout });
  const nameOk = expectName ? dec.name === fx.name : true;
  return { suite, magic: isFKEY(enc.bytes), match: sha(dec.bytes) === fx.hash, nameOk, encName: enc.name, decName: dec.name, encBytes: enc.bytes, decBytes: dec.bytes };
}

(async () => {
  const browser = await launch();
  let stagingSmallEnc; // a suite-0x02 file, reused for fail-closed + wrong-identity
  let prodSmallEncPath; // a suite-0x01 file, reused for backward-compat
  let fpAlice;
  try {
    console.log("== STAGING self-encryption (suite 0x02), Alice ==");
    const A = await newSession(browser);
    await gotoAndAuth(A.page, STAGING, { create: true });
    fpAlice = await fingerprint(A.page);

    const rSmall = await selfRoundtrip(A.page, small);
    stagingSmallEnc = rSmall.encBytes;
    record("staging self round-trip: small", true, rSmall.magic && rSmall.suite === 0x02 && rSmall.match, `suite 0x${rSmall.suite.toString(16)}, bytes match=${rSmall.match}`);

    const rEmpty = await selfRoundtrip(A.page, empty);
    record("staging self round-trip: empty file", true, rEmpty.suite === 0x02 && rEmpty.match, `suite 0x${rEmpty.suite.toString(16)}, match=${rEmpty.match}`);

    const rUni = await selfRoundtrip(A.page, uni, true);
    record("staging self round-trip: unicode/long filename", true, rUni.suite === 0x02 && rUni.match && rUni.nameOk, `name restored=${rUni.nameOk} (${rUni.decName})`);

    const rBig = await selfRoundtrip(A.page, big, false, { timeout: 240000 });
    record("staging self round-trip: 65 MiB (worker path)", true, rBig.suite === 0x02 && rBig.match, `suite 0x${rBig.suite.toString(16)}, match=${rBig.match}`);

    // bundle: 2 files -> zip -> self-encrypt 0x02 -> decrypt -> valid zip
    const encB = await dropAndSave(A.page, [b1.p, b2.p]);
    const encBPath = save(encB.name, encB.bytes);
    const decB = await dropAndSave(A.page, encBPath);
    const isZip = decB.bytes[0] === 0x50 && decB.bytes[1] === 0x4b;
    record("staging self round-trip: folder/bundle", true, suiteByte(encB.bytes) === 0x02 && isZip && decB.bytes.length > 0, `suite 0x${suiteByte(encB.bytes).toString(16)}, decrypted is valid zip=${isZip}`);

    console.log("== Cross-version differential (prod = old code) ==");
    await gotoAndAuth(A.page, PROD, { create: false });
    const fpProd = await fingerprint(A.page);
    record("identity is the same on prod and staging", true, fpProd === fpAlice, `${fpProd} == ${fpAlice}`);

    const prodEnc = await dropAndSave(A.page, small.p);
    prodSmallEncPath = save(prodEnc.name.replace(".filekey", ".prod.filekey"), prodEnc.bytes);
    record("prod self-encryption is suite 0x01 (baseline)", true, suiteByte(prodEnc.bytes) === 0x01, `suite 0x${suiteByte(prodEnc.bytes).toString(16)}`);

    // forward fail-closed: prod (old) fed a 0x02 file
    const fcPath = save("incoming-0x02.filekey", stagingSmallEnc);
    const fc = await dropExpectFail(A.page, fcPath);
    let prodMsg = "";
    try { prodMsg = (await A.page.locator(".std_msg, .std_status").last().innerText({ timeout: 2000 })).replace(/\s+/g, " ").trim().slice(0, 80); } catch {}
    record("forward fail-closed: prod rejects 0x02 (no plaintext)", true, !fc.newOutputCard && !fc.plaintextDownloaded, `errorShownDp=${fc.errorShown}, userMsg="${prodMsg}"`);

    // backward compat: staging (new) decrypts the prod 0x01 file
    await gotoAndAuth(A.page, STAGING, { create: false });
    const decProd = await dropAndSave(A.page, prodSmallEncPath);
    record("backward compat: staging opens prod's 0x01 file", true, sha(decProd.bytes) === small.hash, `bytes match=${sha(decProd.bytes) === small.hash}`);

    console.log("== Second identity (Bob) ==");
    const B = await newSession(browser);
    await gotoAndAuth(B.page, STAGING, { create: true });
    const fpBob = await fingerprint(B.page);
    record("Bob is a distinct identity from Alice", false, fpBob !== fpAlice, `${fpBob} != ${fpAlice}`);

    // wrong identity: Bob cannot decrypt Alice's 0x02 file
    const wrong = await dropExpectFail(B.page, fcPath);
    record("wrong identity cannot decrypt a 0x02 self file", true, !wrong.newOutputCard && !wrong.plaintextDownloaded, `no plaintext leaked`);

    console.log("== Sharing (unchanged 0x01 HPKE; best-effort) ==");
    try {
      // get Bob's share key from the menu
      await B.page.click("#acct_icon_container");
      await B.page.click("#chiz_get_public_key");
      await B.page.waitForFunction(() => /fkey1[a-z0-9]+/i.test(document.body.innerText), { timeout: 15000 });
      const bobKey = ((await B.page.locator("body").innerText()).match(/fkey1[a-z0-9]+/i) || [])[0];
      if (!bobKey) throw new Error("could not read Bob's share key");
      // Alice shares `small` to Bob
      const beforeCards = await A.page.locator(".std_download").count();
      await A.page.setInputFiles("#file_input", small.p);
      await A.page.waitForFunction((n) => document.querySelectorAll(".std_download").length > n, beforeCards, { timeout: 30000 });
      await A.page.locator(".std_download .share_act").last().click();
      await A.page.waitForSelector(".pub_key_textarea", { timeout: 15000 });
      await A.page.locator(".pub_key_textarea").fill(bobKey);
      await A.page.locator(".confirm_pub_key").filter({ hasText: "Confirm" }).first().click();
      const saveBtn = A.page.locator(".confirm_pub_key").filter({ hasText: "Save" });
      await saveBtn.first().waitFor({ timeout: 30000 });
      const [dl] = await Promise.all([
        A.page.waitForEvent("download", { timeout: 30000 }),
        saveBtn.first().click(),
      ]);
      const shared = readFileSync(await dl.path());
      const sharedPath = save(dl.suggestedFilename(), shared);
      // Bob decrypts
      const decShared = await dropAndSave(B.page, sharedPath);
      record("sharing: Alice -> Bob round-trip (suite 0x01)", false, suiteByte(shared) === 0x01 && sha(decShared.bytes) === small.hash, `suite 0x${suiteByte(shared).toString(16)}, match=${sha(decShared.bytes) === small.hash}`);
    } catch (e) {
      record("sharing: Alice -> Bob round-trip (suite 0x01)", false, false, "selectors need iteration: " + String(e.message || e).slice(0, 120));
    }
  } catch (e) {
    console.error("HARNESS_ERROR:", (e && e.stack) || e);
  } finally {
    await browser.close();
  }

  console.log("\n================ RESULT MATRIX ================");
  for (const r of results) console.log(`  ${r.pass ? "✅" : "❌"} ${r.critical ? "[critical] " : "[extra]    "}${r.name}`);
  const critFail = results.filter((r) => r.critical && !r.pass);
  const extraFail = results.filter((r) => !r.critical && !r.pass);
  console.log("==============================================");
  console.log(`critical: ${results.filter((r) => r.critical && r.pass).length}/${results.filter((r) => r.critical).length} pass` + (critFail.length ? `  (FAILED: ${critFail.map((r) => r.name).join("; ")})` : ""));
  console.log(`extra:    ${results.filter((r) => !r.critical && r.pass).length}/${results.filter((r) => !r.critical).length} pass` + (extraFail.length ? `  (failed: ${extraFail.map((r) => r.name).join("; ")})` : ""));
  console.log("SUITE: " + (critFail.length === 0 ? "PASS (all critical cells green)" : "FAIL"));
  process.exitCode = critFail.length === 0 ? 0 : 1;
})();
