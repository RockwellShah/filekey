// FileKey suite-0x02 full differential E2E suite. Headless, virtual-passkey (zero fingerprints),
// real deployed prod (filekey.app) + staging (go.filekey.app).
// Run: node run.mjs   (exit 0 = all critical cells pass)
// The gate EXPECTS prod to emit suite 0x02 (the steady state since 1.12.1); a prod that
// emits 0x01 reads as a rollback and fails loudly. For a future staged migration where
// staging is deliberately ahead of prod, run with EXPECT_PROD_SUITE=0x01 to re-enable
// the old-prod differential assertions (fail-closed reject of the newer suite).
import { launch, newSession, gotoAndAuth, fingerprint, dropAndSave, dropExpectFail, sha, suiteByte, isFKEY, STAGING, PROD } from "./lib.mjs";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
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
  let stagingSmallEnc; // a suite-0x02 file, reused for the forward path + wrong-identity
  let prodSmallEncPath; // a prod-made file (0x01 or 0x02), reused for cross-deploy compat
  let fpAlice;
  let harnessError = null;
  let workers = 0;
  try {
    // Deploy-surface check: the static assets the head/manifest declare must actually be
    // served. Guards the iOS favicon fix and the og card (the og:image meta tags declare
    // 2000x1050; gen-og.mjs enforces that at build time, this enforces it at serve time).
    console.log("== Static assets (staging) ==");
    try {
      const assets = ["/favicon.ico", "/apple-touch-icon.png", "/icon-192.png", "/icon-512.png", "/og.png"];
      const checks = [];
      let ogDetail = "";
      for (const path of assets) {
        const res = await fetch(STAGING + path, { signal: AbortSignal.timeout(15000) });
        const type = res.headers.get("content-type") || "";
        const cc = res.headers.get("cache-control") || "";
        let ok = res.status === 200 && type.startsWith("image/");
        // The icons ship with a vercel.json Cache-Control rule; assert it actually matched
        // (a silently non-matching path pattern would leave them on max-age=0 forever).
        if (path !== "/og.png") ok = ok && cc.includes("max-age=86400");
        const PNG_DIMS = { "/og.png": [2000, 1050], "/apple-touch-icon.png": [180, 180], "/icon-192.png": [192, 192], "/icon-512.png": [512, 512] };
        if (PNG_DIMS[path] && ok) {
          const b = Buffer.from(await res.arrayBuffer());
          const w = b.length >= 24 ? b.readUInt32BE(16) : 0, h = b.length >= 24 ? b.readUInt32BE(20) : 0;
          if (path === "/og.png") ogDetail = `, og ${w}x${h}`;
          ok = w === PNG_DIMS[path][0] && h === PNG_DIMS[path][1];
        }
        checks.push({ path, ok, why: `${res.status} ${type}${cc ? " cc=" + cc : ""}` });
      }
      record("static assets served (icons + og card)", true, checks.every((c) => c.ok), checks.map((c) => `${c.path}=${c.ok ? "ok" : c.why}`).join(", ") + ogDetail);
    } catch (e) {
      record("static assets served (icons + og card)", true, false, "fetch failed: " + String((e && e.message) || e).slice(0, 120));
    }

    console.log("== STAGING self-encryption (suite 0x02), Alice ==");
    const A = await newSession(browser);
    A.page.on("worker", () => workers++); // count Web Workers (large files route to web/worker.ts)
    await gotoAndAuth(A.page, STAGING, { create: true });
    fpAlice = await fingerprint(A.page);

    const rSmall = await selfRoundtrip(A.page, small);
    stagingSmallEnc = rSmall.encBytes;
    record("staging self round-trip: small", true, rSmall.magic && rSmall.suite === 0x02 && rSmall.match, `suite 0x${rSmall.suite.toString(16)}, bytes match=${rSmall.match}`);

    const rEmpty = await selfRoundtrip(A.page, empty);
    record("staging self round-trip: empty file", true, rEmpty.suite === 0x02 && rEmpty.match, `suite 0x${rEmpty.suite.toString(16)}, match=${rEmpty.match}`);

    const rUni = await selfRoundtrip(A.page, uni, true);
    record("staging self round-trip: unicode/long filename", true, rUni.suite === 0x02 && rUni.match && rUni.nameOk, `name restored=${rUni.nameOk} (${rUni.decName})`);

    const wBefore = workers;
    const rBig = await selfRoundtrip(A.page, big, false, { timeout: 240000 });
    const workerRan = workers > wBefore; // a Web Worker must have been created for the >=64 MiB path
    record("staging self round-trip: 65 MiB (worker path)", true, rBig.suite === 0x02 && rBig.match && workerRan, `suite 0x${rBig.suite.toString(16)}, match=${rBig.match}, workerCreated=${workerRan}`);

    // bundle: 2 files -> zip -> self-encrypt 0x02 -> decrypt -> verify the zip's exact entries + hashes
    const encB = await dropAndSave(A.page, [b1.p, b2.p]);
    const encBPath = save(encB.name, encB.bytes);
    const decB = await dropAndSave(A.page, encBPath);
    let bundleOk = false, bundleDetail = "";
    try {
      const { unzipSync } = await import("fflate");
      const entries = unzipSync(new Uint8Array(decB.bytes));
      const oneOk = entries["one.txt"] && sha(Buffer.from(entries["one.txt"])) === b1.hash;
      const twoOk = entries["two.txt"] && sha(Buffer.from(entries["two.txt"])) === b2.hash;
      bundleOk = !!(oneOk && twoOk);
      bundleDetail = `entries=${JSON.stringify(Object.keys(entries))}, one=${!!oneOk}, two=${!!twoOk}`;
    } catch (e) { bundleDetail = "unzip failed: " + String((e && e.message) || e); }
    record("staging self round-trip: folder/bundle", true, suiteByte(encB.bytes) === 0x02 && bundleOk, `suite 0x${suiteByte(encB.bytes).toString(16)}, ${bundleDetail}`);

    console.log("== Cross-version differential (adapts to prod's deployed suite) ==");
    await gotoAndAuth(A.page, PROD, { create: false });
    const fpProd = await fingerprint(A.page);
    record("identity is the same on prod and staging", true, fpProd === fpAlice, `${fpProd} == ${fpAlice}`);

    // Prod must emit the suite we EXPECT (default 0x02, steady state). An unexpected
    // 0x01 here is a rollback to pre-PQ code, not a benign differential state; only an
    // explicit EXPECT_PROD_SUITE=0x01 (staged-migration mode) accepts it.
    const EXPECT_PROD_SUITE = parseInt(process.env.EXPECT_PROD_SUITE || "0x02", 16);
    const prodEnc = await dropAndSave(A.page, small.p);
    prodSmallEncPath = save(prodEnc.name.replace(".filekey", ".prod.filekey"), prodEnc.bytes);
    const prodSuite = suiteByte(prodEnc.bytes);
    const prodIsOld = prodSuite === 0x01;
    record("prod self-encryption suite matches the expected deploy state", true, prodSuite === EXPECT_PROD_SUITE, `suite 0x${prodSuite.toString(16)}, expected 0x${EXPECT_PROD_SUITE.toString(16)}${prodIsOld && EXPECT_PROD_SUITE === 0x01 ? " (staged-migration mode: staging ahead of prod)" : ""}`);

    // forward path: prod fed staging's 0x02 file. Old prod must fail closed; current prod must open it.
    const fcIs02 = suiteByte(stagingSmallEnc) === 0x02; // assert the cell's own input, not just inherit it
    const fcPath = save("incoming-0x02.filekey", stagingSmallEnc);
    if (prodIsOld) {
      const fc = await dropExpectFail(A.page, fcPath);
      let prodMsg = "";
      try { prodMsg = (await A.page.locator(".std_msg, .std_status").last().innerText({ timeout: 2000 })).replace(/\s+/g, " ").trim().slice(0, 80); } catch {}
      record("forward path: prod handles staging's 0x02 file correctly", true, fcIs02 && fc.processed && fc.rejected && !fc.newOutputCard && !fc.plaintextDownloaded, `input=0x02:${fcIs02}, old prod fail-closed: processed=${fc.processed}, rejected=${fc.rejected}, noCard=${!fc.newOutputCard}, userMsg="${prodMsg}"`);
    } else {
      const fwd = await dropAndSave(A.page, fcPath);
      record("forward path: prod handles staging's 0x02 file correctly", true, fcIs02 && sha(fwd.bytes) === small.hash, `input=0x02:${fcIs02}, current prod decrypts 0x02: bytes match=${sha(fwd.bytes) === small.hash}`);
    }

    // cross-deploy compat: staging (new) decrypts whatever prod produced (0x01 or 0x02)
    await gotoAndAuth(A.page, STAGING, { create: false });
    const decProd = await dropAndSave(A.page, prodSmallEncPath);
    record("cross-deploy compat: staging opens prod's file", true, sha(decProd.bytes) === small.hash, `prod suite 0x${prodSuite.toString(16)}, bytes match=${sha(decProd.bytes) === small.hash}`);

    console.log("== Second identity (Bob) ==");
    const B = await newSession(browser);
    await gotoAndAuth(B.page, STAGING, { create: true });
    const fpBob = await fingerprint(B.page);
    record("Bob is a distinct identity from Alice", false, fpBob !== fpAlice, `${fpBob} != ${fpAlice}`);

    // wrong identity: Bob cannot decrypt Alice's 0x02 file
    const wrong = await dropExpectFail(B.page, fcPath);
    record("wrong identity cannot decrypt a 0x02 self file", true, wrong.processed && wrong.rejected && !wrong.newOutputCard && !wrong.plaintextDownloaded, `processed=${wrong.processed}, rejected=${wrong.rejected}, noPlaintext=${!wrong.plaintextDownloaded}`);

    // Sharing still emits suite 0x01 (HPKE), so this cell doubles as the deployed
    // legacy-decrypt gate: once prod is on 0x02, no differential cell mints a 0x01
    // file any more, and without this a broken 0x01 decryptor would strand every
    // pre-0x02 ciphertext while the suite stayed green. Critical for that reason.
    console.log("== Sharing (suite 0x01 HPKE; also the deployed legacy-decrypt gate) ==");
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
      record("sharing: Alice -> Bob round-trip (suite 0x01)", true, suiteByte(shared) === 0x01 && sha(decShared.bytes) === small.hash, `suite 0x${suiteByte(shared).toString(16)}, match=${sha(decShared.bytes) === small.hash}`);
    } catch (e) {
      record("sharing: Alice -> Bob round-trip (suite 0x01)", true, false, "sharing flow failed: " + String(e.message || e).slice(0, 120));
    }
  } catch (e) {
    harnessError = String((e && e.stack) || e);
    console.error("HARNESS_ERROR:", harnessError);
  } finally {
    await browser.close();
    rmSync(dir, { recursive: true, force: true }); // ~130 MB of plaintext/ciphertext fixtures per run
  }

  // A trustworthy gate requires every expected critical cell to have RUN and passed. A mid-run exception
  // (harnessError) or a cell that never executed counts as FAIL, never a silent green.
  const EXPECTED_CRITICAL = [
    "static assets served (icons + og card)",
    "staging self round-trip: small",
    "staging self round-trip: empty file",
    "staging self round-trip: unicode/long filename",
    "staging self round-trip: 65 MiB (worker path)",
    "staging self round-trip: folder/bundle",
    "identity is the same on prod and staging",
    "prod self-encryption suite matches the expected deploy state",
    "forward path: prod handles staging's 0x02 file correctly",
    "cross-deploy compat: staging opens prod's file",
    "wrong identity cannot decrypt a 0x02 self file",
    "sharing: Alice -> Bob round-trip (suite 0x01)",
  ];
  const ran = new Set(results.map((r) => r.name));
  const missing = EXPECTED_CRITICAL.filter((n) => !ran.has(n));

  console.log("\n================ RESULT MATRIX ================");
  for (const r of results) console.log(`  ${r.pass ? "✅" : "❌"} ${r.critical ? "[critical] " : "[extra]    "}${r.name}`);
  for (const n of missing) console.log(`  ❌ [critical] ${n} (NEVER RAN — counted as FAIL)`);
  const critFail = results.filter((r) => r.critical && !r.pass);
  const extraFail = results.filter((r) => !r.critical && !r.pass);
  console.log("==============================================");
  if (harnessError) console.log("HARNESS ERROR (suite did not complete): " + harnessError.split("\n")[0]);
  console.log(`critical: ${results.filter((r) => r.critical && r.pass).length}/${EXPECTED_CRITICAL.length} pass` + (critFail.length ? `  (FAILED: ${critFail.map((r) => r.name).join("; ")})` : "") + (missing.length ? `  (MISSING: ${missing.join("; ")})` : ""));
  console.log(`extra:    ${results.filter((r) => !r.critical && r.pass).length}/${results.filter((r) => !r.critical).length} pass` + (extraFail.length ? `  (failed: ${extraFail.map((r) => r.name).join("; ")})` : ""));
  const ok = !harnessError && missing.length === 0 && critFail.length === 0;
  console.log("SUITE: " + (ok ? "PASS (all critical cells ran and passed)" : "FAIL"));
  process.exitCode = ok ? 0 : 1;
})();
