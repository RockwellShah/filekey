// Renders og-card.html into web/og.png (2000×1050), the social share card the
// whole site serves at /og.png (homepage, blog posts, legal pages all point at it).
// The card self-fits (it scales the logo row to the tagline width after fonts load),
// so we wait for its data-fitted signal and refuse to render if Inter didn't load —
// a fallback-font wordmark is exactly the bug this script exists to prevent.
// Re-run after changing og-card.html:
//   bun run gen:og      (or: node e2e/gen-og.mjs)
import { chromium } from "playwright-core";
import { writeFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { CHROME } from "./lib.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const OUT_W = 2000, OUT_H = 1050; // must match the og:image width/height meta tags

// Reuse the e2e Chrome-for-Testing binary (lib.mjs pins the revision and honors
// FILEKEY_E2E_CHROME); fall back to system Chrome. Log the pick so a fallback
// render is visible in the output (the committed card depends on the browser used).
const candidates = [CHROME, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"];

let browser;
for (const executablePath of candidates) {
  try { browser = await chromium.launch({ headless: true, executablePath }); console.log("gen-og: using " + executablePath); break; } catch { /* try next */ }
}
if (!browser) { console.error("gen-og: no Chromium/Chrome binary found"); process.exit(1); }

const page = await browser.newPage({ viewport: { width: 1200, height: 630 }, deviceScaleFactor: OUT_W / 1200 });
await page.goto(pathToFileURL(join(root, "og-card.html")).href, { waitUntil: "load" });
await page.waitForSelector("html[data-fitted]", { state: "attached" });
if (!(await page.evaluate(() => document.fonts.check("680 100px Inter")))) {
  console.error("gen-og: Inter did not load (check the @font-face path in og-card.html)");
  await browser.close();
  process.exit(1);
}
// The card's fit script scales the lockup to span the tagline; a blank or unfitted
// render (zero-width row, broken SVG) must never be written silently.
const fit = await page.evaluate(() => {
  const row = document.querySelector(".row"), tag = document.querySelector(".tag");
  return { row: row ? row.offsetWidth : 0, tag: tag ? tag.offsetWidth : 0 };
});
if (!fit.row || !fit.tag || Math.abs(fit.row - fit.tag) / fit.tag > 0.01) {
  console.error(`gen-og: lockup did not fit the tagline (row=${fit.row}px, tag=${fit.tag}px)`);
  await browser.close();
  process.exit(1);
}
const buf = await page.screenshot({ type: "png" });
await browser.close();

// PNG IHDR sanity check: bytes 16–23 are big-endian width, height.
const w = buf.readUInt32BE(16), h = buf.readUInt32BE(20);
if (w !== OUT_W || h !== OUT_H) {
  console.error(`gen-og: rendered ${w}×${h}, expected ${OUT_W}×${OUT_H}`);
  process.exit(1);
}
writeFileSync(join(root, "web", "og.png"), buf);
console.log(`gen-og: wrote web/og.png (${OUT_W}×${OUT_H}, ${(buf.length / 1024).toFixed(0)} KB)`);
