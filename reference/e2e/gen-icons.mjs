// Rasterizes web/icon.svg into the PNG/ICO icon set that iOS and legacy browsers need.
// Why: iOS WebKit (which Chrome on iOS is built on) ignores SVG apple-touch-icons and
// does not use SVG favicons for its preview/tile surfaces, so an SVG-only icon set shows
// no favicon on iOS. We ship raster fallbacks alongside the SVG. icon.svg is the source
// of truth (square, white background, #1377F9 glyph). Re-run after changing icon.svg:
//   bun run gen:icons      (or: node e2e/gen-icons.mjs)
import { chromium } from "playwright-core";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const webDir = join(here, "..", "web");
const svg = readFileSync(join(webDir, "icon.svg"), "utf8");

// Reuse the e2e Chrome-for-Testing binary; fall back to system Chrome.
const candidates = [
  process.env.FILEKEY_E2E_CHROME,
  process.env.HOME + "/Library/Caches/ms-playwright/chromium-1208/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
].filter(Boolean);

let browser;
for (const executablePath of candidates) {
  try { browser = await chromium.launch({ headless: true, executablePath }); break; } catch { /* try next */ }
}
if (!browser) { console.error("gen-icons: no Chromium/Chrome binary found"); process.exit(1); }

// Render icon.svg to an exact size×size opaque PNG (the SVG carries its own white bg rect).
async function png(size) {
  const page = await browser.newPage({ viewport: { width: size, height: size }, deviceScaleFactor: 1 });
  await page.setContent(
    `<!doctype html><meta charset=utf-8>` +
    `<style>*{margin:0;padding:0}html,body{width:${size}px;height:${size}px;overflow:hidden}` +
    `svg{display:block;width:${size}px;height:${size}px}</style>${svg}`,
    { waitUntil: "load" },
  );
  const buf = await page.screenshot({ type: "png", clip: { x: 0, y: 0, width: size, height: size } });
  await page.close();
  return buf;
}

// Minimal ICO that embeds PNG frames (supported by every browser that matters, IE Vista+).
function ico(frames) {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0);                 // reserved
  header.writeUInt16LE(1, 2);                 // type = icon
  header.writeUInt16LE(frames.length, 4);     // count
  const dir = Buffer.alloc(16 * frames.length);
  let offset = 6 + dir.length;
  const blobs = [];
  frames.forEach(({ size, buf }, i) => {
    const e = i * 16;
    dir.writeUInt8(size >= 256 ? 0 : size, e + 0);   // width  (0 => 256)
    dir.writeUInt8(size >= 256 ? 0 : size, e + 1);   // height (0 => 256)
    dir.writeUInt8(0, e + 2);                          // palette
    dir.writeUInt8(0, e + 3);                          // reserved
    dir.writeUInt16LE(1, e + 4);                      // color planes
    dir.writeUInt16LE(32, e + 6);                     // bits per pixel
    dir.writeUInt32LE(buf.length, e + 8);            // size of PNG data
    dir.writeUInt32LE(offset, e + 12);               // offset
    offset += buf.length;
    blobs.push(buf);
  });
  return Buffer.concat([header, dir, ...blobs]);
}

const [at180, i192, i512, f16, f32, f48] = await Promise.all(
  [180, 192, 512, 16, 32, 48].map(png),
);

writeFileSync(join(webDir, "apple-touch-icon.png"), at180);
writeFileSync(join(webDir, "icon-192.png"), i192);
writeFileSync(join(webDir, "icon-512.png"), i512);
writeFileSync(join(webDir, "favicon.ico"), ico([{ size: 16, buf: f16 }, { size: 32, buf: f32 }, { size: 48, buf: f48 }]));

await browser.close();
console.log("gen-icons: wrote apple-touch-icon.png (180), icon-192.png, icon-512.png, favicon.ico (16/32/48) to web/");
