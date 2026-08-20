// Rasterizes the brand SVGs into the PNG/ICO icon set that iOS and legacy browsers need.
// Why: iOS WebKit (which Chrome on iOS is built on) ignores SVG apple-touch-icons and
// does not use SVG favicons for its preview/tile surfaces, so an SVG-only icon set shows
// no favicon on iOS. We ship raster fallbacks alongside the SVG. icon.svg (square, white
// background, #1377F9 glyph) is the source for the padded app icons; the ICO favicon
// frames render full-bleed from logo.svg on a transparent tile so the 16 px tab icon
// stays legible instead of reading as a speck. Re-run after changing either SVG:
//   bun run gen:icons      (or: node e2e/gen-icons.mjs)
import { chromium } from "playwright-core";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { CHROME } from "./lib.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const webDir = join(here, "..", "web");
const iconSvg = readFileSync(join(webDir, "icon.svg"), "utf8");
const logoSvg = readFileSync(join(webDir, "logo.svg"), "utf8");

// Reuse the e2e Chrome-for-Testing binary (lib.mjs pins the revision and honors
// FILEKEY_E2E_CHROME); fall back to system Chrome. Log the pick so a fallback
// render is visible in the output (committed assets depend on the browser used).
const candidates = [CHROME, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"];

let browser;
for (const executablePath of candidates) {
  try { browser = await chromium.launch({ headless: true, executablePath }); console.log("gen-icons: using " + executablePath); break; } catch { /* try next */ }
}
if (!browser) { console.error("gen-icons: no Chromium/Chrome binary found"); process.exit(1); }

// Render an SVG to an exact size×size PNG. Opaque sources (icon.svg) carry their own
// white bg rect; transparent=true renders the glyph full-bleed on a transparent tile
// (logo.svg is 22x27, so preserveAspectRatio centers it at full height).
async function png(svg, size, transparent = false) {
  const page = await browser.newPage({ viewport: { width: size, height: size }, deviceScaleFactor: 1 });
  await page.setContent(
    `<!doctype html><meta charset=utf-8>` +
    `<style>*{margin:0;padding:0}html,body{width:${size}px;height:${size}px;overflow:hidden${transparent ? ";background:transparent" : ""}}` +
    `svg{display:block;width:${size}px;height:${size}px}</style>${svg}`,
    { waitUntil: "load" },
  );
  const buf = await page.screenshot({ type: "png", clip: { x: 0, y: 0, width: size, height: size }, omitBackground: transparent });
  await page.close();
  // PNG IHDR sanity check (mirrors gen-og.mjs): never write a wrong-size frame silently.
  const w = buf.readUInt32BE(16), h = buf.readUInt32BE(20);
  if (w !== size || h !== size) throw new Error(`rendered ${w}x${h}, expected ${size}x${size}`);
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

try {
  const [at180, i192, i512, f16, f32, f48] = await Promise.all([
    png(iconSvg, 180), png(iconSvg, 192), png(iconSvg, 512),
    png(logoSvg, 16, true), png(logoSvg, 32, true), png(logoSvg, 48, true),
  ]);
  writeFileSync(join(webDir, "apple-touch-icon.png"), at180);
  writeFileSync(join(webDir, "icon-192.png"), i192);
  writeFileSync(join(webDir, "icon-512.png"), i512);
  writeFileSync(join(webDir, "favicon.ico"), ico([{ size: 16, buf: f16 }, { size: 32, buf: f32 }, { size: 48, buf: f48 }]));
  console.log("gen-icons: wrote apple-touch-icon.png (180), icon-192.png, icon-512.png, favicon.ico (16/32/48, full-bleed logo) to web/");
} catch (e) {
  console.error("gen-icons: " + String((e && e.message) || e));
  process.exitCode = 1;
} finally {
  await browser.close();
}
