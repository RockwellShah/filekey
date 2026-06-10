// Bundles web/recover.ts (UI + the real src/ crypto core) into ONE self-contained,
// offline, dependency-free web/recover.html — the break-glass file a user keeps so they
// can decrypt with just their recovery code if FileKey ever disappears.
// Run: bun run web/build-recover.ts  (also invoked by build:web)
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const webDir = dirname(fileURLToPath(import.meta.url));

const result = await Bun.build({
  entrypoints: [join(webDir, "recover.ts")],
  target: "browser",
  minify: true,
  format: "iife", // a plain inline <script> — works when opened directly from disk (file://)
});
if (!result.success) {
  for (const log of result.logs) console.error(log);
  throw new Error("recover.ts bundle failed");
}
let js = await result.outputs[0]!.text();
js = js.replace(/<\/script>/gi, "<\\/script>"); // safe to inline even if a string contains </script>

// Strict no-egress CSP: default-src 'none' denies every fetch directive by default, so the only things
// that load are the inline <script>/<style> we explicitly allow. connect-src 'none' blocks all
// fetch/XHR/WebSocket/beacon and (with no script-src host) an injected external <script> can't load or
// exfiltrate via its URL — the page physically cannot phone home. Inline <script>/<style> and blob
// downloads still work (a `download` anchor isn't a CSP fetch).
const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'none'; font-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>FileKey · Offline Recovery</title>
</head>
<body>
<noscript>This recovery tool needs JavaScript. It runs entirely on your device and makes no network requests.</noscript>
<script>${js}</script>
</body>
</html>
`;

const out = join(webDir, "recover.html");
writeFileSync(out, html);
console.log(`wrote web/recover.html (${(html.length / 1024).toFixed(0)} KB, fully self-contained)`);
