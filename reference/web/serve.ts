// Minimal static dev server for the FileKey reference app.
// Serves on http://localhost:8787 — localhost is a WebAuthn secure context.
import { fileURLToPath } from "node:url";
import { dirname, join, normalize } from "node:path";

const webDir = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT ?? 8787);

const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".map": "application/json; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".svg": "image/svg+xml; charset=utf-8",
  ".webmanifest": "application/manifest+json; charset=utf-8",
  ".woff2": "font/woff2",
};

function contentType(path: string): string {
  const dot = path.lastIndexOf(".");
  return TYPES[path.slice(dot)] ?? "application/octet-stream";
}

const server = Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url);
    let pathname = decodeURIComponent(url.pathname);
    if (pathname === "/") pathname = "/index.html";
    // Prevent path traversal.
    const rel = normalize(pathname).replace(/^(\.\.[/\\])+/, "");
    const filePath = join(webDir, rel);
    if (!filePath.startsWith(webDir)) return new Response("forbidden", { status: 403 });

    const file = Bun.file(filePath);
    if (!(await file.exists())) return new Response("not found", { status: 404 });
    return new Response(file, { headers: { "content-type": contentType(filePath) } });
  },
});

console.log(`FileKey reference app → http://localhost:${server.port}`);
console.log(`(localhost is a WebAuthn secure context; enroll a passkey and test the full flow.)`);
