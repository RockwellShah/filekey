// Generates the static FileKey blog from Markdown in reference/blog/ into web/blog/
// (plus web/sitemap.xml, web/feed.xml, and the /privacy /terms /license pages).
// Zero runtime JS on the pages except /blog.js (the theme switch). Hand-rolled
// Markdown (no deps): we author every post, so the supported subset is enough.
// Run: bun run web/build-blog.ts  (also invoked by build:web)
import { readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const webDir = dirname(fileURLToPath(import.meta.url));
const root = join(webDir, "..");
const blogSrc = join(root, "blog");
const blogOut = join(webDir, "blog");
const SITE = "https://filekey.app";
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

const CATEGORIES = [
  { key: "guides", singular: "Guide", label: "Guides", blurb: "Practical walkthroughs for sending sensitive things safely." },
  { key: "comparisons", singular: "Comparison", label: "Comparisons", blurb: "How FileKey compares to the usual ways people send files." },
  { key: "deep-dives", singular: "Deep dive", label: "Deep dives", blurb: "The engineering and cryptography under the hood." },
  { key: "news", singular: "News", label: "News", blurb: "Announcements and what we're building." },
  { key: "updates", singular: "Update", label: "Updates", blurb: "Release notes and what's new in each version." },
];
const catBySingular = (s: string) => CATEGORIES.find((c) => c.singular.toLowerCase() === s.toLowerCase());

const MARK = '<path fill="currentColor" d="M21.9873 8.81596C21.9827 8.75523 21.9678 8.69679 21.9506 8.63607C21.9334 8.57648 21.9174 8.51919 21.8899 8.46419C21.8807 8.44471 21.8796 8.42409 21.8693 8.40461C19.9924 5.27768 17.349 2.63298 14.2221 0.757408C14.2037 0.74595 14.182 0.74595 14.1625 0.735638C14.1086 0.708138 14.0525 0.692095 13.9929 0.674909C13.931 0.657721 13.8715 0.64168 13.8084 0.638242C13.7878 0.638242 13.7706 0.62793 13.75 0.62793H5.5C2.46693 0.62793 0 3.09492 0 6.12793V20.7946C0 23.8277 2.46699 26.2946 5.5 26.2946H16.5C19.5331 26.2946 22 23.8276 22 20.7946V8.87793C22 8.85616 21.9896 8.83773 21.9873 8.81596ZM19.3748 7.96116H18.3332C16.312 7.96116 14.6666 6.31573 14.6666 4.29449V3.25292C16.4793 4.55459 18.073 6.14839 19.3748 7.96116ZM16.4999 24.4612H5.49992C3.47867 24.4612 1.83325 22.8157 1.83325 20.7945V6.12783C1.83325 4.10658 3.47867 2.46116 5.49992 2.46116H12.8332V4.29449C12.8332 7.32756 15.3002 9.79449 18.3332 9.79449H20.1666V20.7945C20.1666 22.8157 18.5212 24.4612 16.4999 24.4612ZM14.6666 14.5462V12.5444C14.6666 10.5232 13.0212 8.87777 10.9999 8.87777C8.97867 8.87777 7.33325 10.5232 7.33325 12.5444V14.5462C6.26877 14.9266 5.49992 15.9338 5.49992 17.1278V19.8778C5.49992 21.3937 6.73397 22.6278 8.24992 22.6278H13.7499C15.2659 22.6278 16.4999 21.3937 16.4999 19.8778V17.1278C16.4999 15.9338 15.7311 14.9266 14.6666 14.5462ZM9.16658 12.5444C9.16658 11.5338 9.98929 10.7111 10.9999 10.7111C12.0105 10.7111 12.8332 11.5338 12.8332 12.5444V14.3778H9.16658V12.5444ZM14.6666 19.8778C14.6666 20.3831 14.2552 20.7944 13.7499 20.7944H8.24992C7.74459 20.7944 7.33325 20.3831 7.33325 19.8778V17.1278C7.33325 16.6224 7.74459 16.2111 8.24992 16.2111H13.7499C14.2552 16.2111 14.6666 16.6224 14.6666 17.1278V19.8778Z"/>';
const SUN = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>';
const INFO = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 8h.01M12 11v5"/></svg>';

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
// Inline formatting. Split on backtick-delimited code spans (capturing group -> odd
// indices hold code content), so links/bold never reach inside code. No placeholders.
function inline(text: string): string {
  const parts = text.split(/`([^`]+)`/);
  let out = "";
  for (let k = 0; k < parts.length; k++) {
    if (k % 2 === 1) { out += '<code class="md-code">' + esc(parts[k]) + "</code>"; continue; }
    let t = esc(parts[k]);
    t = t.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_m, label, url) => '<a href="' + url.replace(/"/g, "&quot;") + '">' + label + "</a>");
    t = t.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    out += t;
  }
  return out;
}
function isBlockStart(l: string): boolean { return /^(#{2,3}\s|```|>\s?|---+\s*$|[-*]\s+|\d+\.\s+|\|)/.test(l); }
function splitRow(l: string): string[] { return l.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((s) => s.trim()); }

function mdToHtml(md: string): string {
  const lines = md.replace(/\r\n/g, "\n").split("\n");
  const out: string[] = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (/^\s*$/.test(line)) { i++; continue; }
    if (/^```/.test(line)) {
      i++; const buf: string[] = [];
      while (i < lines.length && !/^```/.test(lines[i])) { buf.push(lines[i]); i++; }
      i++; out.push('<pre class="md-pre"><code>' + esc(buf.join("\n")) + "</code></pre>"); continue;
    }
    const h = line.match(/^(#{2,3})\s+(.*)$/);
    if (h) { const lvl = h[1].length; out.push("<h" + lvl + ">" + inline(h[2].trim()) + "</h" + lvl + ">"); i++; continue; }
    if (/^---+\s*$/.test(line)) { out.push("<hr>"); i++; continue; }
    if (/^>\s?/.test(line)) {
      const buf: string[] = [];
      while (i < lines.length && /^>\s?/.test(lines[i])) { buf.push(lines[i].replace(/^>\s?/, "")); i++; }
      out.push('<div class="md-note"><span class="md-note-ic">' + INFO + "</span><div>" + mdToHtml(buf.join("\n")) + "</div></div>"); continue;
    }
    if (/^\|.*\|\s*$/.test(line) && i + 1 < lines.length && /^\|[\s:|-]+\|\s*$/.test(lines[i + 1])) {
      const header = splitRow(line); i += 2; const rows: string[][] = [];
      while (i < lines.length && /^\|.*\|\s*$/.test(lines[i])) { rows.push(splitRow(lines[i])); i++; }
      const thead = "<thead><tr>" + header.map((c) => "<th>" + inline(c) + "</th>").join("") + "</tr></thead>";
      const tbody = "<tbody>" + rows.map((r) => "<tr>" + r.map((c) => "<td>" + inline(c) + "</td>").join("") + "</tr>").join("") + "</tbody>";
      out.push('<div class="md-table-wrap"><table class="md-table">' + thead + tbody + "</table></div>"); continue;
    }
    if (/^[-*]\s+/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^[-*]\s+/.test(lines[i])) { items.push(inline(lines[i].replace(/^[-*]\s+/, ""))); i++; }
      out.push('<ul class="md-ul">' + items.map((it) => "<li>" + it + "</li>").join("") + "</ul>"); continue;
    }
    if (/^\d+\.\s+/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\d+\.\s+/.test(lines[i])) { items.push(inline(lines[i].replace(/^\d+\.\s+/, ""))); i++; }
      out.push('<ol class="md-ol">' + items.map((it) => "<li>" + it + "</li>").join("") + "</ol>"); continue;
    }
    // Consume the current line unconditionally so the loop always advances. A line
    // that starts with "|" but isn't a valid table is a block-start with no handler;
    // without this seed, i would never advance and the build would hang.
    const buf: string[] = [lines[i]]; i++;
    while (i < lines.length && !/^\s*$/.test(lines[i]) && !isBlockStart(lines[i])) { buf.push(lines[i]); i++; }
    out.push("<p>" + inline(buf.join(" ")) + "</p>");
  }
  return out.join("\n");
}

function parse(raw: string): { meta: Record<string, string>; body: string } {
  const m = raw.match(/^---\n([\s\S]*?)\n---\n?([\s\S]*)$/);
  if (!m) return { meta: {}, body: raw };
  const meta: Record<string, string> = {};
  for (const line of m[1].split("\n")) {
    const mm = line.match(/^([a-zA-Z0-9_]+):\s*(.*)$/);
    if (!mm) continue;
    let v = mm[2].trim();
    if (v.length >= 2 && ((v[0] === '"' && v.endsWith('"')) || (v[0] === "'" && v.endsWith("'")))) v = v.slice(1, -1);
    meta[mm[1]] = v;
  }
  return { meta, body: m[2] };
}
function fmtDate(iso: string): string { const [y, mo, d] = iso.split("-").map(Number); return MONTHS[mo - 1] + " " + d + ", " + y; }
function rfc822(iso: string): string { return new Date(iso + "T12:00:00Z").toUTCString(); }
function readMin(body: string): number { const w = body.trim().split(/\s+/).filter(Boolean).length; return Math.max(1, Math.round(w / 200)); }
// Reduce a frontmatter slug/path segment to a safe clean-URL token: lowercase
// alphanumerics and hyphens only. Neutralizes "../", quotes, and anything else
// that could escape the output directory or inject into href/XML/sitemap.
function slugify(s: string): string { return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "post"; }

type Post = { slug: string; title: string; description: string; date: string; dateFmt: string; cat: typeof CATEGORIES[number]; author: string; html: string; readMin: number; url: string; next?: Post };
type Page = { title: string; description: string; path: string; html: string };

function metaLine(p: Post, link: boolean): string {
  const cat = link ? '<a class="cat" href="/blog/' + p.cat.key + '/">' + esc(p.cat.singular) + "</a>" : '<span class="cat">' + esc(p.cat.singular) + "</span>";
  return cat + " &middot; " + p.dateFmt + " &middot; " + p.readMin + " min read";
}
function postRow(p: Post): string {
  return '<a class="item" href="' + p.url + '"><p class="meta">' + metaLine(p, false) + "</p><h3>" + esc(p.title) + '</h3><p class="dek">' + esc(p.description) + "</p></a>";
}
function chips(activeKey: string, cats: typeof CATEGORIES): string {
  const all = '<a class="chip' + (activeKey === "all" ? " on" : "") + '" href="/blog/">All</a>';
  const rest = cats.map((c) => '<a class="chip' + (activeKey === c.key ? " on" : "") + '" href="/blog/' + c.key + '/">' + c.label + "</a>").join("");
  return '<nav class="chips">' + all + rest + "</nav>";
}
function ctaCard(): string {
  return '<aside class="cta"><div><h4>Send files the safe way</h4><p>Free, open source, end-to-end encrypted. No account needed.</p></div><a class="btn" href="/">Open FileKey</a></aside>';
}
function header(): string {
  return '<header class="hd"><div class="wrap hd-in"><a class="brand" href="/blog/"><svg class="mk" width="17" height="21" viewBox="0 0 22 27" aria-hidden="true">' + MARK + '</svg><span class="wm">FileKey</span><span class="badge">Blog</span></a><div class="hd-right"><button class="theme-btn" type="button" id="themeBtn" aria-label="Switch theme">' + SUN + '</button><a class="btn" href="/">Open FileKey</a></div></div></header>';
}
function footer(): string {
  return '<footer class="ft"><div class="wrap ft-in"><nav class="ft-links"><a href="/">Home</a><a href="/terms/">Terms</a><a href="/privacy/">Privacy</a><a href="/license/">License</a><a href="mailto:contact@filekey.app">Contact</a></nav><p class="ft-note">No trackers, no cookies, no analytics.</p><p class="ft-copy">&copy; 2026 FileKey</p></div></footer>';
}
function layout(o: { title: string; description: string; canonical: string; ogType?: string; ogTitle?: string; main: string }): string {
  return '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1">\n' +
    "<title>" + esc(o.title) + "</title>\n" +
    '<meta name="description" content="' + esc(o.description) + '">\n' +
    '<link rel="canonical" href="' + o.canonical + '">\n' +
    '<link rel="icon" href="/logo.svg" type="image/svg+xml">\n' +
    '<meta name="theme-color" content="#ffffff" media="(prefers-color-scheme: light)">\n' +
    '<meta name="theme-color" content="#0c0c0e" media="(prefers-color-scheme: dark)">\n' +
    '<meta property="og:type" content="' + (o.ogType || "website") + '">\n' +
    '<meta property="og:site_name" content="FileKey">\n' +
    '<meta property="og:title" content="' + esc(o.ogTitle || o.title) + '">\n' +
    '<meta property="og:description" content="' + esc(o.description) + '">\n' +
    '<meta property="og:url" content="' + o.canonical + '">\n' +
    '<meta property="og:image" content="' + SITE + '/og.png">\n' +
    '<meta name="twitter:card" content="summary_large_image">\n' +
    '<meta name="twitter:title" content="' + esc(o.ogTitle || o.title) + '">\n' +
    '<meta name="twitter:description" content="' + esc(o.description) + '">\n' +
    '<meta name="twitter:image" content="' + SITE + '/og.png">\n' +
    '<link rel="alternate" type="application/rss+xml" title="FileKey Blog" href="/feed.xml">\n' +
    '<script src="/blog.js"></script>\n' +
    '<link rel="stylesheet" href="/blog.css">\n' +
    "</head>\n<body>\n" + header() + '\n<main class="wrap">\n' + o.main + "\n</main>\n" + footer() + "\n</body>\n</html>\n";
}

function write(path: string, html: string) { mkdirSync(dirname(path), { recursive: true }); writeFileSync(path, html); }

// ---- build ----
if (existsSync(blogOut)) rmSync(blogOut, { recursive: true, force: true });

const files = existsSync(blogSrc) ? readdirSync(blogSrc).filter((f) => f.endsWith(".md")) : [];
const posts: Post[] = [];
const pages: Page[] = [];

for (const f of files) {
  const { meta, body } = parse(readFileSync(join(blogSrc, f), "utf8"));
  const html = mdToHtml(body);
  if (meta.path) { const safePath = "/" + meta.path.replace(/^\/+/, "").split("/").map(slugify).filter(Boolean).join("/"); pages.push({ title: meta.title || "", description: meta.description || "", path: safePath, html }); continue; }
  const cat = catBySingular(meta.category || "");
  if (!cat) { console.warn("skip " + f + " (unknown category: " + meta.category + ")"); continue; }
  const slug = slugify(meta.slug || f.replace(/^\d{4}-\d{2}-\d{2}-/, "").replace(/\.md$/, ""));
  posts.push({ slug, title: meta.title || slug, description: meta.description || "", date: meta.date || "1970-01-01", dateFmt: fmtDate(meta.date || "1970-01-01"), cat, author: meta.author || "FileKey.app", html, readMin: readMin(body), url: "/blog/" + slug + "/" });
}
posts.sort((a, b) => (a.date < b.date ? 1 : -1));
posts.forEach((p, i) => { if (posts.length > 1) p.next = posts[(i + 1) % posts.length]; });

const usedCats = CATEGORIES.filter((c) => posts.some((p) => p.cat.key === c.key));
// Show the chip row once at least two categories have posts. Chips render only
// populated categories (see usedCats), so there are never empty drawers.
const showChips = usedCats.length >= 2;

// Home
const [feat, ...rest] = posts;
const homeMain =
  '<div class="mast"><h1>Sending sensitive things safely</h1><p class="tag">Plain-language guides, and the engineering underneath.</p></div>\n' +
  (showChips ? chips("all", usedCats) : "") +
  (feat ? '<a class="feat" href="' + feat.url + '"><p class="meta">' + metaLine(feat, false) + "</p><h2>" + esc(feat.title) + '</h2><p class="dek">' + esc(feat.description) + "</p></a>\n" : "") +
  rest.map(postRow).join("\n") + "\n" + ctaCard();
write(join(blogOut, "index.html"), layout({ title: "FileKey Blog", description: "Plain-language guides to sending sensitive things safely, and the engineering underneath.", canonical: SITE + "/blog/", main: homeMain }));

// Categories (only those with posts)
for (const c of usedCats) {
  const cp = posts.filter((p) => p.cat.key === c.key);
  const main = '<div class="mast"><h1>' + esc(c.label) + '</h1><p class="tag">' + esc(c.blurb) + "</p></div>\n" +
    (showChips ? chips(c.key, usedCats) : "") +
    (cp.length ? cp.map(postRow).join("\n") : '<p class="empty">No posts here yet.</p>') + "\n" + ctaCard();
  write(join(blogOut, c.key, "index.html"), layout({ title: c.label + " &middot; FileKey Blog", description: c.blurb, canonical: SITE + "/blog/" + c.key + "/", main }));
}

// Articles
for (const p of posts) {
  const main = '<article class="art"><p class="meta">' + metaLine(p, true) + "</p><h1>" + esc(p.title) + "</h1>" +
    (p.author ? '<p class="byline">By ' + esc(p.author) + "</p>" : "") +
    '<div class="md-body">' + p.html + "</div>" + ctaCard() +
    (p.next ? '<nav class="next"><p>Read next</p><a href="' + p.next.url + '">' + esc(p.next.title) + " &rarr;</a></nav>" : "") +
    "</article>";
  write(join(blogOut, p.slug, "index.html"), layout({ title: p.title + " &middot; FileKey", description: p.description, canonical: SITE + p.url, ogType: "article", main }));
}

// Standalone pages (privacy, terms, license)
for (const pg of pages) {
  const main = '<article class="art page"><h1>' + esc(pg.title) + '</h1><div class="md-body">' + pg.html + "</div></article>";
  write(join(webDir, pg.path.replace(/^\//, ""), "index.html"), layout({ title: pg.title + " &middot; FileKey", description: pg.description, canonical: SITE + pg.path + "/", main }));
}

// sitemap.xml (app + blog)
const urls = [SITE + "/", SITE + "/blog/"]
  .concat(usedCats.map((c) => SITE + "/blog/" + c.key + "/"))
  .concat(posts.map((p) => SITE + p.url))
  .concat(pages.map((pg) => SITE + pg.path + "/"));
const sitemap = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' +
  urls.map((u) => "  <url><loc>" + u + "</loc></url>").join("\n") + "\n</urlset>\n";
writeFileSync(join(webDir, "sitemap.xml"), sitemap);

// feed.xml (RSS 2.0)
const items = posts.map((p) =>
  "    <item>\n      <title>" + esc(p.title) + "</title>\n      <link>" + SITE + p.url + "</link>\n      <guid>" + SITE + p.url + "</guid>\n      <pubDate>" + rfc822(p.date) + "</pubDate>\n      <description>" + esc(p.description) + "</description>\n    </item>"
).join("\n");
const feed = '<?xml version="1.0" encoding="UTF-8"?>\n<rss version="2.0">\n  <channel>\n    <title>FileKey Blog</title>\n    <link>' + SITE + "/blog/</link>\n    <description>Plain-language guides to sending sensitive things safely, and the engineering underneath.</description>\n    <language>en</language>\n" + items + "\n  </channel>\n</rss>\n";
writeFileSync(join(webDir, "feed.xml"), feed);

console.log("wrote web/blog/ (" + posts.length + " posts, " + usedCats.length + " categories, " + pages.length + " pages) + sitemap.xml + feed.xml");
