// FileKey — Offline Recovery Tool (entry for the single self-contained recover.html).
//
// Break-glass utility: decrypt your .filekey files using your RECOVERY CODE alone —
// no passkey, no account, no server — even if filekey.app no longer exists. It reuses
// the exact audited core (src/), so it decrypts byte-for-byte what FileKey produced:
//
//     recovery code  ->  master_prk  ->  deriveIdentity(file's namespace)  ->  decrypt
//
// Everything runs locally; the page makes zero network requests (enforced by its CSP).
// Bundled into web/recover.html by web/build-recover.ts.
import {
  decodeRecoveryAuto,
  deriveIdentity,
  Namespace,
  NamespaceSet,
  decrypt,
  FileKeyError,
  type Metadata,
} from "../src/index.js";

const LOGO = `<svg viewBox="0 0 22 27" fill="#1377F9" width="26" height="32" aria-hidden="true"><path d="M21.9873 8.81596C21.9827 8.75523 21.9678 8.69679 21.9506 8.63607C21.9334 8.57648 21.9174 8.51919 21.8899 8.46419C21.8807 8.44471 21.8796 8.42409 21.8693 8.40461C19.9924 5.27768 17.349 2.63298 14.2221 0.757408C14.2037 0.74595 14.182 0.74595 14.1625 0.735638C14.1086 0.708138 14.0525 0.692095 13.9929 0.674909C13.931 0.657721 13.8715 0.64168 13.8084 0.638242C13.7878 0.638242 13.7706 0.62793 13.75 0.62793H5.5C2.46693 0.62793 0 3.09492 0 6.12793V20.7946C0 23.8277 2.46699 26.2946 5.5 26.2946H16.5C19.5331 26.2946 22 23.8276 22 20.7946V8.87793C22 8.85616 21.9896 8.83773 21.9873 8.81596ZM19.3748 7.96116H18.3332C16.312 7.96116 14.6666 6.31573 14.6666 4.29449V3.25292C16.4793 4.55459 18.073 6.14839 19.3748 7.96116ZM16.4999 24.4612H5.49992C3.47867 24.4612 1.83325 22.8157 1.83325 20.7945V6.12783C1.83325 4.10658 3.47867 2.46116 5.49992 2.46116H12.8332V4.29449C12.8332 7.32756 15.3002 9.79449 18.3332 9.79449H20.1666V20.7945C20.1666 22.8157 18.5212 24.4612 16.4999 24.4612ZM14.6666 14.5462V12.5444C14.6666 10.5232 13.0212 8.87777 10.9999 8.87777C8.97867 8.87777 7.33325 10.5232 7.33325 12.5444V14.5462C6.26877 14.9266 5.49992 15.9338 5.49992 17.1278V19.8778C5.49992 21.3937 6.73397 22.6278 8.24992 22.6278H13.7499C15.2659 22.6278 16.4999 21.3937 16.4999 19.8778V17.1278C16.4999 15.9338 15.7311 14.9266 14.6666 14.5462ZM9.16658 12.5444C9.16658 11.5338 9.98929 10.7111 10.9999 10.7111C12.0105 10.7111 12.8332 11.5338 12.8332 12.5444V14.3778H9.16658V12.5444ZM14.6666 19.8778C14.6666 20.3831 14.2552 20.7944 13.7499 20.7944H8.24992C7.74459 20.7944 7.33325 20.3831 7.33325 19.8778V17.1278C7.33325 16.6224 7.74459 16.2111 8.24992 16.2111H13.7499C14.2552 16.2111 14.6666 16.6224 14.6666 17.1278V19.8778Z"/></svg>`;

const CSS = `
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,system-ui,"Segoe UI",Roboto,sans-serif;color:#0d0d0d;background:#fff;line-height:1.5;-webkit-font-smoothing:antialiased}
.wrap{max-width:640px;margin:0 auto;padding:44px 24px 96px}
.hd{display:flex;align-items:center;gap:11px;margin-bottom:8px}
.hd h1{font-size:22px;font-weight:700;margin:0;letter-spacing:-.02em}
.sub{color:#555;margin:0 0 30px;font-size:15px}
.step{margin:0 0 22px}
.step label{display:block;font-weight:600;font-size:14px;margin-bottom:7px}
.hint{color:#888;font-size:13px;margin:7px 0 0}
textarea,input[type=text]{width:100%;border:1px solid #0000001f;border-radius:10px;padding:12px 14px;font-size:15px;font-family:inherit;color:#0d0d0d;outline:none;background:#fff}
textarea{min-height:84px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;line-height:1.6}
textarea:focus,input[type=text]:focus{border-color:#1377f9aa}
#drop{border:1.5px dashed #c8c8ce;border-radius:12px;padding:26px;text-align:center;color:#666;cursor:pointer;background:#fbfbfd;font-size:14px}
#drop:hover{border-color:#9aa}
#drop.over{border-color:#1377F9;background:#1377f90d;color:#1377F9}
#files_list{list-style:none;padding:0;margin:12px 0 0}
#files_list li{font-size:13px;color:#444;padding:3px 0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
#go{background:#1377F9;color:#fff;border:none;border-radius:10px;padding:13px 22px;font-size:15px;font-weight:600;cursor:pointer;font-family:inherit}
#go:hover{background:#0e63d6}
#go:disabled{opacity:.5;cursor:default}
#out{margin-top:24px;display:flex;flex-direction:column;gap:10px}
.res{border:1px solid #0000001a;border-radius:10px;padding:12px 14px;display:flex;align-items:center;gap:12px;font-size:14px}
.res.ok{background:#34c75914;border-color:#34c75955}
.res.err{background:#ff3b3010;border-color:#ff3b3055}
.res .name{flex-grow:1;word-break:break-all}
.res a{color:#1377F9;font-weight:600;text-decoration:none;white-space:nowrap;cursor:pointer}
.res a:hover{text-decoration:underline}
#msg{font-size:14px;color:#c1121f;margin:12px 0 0}
.note{margin-top:42px;font-size:12.5px;color:#999;border-top:1px solid #0000000f;padding-top:16px;line-height:1.6}
.note b{color:#666}
`;

const MARKUP = `
<div class="wrap">
  <div class="hd">${LOGO}<h1>FileKey · Offline Recovery</h1></div>
  <p class="sub">Decrypt your FileKey files with your <b>recovery code</b>. No passkey, no account, no server. Works even if filekey.app is gone. Everything happens on this device.</p>

  <div class="step">
    <label for="rec">1 &middot; Your recovery code</label>
    <textarea id="rec" spellcheck="false" autocapitalize="off" autocorrect="off" autocomplete="off" placeholder="Insert your 24 recovery words"></textarea>
  </div>

  <div class="step">
    <label for="site">2 &middot; FileKey site</label>
    <input id="site" type="text" spellcheck="false" autocapitalize="off" autocorrect="off" autocomplete="off" value="filekey.app">
    <p class="hint">The site your files were encrypted on (usually filekey.app). Files are cryptographically bound to their site.</p>
  </div>

  <div class="step">
    <label>3 &middot; Your .filekey files</label>
    <div id="drop">Drop files here, or click to choose</div>
    <input id="picker" type="file" multiple hidden>
    <ul id="files_list"></ul>
  </div>

  <button id="go">Decrypt</button>
  <p id="msg" hidden></p>
  <div id="out"></div>

  <p class="note"><b>100% offline.</b> This page makes no network requests. Your recovery code and files never leave this device. It runs the same open-source cryptography as FileKey. Save this file somewhere safe; you don't need the internet to use it.</p>
</div>
`;

const style = document.createElement("style");
style.textContent = CSS;
document.head.appendChild(style);
document.body.innerHTML = MARKUP;

const byId = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const recEl = byId<HTMLTextAreaElement>("rec");
const siteEl = byId<HTMLInputElement>("site");
const dropEl = byId<HTMLElement>("drop");
const pickerEl = byId<HTMLInputElement>("picker");
const listEl = byId<HTMLElement>("files_list");
const outEl = byId<HTMLElement>("out");
const msgEl = byId<HTMLElement>("msg");
const goEl = byId<HTMLButtonElement>("go");

let chosen: File[] = [];

const escapeHtml = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const fmtSize = (n: number) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`);
// Also strip Unicode bidi override/isolate controls (U+202A–202E, U+2066–2069): a sender-controlled
// filename can otherwise use RLO to disguise its extension on display/save (e.g. "x<RLO>gpj.exe").
const sanitize = (n: string) => (n.replace(/[\u202a-\u202e\u2066-\u2069]/g, "").replace(/[/\\]/g, "_").replace(/[\x00-\x1f]/g, "").trim() || "decrypted").slice(0, 200);

function renderList() {
  listEl.innerHTML = chosen.map((f) => `<li>${escapeHtml(f.name)} &middot; ${fmtSize(f.size)}</li>`).join("");
}
function addFiles(fl: FileList | null) {
  if (!fl) return;
  for (const f of Array.from(fl)) chosen.push(f);
  renderList();
}
function setMsg(t: string) {
  msgEl.textContent = t;
  msgEl.hidden = !t;
}

dropEl.addEventListener("click", () => pickerEl.click());
pickerEl.addEventListener("change", () => { addFiles(pickerEl.files); pickerEl.value = ""; });
for (const e of ["dragenter", "dragover"]) dropEl.addEventListener(e, (ev) => { ev.preventDefault(); dropEl.classList.add("over"); });
for (const e of ["dragleave", "dragend"]) dropEl.addEventListener(e, (ev) => { ev.preventDefault(); dropEl.classList.remove("over"); });
dropEl.addEventListener("drop", (ev) => { ev.preventDefault(); dropEl.classList.remove("over"); addFiles((ev as DragEvent).dataTransfer?.files ?? null); });
goEl.addEventListener("click", () => void run());

// Canonicalize a pasted site to a bare lowercase host (handles https://host/path, ports, trailing dot).
function canonSite(s: string): string {
  const host = s.trim().toLowerCase().replace(/^[a-z]+:\/\//, "").replace(/[/:?#].*$/, "").replace(/\.$/, "");
  // Match the app's deploymentRpId normalization (registrable domain) so a file encrypted on a
  // subdomain deployment recovers under the same namespace the app used to encrypt it.
  if (host === "localhost") return host;
  const parts = host.split(".");
  return parts.length > 2 ? parts.slice(-2).join(".") : host;
}

function download(bytes: Uint8Array, name: string, mime: string) {
  const blob = new Blob([bytes as unknown as BlobPart], { type: mime || "application/octet-stream" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 8000);
}

function addOk(srcName: string, meta: Metadata, plaintext: Uint8Array) {
  const name = sanitize(meta.filename || srcName.replace(/\.filekey$/i, "") || "decrypted");
  const row = document.createElement("div");
  row.className = "res ok";
  row.innerHTML = `<span class="name">✓ <b>${escapeHtml(name)}</b> &middot; ${fmtSize(plaintext.length)}</span>`;
  const a = document.createElement("a");
  a.textContent = "Download";
  a.addEventListener("click", () => download(plaintext, name, meta.mimeType));
  row.appendChild(a);
  outEl.appendChild(row);
}
function addErr(srcName: string, e: unknown) {
  const code = e instanceof FileKeyError ? e.code : "";
  const why =
    code === "wrong_namespace" ? "encrypted for a different site (set the correct domain in step 2)"
    : code === "auth_failed" ? "couldn't decrypt (wrong recovery code, or this file wasn't encrypted for you)"
    : (e as Error).message || "couldn't read this file";
  const row = document.createElement("div");
  row.className = "res err";
  row.innerHTML = `<span class="name">✗ ${escapeHtml(srcName)}: ${escapeHtml(why)}</span>`;
  outEl.appendChild(row);
}

async function run() {
  setMsg("");
  outEl.innerHTML = "";
  const code = recEl.value.trim();
  const siteRaw = siteEl.value.trim();
  const site = canonSite(siteRaw);
  if (!code) { setMsg("Enter your recovery code in step 1."); return; }
  if (!chosen.length) { setMsg("Add at least one .filekey file in step 3."); return; }

  let nsSet: NamespaceSet;
  try { nsSet = new NamespaceSet([site]); }
  catch { setMsg(`"${siteRaw}" isn't a valid site domain.`); return; }

  let masterPrk: Uint8Array;
  try { masterPrk = decodeRecoveryAuto(code, nsSet).masterPrk; }
  catch (e) {
    setMsg((e as FileKeyError).code === "wrong_namespace"
      ? "That recovery code is for a different site. Set the correct domain in step 2."
      : `That doesn't look like a valid recovery code: ${(e as Error).message}`);
    return;
  }

  goEl.disabled = true;
  goEl.textContent = "Decrypting…";
  for (const f of chosen) {
    try {
      const bytes = new Uint8Array(await f.arrayBuffer());
      const res = await decrypt({
        file: bytes,
        namespaces: nsSet,
        resolveIdentity: (ns: Namespace) => deriveIdentity(masterPrk, ns),
      });
      addOk(f.name, res.metadata, res.plaintext);
    } catch (e) {
      addErr(f.name, e);
    }
  }
  goEl.disabled = false;
  goEl.textContent = "Decrypt";
}

// Defensive: Web Crypto needs a secure context. file:// IS a secure context in major desktop
// browsers, but if one ever withholds it for local files, fail loudly instead of cryptically.
if (typeof crypto === "undefined" || !crypto.subtle) {
  setMsg("Your browser disabled secure crypto for local files. Open this page over http(s)/localhost (e.g. run a local server in this folder), or try Chrome or Firefox.");
  goEl.disabled = true;
}
