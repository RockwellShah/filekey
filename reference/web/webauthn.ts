// WebAuthn PRF provider (browser-only). Produces the 32-byte prf_secret the core consumes.
// The credential is discoverable (residentKey: required), so re-authentication needs no
// stored credential ID — nothing is stored beyond the passkey (§1.1 rule 1).
import { PRF_INPUT_SALT, bs } from "../src/index.js";

export interface PrfSupport {
  webauthn: boolean;
  secureContext: boolean;
}

export function checkSupport(): PrfSupport {
  return {
    webauthn: typeof PublicKeyCredential !== "undefined" && !!navigator.credentials,
    secureContext: window.isSecureContext,
  };
}

/**
 * Browser-level PRF capability via getClientCapabilities() (where available).
 * Returns false only when the browser explicitly reports no PRF; true when it reports
 * PRF; undefined when unknown (older browsers without the API, or no explicit answer) —
 * the caller should then just attempt the ceremony. Note this reflects the *browser*,
 * not the chosen authenticator, so a `true` still needs the post-create prf.enabled
 * check (e.g. Windows Hello before 11 25H2 reports browser-PRF but can't do it).
 */
export async function prfBrowserSupport(): Promise<boolean | undefined> {
  const PKC = typeof PublicKeyCredential !== "undefined"
    ? (PublicKeyCredential as unknown as { getClientCapabilities?: () => Promise<Record<string, boolean>> })
    : undefined;
  if (!PKC?.getClientCapabilities) return undefined;
  try {
    const v = (await PKC.getClientCapabilities())["extension:prf"];
    return v === true ? true : v === false ? false : undefined;
  } catch { return undefined; }
}

function randomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

/**
 * The RP-ID / namespace for this deployment, normalized to the registrable domain (apex) so the
 * derived identity survives being served from a subdomain (v1.filekey.app, www.filekey.app, …).
 * This is the same normalization v1 uses, so both apps agree on the rp.id and share the passkey.
 * localhost and bare (≤2-label) hostnames are returned unchanged.
 */
export function deploymentRpId(): string {
  const host = location.hostname;
  if (host === "localhost") return host;
  const parts = host.split(".");
  return parts.length > 2 ? parts.slice(-2).join(".") : host;
}

/**
 * Enroll a new passkey with the PRF extension enabled (§4.1). Throws if PRF is unsupported.
 * Returns nothing persistent — the credential is discoverable.
 */
export async function enrollPasskey(displayName: string): Promise<void> {
  const cred = (await navigator.credentials.create({
    publicKey: {
      rp: { id: deploymentRpId(), name: "FileKey Reference" },
      user: { id: bs(randomBytes(16)), name: displayName || "FileKey", displayName: displayName || "FileKey" },
      challenge: bs(randomBytes(32)),
      pubKeyCredParams: [
        { type: "public-key", alg: -7 }, // ES256
        { type: "public-key", alg: -257 }, // RS256
      ],
      authenticatorSelection: { residentKey: "required", userVerification: "preferred" },
      timeout: 60_000,
      extensions: { prf: {} } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;

  if (!cred) throw new Error("passkey creation returned null");
  const ext = cred.getClientExtensionResults() as { prf?: { enabled?: boolean } };
  if (!ext.prf?.enabled) {
    throw new Error("this authenticator/browser does not support the PRF extension");
  }
}

/**
 * Perform a PRF assertion and return the 32-byte prf_secret (§4.1).
 * Uses a discoverable-credential get() with no allowCredentials.
 */
export async function getPrfSecret(): Promise<Uint8Array> {
  const assertion = (await navigator.credentials.get({
    publicKey: {
      rpId: deploymentRpId(),
      challenge: bs(randomBytes(32)),
      userVerification: "preferred",
      timeout: 60_000,
      extensions: {
        prf: { eval: { first: bs(PRF_INPUT_SALT) } },
      } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;

  if (!assertion) throw new Error("assertion returned null");
  const ext = assertion.getClientExtensionResults() as { prf?: { results?: { first?: ArrayBuffer } } };
  const first = ext.prf?.results?.first;
  if (!first) {
    throw new Error("no PRF output returned (authenticator may not support PRF, or no passkey enrolled here)");
  }
  const out = new Uint8Array(first);
  if (out.length !== 32) throw new Error(`PRF output is ${out.length} bytes, expected 32`);
  return out;
}
