/**
 * App Store Connect API — the "rejection recovery" half of Ship Doctor.
 *
 * Auth uses a JWT signed with your App Store Connect API key (.p8, ES256).
 * We sign it with Node's built-in crypto (no jsonwebtoken dependency) using the
 * IEEE-P1363 (JOSE) signature encoding Apple requires.
 *
 * Credentials come from env vars so keys never touch the repo:
 *   ASC_KEY_ID      – the 10-char Key ID
 *   ASC_ISSUER_ID   – the issuer UUID from Users and Access → Integrations
 *   ASC_PRIVATE_KEY – the .p8 contents, OR
 *   ASC_PRIVATE_KEY_PATH – path to the .p8 file
 */
import { createSign } from "node:crypto";
import { readFile } from "node:fs/promises";

const ASC_BASE = "https://api.appstoreconnect.apple.com/v1";

export interface AscCreds {
  keyId: string;
  issuerId: string;
  privateKeyPem: string;
}

export class AscConfigError extends Error {}

/** Load credentials from the environment, with a helpful error if incomplete. */
export async function loadAscCreds(): Promise<AscCreds> {
  const keyId = process.env.ASC_KEY_ID;
  const issuerId = process.env.ASC_ISSUER_ID;
  let privateKeyPem = process.env.ASC_PRIVATE_KEY;
  const keyPath = process.env.ASC_PRIVATE_KEY_PATH;

  if (!privateKeyPem && keyPath) {
    try {
      privateKeyPem = await readFile(keyPath, "utf8");
    } catch {
      throw new AscConfigError(`ASC_PRIVATE_KEY_PATH is set but the file could not be read: ${keyPath}`);
    }
  }

  const missing: string[] = [];
  if (!keyId) missing.push("ASC_KEY_ID");
  if (!issuerId) missing.push("ASC_ISSUER_ID");
  if (!privateKeyPem) missing.push("ASC_PRIVATE_KEY or ASC_PRIVATE_KEY_PATH");
  if (missing.length) {
    throw new AscConfigError(
      `App Store Connect is not configured. Missing: ${missing.join(", ")}.\n\n` +
        `Create an API key at App Store Connect → Users and Access → Integrations → App Store Connect API, ` +
        `then set these env vars in the MCP server config.`
    );
  }

  return { keyId: keyId!, issuerId: issuerId!, privateKeyPem: privateKeyPem! };
}

const b64url = (input: Buffer | string): string =>
  Buffer.from(input).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/**
 * Build a short-lived ES256 JWT for the App Store Connect API.
 * NOTE: crypto's default EC signature is DER; Apple requires JOSE (raw r||s),
 * hence dsaEncoding: "ieee-p1363".
 *
 * `iatSeconds` must be supplied by the caller (workflow scripts and tests can't
 * call Date.now()); the MCP tool layer passes real time.
 */
export function buildAscJwt(creds: AscCreds, iatSeconds: number): string {
  const header = { alg: "ES256", kid: creds.keyId, typ: "JWT" };
  const payload = {
    iss: creds.issuerId,
    iat: iatSeconds,
    exp: iatSeconds + 15 * 60, // Apple caps token lifetime at 20 minutes.
    aud: "appstoreconnect-v1",
  };
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const signer = createSign("SHA256");
  signer.update(signingInput);
  signer.end();
  const signature = signer.sign({ key: creds.privateKeyPem, dsaEncoding: "ieee-p1363" });
  return `${signingInput}.${b64url(signature)}`;
}

async function ascFetch(path: string, token: string): Promise<any> {
  const res = await fetch(`${ASC_BASE}${path}`, {
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`App Store Connect API ${res.status} on ${path}: ${body.slice(0, 500)}`);
  }
  return res.json();
}

/** List apps on the account. */
export async function listApps(token: string): Promise<{ id: string; name: string; bundleId: string }[]> {
  const data = await ascFetch("/apps?limit=200", token);
  return (data.data ?? []).map((a: any) => ({
    id: a.id,
    name: a.attributes?.name ?? "(unknown)",
    bundleId: a.attributes?.bundleId ?? "(unknown)",
  }));
}

export interface RejectionMessage {
  versionString?: string;
  state?: string;
  createdDate?: string;
  message: string;
}

/**
 * Fetch the latest App Store review rejection feedback for an app.
 * Walks: app → appStoreVersions → appStoreReviewDetail / resolution-center-ish
 * data exposed via the appStoreVersion's review state and any reject reasons.
 */
export async function getRejections(token: string, appId: string): Promise<RejectionMessage[]> {
  const versions = await ascFetch(
    `/apps/${appId}/appStoreVersions?limit=10&fields[appStoreVersions]=versionString,appStoreState,createdDate`,
    token
  );
  const out: RejectionMessage[] = [];
  for (const v of versions.data ?? []) {
    const state: string = v.attributes?.appStoreState ?? "";
    const versionString: string = v.attributes?.versionString;
    const createdDate: string = v.attributes?.createdDate;
    // States that indicate a rejection / metadata reject / dev-rejected.
    if (/REJECT|METADATA_REJECTED|DEVELOPER_REJECTED|INVALID/i.test(state)) {
      // Attempt to pull the human review feedback attached to this version.
      let message = `Version ${versionString} is in state ${state}.`;
      try {
        const detail = await ascFetch(
          `/appStoreVersions/${v.id}/appStoreReviewDetail`,
          token
        );
        const notes = detail?.data?.attributes?.contactEmail
          ? `Review contact: ${detail.data.attributes.contactEmail}. `
          : "";
        message = `${notes}${message} Open Resolution Center in App Store Connect for the full reviewer message.`;
      } catch {
        /* review detail not always available; keep the state summary */
      }
      out.push({ versionString, state, createdDate, message });
    }
  }
  return out;
}

/**
 * Common App Store Review Guideline numbers → plain-language summary + typical fix.
 * Lets Claude map a rejection's guideline reference to something actionable.
 */
export const GUIDELINE_MAP: Record<string, { title: string; summary: string; fix: string }> = {
  "2.1": {
    title: "App Completeness",
    summary: "Crashes, bugs, placeholder content, broken links, or a build that reviewers couldn't fully exercise (often: no demo account).",
    fix: "Provide working demo credentials in App Review notes, fix crashes, remove placeholder/'lorem ipsum' content.",
  },
  "2.3": {
    title: "Accurate Metadata",
    summary: "Screenshots, description, or preview don't match the actual app, or reference other platforms.",
    fix: "Update screenshots/description to reflect the real app; remove Android/other-platform mentions.",
  },
  "2.3.1": {
    title: "Hidden/undocumented features",
    summary: "App contains hidden, dormant, or undocumented features.",
    fix: "Remove any hidden functionality or feature flags reviewers can't see.",
  },
  "3.1.1": {
    title: "In-App Purchase",
    summary: "Unlocking features/content requires payment via a mechanism other than Apple IAP.",
    fix: "Use StoreKit IAP for digital goods; don't link out to external payment for in-app digital content.",
  },
  "3.1.2": {
    title: "Subscriptions",
    summary:
      "Auto-renewable subscription app is missing required disclosures: subscription title/length/price, or functional Privacy Policy and Terms of Use (EULA) links — both at the point of purchase AND in the App Store description/metadata.",
    fix: "Put subscription title, duration and price on the paywall, add tappable Privacy Policy + Terms of Use links there, and repeat both URLs as text in the App Store description plus the App Information fields (Privacy Policy URL, License Agreement).",
  },
  "4.0": {
    title: "Design",
    summary: "UI is copied, low-quality, or not designed for iOS.",
    fix: "Follow the Human Interface Guidelines; ensure native-feeling, polished UI.",
  },
  "4.3": {
    title: "Spam / Duplicate",
    summary: "App is a duplicate of something already on the store or a template with minimal differentiation.",
    fix: "Add genuinely unique functionality/content; consolidate duplicate submissions.",
  },
  "5.1.1": {
    title: "Data Collection and Storage (Privacy)",
    summary: "Requests permissions without justification, missing/weak purpose strings, or collects data not disclosed in the privacy nutrition label.",
    fix: "Add clear NS…UsageDescription strings, only request needed permissions, and align App Privacy details.",
  },
  "5.1.2": {
    title: "Data Use and Sharing",
    summary: "Uses/shares user data (or IDFA) without proper consent (App Tracking Transparency).",
    fix: "Implement ATT prompt before tracking; add NSUserTrackingUsageDescription.",
  },
};

/** Extract guideline numbers like "2.1" or "5.1.1" from a rejection message. */
export function extractGuidelines(message: string): string[] {
  const matches = message.match(/\b\d(?:\.\d){1,3}\b/g) ?? [];
  return [...new Set(matches)].filter((g) => GUIDELINE_MAP[g]);
}
