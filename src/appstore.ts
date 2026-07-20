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

/** The version App Store Connect would submit next (newest editable one). */
async function latestVersion(
  token: string,
  appId: string
): Promise<{ id: string; versionString: string; state: string } | null> {
  const versions = await ascFetch(
    `/apps/${appId}/appStoreVersions?limit=5&fields[appStoreVersions]=versionString,appStoreState`,
    token
  );
  const v = (versions.data ?? [])[0];
  if (!v) return null;
  return {
    id: v.id,
    versionString: v.attributes?.versionString ?? "?",
    state: v.attributes?.appStoreState ?? "?",
  };
}

export interface ReviewDetail {
  demoAccountRequired: boolean | null;
  demoAccountName: string | null;
  demoAccountPassword: string | null;
  notes: string | null;
  contactEmail: string | null;
}

/**
 * Read the App Review Information for the next version — the demo credentials
 * reviewers use to get past a login wall (Guideline 2.1).
 */
export async function getReviewDetail(
  token: string,
  versionId: string
): Promise<ReviewDetail | null> {
  try {
    const detail = await ascFetch(`/appStoreVersions/${versionId}/appStoreReviewDetail`, token);
    const a = detail?.data?.attributes ?? {};
    return {
      demoAccountRequired: a.demoAccountRequired ?? null,
      demoAccountName: a.demoAccountName ?? null,
      demoAccountPassword: a.demoAccountPassword ?? null,
      notes: a.notes ?? null,
      contactEmail: a.contactEmail ?? null,
    };
  } catch {
    return null; // not created yet — which is itself the finding
  }
}

export interface ScreenshotCoverage {
  locale: string;
  /** displayType → number of screenshots uploaded. */
  sets: Record<string, number>;
}

/** Display types Apple requires for every submission (as of iOS 18 / 2024+). */
export const REQUIRED_SCREENSHOT_TYPES: { type: string; label: string }[] = [
  { type: "APP_IPHONE_67", label: "iPhone 6.7\" / 6.9\" (required)" },
];

/** Count uploaded screenshots per localization and display type. */
export async function getScreenshotCoverage(
  token: string,
  versionId: string
): Promise<ScreenshotCoverage[]> {
  const locs = await ascFetch(
    `/appStoreVersions/${versionId}/appStoreVersionLocalizations?limit=50&fields[appStoreVersionLocalizations]=locale`,
    token
  );
  const out: ScreenshotCoverage[] = [];
  for (const loc of locs.data ?? []) {
    const sets: Record<string, number> = {};
    try {
      const setsData = await ascFetch(
        `/appStoreVersionLocalizations/${loc.id}/appScreenshotSets?limit=50&include=appScreenshots`,
        token
      );
      for (const s of setsData.data ?? []) {
        const type = s.attributes?.screenshotDisplayType ?? "UNKNOWN";
        sets[type] = (s.relationships?.appScreenshots?.data ?? []).length;
      }
    } catch {
      /* localization without sets yet */
    }
    out.push({ locale: loc.attributes?.locale ?? "?", sets });
  }
  return out;
}

export interface SubmissionCheck {
  version: { id: string; versionString: string; state: string } | null;
  review: ReviewDetail | null;
  screenshots: ScreenshotCoverage[];
  findings: { severity: "error" | "warning" | "info"; title: string; detail: string; fix?: string }[];
}

/**
 * The metadata half of preflight: things only App Store Connect knows —
 * whether demo credentials are actually filled in, and whether the required
 * screenshot sets have anything in them.
 */
export async function checkSubmission(token: string, appId: string): Promise<SubmissionCheck> {
  const version = await latestVersion(token, appId);
  const result: SubmissionCheck = { version, review: null, screenshots: [], findings: [] };
  if (!version) {
    result.findings.push({
      severity: "warning",
      title: "No App Store version found for this app",
      detail: "Create the version in App Store Connect before submitting.",
    });
    return result;
  }

  const [review, screenshots] = await Promise.all([
    getReviewDetail(token, version.id),
    getScreenshotCoverage(token, version.id).catch(() => [] as ScreenshotCoverage[]),
  ]);
  result.review = review;
  result.screenshots = screenshots;

  // ── Demo account (Guideline 2.1) ──
  if (!review) {
    result.findings.push({
      severity: "warning",
      title: "App Review Information has not been filled in",
      detail: `Version ${version.versionString} has no review detail record — no contact info and no demo account.`,
      fix: "App Store Connect → the version → App Review Information.",
    });
  } else if (review.demoAccountRequired && !(review.demoAccountName && review.demoAccountPassword)) {
    result.findings.push({
      severity: "error",
      title: "Sign-in is marked required but demo credentials are empty",
      detail:
        "Reviewers cannot get past the login screen. This is a guaranteed 2.1 rejection and usually costs a full review cycle.",
      fix: "Fill in the demo username and password (and keep that account working for the whole review).",
    });
  } else if (!review.demoAccountRequired) {
    result.findings.push({
      severity: "info",
      title: "Sign-in marked not required for review",
      detail:
        "If the app actually has a login wall, tick 'Sign-in required' and supply credentials — otherwise the reviewer will be stuck.",
    });
  } else {
    result.findings.push({
      severity: "info",
      title: "Demo account provided for App Review",
      detail: `Username "${review.demoAccountName}" is set. Verify it still works right before you submit.`,
    });
  }

  if (!review?.notes) {
    result.findings.push({
      severity: "info",
      title: "App Review notes are empty",
      detail:
        "Notes are where you explain non-obvious flows, where account deletion lives, and why any unusual permission or background mode is needed. Filling them prevents avoidable rejections.",
    });
  }

  // ── Screenshots ──
  if (screenshots.length === 0) {
    result.findings.push({
      severity: "warning",
      title: "Could not read screenshot sets",
      detail: "No localizations returned, or the API key lacks access. Check screenshots manually.",
    });
  } else {
    for (const loc of screenshots) {
      for (const req of REQUIRED_SCREENSHOT_TYPES) {
        const count = loc.sets[req.type] ?? 0;
        if (count === 0) {
          result.findings.push({
            severity: "error",
            title: `No ${req.label} screenshots for ${loc.locale}`,
            detail:
              "App Store Connect blocks submission without the required iPhone screenshot set — and a wrong/empty set is caught at the last step, after you've already waited for the build to process.",
            fix: "Upload at least one 6.7\"/6.9\" iPhone screenshot for this localization.",
          });
        }
      }
    }
    if (!result.findings.some((f) => f.severity === "error" && /screenshots/.test(f.title))) {
      result.findings.push({
        severity: "info",
        title: `Screenshot sets present for ${screenshots.length} localization(s)`,
        detail: screenshots
          .map((l) => `${l.locale}: ${Object.entries(l.sets).map(([t, n]) => `${t}×${n}`).join(", ") || "none"}`)
          .join(" | "),
      });
    }
  }

  return result;
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
  "2.5.4": {
    title: "Background modes",
    summary: "App declares a background mode (location, audio, VoIP…) it doesn't actually implement, or uses one to keep itself alive.",
    fix: "Remove unused entries from UIBackgroundModes; only declare modes tied to a real, reviewable feature.",
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
  "4.8": {
    title: "Sign in with Apple",
    summary: "App offers a third-party or social login (Google, Facebook, …) without offering Sign in with Apple as an equivalent option.",
    fix: "Add Sign in with Apple alongside the other providers. Apps with only their own email/password accounts are exempt.",
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
