import { readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join, extname, basename, relative } from "node:path";
import { XMLParser } from "fast-xml-parser";
import {
  REQUIRED_REASON_CATEGORIES,
  USAGE_DESCRIPTION_RULES,
  CREDENTIAL_TRAPS,
  REASON_HINTS,
  PURCHASE_SIGNATURES,
  ACCOUNT_SIGNATURES,
  PRIVACY_LINK_PATTERNS,
  TERMS_LINK_PATTERNS,
  APPLE_STANDARD_EULA,
  SOCIAL_LOGIN_SIGNATURES,
  APPLE_LOGIN_SIGNATURES,
  EXTERNAL_PAYMENT_SIGNATURES,
  BACKGROUND_MODE_RULES,
  PLACEHOLDER_PATTERNS,
  TEMPLATE_APP_NAMES,
} from "./knowledge.js";

/** Severity ordering for report sorting. */
export type Severity = "error" | "warning" | "info";

export interface Finding {
  severity: Severity;
  check: string;
  title: string;
  detail: string;
  /** Concrete next step, ideally something Claude can act on. */
  fix?: string;
  /** Where it was found, if applicable. */
  location?: string;
}

const SOURCE_EXTS = new Set([".swift", ".m", ".mm", ".h", ".c", ".cpp", ".js", ".jsx", ".ts", ".tsx"]);
const IGNORE_DIRS = new Set(["node_modules", ".git", "build", "DerivedData", "Pods"]);

/** Recursively collect first-party source files (excludes Pods/node_modules). */
async function collectSourceFiles(root: string, acc: string[] = []): Promise<string[]> {
  let entries;
  try {
    entries = await readdir(root, { withFileTypes: true });
  } catch {
    return acc;
  }
  for (const e of entries) {
    if (e.name.startsWith(".") && e.name !== ".") continue;
    const full = join(root, e.name);
    if (e.isDirectory()) {
      if (IGNORE_DIRS.has(e.name)) continue;
      await collectSourceFiles(full, acc);
    } else if (SOURCE_EXTS.has(extname(e.name))) {
      acc.push(full);
    }
  }
  return acc;
}

/** Read a whole file, tolerating errors. */
async function safeRead(path: string): Promise<string> {
  try {
    return await readFile(path, "utf8");
  } catch {
    return "";
  }
}

/** Parse a plist (.plist / .xcprivacy) into a JS object. */
export async function parsePlist(path: string): Promise<any | null> {
  const raw = await safeRead(path);
  if (!raw) return null;
  const parser = new XMLParser({
    ignoreAttributes: true,
    parseTagValue: false,
    isArray: (name) => name === "dict" || name === "array" || name === "string",
  });
  try {
    return parser.parse(raw);
  } catch {
    return null;
  }
}

/**
 * Pair each <key> with the value element that immediately follows it, scanning
 * the raw plist in document order. This is robust to mixed value types (string,
 * true/false, numbers, nested dict/array) — unlike index-based pairing, which
 * silently misaligns as soon as a non-string value appears between keys.
 *
 * Returns a Map of key -> string value ("" for boolean/array/dict/number nodes
 * we don't need the payload of). Presence is `map.has(key)`.
 */
function parsePlistStringValues(raw: string): Map<string, string> {
  const map = new Map<string, string>();
  const re =
    /<key>([^<]+)<\/key>\s*(?:<string>([\s\S]*?)<\/string>|<(?:true|false)\s*\/>|<(?:integer|real)>([\s\S]*?)<\/(?:integer|real)>|<(?:array|dict)\s*(?:\/>|>))/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw)) !== null) {
    const key = m[1];
    const value = m[2] ?? m[3] ?? "";
    if (!map.has(key)) map.set(key, value);
  }
  return map;
}

/** Locate the primary app source dir + Info.plist inside an ios project root. */
export interface ProjectLayout {
  iosRoot: string;
  appSourceDir: string | null;
  infoPlistPath: string | null;
  appPrivacyManifestPath: string | null;
  podsDir: string | null;
}

export async function resolveLayout(projectPath: string): Promise<ProjectLayout> {
  // Accept either the repo root or the ios/ dir.
  let iosRoot = projectPath;
  try {
    const asIos = join(projectPath, "ios");
    if ((await stat(asIos)).isDirectory()) iosRoot = asIos;
  } catch {
    /* projectPath already is the ios dir (or a flat project) */
  }

  const layout: ProjectLayout = {
    iosRoot,
    appSourceDir: null,
    infoPlistPath: null,
    appPrivacyManifestPath: null,
    podsDir: null,
  };

  let entries;
  try {
    entries = await readdir(iosRoot, { withFileTypes: true });
  } catch {
    return layout;
  }

  for (const e of entries) {
    if (e.isDirectory() && e.name === "Pods") layout.podsDir = join(iosRoot, "Pods");
  }

  // Find an Info.plist that is NOT inside Pods (the app target's plist).
  for (const e of entries) {
    if (!e.isDirectory()) continue;
    if (IGNORE_DIRS.has(e.name)) continue;
    if (e.name.endsWith(".xcodeproj") || e.name.endsWith(".xcworkspace")) continue;
    const candidate = join(iosRoot, e.name, "Info.plist");
    try {
      await stat(candidate);
      layout.appSourceDir = join(iosRoot, e.name);
      layout.infoPlistPath = candidate;
      const pm = join(iosRoot, e.name, "PrivacyInfo.xcprivacy");
      try {
        await stat(pm);
        layout.appPrivacyManifestPath = pm;
      } catch {
        /* no app manifest yet */
      }
      break;
    } catch {
      /* keep looking */
    }
  }

  return layout;
}

/**
 * Every first-party source file plus the dependency manifests, read once.
 * Most checks only need the concatenated text; `files` is there for the ones
 * that must report *where* a hit was.
 */
export interface SourceCorpus {
  text: string;
  files: { path: string; text: string }[];
}

/**
 * Drop comments before signature matching. Without this, a comment that merely
 * *mentions* an SDK ("we deliberately don't use StoreKit here") reads as usage,
 * and a "// TODO: add a Terms of Use link" reads as the link already existing.
 * The `[^:]` guard keeps the `//` in https:// URLs — those are real evidence.
 */
export function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'\w])\/\/.*$/gm, "$1");
}

export async function buildCorpus(layout: ProjectLayout): Promise<SourceCorpus> {
  const files: SourceCorpus["files"] = [];
  const seen = new Set<string>();
  const dirs = [layout.appSourceDir, layout.iosRoot].filter(Boolean) as string[];
  for (const dir of dirs) {
    for (const f of await collectSourceFiles(dir)) {
      if (seen.has(f)) continue;
      seen.add(f);
      files.push({ path: f, text: stripComments(await safeRead(f)) });
    }
  }
  // Dependency manifests: SDK names live here, not in source.
  for (const manifest of ["Podfile", "Package.swift", join("..", "package.json"), "package.json"]) {
    const path = join(layout.iosRoot, manifest);
    if (seen.has(path)) continue;
    seen.add(path);
    const text = await safeRead(path);
    if (text) files.push({ path, text });
  }
  return { text: files.map((f) => f.text).join("\n"), files };
}

/** First file in the corpus matching `needle`, as an iosRoot-relative path. */
function locate(corpus: SourceCorpus, layout: ProjectLayout, needle: string | RegExp): string | undefined {
  const hit = corpus.files.find((f) =>
    typeof needle === "string" ? f.text.includes(needle) : needle.test(f.text)
  );
  return hit ? relative(layout.iosRoot, hit.path) : undefined;
}

/** Word-ish match of a signature within source text. */
function usesSignature(haystack: string, sig: string): boolean {
  // Simple contains match is good enough and avoids false negatives from
  // member-access chains; guarded by requiring the raw substring.
  return haystack.includes(sig);
}

// ─────────────────────────────────────────────────────────────────────────────
// CHECK 1: Required-reason APIs vs the app's privacy manifest
// ─────────────────────────────────────────────────────────────────────────────

export interface PrivacyScanResult {
  declaredCategories: string[];
  usedCategories: { category: string; label: string; sampleFiles: string[] }[];
  missing: { category: string; label: string; sampleFiles: string[]; defaultReason: string }[];
  invalidReasons: { category: string; reason: string; validReasons: string[] }[];
  manifestExists: boolean;
  manifestPath: string | null;
  findings: Finding[];
}

export async function scanPrivacyManifest(projectPath: string): Promise<PrivacyScanResult> {
  const layout = await resolveLayout(projectPath);
  const findings: Finding[] = [];

  const sourceFiles = layout.appSourceDir
    ? await collectSourceFiles(layout.appSourceDir)
    : [];

  // Detect which categories the first-party code actually uses.
  const usedMap = new Map<string, Set<string>>(); // category -> files
  for (const file of sourceFiles) {
    const text = await safeRead(file);
    if (!text) continue;
    for (const cat of REQUIRED_REASON_CATEGORIES) {
      if (cat.signatures.some((s) => usesSignature(text, s))) {
        if (!usedMap.has(cat.category)) usedMap.set(cat.category, new Set());
        usedMap.get(cat.category)!.add(relative(layout.iosRoot, file));
      }
    }
  }

  // Parse declared manifest.
  const declared: { category: string; reasons: string[] }[] = [];
  if (layout.appPrivacyManifestPath) {
    const parsed = await parsePlist(layout.appPrivacyManifestPath);
    const dict = parsed?.plist?.dict;
    const top = Array.isArray(dict) ? dict[0] : dict;
    // NSPrivacyAccessedAPITypes is an array of dicts. With our parser config,
    // nested dicts land under top.array[k].dict.
    const arrays = top?.array ? ([] as any[]).concat(top.array) : [];
    for (const arr of arrays) {
      const inner = arr?.dict ? ([] as any[]).concat(arr.dict) : [];
      for (const d of inner) {
        const keys = ([] as any[]).concat(d.key ?? []);
        const strings = ([] as any[]).concat(d.string ?? []);
        const typeIdx = keys.indexOf("NSPrivacyAccessedAPIType");
        const category = typeIdx >= 0 ? strings[typeIdx] : undefined;
        // Reasons are a nested <array><string>. fast-xml-parser nests them under
        // d.array.string.
        let reasons: string[] = [];
        if (d.array) {
          const ra = ([] as any[]).concat(d.array);
          for (const r of ra) reasons = reasons.concat(([] as any[]).concat(r.string ?? []));
        }
        // The first string is the category itself in some shapes; filter it out.
        reasons = reasons.filter((r) => typeof r === "string" && r !== category);
        if (category) declared.push({ category, reasons });
      }
    }
  }
  const declaredCategories = declared.map((d) => d.category);

  // Missing: used-but-not-declared.
  const missing = [] as PrivacyScanResult["missing"];
  for (const [category, files] of usedMap) {
    if (!declaredCategories.includes(category)) {
      const meta = REQUIRED_REASON_CATEGORIES.find((c) => c.category === category)!;
      missing.push({
        category,
        label: meta.label,
        sampleFiles: [...files].slice(0, 5),
        defaultReason: meta.defaultReason,
      });
    }
  }

  // Invalid reason codes on declared entries.
  const invalidReasons = [] as PrivacyScanResult["invalidReasons"];
  for (const d of declared) {
    const meta = REQUIRED_REASON_CATEGORIES.find((c) => c.category === d.category);
    if (!meta) continue;
    for (const r of d.reasons) {
      if (!meta.validReasons.includes(r)) {
        invalidReasons.push({ category: d.category, reason: r, validReasons: meta.validReasons });
      }
    }
  }

  // Build findings.
  if (!layout.appPrivacyManifestPath) {
    if (usedMap.size > 0) {
      findings.push({
        severity: "error",
        check: "privacy-manifest",
        title: "No PrivacyInfo.xcprivacy in the app target, but required-reason APIs are used",
        detail: `Your code uses ${usedMap.size} required-reason API categor${usedMap.size === 1 ? "y" : "ies"} but the app has no privacy manifest. Apple will reject the upload.`,
        fix: "Run generate_privacy_manifest to create a valid PrivacyInfo.xcprivacy, then add it to the app target in Xcode.",
      });
    } else {
      findings.push({
        severity: "warning",
        check: "privacy-manifest",
        title: "No PrivacyInfo.xcprivacy found in the app target",
        detail: "No required-reason API usage detected in first-party code, but a privacy manifest is still recommended and may be required depending on collected data.",
        fix: "Consider adding a PrivacyInfo.xcprivacy declaring tracking + collected data types.",
      });
    }
  }

  for (const m of missing) {
    findings.push({
      severity: "error",
      check: "privacy-manifest",
      title: `Undeclared required-reason API: ${m.label}`,
      detail: `Code uses ${m.category} (e.g. ${m.sampleFiles.join(", ") || "first-party source"}) but it is not declared in the privacy manifest.`,
      location: m.sampleFiles[0],
      fix: `Add ${m.category} with reason ${m.defaultReason} (${REASON_HINTS[m.defaultReason] ?? "see Apple docs"}) — generate_privacy_manifest can do this automatically.`,
    });
  }

  for (const iv of invalidReasons) {
    findings.push({
      severity: "error",
      check: "privacy-manifest",
      title: `Invalid reason code for ${iv.category}`,
      detail: `Reason "${iv.reason}" is not accepted by Apple for this category.`,
      fix: `Use one of: ${iv.validReasons.join(", ")}.`,
    });
  }

  if (findings.length === 0 && layout.appPrivacyManifestPath) {
    findings.push({
      severity: "info",
      check: "privacy-manifest",
      title: "Privacy manifest looks consistent with first-party API usage",
      detail: `Declared ${declaredCategories.length} categor${declaredCategories.length === 1 ? "y" : "ies"}; all used required-reason APIs are covered.`,
    });
  }

  return {
    declaredCategories,
    usedCategories: [...usedMap].map(([category, files]) => ({
      category,
      label: REQUIRED_REASON_CATEGORIES.find((c) => c.category === category)?.label ?? category,
      sampleFiles: [...files].slice(0, 5),
    })),
    missing,
    invalidReasons,
    manifestExists: !!layout.appPrivacyManifestPath,
    manifestPath: layout.appPrivacyManifestPath,
    findings,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// CHECK 2: Usage-description keys in Info.plist
// ─────────────────────────────────────────────────────────────────────────────

export async function checkUsageDescriptions(projectPath: string): Promise<Finding[]> {
  const layout = await resolveLayout(projectPath);
  const findings: Finding[] = [];
  if (!layout.infoPlistPath) {
    return [
      {
        severity: "warning",
        check: "usage-descriptions",
        title: "Could not locate the app's Info.plist",
        detail: `Looked under ${layout.iosRoot}. Point the tool at the ios/ directory or repo root.`,
      },
    ];
  }

  const infoRaw = await safeRead(layout.infoPlistPath);
  const map = parsePlistStringValues(infoRaw);

  // Gather all first-party + Podfile signatures to know which permissions are used.
  const sourceFiles = layout.appSourceDir ? await collectSourceFiles(layout.appSourceDir) : [];
  let corpus = "";
  for (const f of sourceFiles) corpus += await safeRead(f);
  // Include Podfile + package.json names as strong hints for RN/Expo modules.
  corpus += await safeRead(join(layout.iosRoot, "Podfile"));
  corpus += await safeRead(join(layout.iosRoot, "..", "package.json"));

  for (const rule of USAGE_DESCRIPTION_RULES) {
    const used = rule.signatures.some((s) => usesSignature(corpus, s));
    if (!used) continue;
    const value = map.get(rule.key);
    if (value === undefined) {
      findings.push({
        severity: "error",
        check: "usage-descriptions",
        title: `Missing ${rule.key} (${rule.label})`,
        detail: `The project appears to use ${rule.label}, but Info.plist has no ${rule.key}. The app will crash on first use of the API and be rejected.`,
        location: relative(layout.iosRoot, layout.infoPlistPath),
        fix: `Add <key>${rule.key}</key><string>…clear user-facing purpose…</string> to Info.plist.`,
      });
    } else if (typeof value === "string" && value.trim().length < 10) {
      findings.push({
        severity: "warning",
        check: "usage-descriptions",
        title: `${rule.key} purpose string is too short / vague`,
        detail: `"${value}" is likely to be rejected for not clearly explaining why the app needs ${rule.label}.`,
        location: relative(layout.iosRoot, layout.infoPlistPath),
        fix: "Write a specific, user-facing sentence describing the feature that needs this permission.",
      });
    }
  }

  if (findings.length === 0) {
    findings.push({
      severity: "info",
      check: "usage-descriptions",
      title: "Usage-description keys look complete",
      detail: "Every permission the project appears to use has a corresponding Info.plist purpose string.",
    });
  }
  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// CHECK 3: Third-party dependencies missing privacy manifests
// ─────────────────────────────────────────────────────────────────────────────

/**
 * SDKs Apple explicitly lists as "commonly used" — these MUST ship a signed
 * privacy manifest, and Apple enforces it. If a pod matches one of these names
 * and has no PrivacyInfo.xcprivacy, that's a hard reject.
 */
const APPLE_LISTED_SDK_HINTS = [
  "Firebase", "GoogleUtilities", "GoogleMobileAds", "nanopb", "abseil",
  "FBLPromises", "OneSignal", "Alamofire", "SDWebImage", "Lottie",
  "AppsFlyer", "RevenueCat", "Sentry", "Realm",
];

export async function auditDependencies(projectPath: string): Promise<Finding[]> {
  const layout = await resolveLayout(projectPath);
  const findings: Finding[] = [];
  let scannedSomething = false;

  // ── CocoaPods ──
  if (layout.podsDir) {
    scannedSomething = true;
    let pods: any[] = [];
    try {
      pods = await readdir(layout.podsDir, { withFileTypes: true });
    } catch {
      /* ignore */
    }
    for (const pod of pods) {
      if (!pod.isDirectory()) continue;
      if (["Target Support Files", "Headers", "Local Podspecs", "Manifest.lock"].includes(pod.name)) continue;
      const podDir = join(layout.podsDir, pod.name);
      const hasManifest = await containsFile(podDir, "PrivacyInfo.xcprivacy");
      const isListed = APPLE_LISTED_SDK_HINTS.some((h) => pod.name.toLowerCase().includes(h.toLowerCase()));
      if (!hasManifest && isListed) {
        findings.push({
          severity: "error",
          check: "dependencies",
          title: `SDK "${pod.name}" (CocoaPods) is on Apple's required-manifest list but ships no PrivacyInfo.xcprivacy`,
          detail: "Apple requires this commonly-used SDK to include a signed privacy manifest. The build will be rejected.",
          location: relative(layout.iosRoot, podDir),
          fix: `Update ${pod.name} to a version that bundles a privacy manifest (most have shipped one since 2024).`,
        });
      }
    }
  }

  // ── Swift Package Manager ──
  const resolved = await findPackageResolved(layout);
  if (resolved) {
    scannedSomething = true;
    const names = await parseResolvedPackageNames(resolved);
    for (const name of names) {
      const isListed = APPLE_LISTED_SDK_HINTS.some((h) => name.toLowerCase().includes(h.toLowerCase()));
      if (isListed) {
        findings.push({
          severity: "warning",
          check: "dependencies",
          title: `SwiftPM package "${name}" is on Apple's required-manifest list — verify it ships a privacy manifest`,
          detail: "SwiftPM sources aren't checked into the repo, so Ship Doctor can't inspect the manifest directly. Older pinned versions may lack one.",
          location: relative(layout.iosRoot, resolved),
          fix: `Ensure ${name} is pinned to a version that bundles PrivacyInfo.xcprivacy (2024+).`,
        });
      }
    }
  }

  if (!scannedSomething) {
    findings.push({
      severity: "info",
      check: "dependencies",
      title: "No CocoaPods or SwiftPM manifests found",
      detail: "No Pods/ directory and no Package.resolved to audit.",
    });
  } else if (findings.length === 0) {
    findings.push({
      severity: "info",
      check: "dependencies",
      title: "Dependency privacy manifests look OK",
      detail: "No Apple-listed SDK with a missing/unverifiable privacy manifest was found.",
    });
  }
  return findings;
}

/** Locate a Package.resolved in the usual SwiftPM spots. */
async function findPackageResolved(layout: ProjectLayout): Promise<string | null> {
  const candidates = [
    join(layout.iosRoot, "Package.resolved"),
    join(layout.iosRoot, "..", "Package.resolved"),
  ];
  // Also look inside any .xcodeproj/.xcworkspace under iosRoot.
  try {
    const entries = await readdir(layout.iosRoot, { withFileTypes: true });
    for (const e of entries) {
      if (e.isDirectory() && (e.name.endsWith(".xcodeproj") || e.name.endsWith(".xcworkspace"))) {
        candidates.push(
          join(layout.iosRoot, e.name, "project.xcworkspace", "xcshareddata", "swiftpm", "Package.resolved")
        );
      }
    }
  } catch {
    /* ignore */
  }
  for (const c of candidates) {
    try {
      await stat(c);
      return c;
    } catch {
      /* keep looking */
    }
  }
  return null;
}

/** Parse package names out of a Package.resolved (v1 or v2 schema). */
async function parseResolvedPackageNames(path: string): Promise<string[]> {
  const raw = await safeRead(path);
  if (!raw) return [];
  try {
    const json = JSON.parse(raw);
    const pins = json.pins ?? json.object?.pins ?? [];
    return pins
      .map((p: any) => p.identity ?? p.package ?? "")
      .filter((s: string) => s.length > 0);
  } catch {
    return [];
  }
}

async function containsFile(dir: string, name: string, depth = 6): Promise<boolean> {
  if (depth < 0) return false;
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return false;
  }
  for (const e of entries) {
    if (e.isFile() && e.name === name) return true;
  }
  for (const e of entries) {
    if (e.isDirectory()) {
      if (await containsFile(join(dir, e.name), name, depth - 1)) return true;
    }
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// CHECK 4: Credential / placeholder traps (e.g. AdMob test IDs)
// ─────────────────────────────────────────────────────────────────────────────

export async function checkCredentialTraps(projectPath: string): Promise<Finding[]> {
  const layout = await resolveLayout(projectPath);
  const findings: Finding[] = [];
  if (!layout.infoPlistPath) return findings;
  const raw = await safeRead(layout.infoPlistPath);

  for (const trap of CREDENTIAL_TRAPS) {
    for (const bad of trap.badValues) {
      if (raw.includes(bad)) {
        findings.push({
          severity: "error",
          check: "credential-traps",
          title: trap.label,
          detail: `Found placeholder/test value "${bad}"${trap.plistKey ? ` for ${trap.plistKey}` : ""} in Info.plist.`,
          location: relative(layout.iosRoot, layout.infoPlistPath),
          fix: trap.advice,
        });
      }
    }
  }
  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// Manifest generator
// ─────────────────────────────────────────────────────────────────────────────

export async function buildPrivacyManifestXml(projectPath: string): Promise<{
  xml: string;
  categories: string[];
  targetPath: string | null;
}> {
  const scan = await scanPrivacyManifest(projectPath);
  const layout = await resolveLayout(projectPath);

  // Union of already-declared + newly-detected categories.
  const categories = new Set<string>(scan.declaredCategories);
  for (const m of scan.missing) categories.add(m.category);
  for (const u of scan.usedCategories) categories.add(u.category);

  const entries = [...categories].map((cat) => {
    const meta = REQUIRED_REASON_CATEGORIES.find((c) => c.category === cat);
    const reason = meta?.defaultReason ?? "C617.1";
    return `		<dict>
			<key>NSPrivacyAccessedAPIType</key>
			<string>${cat}</string>
			<key>NSPrivacyAccessedAPITypeReasons</key>
			<array>
				<string>${reason}</string>
			</array>
		</dict>`;
  });

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>NSPrivacyAccessedAPITypes</key>
	<array>
${entries.join("\n")}
	</array>
	<key>NSPrivacyCollectedDataTypes</key>
	<array/>
	<key>NSPrivacyTracking</key>
	<false/>
	<key>NSPrivacyTrackingDomains</key>
	<array/>
</dict>
</plist>
`;

  return {
    xml,
    categories: [...categories],
    targetPath: layout.appSourceDir ? join(layout.appSourceDir, "PrivacyInfo.xcprivacy") : null,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// CHECK 5: Export compliance (ITSAppUsesNonExemptEncryption)
// ─────────────────────────────────────────────────────────────────────────────

export async function checkExportCompliance(projectPath: string): Promise<Finding[]> {
  const layout = await resolveLayout(projectPath);
  if (!layout.infoPlistPath) return [];
  const raw = await safeRead(layout.infoPlistPath);
  if (raw.includes("<key>ITSAppUsesNonExemptEncryption</key>")) {
    return [
      {
        severity: "info",
        check: "export-compliance",
        title: "Export compliance declared",
        detail: "ITSAppUsesNonExemptEncryption is set — App Store Connect won't block each submission asking about encryption.",
      },
    ];
  }
  return [
    {
      severity: "warning",
      check: "export-compliance",
      title: "Missing ITSAppUsesNonExemptEncryption in Info.plist",
      detail: "Without this key, App Store Connect prompts you about encryption on every single submission, and TestFlight builds sit in 'Missing Compliance' until answered.",
      location: relative(layout.iosRoot, layout.infoPlistPath),
      fix: "Add <key>ITSAppUsesNonExemptEncryption</key><false/> if you only use standard HTTPS/TLS (true if you ship custom/proprietary encryption and have the paperwork).",
    },
  ];
}

// ─────────────────────────────────────────────────────────────────────────────
// CHECK 6: App Transport Security (arbitrary loads)
// ─────────────────────────────────────────────────────────────────────────────

export async function checkAppTransportSecurity(projectPath: string): Promise<Finding[]> {
  const layout = await resolveLayout(projectPath);
  if (!layout.infoPlistPath) return [];
  const raw = await safeRead(layout.infoPlistPath);
  // Crude but effective: NSAllowsArbitraryLoads immediately followed by <true/>.
  const m = raw.match(/<key>NSAllowsArbitraryLoads<\/key>\s*<(true|false)\/>/);
  if (m && m[1] === "true") {
    return [
      {
        severity: "warning",
        check: "app-transport-security",
        title: "NSAllowsArbitraryLoads is enabled (ATS disabled globally)",
        detail: "Shipping with ATS fully disabled is a common review question and, if unjustified, a rejection under the security guidelines.",
        location: relative(layout.iosRoot, layout.infoPlistPath),
        fix: "Prefer per-domain NSExceptionDomains over a global NSAllowsArbitraryLoads=true, or be ready to justify it in the review notes.",
      },
    ];
  }
  return [
    {
      severity: "info",
      check: "app-transport-security",
      title: "App Transport Security not globally disabled",
      detail: "No global NSAllowsArbitraryLoads=true found.",
    },
  ];
}

// ─────────────────────────────────────────────────────────────────────────────
// CHECK 7: App icon asset present
// ─────────────────────────────────────────────────────────────────────────────

export async function checkAppIcon(projectPath: string): Promise<Finding[]> {
  const layout = await resolveLayout(projectPath);
  if (!layout.appSourceDir) return [];
  // Look for an AppIcon.appiconset anywhere under the app source dir.
  const hasIconSet = await containsDir(layout.appSourceDir, "AppIcon.appiconset");
  if (hasIconSet) {
    return [
      {
        severity: "info",
        check: "app-icon",
        title: "App icon asset found",
        detail: "An AppIcon.appiconset exists in the app's asset catalog.",
      },
    ];
  }
  return [
    {
      severity: "error",
      check: "app-icon",
      title: "No AppIcon.appiconset found",
      detail: "Apps submitted without a complete app icon are rejected. No AppIcon.appiconset was found under the app source directory.",
      location: relative(layout.iosRoot, layout.appSourceDir),
      fix: "Add an AppIcon set to Assets.xcassets with all required sizes (a 1024×1024 marketing icon is mandatory).",
    },
  ];
}

// ─────────────────────────────────────────────────────────────────────────────
// CHECK 8: Deprecated/banned APIs (UIWebView)
// ─────────────────────────────────────────────────────────────────────────────

export async function checkDeprecatedApis(projectPath: string): Promise<Finding[]> {
  const layout = await resolveLayout(projectPath);
  const findings: Finding[] = [];
  const dirs = [layout.appSourceDir].filter(Boolean) as string[];
  let hitFile: string | null = null;
  for (const dir of dirs) {
    const files = await collectSourceFiles(dir);
    for (const f of files) {
      const text = await safeRead(f);
      if (/\bUIWebView\b/.test(text)) {
        hitFile = relative(layout.iosRoot, f);
        break;
      }
    }
    if (hitFile) break;
  }
  if (hitFile) {
    findings.push({
      severity: "error",
      check: "deprecated-apis",
      title: "UIWebView reference found (banned by Apple)",
      detail: "Apple rejects any binary that references the deprecated UIWebView API.",
      location: hitFile,
      fix: "Replace UIWebView with WKWebView. Also check that no third-party dependency still links UIWebView.",
    });
  } else {
    findings.push({
      severity: "info",
      check: "deprecated-apis",
      title: "No banned UIWebView references in first-party code",
      detail: "Note: this scans first-party source only — a dependency could still reference it.",
    });
  }
  return findings;
}

/** True if a directory named `name` exists anywhere under `root`. */
async function containsDir(root: string, name: string, depth = 6): Promise<boolean> {
  if (depth < 0) return false;
  let entries;
  try {
    entries = await readdir(root, { withFileTypes: true });
  } catch {
    return false;
  }
  for (const e of entries) {
    if (e.isDirectory()) {
      if (e.name === name) return true;
      if (IGNORE_DIRS.has(e.name)) continue;
      if (await containsDir(join(root, e.name), name, depth - 1)) return true;
    }
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// CHECK 9: Launch screen
// ─────────────────────────────────────────────────────────────────────────────

export async function checkLaunchScreen(projectPath: string): Promise<Finding[]> {
  const layout = await resolveLayout(projectPath);
  if (!layout.infoPlistPath) return [];
  const raw = await safeRead(layout.infoPlistPath);
  const hasStoryboard = raw.includes("<key>UILaunchStoryboardName</key>");
  const hasLaunchScreen = raw.includes("<key>UILaunchScreen</key>");
  if (hasStoryboard || hasLaunchScreen) {
    return [
      {
        severity: "info",
        check: "launch-screen",
        title: "Launch screen configured",
        detail: "Info.plist declares a launch storyboard / launch screen.",
      },
    ];
  }
  return [
    {
      severity: "warning",
      check: "launch-screen",
      title: "No launch screen configured",
      detail: "Apps without a launch storyboard render at a non-native resolution and are commonly rejected under the design guidelines.",
      location: relative(layout.iosRoot, layout.infoPlistPath),
      fix: "Add UILaunchStoryboardName (e.g. LaunchScreen) or a UILaunchScreen dict to Info.plist.",
    },
  ];
}

// ─────────────────────────────────────────────────────────────────────────────
// CHECK 10: Version / build number sanity
// ─────────────────────────────────────────────────────────────────────────────

export async function checkVersionSanity(projectPath: string): Promise<Finding[]> {
  const layout = await resolveLayout(projectPath);
  if (!layout.infoPlistPath) return [];
  const raw = await safeRead(layout.infoPlistPath);
  const findings: Finding[] = [];
  if (!raw.includes("<key>CFBundleShortVersionString</key>")) {
    findings.push({
      severity: "error",
      check: "version-sanity",
      title: "Missing CFBundleShortVersionString (marketing version)",
      detail: "Every submitted build needs a marketing version string.",
      location: relative(layout.iosRoot, layout.infoPlistPath),
      fix: "Add <key>CFBundleShortVersionString</key><string>1.0.0</string> (or $(MARKETING_VERSION)).",
    });
  }
  if (!raw.includes("<key>CFBundleVersion</key>")) {
    findings.push({
      severity: "error",
      check: "version-sanity",
      title: "Missing CFBundleVersion (build number)",
      detail: "Every submitted build needs a build number.",
      location: relative(layout.iosRoot, layout.infoPlistPath),
      fix: "Add <key>CFBundleVersion</key><string>1</string> (or $(CURRENT_PROJECT_VERSION)).",
    });
  }
  if (findings.length === 0) {
    findings.push({
      severity: "info",
      check: "version-sanity",
      title: "Version and build number present",
      detail: "Both CFBundleShortVersionString and CFBundleVersion are set.",
    });
  }
  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// CHECK 11: Deployment target (from Podfile, best-effort)
// ─────────────────────────────────────────────────────────────────────────────

export async function checkDeploymentTarget(projectPath: string): Promise<Finding[]> {
  const layout = await resolveLayout(projectPath);
  const podfile = await safeRead(join(layout.iosRoot, "Podfile"));
  const m = podfile.match(/platform\s+:ios,\s*['"](\d+)(?:\.\d+)?['"]/);
  if (!m) return []; // no Podfile / not declared here — skip quietly
  const major = parseInt(m[1], 10);
  if (major < 13) {
    return [
      {
        severity: "warning",
        check: "deployment-target",
        title: `Very old iOS deployment target (iOS ${m[1]})`,
        detail: "Supporting very old iOS versions increases the surface for review issues and misses required-API behavior changes.",
        location: "Podfile",
        fix: "Consider raising platform :ios to a currently-supported minimum (13+).",
      },
    ];
  }
  return [
    {
      severity: "info",
      check: "deployment-target",
      title: `Deployment target iOS ${m[1]}`,
      detail: "Minimum iOS version looks reasonable.",
    },
  ];
}

// ─────────────────────────────────────────────────────────────────────────────
// CHECK 12: Privacy Policy + Terms of Use (EULA) links — Guideline 3.1.2 / 5.1.1
// ─────────────────────────────────────────────────────────────────────────────

/**
 * The single most common *metadata* rejection: an app that sells subscriptions
 * ships without functional privacy-policy and Terms-of-Use links — in the app
 * at the point of purchase, and in the App Store Connect description.
 *
 * We can only see the binary side from source, so the App Store Connect side is
 * always reported as a manual confirmation when purchases are detected.
 */
export async function checkLegalLinks(projectPath: string): Promise<Finding[]> {
  const layout = await resolveLayout(projectPath);
  const findings: Finding[] = [];

  const blob = (await buildCorpus(layout)).text;
  if (!blob.trim()) return [];

  const sellsSubscriptions = PURCHASE_SIGNATURES.some((s) => blob.includes(s));
  const hasPrivacyLink = PRIVACY_LINK_PATTERNS.some((re) => re.test(blob));
  const hasTermsLink = TERMS_LINK_PATTERNS.some((re) => re.test(blob));

  if (sellsSubscriptions) {
    if (!hasTermsLink) {
      findings.push({
        severity: "error",
        check: "legal-links",
        title: "In-app purchases detected, but no Terms of Use (EULA) link anywhere in the app",
        detail:
          "Guideline 3.1.2 requires auto-renewable subscriptions to show a functional link to the Terms of Use (EULA) at the point of purchase, AND to repeat that link in the App Store Connect description. Missing it is a routine metadata rejection.",
        fix: `Add a tappable "Terms of Use" link on the paywall (Apple's standard EULA is fine: ${APPLE_STANDARD_EULA}), and paste the same URL into the App Store description text and the App Store Connect "License Agreement" field.`,
      });
    }
    if (!hasPrivacyLink) {
      findings.push({
        severity: "error",
        check: "legal-links",
        title: "In-app purchases detected, but no Privacy Policy link anywhere in the app",
        detail:
          "Guideline 3.1.2 requires a functional privacy-policy link at the point of purchase as well as in the App Store description.",
        fix: 'Add a tappable "Privacy Policy" link on the paywall, and include the same URL in the App Store description text.',
      });
    }
    findings.push({
      severity: "warning",
      check: "legal-links",
      title: "Confirm the App Store Connect description contains both legal links",
      detail:
        "Ship Doctor can only see the app binary. Reviewers also check the metadata: the description text itself must contain working Privacy Policy and Terms of Use (EULA) URLs, plus subscription title, length, and price. Links only in the app — or only in the ASC URL fields — still get rejected under 3.1.2.",
      fix: 'In App Store Connect → App Information, fill "Privacy Policy URL" and "License Agreement", and paste both URLs as plain text at the end of the app description.',
    });
  } else {
    if (!hasPrivacyLink) {
      findings.push({
        severity: "warning",
        check: "legal-links",
        title: "No Privacy Policy link found in the app",
        detail:
          "A Privacy Policy URL is mandatory in App Store Connect for every app, and reviewers expect it to be reachable from inside the app too (typically Settings/About).",
        fix: 'Add a "Privacy Policy" link in-app and set the Privacy Policy URL in App Store Connect → App Information.',
      });
    } else {
      findings.push({
        severity: "info",
        check: "legal-links",
        title: "Privacy Policy link present in the app",
        detail: "Still confirm the Privacy Policy URL field is filled in App Store Connect — it is required for every app.",
      });
    }
  }

  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// CHECK 13: Account requirements — demo credentials, deletion, 4.8 Apple sign-in
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Everything that follows from "this app has accounts":
 *  - 2.1  a login wall with no demo account = reviewer never sees the app
 *  - 5.1.1(v) account creation obliges in-app account deletion
 *  - 4.8  offering a third-party login obliges offering Sign in with Apple
 */
export async function checkAccountRequirements(projectPath: string): Promise<Finding[]> {
  const layout = await resolveLayout(projectPath);
  const corpus = await buildCorpus(layout);
  const blob = corpus.text;
  if (!blob.trim()) return [];

  const findings: Finding[] = [];
  const hasAccounts = ACCOUNT_SIGNATURES.some((s) => blob.includes(s));
  const socialHit = SOCIAL_LOGIN_SIGNATURES.find((s) => blob.includes(s));
  const hasApple = APPLE_LOGIN_SIGNATURES.some((s) => blob.includes(s));

  if (!hasAccounts && !socialHit) return findings;

  findings.push({
    severity: "warning",
    check: "demo-account",
    title: "Login detected — App Review needs working demo credentials",
    detail:
      "Guideline 2.1: if a reviewer can't get past your sign-in screen, the app is rejected without the rest of it ever being seen. This is the single most common avoidable rejection for account-based apps.",
    location: locate(corpus, layout, ACCOUNT_SIGNATURES.find((s) => blob.includes(s)) ?? ""),
    fix: "In App Store Connect → the version → App Review Information, tick 'Sign-in required' and provide a demo username/password that stays valid for the whole review. Use asc_check_submission to verify the field is actually filled.",
  });

  if (hasAccounts) {
    findings.push({
      severity: "warning",
      check: "account-deletion",
      title: "App creates user accounts — in-app account deletion is required",
      detail:
        "Guideline 5.1.1(v): any app that supports account creation must also let users initiate account deletion from inside the app. A support-email-only flow is rejected.",
      fix: "Add a 'Delete account' action in the app's settings that deletes the account and its data (not just a sign-out), and mention where it lives in the App Review notes.",
    });
  }

  if (socialHit && !hasApple) {
    findings.push({
      severity: "error",
      check: "sign-in-with-apple",
      title: `Third-party login (${socialHit}) without Sign in with Apple`,
      detail:
        "Guideline 4.8: an app that offers a third-party or social login service must also offer Sign in with Apple as an equivalent option. Apps whose only login is their own email/password account system are exempt.",
      location: locate(corpus, layout, socialHit),
      fix: "Add Sign in with Apple (ASAuthorizationAppleIDProvider / SignInWithAppleButton) alongside the existing provider, and enable the Sign in with Apple capability on the app target.",
    });
  } else if (socialHit && hasApple) {
    findings.push({
      severity: "info",
      check: "sign-in-with-apple",
      title: "Sign in with Apple offered alongside third-party login",
      detail: "Guideline 4.8 satisfied.",
    });
  }

  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// CHECK 14: External payment rails for digital content (3.1.1)
// ─────────────────────────────────────────────────────────────────────────────

export async function checkExternalPayments(projectPath: string): Promise<Finding[]> {
  const layout = await resolveLayout(projectPath);
  const corpus = await buildCorpus(layout);
  const blob = corpus.text;
  if (!blob.trim()) return [];

  const paymentHit = EXTERNAL_PAYMENT_SIGNATURES.find((s) => blob.includes(s));
  if (!paymentHit) return [];

  const hasStoreKit = PURCHASE_SIGNATURES.some((s) => blob.includes(s));
  if (hasStoreKit) {
    return [
      {
        severity: "info",
        check: "external-payments",
        title: `Non-Apple payments (${paymentHit}) present alongside StoreKit`,
        detail:
          "Both rails are in the binary. That's fine as long as the non-Apple one is only ever used for physical goods or services consumed outside the app — digital content must go through StoreKit (3.1.1).",
      },
    ];
  }

  return [
    {
      severity: "warning",
      check: "external-payments",
      title: `Non-Apple payment SDK (${paymentHit}) and no StoreKit in the project`,
      detail:
        "Guideline 3.1.1: unlocking digital content or features must use Apple's in-app purchase. Taking payment for digital goods through an external processor — or linking out to a web checkout for them — is a hard reject. Physical goods, and services consumed outside the app, are explicitly allowed.",
      location: locate(corpus, layout, paymentHit),
      fix: "If you sell digital content, move that purchase to StoreKit. If you sell physical goods/real-world services, this is fine — make sure the App Review notes say so, since reviewers will ask.",
    },
  ];
}

// ─────────────────────────────────────────────────────────────────────────────
// CHECK 15: Background modes declared but never used (2.5.4)
// ─────────────────────────────────────────────────────────────────────────────

/** Pull the UIBackgroundModes string array out of a raw Info.plist. */
export function parseBackgroundModes(plistRaw: string): string[] {
  const m = plistRaw.match(/<key>UIBackgroundModes<\/key>\s*<array>([\s\S]*?)<\/array>/);
  if (!m) return [];
  return [...m[1].matchAll(/<string>([^<]*)<\/string>/g)].map((x) => x[1].trim()).filter(Boolean);
}

export async function checkBackgroundModes(projectPath: string): Promise<Finding[]> {
  const layout = await resolveLayout(projectPath);
  if (!layout.infoPlistPath) return [];
  const modes = parseBackgroundModes(await safeRead(layout.infoPlistPath));
  if (modes.length === 0) return [];

  const blob = (await buildCorpus(layout)).text;
  const findings: Finding[] = [];
  const plistLoc = relative(layout.iosRoot, layout.infoPlistPath);

  for (const mode of modes) {
    const rule = BACKGROUND_MODE_RULES.find((r) => r.mode === mode);
    if (!rule) continue; // unknown/newer mode — don't guess
    if (rule.signatures.some((s) => blob.includes(s))) continue;
    findings.push({
      severity: "warning",
      check: "background-modes",
      title: `UIBackgroundModes declares "${mode}" but no matching API use was found`,
      detail: `Guideline 2.5.4: an app may only declare a background mode it actually implements. Nothing in first-party code looks like ${rule.label}, so a reviewer checking this will ask why the mode is there.`,
      location: plistLoc,
      fix: `Remove "${mode}" from UIBackgroundModes, or — if a dependency provides the behavior — explain it in the App Review notes.`,
    });
  }

  if (findings.length === 0) {
    findings.push({
      severity: "info",
      check: "background-modes",
      title: `Background modes justified (${modes.join(", ")})`,
      detail: "Every declared mode has corresponding API usage in first-party code.",
    });
  }
  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// CHECK 16: Placeholder / template content (2.1)
// ─────────────────────────────────────────────────────────────────────────────

export async function checkPlaceholderContent(projectPath: string): Promise<Finding[]> {
  const layout = await resolveLayout(projectPath);
  const corpus = await buildCorpus(layout);
  const findings: Finding[] = [];

  const infoRaw = layout.infoPlistPath ? await safeRead(layout.infoPlistPath) : "";
  // Scan source + the app's Info.plist (placeholders hide in both).
  const haystack: { path: string; text: string }[] = [...corpus.files];
  if (infoRaw && layout.infoPlistPath) haystack.push({ path: layout.infoPlistPath, text: infoRaw });

  for (const p of PLACEHOLDER_PATTERNS) {
    const hit = haystack.find((f) => p.pattern.test(f.text));
    if (!hit) continue;
    const match = hit.text.match(p.pattern);
    findings.push({
      severity: p.severity,
      check: "placeholder-content",
      title: p.label,
      detail: `Found ${match ? `"${match[0].slice(0, 60)}"` : "a placeholder"} in shipped content. Guideline 2.1 rejects apps containing placeholder text, dead links, or unconfigured keys.`,
      location: relative(layout.iosRoot, hit.path),
      fix: p.advice,
    });
  }

  // The app's display name is the most visible template leftover of all.
  const displayName = parsePlistStringValues(infoRaw).get("CFBundleDisplayName");
  if (displayName && TEMPLATE_APP_NAMES.has(displayName.trim())) {
    findings.push({
      severity: "warning",
      check: "placeholder-content",
      title: `CFBundleDisplayName is still the template name "${displayName}"`,
      detail: "The name under the icon on the Home Screen is a project template default.",
      location: layout.infoPlistPath ? relative(layout.iosRoot, layout.infoPlistPath) : undefined,
      fix: "Set CFBundleDisplayName to the real app name (it should match the App Store name closely — mismatches also draw 2.3 metadata rejections).",
    });
  }

  if (findings.length === 0) {
    findings.push({
      severity: "info",
      check: "placeholder-content",
      title: "No placeholder or template content detected",
      detail: "Checked source and Info.plist for filler text, test keys, example.com links, and template app names.",
    });
  }
  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// Auto-fix: insert a key/value pair into a plist's top-level dict
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Insert `<key>…</key>\n<valueXml>` just before the top-level dict's closing tag.
 * The top-level dict close is the last `</dict>` that appears before `</plist>`.
 * Returns the new document, or null if the key already exists / structure is odd.
 */
export function insertPlistKey(doc: string, key: string, valueXml: string): string | null {
  if (doc.includes(`<key>${key}</key>`)) return null; // already present
  const plistClose = doc.lastIndexOf("</plist>");
  if (plistClose < 0) return null;
  const dictClose = doc.lastIndexOf("</dict>", plistClose);
  if (dictClose < 0) return null;
  const before = doc.slice(0, dictClose);
  const after = doc.slice(dictClose);
  const snippet = `\t<key>${key}</key>\n\t${valueXml}\n`;
  return `${before}${snippet}${after}`;
}

export interface AutoFixResult {
  applied: { title: string; detail: string }[];
  manual: { title: string; detail: string }[];
  changedFiles: string[];
}

/**
 * Apply the safe, unambiguous fixes:
 *  - add ITSAppUsesNonExemptEncryption=false (HTTPS/TLS-only assumption)
 *  - (re)generate PrivacyInfo.xcprivacy to cover detected required-reason APIs
 *  - add stub NS…UsageDescription strings for detected permissions (flagged)
 * Everything requiring a human decision (real AdMob ID, missing icon, UIWebView,
 * dependency updates) is returned under `manual`.
 */
export async function applyAutoFixes(
  projectPath: string,
  opts: { addUsageStubs?: boolean } = {}
): Promise<AutoFixResult> {
  const layout = await resolveLayout(projectPath);
  const result: AutoFixResult = { applied: [], manual: [], changedFiles: [] };

  // 1) Export compliance key.
  if (layout.infoPlistPath) {
    let raw = await safeRead(layout.infoPlistPath);
    let touched = false;

    if (!raw.includes("<key>ITSAppUsesNonExemptEncryption</key>")) {
      const next = insertPlistKey(raw, "ITSAppUsesNonExemptEncryption", "<false/>");
      if (next) {
        raw = next;
        touched = true;
        result.applied.push({
          title: "Added ITSAppUsesNonExemptEncryption = false",
          detail: "Assumes standard HTTPS/TLS only. If you ship custom/proprietary encryption, set this to true and file the paperwork.",
        });
      }
    }

    // 2) Usage-description stubs (opt-in; stubs still need real copy before review).
    if (opts.addUsageStubs) {
      const sourceFiles = layout.appSourceDir ? await collectSourceFiles(layout.appSourceDir) : [];
      let corpus = "";
      for (const f of sourceFiles) corpus += await safeRead(f);
      corpus += await safeRead(join(layout.iosRoot, "Podfile"));
      corpus += await safeRead(join(layout.iosRoot, "..", "package.json"));
      for (const rule of USAGE_DESCRIPTION_RULES) {
        const used = rule.signatures.some((s) => corpus.includes(s));
        if (used && !raw.includes(`<key>${rule.key}</key>`)) {
          const stub = `This app uses ${rule.label.toLowerCase()} to provide its core features.`;
          const next = insertPlistKey(raw, rule.key, `<string>${stub}</string>`);
          if (next) {
            raw = next;
            touched = true;
            result.applied.push({
              title: `Added ${rule.key} (stub)`,
              detail: `Inserted a placeholder purpose string — REVIEW IT: "${stub}". Apple rejects vague strings, so tailor it to your actual feature.`,
            });
          }
        }
      }
    }

    if (touched) {
      await writeFile(layout.infoPlistPath, raw, "utf8");
      result.changedFiles.push(relative(layout.iosRoot, layout.infoPlistPath));
    }
  }

  // 3) Privacy manifest.
  const privacy = await scanPrivacyManifest(projectPath);
  if (privacy.missing.length > 0 || !privacy.manifestExists) {
    const { xml, targetPath, categories } = await buildPrivacyManifestXml(projectPath);
    if (targetPath) {
      await writeFile(targetPath, xml, "utf8");
      result.changedFiles.push(relative(layout.iosRoot, targetPath));
      result.applied.push({
        title: `${privacy.manifestExists ? "Updated" : "Created"} PrivacyInfo.xcprivacy`,
        detail: `Covers: ${categories.join(", ") || "no required-reason categories"}. Add it to the app target in Xcode if it's new.`,
      });
    }
  }

  // 4) Things a machine must not guess.
  const traps = await checkCredentialTraps(projectPath);
  for (const t of traps) result.manual.push({ title: t.title, detail: t.fix ?? t.detail });
  const icon = await checkAppIcon(projectPath);
  for (const f of icon) if (f.severity === "error") result.manual.push({ title: f.title, detail: f.fix ?? f.detail });
  const dep = await checkDeprecatedApis(projectPath);
  for (const f of dep) if (f.severity === "error") result.manual.push({ title: f.title, detail: f.fix ?? f.detail });

  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Aggregate preflight
// ─────────────────────────────────────────────────────────────────────────────

export async function runPreflight(projectPath: string): Promise<{
  findings: Finding[];
  summary: { errors: number; warnings: number; infos: number; verdict: string };
}> {
  const privacy = await scanPrivacyManifest(projectPath);
  const [
    usage,
    deps,
    traps,
    exportComp,
    ats,
    icon,
    deprecated,
    launch,
    version,
    deployment,
    legal,
    accounts,
    payments,
    backgroundModes,
    placeholders,
  ] = await Promise.all([
      checkUsageDescriptions(projectPath),
      auditDependencies(projectPath),
      checkCredentialTraps(projectPath),
      checkExportCompliance(projectPath),
      checkAppTransportSecurity(projectPath),
      checkAppIcon(projectPath),
      checkDeprecatedApis(projectPath),
      checkLaunchScreen(projectPath),
      checkVersionSanity(projectPath),
      checkDeploymentTarget(projectPath),
      checkLegalLinks(projectPath),
      checkAccountRequirements(projectPath),
      checkExternalPayments(projectPath),
      checkBackgroundModes(projectPath),
      checkPlaceholderContent(projectPath),
    ]);

  const all = [
    ...privacy.findings,
    ...usage,
    ...deps,
    ...traps,
    ...exportComp,
    ...ats,
    ...icon,
    ...deprecated,
    ...launch,
    ...version,
    ...deployment,
    ...legal,
    ...accounts,
    ...payments,
    ...backgroundModes,
    ...placeholders,
  ];
  const order: Record<Severity, number> = { error: 0, warning: 1, info: 2 };
  all.sort((a, b) => order[a.severity] - order[b.severity]);

  const errors = all.filter((f) => f.severity === "error").length;
  const warnings = all.filter((f) => f.severity === "warning").length;
  const infos = all.filter((f) => f.severity === "info").length;

  const verdict =
    errors > 0
      ? `NOT READY — ${errors} blocking issue${errors === 1 ? "" : "s"} will fail App Store review.`
      : warnings > 0
        ? `LIKELY OK — no blockers, but ${warnings} warning${warnings === 1 ? "" : "s"} worth fixing.`
        : "READY — no blocking review issues detected by Ship Doctor.";

  return { findings: all, summary: { errors, warnings, infos, verdict } };
}
