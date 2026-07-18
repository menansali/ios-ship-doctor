import { readFile, readdir, stat } from "node:fs/promises";
import { join, extname, basename, relative } from "node:path";
import { XMLParser } from "fast-xml-parser";
import {
  REQUIRED_REASON_CATEGORIES,
  USAGE_DESCRIPTION_RULES,
  CREDENTIAL_TRAPS,
  REASON_HINTS,
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
 * plist <dict> is parsed as parallel <key> and value arrays. This flattens the
 * top-level dict into a Map of key -> raw value node.
 */
function plistDictToMap(dictNode: any): Map<string, any> {
  const map = new Map<string, any>();
  if (!dictNode) return map;
  const dict = Array.isArray(dictNode) ? dictNode[0] : dictNode;
  if (!dict || typeof dict !== "object") return map;
  const keys = ([] as any[]).concat(dict.key ?? []);
  // Collect value nodes in document order is non-trivial with this parser, so we
  // rely on the fact that for our checks we only need presence + string values,
  // which we extract structurally below where needed. For usage-description keys
  // (string values) we can match key->string by index.
  const strings = ([] as any[]).concat(dict.string ?? []);
  keys.forEach((k: string, i: number) => {
    map.set(String(k), strings[i]);
  });
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

  const parsed = await parsePlist(layout.infoPlistPath);
  const map = plistDictToMap(parsed?.plist?.dict);

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
  if (!layout.podsDir) {
    findings.push({
      severity: "info",
      check: "dependencies",
      title: "No Pods directory found",
      detail: "Skipping CocoaPods dependency manifest audit (SwiftPM/manual frameworks are not scanned in this version).",
    });
    return findings;
  }

  let pods;
  try {
    pods = await readdir(layout.podsDir, { withFileTypes: true });
  } catch {
    return findings;
  }

  for (const pod of pods) {
    if (!pod.isDirectory()) continue;
    if (["Target Support Files", "Headers", "Local Podspecs", "Manifest.lock"].includes(pod.name)) continue;
    const podDir = join(layout.podsDir, pod.name);
    // Does this pod contain any PrivacyInfo.xcprivacy anywhere inside it?
    const hasManifest = await containsFile(podDir, "PrivacyInfo.xcprivacy");
    const isListed = APPLE_LISTED_SDK_HINTS.some((h) =>
      pod.name.toLowerCase().includes(h.toLowerCase())
    );
    if (!hasManifest && isListed) {
      findings.push({
        severity: "error",
        check: "dependencies",
        title: `SDK "${pod.name}" is on Apple's required-manifest list but ships no PrivacyInfo.xcprivacy`,
        detail: "Apple requires this commonly-used SDK to include a signed privacy manifest. The build will be rejected.",
        location: relative(layout.iosRoot, podDir),
        fix: `Update ${pod.name} to a version that bundles a privacy manifest (most have shipped one since 2024).`,
      });
    }
  }

  if (findings.length === 0) {
    findings.push({
      severity: "info",
      check: "dependencies",
      title: "Dependency privacy manifests look OK",
      detail: "All Apple-listed SDKs found in Pods bundle a PrivacyInfo.xcprivacy.",
    });
  }
  return findings;
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
// Aggregate preflight
// ─────────────────────────────────────────────────────────────────────────────

export async function runPreflight(projectPath: string): Promise<{
  findings: Finding[];
  summary: { errors: number; warnings: number; infos: number; verdict: string };
}> {
  const privacy = await scanPrivacyManifest(projectPath);
  const [usage, deps, traps] = await Promise.all([
    checkUsageDescriptions(projectPath),
    auditDependencies(projectPath),
    checkCredentialTraps(projectPath),
  ]);

  const all = [...privacy.findings, ...usage, ...deps, ...traps];
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
