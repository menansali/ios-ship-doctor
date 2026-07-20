/**
 * Minimal project.pbxproj reader.
 *
 * Modern Xcode projects (Xcode 13+ templates) ship NO Info.plist file at all:
 * GENERATE_INFOPLIST_FILE=YES and every key lives in build settings as
 * INFOPLIST_KEY_<Name>. A scanner that only reads Info.plist sees an empty
 * project and reports it clean — which is exactly what Ship Doctor did before
 * this module existed.
 *
 * This is a targeted extractor, not a general OpenStep plist parser: it pulls
 * XCBuildConfiguration setting blocks and reads the handful of settings that
 * affect App Store review.
 */
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";

export type SettingValue = string | string[];
export type BuildSettings = Map<string, SettingValue>;

/** Strip the quoting pbxproj applies to values that aren't bare identifiers. */
function unquote(raw: string): string {
  const v = raw.trim();
  if (v.startsWith('"') && v.endsWith('"') && v.length >= 2) {
    return v.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, "\\");
  }
  return v;
}

/**
 * Parse the `KEY = VALUE;` pairs inside one settings block. Handles bare values,
 * quoted strings, and `( "a", "b", )` arrays (used by e.g. UIBackgroundModes).
 */
export function parseSettingsBlock(block: string): BuildSettings {
  const out: BuildSettings = new Map();
  const re = /([A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?)\s*=\s*(\([\s\S]*?\)|"(?:[^"\\]|\\.)*"|[^;\n]*)\s*;/g;
  for (const m of block.matchAll(re)) {
    const key = m[1];
    const raw = m[2].trim();
    if (raw.startsWith("(")) {
      const items = [...raw.slice(1, -1).matchAll(/"(?:[^"\\]|\\.)*"|[^,\s]+/g)]
        .map((x) => unquote(x[0]))
        .filter((x) => x && x !== ",");
      out.set(key, items);
    } else {
      out.set(key, unquote(raw));
    }
  }
  return out;
}

/** Every XCBuildConfiguration buildSettings block in the file. */
export function parseBuildConfigurations(pbxproj: string): BuildSettings[] {
  const blocks: BuildSettings[] = [];
  const re = /buildSettings\s*=\s*\{([\s\S]*?)\n\s*\};/g;
  for (const m of pbxproj.matchAll(re)) blocks.push(parseSettingsBlock(m[1]));
  return blocks;
}

export interface XcodeProject {
  path: string;
  /** Merged settings for the primary app target. */
  settings: BuildSettings;
  /** Info.plist keys declared as INFOPLIST_KEY_* build settings. */
  infoPlistKeys: Map<string, SettingValue>;
  /** Bundle id chosen as the app's (shortest — extensions suffix onto it). */
  bundleId: string | null;
}

const NON_APP_HINTS = /tests?$|uitests?$|widget|extension|watchkit|clip|intents|notificationservice/i;

/**
 * Pick the app target's configurations and merge them.
 *
 * Heuristic: extensions and test targets suffix onto the app's bundle id
 * (com.acme.App.Widget), so the shortest bundle id that isn't obviously a test
 * or extension is the app. Debug/Release for that target are merged; where they
 * differ, Release wins because that's what gets submitted.
 */
export function selectAppSettings(configs: BuildSettings[]): { settings: BuildSettings; bundleId: string | null } {
  const withId = configs.filter((c) => typeof c.get("PRODUCT_BUNDLE_IDENTIFIER") === "string");
  const ids = withId
    .map((c) => c.get("PRODUCT_BUNDLE_IDENTIFIER") as string)
    .filter((id) => !NON_APP_HINTS.test(id));
  ids.sort((a, b) => a.length - b.length || a.localeCompare(b));
  const bundleId = ids[0] ?? null;

  // Configs belonging to the app target, Debug first so Release overwrites it.
  let appConfigs = bundleId ? withId.filter((c) => c.get("PRODUCT_BUNDLE_IDENTIFIER") === bundleId) : [];
  if (appConfigs.length === 0) {
    // No bundle ids at all (rare) — fall back to any config that configures a plist.
    appConfigs = configs.filter(
      (c) => c.has("GENERATE_INFOPLIST_FILE") || c.has("INFOPLIST_FILE") || [...c.keys()].some((k) => k.startsWith("INFOPLIST_KEY_"))
    );
  }
  appConfigs.sort((a, b) => {
    const rank = (c: BuildSettings) => (String(c.get("SWIFT_OPTIMIZATION_LEVEL") ?? "").includes("Onone") ? 0 : 1);
    return rank(a) - rank(b);
  });

  const settings: BuildSettings = new Map();
  for (const c of appConfigs) for (const [k, v] of c) settings.set(k, v);
  return { settings, bundleId };
}

/** Find the app's .xcodeproj under `root` (ignores Pods.xcodeproj). */
export async function findXcodeProject(root: string): Promise<string | null> {
  let entries;
  try {
    entries = await readdir(root, { withFileTypes: true });
  } catch {
    return null;
  }
  const projects = entries
    .filter((e) => e.isDirectory() && e.name.endsWith(".xcodeproj") && e.name !== "Pods.xcodeproj")
    .map((e) => join(root, e.name));
  return projects[0] ?? null;
}

export async function readXcodeProject(root: string): Promise<XcodeProject | null> {
  const path = await findXcodeProject(root);
  if (!path) return null;
  let raw: string;
  try {
    raw = await readFile(join(path, "project.pbxproj"), "utf8");
  } catch {
    return null;
  }
  const { settings, bundleId } = selectAppSettings(parseBuildConfigurations(raw));
  const infoPlistKeys = new Map<string, SettingValue>();
  for (const [k, v] of settings) {
    if (k.startsWith("INFOPLIST_KEY_")) infoPlistKeys.set(k.slice("INFOPLIST_KEY_".length), v);
  }
  return { path, settings, infoPlistKeys, bundleId };
}

/** Build-setting names whose values Xcode writes into the generated Info.plist. */
export const GENERATED_PLIST_EQUIVALENTS: Record<string, string> = {
  CFBundleShortVersionString: "MARKETING_VERSION",
  CFBundleVersion: "CURRENT_PROJECT_VERSION",
  CFBundleDisplayName: "INFOPLIST_KEY_CFBundleDisplayName",
};
