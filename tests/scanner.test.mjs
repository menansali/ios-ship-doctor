import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { cp, rm, readFile, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { generateKeyPairSync, createVerify } from "node:crypto";

import {
  runPreflight,
  insertPlistKey,
  applyAutoFixes,
  buildPrivacyManifestXml,
  stripComments,
  usesSignature,
  parsePlistEntries,
} from "../dist/scanner.js";
import { buildAscJwt, extractGuidelines } from "../dist/appstore.js";
import { CLIENTS, renderClientConfig, stableNodePath } from "../dist/clients.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const BAD = join(HERE, "fixtures", "BadApp");
const GOOD = join(HERE, "fixtures", "GoodApp");
const WEBPAY = join(HERE, "fixtures", "WebPayApp");
const MODERN = join(HERE, "fixtures", "ModernApp");

const errorChecks = (findings) => new Set(findings.filter((f) => f.severity === "error").map((f) => f.check));

test("preflight flags every planted issue in BadApp", async () => {
  const { findings, summary } = await runPreflight(BAD);
  assert.ok(summary.errors > 0, "should have blocking errors");
  assert.match(summary.verdict, /NOT READY/);
  const errs = errorChecks(findings);
  for (const expected of ["credential-traps", "privacy-manifest", "usage-descriptions", "deprecated-apis", "app-icon", "legal-links"]) {
    assert.ok(errs.has(expected), `expected an error for "${expected}", got: ${[...errs].join(", ")}`);
  }
});

test("preflight passes a clean app (GoodApp)", async () => {
  const { findings, summary } = await runPreflight(GOOD);
  assert.equal(summary.errors, 0, `expected 0 errors, got: ${findings.filter((f) => f.severity === "error").map((f) => f.title).join(" | ")}`);
  assert.match(summary.verdict, /NO BLOCKERS DETECTED/);
});

test("subscription app without legal links is flagged for both privacy policy and EULA", async () => {
  const { findings } = await runPreflight(BAD);
  const legal = findings.filter((f) => f.check === "legal-links");
  assert.ok(legal.some((f) => f.severity === "error" && /Terms of Use/.test(f.title)), "missing EULA error");
  assert.ok(legal.some((f) => f.severity === "error" && /Privacy Policy/.test(f.title)), "missing privacy policy error");
  // the App Store Connect description side can't be seen from source — always surfaced
  assert.ok(legal.some((f) => /App Store Connect description/.test(f.title)));
  // account creation implies the 5.1.1(v) deletion requirement
  assert.ok(findings.some((f) => f.check === "account-deletion"));
});

test("account-based app is flagged for demo credentials, deletion and Sign in with Apple", async () => {
  const { findings } = await runPreflight(BAD);
  const byCheck = (name) => findings.filter((f) => f.check === name);
  assert.ok(byCheck("demo-account").some((f) => f.severity === "warning"), "demo account reminder");
  assert.ok(byCheck("account-deletion").length === 1, "5.1.1(v) account deletion");
  const apple = byCheck("sign-in-with-apple");
  assert.ok(apple.some((f) => f.severity === "error" && /GIDSignIn/.test(f.title)), "4.8 error");
});

test("background modes without matching API use are flagged", async () => {
  const { findings } = await runPreflight(BAD);
  const modes = findings.filter((f) => f.check === "background-modes");
  // BadApp declares location + audio and implements neither
  assert.equal(modes.length, 2);
  assert.ok(modes.every((f) => f.severity === "warning"));
  assert.ok(modes.some((f) => /"location"/.test(f.title)));
  assert.ok(modes.some((f) => /"audio"/.test(f.title)));
});

test("placeholder content is caught in source and Info.plist", async () => {
  const { findings } = await runPreflight(BAD);
  const titles = findings.filter((f) => f.check === "placeholder-content").map((f) => f.title);
  assert.ok(titles.some((t) => /Lorem ipsum/i.test(t)), `expected lorem ipsum, got: ${titles.join(" | ")}`);
  assert.ok(titles.some((t) => /Unfilled configuration/.test(t)), "expected YOUR_API_KEY");
  assert.ok(titles.some((t) => /Placeholder support email/.test(t)), "expected test@example.com");
});

test("external payments without StoreKit are flagged; alongside StoreKit they are not", async () => {
  const web = await runPreflight(WEBPAY);
  const pay = web.findings.filter((f) => f.check === "external-payments");
  assert.equal(pay.length, 1);
  assert.equal(pay[0].severity, "warning");
  assert.match(pay[0].title, /StripePaymentSheet/);

  // BadApp has StoreKit and no external processor → no warning at all
  const bad = await runPreflight(BAD);
  assert.equal(bad.findings.filter((f) => f.check === "external-payments").length, 0);
});

test("template app name and Stripe test key are caught", async () => {
  const { findings } = await runPreflight(WEBPAY);
  const titles = findings.filter((f) => f.check === "placeholder-content").map((f) => f.title);
  assert.ok(titles.some((t) => /template name "MyApp"/.test(t)), `got: ${titles.join(" | ")}`);
  assert.ok(titles.some((t) => /Stripe TEST API key/.test(t)));
});

test("modern project with a generated Info.plist is fully analysed", async () => {
  // Regression: ModernApp has NO Info.plist file — every key is a build
  // setting. This layout used to scan as an empty project and report clean.
  const { findings } = await runPreflight(MODERN);
  const checks = new Set(findings.map((f) => f.check));
  assert.ok(checks.has("usage-descriptions"), "must have looked at permissions");

  // Keys declared only in build settings must count as declared.
  const errs = findings.filter((f) => f.severity === "error").map((f) => f.title).join(" | ");
  assert.doesNotMatch(errs, /NSCameraUsageDescription/, "camera string is in INFOPLIST_KEY_*");
  assert.doesNotMatch(errs, /marketing version|build number/i, "MARKETING_VERSION/CURRENT_PROJECT_VERSION are set");
  const all = findings.map((f) => f.title).join(" | ");
  assert.doesNotMatch(all, /No launch screen/, "UILaunchScreen_Generation = YES");
  assert.doesNotMatch(all, /ITSAppUsesNonExemptEncryption/, "declared in build settings");

  // UIBackgroundModes declared as a build-setting array is still cross-checked.
  const modes = findings.filter((f) => f.check === "background-modes");
  assert.equal(modes.length, 2, "audio + location, neither implemented");
});

test("@State is not mistaken for the stat() file-timestamp API", async () => {
  // "stat" is a required-reason C function and a substring of "@State", so a
  // naive contains-match flagged every SwiftUI file in existence.
  const { findings } = await runPreflight(MODERN);
  const fileTimestamp = findings.filter((f) => /File timestamp/.test(f.title));
  assert.equal(fileTimestamp.length, 0, `false positive: ${fileTimestamp.map((f) => f.title).join()}`);
  assert.equal(usesSignature("@State private var x = 1", "stat"), false);
  assert.equal(usesSignature("if stat(path, &buf) == 0 {", "stat"), true);
  // partial-word matches must not fire either
  assert.equal(usesSignature("let status = 1", "stat"), false);
  assert.equal(usesSignature("statistics()", "stat"), false);
});

test("the app target's settings win over an extension's", async () => {
  // The widget config in the fixture sets CFBundleDisplayName = MyApp (a
  // template name). Reading it as the app's would be a false positive.
  const { findings } = await runPreflight(MODERN);
  assert.ok(
    !findings.some((f) => /template name/.test(f.title)),
    "widget settings must not be merged into the app target"
  );
});

test("plist keys holding a dict count as declared", () => {
  const raw = `<plist><dict>
    <key>UILaunchScreen</key><dict><key>UIColorName</key><string>Bg</string></dict>
    <key>UIBackgroundModes</key><array><string>audio</string></array>
    <key>ITSAppUsesNonExemptEncryption</key><false/>
  </dict></plist>`;
  const entries = parsePlistEntries(raw);
  assert.ok(entries.has("UILaunchScreen"), "dict-valued key must register");
  assert.deepEqual(entries.get("UIBackgroundModes"), ["audio"]);
  assert.equal(entries.get("ITSAppUsesNonExemptEncryption"), "NO");
});

test("verdicts do not promise App Store approval", async () => {
  const { summary } = await runPreflight(MODERN);
  assert.doesNotMatch(summary.verdict, /will fail|^READY|guaranteed/);
  assert.match(summary.caveat, /does not predict approval/);
});

test("stripComments removes comments but never breaks URLs", () => {
  assert.equal(stripComments("let x = 1 // uses StoreKit\n").trim(), "let x = 1");
  assert.equal(stripComments("/* uses StoreKit */ let y = 2").trim(), "let y = 2");
  // the // in a URL must survive — it's the evidence the link checks look for
  assert.match(stripComments('let u = "https://acme.dev/privacy"'), /https:\/\/acme\.dev\/privacy/);
});

test("insertPlistKey inserts once and is idempotent", () => {
  const doc = `<plist version="1.0">\n<dict>\n\t<key>Existing</key>\n\t<string>x</string>\n</dict>\n</plist>\n`;
  const added = insertPlistKey(doc, "ITSAppUsesNonExemptEncryption", "<false/>");
  assert.ok(added && added.includes("<key>ITSAppUsesNonExemptEncryption</key>"));
  assert.ok(added.indexOf("</dict>") < added.indexOf("</plist>"));
  // second insert returns null (already present)
  assert.equal(insertPlistKey(added, "ITSAppUsesNonExemptEncryption", "<false/>"), null);
});

test("autofix repairs a copy of BadApp without touching the original", async () => {
  const dir = await mkdtemp(join(tmpdir(), "shipdoctor-"));
  try {
    await cp(BAD, join(dir, "BadApp"), { recursive: true });
    const target = join(dir, "BadApp");
    const r = await applyAutoFixes(target, { addUsageStubs: true });

    // export-compliance + camera stub + PrivacyInfo were applied
    const applied = r.applied.map((a) => a.title).join(" | ");
    assert.match(applied, /ITSAppUsesNonExemptEncryption/);
    assert.match(applied, /PrivacyInfo\.xcprivacy/);
    assert.match(applied, /NSCameraUsageDescription/);

    // AdMob / icon / UIWebView are reported as manual, never auto-guessed
    const manual = r.manual.map((m) => m.title).join(" | ");
    assert.match(manual, /AdMob/);
    assert.match(manual, /UIWebView/);

    // re-running preflight on the fixed copy clears the fixable errors
    const after = await runPreflight(target);
    const errs = errorChecks(after.findings);
    assert.ok(!errs.has("privacy-manifest"), "privacy-manifest should be fixed");
    assert.ok(!errs.has("usage-descriptions"), "usage-descriptions should be fixed");
    // AdMob + icon + UIWebView remain (not machine-fixable)
    assert.ok(errs.has("credential-traps"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("generated privacy manifest is well-formed XML and covers detected APIs", async () => {
  const { xml, categories } = await buildPrivacyManifestXml(BAD);
  assert.match(xml, /<plist version="1.0">/);
  assert.match(xml, /NSPrivacyAccessedAPITypes/);
  assert.ok(categories.includes("NSPrivacyAccessedAPICategoryUserDefaults"));
});

test("every client config snippet is valid and correctly shaped", () => {
  const NODE = "/usr/local/bin/node";
  const SERVER = "/srv/ios-ship-doctor/dist/index.js";

  for (const c of CLIENTS) {
    const out = renderClientConfig(c, NODE, SERVER);
    assert.ok(out.includes(SERVER), `${c.id}: must reference the server path`);
    // Credentials must not be pre-baked: a literal ${VAR} from a client that
    // doesn't expand it reaches the server as a real-looking key and 401s.
    assert.doesNotMatch(out.split("# Optional")[0], /\$\{ASC_/, `${c.id}: no unexpanded env placeholders`);
  }

  const byId = Object.fromEntries(CLIENTS.map((c) => [c.id, c]));
  const parse = (id) => JSON.parse(byId[id].render(NODE, SERVER));
  assert.ok(parse("cursor").mcpServers["ios-ship-doctor"], "cursor uses mcpServers");
  assert.ok(parse("vscode").servers["ios-ship-doctor"], "VS Code uses servers, not mcpServers");
  assert.equal(parse("vscode").servers["ios-ship-doctor"].type, "stdio");
  // Zed nests the binary under command.path instead of a bare command string.
  assert.equal(parse("zed").context_servers["ios-ship-doctor"].command.path, NODE);

  // Codex is TOML and the underscore matters — "mcp-servers" is ignored silently.
  const codex = byId.codex.render(NODE, SERVER);
  assert.match(codex, /^\[mcp_servers\.ios-ship-doctor\]$/m);
  assert.doesNotMatch(codex, /\[mcp-servers/);
});

test("generated node path avoids version-pinned installs", () => {
  // Homebrew Cellar / nvm paths break on the next upgrade — prefer the symlink.
  assert.equal(
    stableNodePath("/opt/homebrew/Cellar/node/24.1.0/bin/node", (p) => p === "/opt/homebrew/bin/node"),
    "/opt/homebrew/bin/node"
  );
  assert.equal(
    stableNodePath("/Users/x/.nvm/versions/node/v22.0.0/bin/node", (p) => p === "/usr/local/bin/node"),
    "/usr/local/bin/node"
  );
  // Already-stable paths are left alone, and we never invent one that isn't there.
  assert.equal(stableNodePath("/usr/bin/node", () => false), "/usr/bin/node");
  assert.equal(
    stableNodePath("/opt/homebrew/Cellar/node/24.1.0/bin/node", () => false),
    "/opt/homebrew/Cellar/node/24.1.0/bin/node"
  );
});

test("App Store Connect JWT is a valid ES256/JOSE signature", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const jwt = buildAscJwt({ keyId: "ABC123", issuerId: "issuer", privateKeyPem: pem }, 1_700_000_000);
  const [h, p, s] = jwt.split(".");
  const sig = Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  const v = createVerify("SHA256");
  v.update(`${h}.${p}`);
  v.end();
  assert.ok(v.verify({ key: publicKey, dsaEncoding: "ieee-p1363" }, sig));
  const header = JSON.parse(Buffer.from(h, "base64url").toString());
  assert.equal(header.alg, "ES256");
  assert.equal(header.kid, "ABC123");
});

test("extractGuidelines picks up known guideline numbers only", () => {
  const g = extractGuidelines("Rejected under 5.1.1 and 2.1 but not 99.9");
  assert.deepEqual(g.sort(), ["2.1", "5.1.1"]);
});
