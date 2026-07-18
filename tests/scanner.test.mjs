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
} from "../dist/scanner.js";
import { buildAscJwt, extractGuidelines } from "../dist/appstore.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const BAD = join(HERE, "fixtures", "BadApp");
const GOOD = join(HERE, "fixtures", "GoodApp");

const errorChecks = (findings) => new Set(findings.filter((f) => f.severity === "error").map((f) => f.check));

test("preflight flags every planted issue in BadApp", async () => {
  const { findings, summary } = await runPreflight(BAD);
  assert.ok(summary.errors > 0, "should have blocking errors");
  assert.match(summary.verdict, /NOT READY/);
  const errs = errorChecks(findings);
  for (const expected of ["credential-traps", "privacy-manifest", "usage-descriptions", "deprecated-apis", "app-icon"]) {
    assert.ok(errs.has(expected), `expected an error for "${expected}", got: ${[...errs].join(", ")}`);
  }
});

test("preflight passes a clean app (GoodApp)", async () => {
  const { findings, summary } = await runPreflight(GOOD);
  assert.equal(summary.errors, 0, `expected 0 errors, got: ${findings.filter((f) => f.severity === "error").map((f) => f.title).join(" | ")}`);
  assert.match(summary.verdict, /READY/);
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
