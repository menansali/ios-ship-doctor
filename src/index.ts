#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { writeFile } from "node:fs/promises";
import { z } from "zod";
import {
  scanPrivacyManifest,
  checkUsageDescriptions,
  auditDependencies,
  checkCredentialTraps,
  checkLegalLinks,
  checkAccountRequirements,
  checkExternalPayments,
  checkBackgroundModes,
  checkPlaceholderContent,
  buildPrivacyManifestXml,
  applyAutoFixes,
  runPreflight,
  type Finding,
} from "./scanner.js";
import {
  loadAscCreds,
  buildAscJwt,
  listApps,
  getRejections,
  checkSubmission,
  extractGuidelines,
  GUIDELINE_MAP,
  AscConfigError,
} from "./appstore.js";

const server = new McpServer({
  name: "ios-ship-doctor",
  version: "0.1.0",
});

const ICON: Record<Finding["severity"], string> = {
  error: "❌",
  warning: "⚠️",
  info: "✅",
};

function renderFindings(findings: Finding[]): string {
  if (findings.length === 0) return "No findings.";
  return findings
    .map((f) => {
      const lines = [`${ICON[f.severity]} [${f.check}] ${f.title}`, `   ${f.detail}`];
      if (f.location) lines.push(`   ↳ ${f.location}`);
      if (f.fix) lines.push(`   💡 ${f.fix}`);
      return lines.join("\n");
    })
    .join("\n\n");
}

const projectPathArg = {
  projectPath: z
    .string()
    .describe(
      "Absolute path to the iOS project. Can be the repo root (containing an ios/ folder) or the ios/ directory itself."
    ),
};

// ── Tool: full preflight ──────────────────────────────────────────────────────
server.tool(
  "preflight",
  "Run ALL App Store readiness checks on an iOS project and return a single prioritized report: privacy manifest vs required-reason API usage, Info.plist usage-description keys, third-party SDK privacy manifests, and placeholder/test-credential traps. Start here — it answers 'is this app ready to submit?'.",
  projectPathArg,
  async ({ projectPath }) => {
    const { findings, summary } = await runPreflight(projectPath);
    const header = `🩺 Ship Doctor preflight — ${projectPath}\n\nVERDICT: ${summary.verdict}\n(${summary.errors} errors, ${summary.warnings} warnings, ${summary.infos} passed)`;
    return {
      content: [{ type: "text", text: `${header}\n\n${renderFindings(findings)}\n\nℹ️ ${summary.caveat}` }],
    };
  }
);

// ── Tool: privacy manifest scan ───────────────────────────────────────────────
server.tool(
  "scan_privacy_manifest",
  "Compare the required-reason APIs actually used in first-party code against what the app's PrivacyInfo.xcprivacy declares. Reports undeclared categories (hard rejects), invalid reason codes, and a missing manifest.",
  projectPathArg,
  async ({ projectPath }) => {
    const result = await scanPrivacyManifest(projectPath);
    const detail =
      `Manifest: ${result.manifestPath ?? "(none found)"}\n` +
      `Declared categories: ${result.declaredCategories.join(", ") || "none"}\n` +
      `Detected required-reason API usage in code: ${result.usedCategories.map((u) => u.label).join(", ") || "none"}\n\n` +
      renderFindings(result.findings);
    return { content: [{ type: "text", text: detail }] };
  }
);

// ── Tool: usage descriptions ──────────────────────────────────────────────────
server.tool(
  "check_usage_descriptions",
  "Detect which permission-gated capabilities (camera, location, photos, mic, contacts, tracking, etc.) the project uses, then verify Info.plist has the required NS…UsageDescription purpose string for each. Missing keys crash the app and fail review.",
  projectPathArg,
  async ({ projectPath }) => {
    const findings = await checkUsageDescriptions(projectPath);
    return { content: [{ type: "text", text: renderFindings(findings) }] };
  }
);

// ── Tool: dependency audit ────────────────────────────────────────────────────
server.tool(
  "audit_dependencies",
  "Scan CocoaPods dependencies for SDKs on Apple's required-privacy-manifest list that ship WITHOUT a PrivacyInfo.xcprivacy. Those are hard rejects at upload time.",
  projectPathArg,
  async ({ projectPath }) => {
    const findings = await auditDependencies(projectPath);
    return { content: [{ type: "text", text: renderFindings(findings) }] };
  }
);

// ── Tool: credential traps ────────────────────────────────────────────────────
server.tool(
  "check_credential_traps",
  "Look for placeholder or public TEST credentials left in Info.plist (e.g. Google's sample AdMob App ID) that must never ship to production.",
  projectPathArg,
  async ({ projectPath }) => {
    const findings = await checkCredentialTraps(projectPath);
    return {
      content: [
        {
          type: "text",
          text: findings.length ? renderFindings(findings) : "✅ No placeholder/test credentials detected in Info.plist.",
        },
      ],
    };
  }
);

// ── Tool: legal links (privacy policy / EULA) ─────────────────────────────────
server.tool(
  "check_legal_links",
  "Check the App Store legal-link requirements: a Privacy Policy link (mandatory for every app) and, for apps with in-app purchases, a Terms of Use (EULA) link — required both at the point of purchase and in the App Store Connect description text (Guideline 3.1.2). Also flags the in-app account-deletion requirement (5.1.1(v)) when account creation is detected.",
  projectPathArg,
  async ({ projectPath }) => {
    const findings = await checkLegalLinks(projectPath);
    return {
      content: [
        {
          type: "text",
          text: findings.length ? renderFindings(findings) : "No purchase or account signals found — nothing to check.",
        },
      ],
    };
  }
);

// ── Tool: account requirements ────────────────────────────────────────────────
server.tool(
  "check_account_requirements",
  "For apps with accounts: flags a missing demo account for App Review (2.1), the in-app account-deletion requirement (5.1.1(v)), and third-party/social login shipped without Sign in with Apple (4.8).",
  projectPathArg,
  async ({ projectPath }) => {
    const findings = await checkAccountRequirements(projectPath);
    return {
      content: [
        { type: "text", text: findings.length ? renderFindings(findings) : "No account/login signals found — nothing to check." },
      ],
    };
  }
);

// ── Tool: external payments ───────────────────────────────────────────────────
server.tool(
  "check_external_payments",
  "Detect non-Apple payment rails (Stripe, PayPal, Braintree, Paddle…) in a project that has no StoreKit. Charging for digital content outside Apple's IAP is Guideline 3.1.1 — a hard reject. Physical goods are exempt, so this reports for judgement rather than asserting a violation.",
  projectPathArg,
  async ({ projectPath }) => {
    const findings = await checkExternalPayments(projectPath);
    return {
      content: [
        { type: "text", text: findings.length ? renderFindings(findings) : "✅ No third-party payment SDKs detected." },
      ],
    };
  }
);

// ── Tool: background modes ────────────────────────────────────────────────────
server.tool(
  "check_background_modes",
  "Cross-check every UIBackgroundModes entry in Info.plist against actual API usage in source. Declaring a background mode the app doesn't implement is Guideline 2.5.4, and reviewers check it specifically.",
  projectPathArg,
  async ({ projectPath }) => {
    const findings = await checkBackgroundModes(projectPath);
    return {
      content: [
        { type: "text", text: findings.length ? renderFindings(findings) : "No UIBackgroundModes declared — nothing to check." },
      ],
    };
  }
);

// ── Tool: placeholder content ─────────────────────────────────────────────────
server.tool(
  "check_placeholder_content",
  "Scan source and Info.plist for content that should never reach review: lorem ipsum, Stripe test keys, YOUR_API_KEY-style template tokens, example.com dead links, and template app names still set as CFBundleDisplayName (Guideline 2.1).",
  projectPathArg,
  async ({ projectPath }) => {
    const findings = await checkPlaceholderContent(projectPath);
    return { content: [{ type: "text", text: renderFindings(findings) }] };
  }
);

// ── Tool: generate manifest ───────────────────────────────────────────────────
server.tool(
  "generate_privacy_manifest",
  "Generate a valid PrivacyInfo.xcprivacy covering every required-reason API detected in first-party code (plus anything already declared). By default only PREVIEWS the XML; pass write=true to save it to the app target directory. After writing, the file still must be added to the app target in Xcode.",
  {
    ...projectPathArg,
    write: z
      .boolean()
      .default(false)
      .describe("If true, write the manifest to <appSourceDir>/PrivacyInfo.xcprivacy. If false, only return the XML for review."),
  },
  async ({ projectPath, write }) => {
    const { xml, categories, targetPath } = await buildPrivacyManifestXml(projectPath);
    if (write) {
      if (!targetPath) {
        return {
          content: [{ type: "text", text: "Could not resolve the app source directory to write the manifest. Run scan_privacy_manifest first to confirm the project layout." }],
          isError: true,
        };
      }
      await writeFile(targetPath, xml, "utf8");
      return {
        content: [
          {
            type: "text",
            text: `✅ Wrote PrivacyInfo.xcprivacy to:\n${targetPath}\n\nCovers: ${categories.join(", ") || "no required-reason categories"}\n\n⚠️ Next: in Xcode, add this file to the app target's "Copy Bundle Resources" build phase (right-click the app group → Add Files), then rebuild.`,
          },
        ],
      };
    }
    return {
      content: [
        {
          type: "text",
          text: `Preview only (write=false). Categories covered: ${categories.join(", ") || "none"}\nWould write to: ${targetPath ?? "(app dir not resolved)"}\n\n${xml}`,
        },
      ],
    };
  }
);

// ── Tool: auto-fix ────────────────────────────────────────────────────────────
server.tool(
  "autofix",
  "Apply the safe, unambiguous App Store fixes automatically: add ITSAppUsesNonExemptEncryption=false, (re)generate PrivacyInfo.xcprivacy to cover detected required-reason APIs, and (optionally) insert stub NS…UsageDescription strings. Anything a machine shouldn't guess (real AdMob ID, missing icon, UIWebView, dependency updates) is reported as manual follow-up. Modifies files on disk.",
  {
    ...projectPathArg,
    addUsageStubs: z
      .boolean()
      .default(false)
      .describe("Also insert placeholder NS…UsageDescription strings for detected permissions. The stubs MUST be reviewed — Apple rejects vague purpose strings."),
  },
  async ({ projectPath, addUsageStubs }) => {
    const r = await applyAutoFixes(projectPath, { addUsageStubs });
    const parts: string[] = [];
    parts.push(
      r.applied.length
        ? `✅ Applied ${r.applied.length} fix(es):\n` + r.applied.map((a) => `   • ${a.title}\n     ${a.detail}`).join("\n")
        : "No automatic fixes were needed."
    );
    if (r.changedFiles.length) parts.push(`📝 Changed files:\n` + r.changedFiles.map((f) => `   • ${f}`).join("\n"));
    if (r.manual.length)
      parts.push(`⚠️ Needs your attention (not auto-fixable):\n` + r.manual.map((m) => `   • ${m.title}\n     ${m.detail}`).join("\n"));
    return { content: [{ type: "text", text: parts.join("\n\n") }] };
  }
);

// ── App Store Connect: rejection recovery ─────────────────────────────────────

/** Mint a fresh short-lived JWT using real wall-clock time. */
async function ascToken(): Promise<string> {
  const creds = await loadAscCreds();
  return buildAscJwt(creds, Math.floor(Date.now() / 1000));
}

function ascErrorContent(e: unknown) {
  const msg = e instanceof AscConfigError ? e.message : e instanceof Error ? e.message : String(e);
  return { content: [{ type: "text" as const, text: `⚠️ ${msg}` }], isError: true };
}

server.tool(
  "asc_list_apps",
  "List the apps on your App Store Connect account (id, name, bundle id). Requires ASC_KEY_ID, ASC_ISSUER_ID, and ASC_PRIVATE_KEY(_PATH) env vars. Use the returned app id with asc_get_rejections.",
  {},
  async () => {
    try {
      const apps = await listApps(await ascToken());
      const text = apps.length
        ? apps.map((a) => `• ${a.name}\n  id: ${a.id}\n  bundle: ${a.bundleId}`).join("\n\n")
        : "No apps found on this account.";
      return { content: [{ type: "text", text }] };
    } catch (e) {
      return ascErrorContent(e);
    }
  }
);

server.tool(
  "asc_get_rejections",
  "Fetch recent App Store review rejections for an app and map any referenced Review Guideline numbers to plain-language summaries and typical fixes. This closes the loop from 'why was I rejected' to 'here's what to change'.",
  {
    appId: z.string().describe("App Store Connect app id (from asc_list_apps)."),
  },
  async ({ appId }) => {
    try {
      const rejections = await getRejections(await ascToken(), appId);
      if (!rejections.length) {
        return { content: [{ type: "text", text: "✅ No rejected / metadata-rejected versions found for this app." }] };
      }
      const blocks = rejections.map((r) => {
        const guidelines = extractGuidelines(r.message);
        const mapped = guidelines
          .map((g) => {
            const info = GUIDELINE_MAP[g];
            return `   📖 Guideline ${g} — ${info.title}\n      ${info.summary}\n      💡 ${info.fix}`;
          })
          .join("\n");
        return [
          `❌ Version ${r.versionString ?? "?"} — ${r.state ?? "rejected"}${r.createdDate ? ` (${r.createdDate})` : ""}`,
          `   ${r.message}`,
          mapped || "   (No known guideline number found in the summary — open Resolution Center for the full reviewer message.)",
        ].join("\n");
      });
      return { content: [{ type: "text", text: blocks.join("\n\n") }] };
    } catch (e) {
      return ascErrorContent(e);
    }
  }
);

server.tool(
  "asc_check_submission",
  "Check the App Store Connect side of readiness for the next version: whether demo credentials are actually filled in for a login-gated app (Guideline 2.1 — the most common avoidable rejection), whether App Review notes exist, and whether the required iPhone screenshot sets have anything in them. Complements the local `preflight`, which can only see the binary.",
  {
    appId: z.string().describe("App Store Connect app id (from asc_list_apps)."),
  },
  async ({ appId }) => {
    try {
      const r = await checkSubmission(await ascToken(), appId);
      const header = r.version
        ? `🩺 App Store Connect check — version ${r.version.versionString} (${r.version.state})`
        : "🩺 App Store Connect check";
      const body = r.findings
        .map((f) => {
          const lines = [`${ICON[f.severity]} ${f.title}`, `   ${f.detail}`];
          if (f.fix) lines.push(`   💡 ${f.fix}`);
          return lines.join("\n");
        })
        .join("\n\n");
      return { content: [{ type: "text", text: `${header}\n\n${body}` }] };
    } catch (e) {
      return ascErrorContent(e);
    }
  }
);

server.tool(
  "explain_guideline",
  "Explain an App Store Review Guideline number (e.g. '5.1.1') in plain language with a typical fix. Works offline — no credentials needed.",
  {
    guideline: z.string().describe("Guideline number, e.g. '2.1', '3.1.1', '5.1.1'."),
  },
  async ({ guideline }) => {
    const info = GUIDELINE_MAP[guideline.trim()];
    if (!info) {
      return {
        content: [
          {
            type: "text",
            text: `No built-in summary for guideline ${guideline}. Known: ${Object.keys(GUIDELINE_MAP).join(", ")}. See https://developer.apple.com/app-store/review/guidelines/`,
          },
        ],
      };
    }
    return {
      content: [
        { type: "text", text: `📖 Guideline ${guideline} — ${info.title}\n\n${info.summary}\n\n💡 Typical fix: ${info.fix}` },
      ],
    };
  }
);

// ── CLI mode ──────────────────────────────────────────────────────────────────
// `ios-ship-doctor-mcp preflight <path> [--json]` runs a one-shot check and exits
// non-zero on blocking errors — handy for CI. With no args it starts the MCP server.
const argv = process.argv.slice(2);
if (argv[0] === "preflight") {
  const json = argv.includes("--json");
  const projectPath = argv.find((a, i) => i > 0 && !a.startsWith("--")) ?? process.cwd();
  const { findings, summary } = await runPreflight(projectPath);
  if (json) {
    console.log(JSON.stringify({ projectPath, summary, findings }, null, 2));
  } else {
    console.log(`🩺 Ship Doctor — ${projectPath}\n${summary.verdict}\n(${summary.errors} errors, ${summary.warnings} warnings, ${summary.infos} passed)\n`);
    console.log(renderFindings(findings));
    console.log(`\nℹ️ ${summary.caveat}`);
  }
  process.exit(summary.errors > 0 ? 1 : 0);
}
if (argv[0] === "--help" || argv[0] === "-h") {
  console.log(
    `ios-ship-doctor-mcp\n\n` +
      `  (no args)                 start the MCP server on stdio\n` +
      `  preflight <path> [--json] run all checks once; exits 1 on blocking errors\n` +
      `  --help                    show this message\n`
  );
  process.exit(0);
}

const transport = new StdioServerTransport();
await server.connect(transport);
// stderr is safe for logs; stdout is reserved for the JSON-RPC protocol.
console.error("ios-ship-doctor MCP server running on stdio");
