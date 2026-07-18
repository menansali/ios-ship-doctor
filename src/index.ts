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
  buildPrivacyManifestXml,
  runPreflight,
  type Finding,
} from "./scanner.js";
import {
  loadAscCreds,
  buildAscJwt,
  listApps,
  getRejections,
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
      content: [{ type: "text", text: `${header}\n\n${renderFindings(findings)}` }],
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

const transport = new StdioServerTransport();
await server.connect(transport);
// stderr is safe for logs; stdout is reserved for the JSON-RPC protocol.
console.error("ios-ship-doctor MCP server running on stdio");
