# iOS Ship Doctor — MCP server

Diagnoses **why an iOS app will be rejected by App Store review — before you hit Submit** — and fixes what it can. Built for Claude users who ship iOS apps.

Existing App Store MCPs are thin API wrappers that *submit* your app. Ship Doctor is different: it reasons over your **project + dependencies + Info.plist** to catch the requirements that silently produce "Invalid Binary" emails and Resolution Center rejections.

## What it checks

| Tool | Catches |
|------|---------|
| `preflight` | Runs everything below and gives a single READY / NOT READY verdict |
| `scan_privacy_manifest` | Required-reason APIs used in code but **not declared** in `PrivacyInfo.xcprivacy` (hard reject), invalid reason codes, missing manifest |
| `check_usage_descriptions` | Permissions used (camera, location, photos, mic, tracking…) with **no `NS…UsageDescription`** in Info.plist (crashes + reject) |
| `audit_dependencies` | CocoaPods SDKs on Apple's required-manifest list shipping **without** a privacy manifest |
| `check_credential_traps` | Placeholder / public **test credentials** left in Info.plist (e.g. Google's sample AdMob App ID) |
| `generate_privacy_manifest` | Writes a valid `PrivacyInfo.xcprivacy` covering every detected required-reason API |

## Install

```bash
git clone https://github.com/menansali/ios-ship-doctor.git
cd ios-ship-doctor
npm install
npm run build
```

## Connect to Claude Code

```bash
claude mcp add ios-ship-doctor -- node "$(pwd)/dist/index.js"
```

Or add to Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`), using the absolute path to `dist/index.js`:

```json
{
  "mcpServers": {
    "ios-ship-doctor": {
      "command": "node",
      "args": ["/absolute/path/to/ios-ship-doctor-mcp/dist/index.js"]
    }
  }
}
```

## Use it

Just ask Claude:

> Is `/Users/menansali/Desktop/DugunTakiTakip` ready to submit to the App Store?

Claude calls `preflight` and reports blockers with fixes. `projectPath` can be the repo root (with an `ios/` folder) or the `ios/` directory itself.

## Roadmap (the "rejection recovery" half)

Add App Store Connect API integration (`.p8` key + issuer ID) to pull Resolution Center rejections, map them to guideline numbers, and draft fixes + reviewer replies — closing the loop from "why was I rejected" to "here's the fix."

## License

MIT
