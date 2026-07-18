# iOS Ship Doctor — MCP server

Diagnoses **why an iOS app will be rejected by App Store review — before you hit Submit** — and fixes what it can. Built for Claude users who ship iOS apps.

Existing App Store MCPs are thin API wrappers that *submit* your app. Ship Doctor is different: it reasons over your **project + dependencies + Info.plist** to catch the requirements that silently produce "Invalid Binary" emails and Resolution Center rejections — and it can pull your real rejections from App Store Connect and map them to fixes.

## What it checks

**Preflight — local, no credentials needed:**

| Tool | Catches |
|------|---------|
| `preflight` | Runs every check below and gives a single READY / NOT READY verdict |
| `scan_privacy_manifest` | Required-reason APIs used in code but **not declared** in `PrivacyInfo.xcprivacy` (hard reject), invalid reason codes, missing manifest |
| `check_usage_descriptions` | Permissions used (camera, location, photos, mic, tracking…) with **no `NS…UsageDescription`** in Info.plist (crashes + reject) |
| `audit_dependencies` | CocoaPods SDKs on Apple's required-manifest list shipping **without** a privacy manifest |
| `check_credential_traps` | Placeholder / public **test credentials** left in Info.plist (e.g. Google's sample AdMob App ID) |
| `generate_privacy_manifest` | Writes a valid `PrivacyInfo.xcprivacy` covering every detected required-reason API |

Preflight also checks **export compliance** (`ITSAppUsesNonExemptEncryption`), **App Transport Security** (global `NSAllowsArbitraryLoads`), **app icon** asset presence, and **banned APIs** (`UIWebView`).

**Rejection recovery — needs an App Store Connect API key:**

| Tool | Does |
|------|------|
| `asc_list_apps` | Lists your apps (id, name, bundle id) |
| `asc_get_rejections` | Pulls recent review rejections and maps referenced Guideline numbers → plain-language summaries + fixes |
| `explain_guideline` | Explains any App Store Review Guideline number (offline, no key needed) |

## Install

```bash
git clone https://github.com/menansali/ios-ship-doctor.git
cd ios-ship-doctor
npm install   # downloads dependencies (the MCP SDK + XML parser)
npm run build
```

That's the whole setup — no registry account or global install needed.

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
      "args": ["/absolute/path/to/ios-ship-doctor/dist/index.js"]
    }
  }
}
```

### Enabling rejection recovery (optional)

Create an API key at **App Store Connect → Users and Access → Integrations → App Store Connect API**, download the `.p8`, and add these env vars to the MCP server config:

```json
{
  "mcpServers": {
    "ios-ship-doctor": {
      "command": "node",
      "args": ["/absolute/path/to/ios-ship-doctor/dist/index.js"],
      "env": {
        "ASC_KEY_ID": "XXXXXXXXXX",
        "ASC_ISSUER_ID": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "ASC_PRIVATE_KEY_PATH": "/absolute/path/to/AuthKey_XXXXXXXXXX.p8"
      }
    }
  }
}
```

The `.p8` never enters the repo — it stays on your machine and is read at runtime.

## Use it

Just ask Claude:

> Is `/path/to/my-ios-app` ready to submit to the App Store?

Claude calls `preflight` and reports blockers with fixes. `projectPath` can be the repo root (with an `ios/` folder) or the `ios/` directory itself.

After a rejection:

> Why did Apple reject my app? App id is 1234567890.

Claude calls `asc_get_rejections`, maps the guideline numbers, and proposes fixes.

## How it works

- **Required-reason APIs** are detected by scanning first-party source for Apple's documented API signatures, then diffed against the declared `PrivacyInfo.xcprivacy`.
- **App Store Connect auth** uses an ES256 JWT signed with Node's built-in `crypto` (no `jsonwebtoken` dependency), in the JOSE (IEEE-P1363) signature format Apple requires.
- Everything is read-only except `generate_privacy_manifest` with `write=true`.

## License

MIT
