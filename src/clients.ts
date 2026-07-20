/**
 * Config snippets for MCP clients.
 *
 * Ship Doctor is a plain stdio MCP server — nothing in it is specific to any
 * one assistant. The only thing that differs between clients is where the
 * config file lives and what the root key is called, which is exactly the part
 * people get wrong. `ios-ship-doctor-mcp config <client>` prints the right
 * shape with the absolute path already filled in.
 */

export interface ClientConfig {
  id: string;
  label: string;
  /** Where the config file lives. */
  path: string;
  /** Rendered snippet. */
  render: (nodePath: string, serverPath: string) => string;
  /** Optional one-line alternative (a CLI that writes the config for you). */
  cli?: (nodePath: string, serverPath: string) => string;
  note?: string;
}

/**
 * The env vars the App Store Connect tools need. Deliberately NOT baked into the
 * generated snippets: clients differ on whether they expand ${VAR}, and a literal
 * "${ASC_KEY_ID}" reaching the server looks like valid config and fails as a
 * confusing 401. Shown separately so you add them only if you want those tools.
 */
export const ASC_ENV_HINT = [
  "# Optional — only for the App Store Connect tools (asc_*). Add to the server entry:",
  '#   "env": { "ASC_KEY_ID": "ABC123", "ASC_ISSUER_ID": "…", "ASC_PRIVATE_KEY_PATH": "/path/AuthKey.p8" }',
  "# Paste real values; most clients do not expand shell variables here.",
].join("\n");

const jsonBlock = (rootKey: string, node: string, server: string, extra: Record<string, unknown> = {}) =>
  JSON.stringify(
    { [rootKey]: { "ios-ship-doctor": { ...extra, command: node, args: [server] } } },
    null,
    2
  );

export const CLIENTS: ClientConfig[] = [
  {
    id: "claude",
    label: "Claude Code",
    path: "managed by the CLI (or ~/.claude.json)",
    cli: (node, server) => `claude mcp add ios-ship-doctor -- ${node} ${server}`,
    render: (node, server) => jsonBlock("mcpServers", node, server),
  },
  {
    id: "gemini",
    label: "Gemini CLI",
    path: "~/.gemini/settings.json  (or .gemini/settings.json in a project)",
    cli: (node, server) => `gemini mcp add ios-ship-doctor ${node} ${server}`,
    render: (node, server) => jsonBlock("mcpServers", node, server),
  },
  {
    id: "codex",
    label: "OpenAI Codex CLI",
    path: "~/.codex/config.toml  (or .codex/config.toml in a trusted project)",
    note: 'The table MUST be "mcp_servers" with an underscore — "mcp-servers" is silently ignored.',
    render: (node, server) =>
      [
        "[mcp_servers.ios-ship-doctor]",
        `command = "${node}"`,
        `args = ["${server}"]`,
        "startup_timeout_sec = 30",
        "# env = { ASC_KEY_ID = \"…\", ASC_ISSUER_ID = \"…\", ASC_PRIVATE_KEY_PATH = \"…\" }",
      ].join("\n"),
  },
  {
    id: "cursor",
    label: "Cursor",
    path: "~/.cursor/mcp.json  (global) or .cursor/mcp.json (per project)",
    render: (node, server) => jsonBlock("mcpServers", node, server),
  },
  {
    id: "vscode",
    label: "VS Code (GitHub Copilot)",
    path: ".vscode/mcp.json",
    note: 'VS Code uses "servers", not "mcpServers", and wants an explicit type.',
    render: (node, server) => jsonBlock("servers", node, server, { type: "stdio" }),
  },
  {
    id: "windsurf",
    label: "Windsurf",
    path: "~/.codeium/windsurf/mcp_config.json",
    render: (node, server) => jsonBlock("mcpServers", node, server),
  },
  {
    id: "zed",
    label: "Zed",
    path: "Zed settings.json",
    note: 'Zed nests the executable under command.path — a different shape from every other client.',
    render: (node, server) =>
      JSON.stringify(
        {
          context_servers: {
            "ios-ship-doctor": {
              source: "custom",
              command: { path: node, args: [server], env: {} },
            },
          },
        },
        null,
        2
      ),
  },
  {
    id: "generic",
    label: "Any other MCP client",
    path: "wherever that client keeps its MCP config",
    note: "Standard stdio transport, protocol 2025-06-18. If a client speaks MCP, this works.",
    render: (node, server) => jsonBlock("mcpServers", node, server),
  },
];

export function renderClientConfig(c: ClientConfig, nodePath: string, serverPath: string): string {
  const lines = [`# ${c.label}`, `# config file: ${c.path}`];
  if (c.note) lines.push(`# note: ${c.note}`);
  if (c.cli) lines.push("", `# one-liner:`, c.cli(nodePath, serverPath));
  lines.push("", c.render(nodePath, serverPath), "", ASC_ENV_HINT);
  return lines.join("\n");
}

/**
 * A `node` path that survives upgrades. process.execPath on Homebrew points at
 * a version-pinned Cellar path (…/node/24.1.0/bin/node) which breaks the config
 * the next time node updates; the symlinked bin directories don't move.
 */
export function stableNodePath(execPath: string, exists: (p: string) => boolean): string {
  if (!/\/Cellar\/|\/\.nvm\/|\/versions\//.test(execPath)) return execPath;
  for (const candidate of ["/opt/homebrew/bin/node", "/usr/local/bin/node", "/usr/bin/node"]) {
    if (exists(candidate)) return candidate;
  }
  return execPath;
}
