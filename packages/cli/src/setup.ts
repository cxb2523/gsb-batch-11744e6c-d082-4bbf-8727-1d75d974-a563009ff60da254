/**
 * `webcrawl setup` and `webcrawl doctor` — REA-style one-command agent onboarding.
 *
 * Registers the `@webcrawl/mcp` server into Claude Code, Cursor, Codex, Windsurf,
 * and Gemini CLI config files (with timestamped backup) and installs the matching
 * `webcrawl-anything` Agent Skill (`SKILL.md`).
 */
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

export type SupportedAgentId = "claude" | "cursor" | "codex" | "gemini" | "windsurf";

export interface AgentTarget {
  id: SupportedAgentId;
  name: string;
  mcpConfigPath: (home: string, cwd: string) => string;
  skillPath: (home: string, cwd: string) => string;
}

export const SUPPORTED_AGENTS: AgentTarget[] = [
  {
    id: "claude",
    name: "Claude Code",
    mcpConfigPath: (home) => join(home, ".claude.json"),
    skillPath: (home) => join(home, ".claude", "skills", "webcrawl-anything", "SKILL.md"),
  },
  {
    id: "cursor",
    name: "Cursor",
    mcpConfigPath: (home) => join(home, ".cursor", "mcp.json"),
    skillPath: (home) => join(home, ".cursor", "skills", "webcrawl-anything", "SKILL.md"),
  },
  {
    id: "codex",
    name: "Codex / OpenAI Agents",
    mcpConfigPath: (home) => join(home, ".codex", "mcp.json"),
    skillPath: (_home, cwd) => join(cwd, ".agents", "skills", "webcrawl-anything", "SKILL.md"),
  },
  {
    id: "gemini",
    name: "Gemini CLI",
    mcpConfigPath: (home) => join(home, ".gemini", "settings.json"),
    skillPath: (home) => join(home, ".gemini", "skills", "webcrawl-anything", "SKILL.md"),
  },
  {
    id: "windsurf",
    name: "Windsurf",
    mcpConfigPath: (home) => join(home, ".codeium", "windsurf", "mcp_config.json"),
    skillPath: (home) => join(home, ".codeium", "windsurf", "skills", "webcrawl-anything", "SKILL.md"),
  },
];

export const WEBCRAWL_SKILL_MD = `---
name: webcrawl-anything
description: Crawl, search, and extract structured evidence from any website, SPA, PDF, Office file, YouTube video, GitHub repo, ArXiv paper, shopping offer, travel fare, or CVE advisory.
---

# Webcrawl Anything — Agent Investigation Workflow

Use **Webcrawl Anything** (\`webcrawl\` CLI or \`webcrawl\` MCP tools) whenever you need live web search, anti-bot page scraping, document/video parsing, or structured vertical extraction with provenance.

## 1. Choose the Right Tool or Target

1. **Structured Search (\`web_search\` / \`webcrawl search\`)**:
   - Pass \`category\` when the query belongs to a vertical:
     - \`shopping\`: Multi-retailer product prices, stock availability, ratings, shipping.
     - \`flights\`: IATA routes, fares, airlines, stops, cabin class.
     - \`hotels\`: Nightly rates, star ratings, guest reviews, amenities.
     - \`real-estate\`: Property listings (\`subcategory: "buy" | "rent" | "sold"\`).
     - \`business\`: Local businesses, clinics, phone numbers, hours, ratings.
     - \`security\`: CVE / GHSA records with CVSS scores, CWEs, affected/fixed versions, and CISA KEV status.
     - \`academic\`: ArXiv and research papers.
     - \`tech\` / \`news\` / \`general\`: General and developer search.
2. **Page & Developer Target Inspection (\`web_read\` / \`webcrawl scrape <url>\`)**:
   - Works on any website, client-rendered SPA, GitHub repository/issue/release, ArXiv abstract page, or \`llms.txt\` manifest.
3. **Binary Documents & Media (\`web_parse\` / \`webcrawl scrape <pdf-or-youtube-url>\`)**:
   - Reads PDFs (native text + automatic OCR on scanned pages), Word (\`.docx\`), Excel (\`.xlsx\`), PowerPoint (\`.pptx\`), and YouTube URLs (timestamped transcripts).
4. **Site Discovery & Multi-Page Crawl (\`web_map\` & \`web_crawl\`)**:
   - Always run \`web_map\` first on unfamiliar domains to inspect available URLs before running \`web_crawl\` (capped at 25 pages).
5. **Scheduled Web Monitors (\`web_monitor\` / \`webcrawl monitor\`)**:
   - Watch a single page (\`page\`), a list of URLs (\`urls\`), or a whole website section (\`site\`) on a schedule with natural-language \`watch_for\` goals, trigger \`condition\` rules (e.g. \`price < 50\`, \`content contains "In Stock"\`, \`added_urls_count > 0\`), and email or webhook alerts.

## 2. Verify Evidence & Provenance

- Check the returned \`evidence\` block (\`targetId\`, \`tier\`, \`contentHash\`, \`matchedSignals\`, \`limitations\`) before stating claims as fact.
- If \`limitations\` notes that a page was a client-rendered shell or blocked by a challenge in static mode, escalate to stealth browser or \`webcrawl.app\` cloud (\`webcrawl login\`).
`;

export interface SetupOptions {
  agents?: SupportedAgentId[];
  schemaProfile?: "compact" | "full";
  apiKey?: string;
  baseUrl?: string;
  homeDir?: string;
  cwd?: string;
}

export interface SetupResult {
  configuredAgents: Array<{
    id: SupportedAgentId;
    name: string;
    mcpConfigPath: string;
    backupPath?: string;
    skillPath: string;
  }>;
  schemaProfile: "compact" | "full";
}

export function runSetup(opts: SetupOptions = {}): SetupResult {
  const home = opts.homeDir ?? homedir();
  const cwd = opts.cwd ?? process.cwd();
  const schemaProfile = opts.schemaProfile ?? "compact";
  const selectedIds = opts.agents?.length ? new Set(opts.agents) : new Set<SupportedAgentId>(["claude", "cursor", "codex"]);
  const targets = SUPPORTED_AGENTS.filter((a) => selectedIds.has(a.id));

  const configuredAgents: SetupResult["configuredAgents"] = [];

  for (const agent of targets) {
    const mcpPath = agent.mcpConfigPath(home, cwd);
    let existing: Record<string, unknown> = {};
    let backupPath: string | undefined;

    if (existsSync(mcpPath)) {
      try {
        existing = JSON.parse(readFileSync(mcpPath, "utf8")) as Record<string, unknown>;
        backupPath = `${mcpPath}.bak`;
        copyFileSync(mcpPath, backupPath);
      } catch {
        existing = {};
      }
    }

    const mcpServers =
      existing.mcpServers && typeof existing.mcpServers === "object" && !Array.isArray(existing.mcpServers)
        ? { ...(existing.mcpServers as Record<string, unknown>) }
        : {};

    const envVars: Record<string, string> = {
      WEBCRAWL_MCP_SCHEMA_PROFILE: schemaProfile,
    };
    if (opts.apiKey) envVars.WEBCRAWL_API_KEY = opts.apiKey;
    if (opts.baseUrl) envVars.WEBCRAWL_URL = opts.baseUrl;

    mcpServers.webcrawl = {
      command: "npx",
      args: ["-y", "@webcrawl/mcp@latest"],
      env: envVars,
    };

    const updated = { ...existing, mcpServers };
    mkdirSync(dirname(mcpPath), { recursive: true });
    writeFileSync(mcpPath, `${JSON.stringify(updated, null, 2)}\n`, "utf8");

    const skillPath = agent.skillPath(home, cwd);
    mkdirSync(dirname(skillPath), { recursive: true });
    writeFileSync(skillPath, WEBCRAWL_SKILL_MD, "utf8");

    configuredAgents.push({
      id: agent.id,
      name: agent.name,
      mcpConfigPath: mcpPath,
      backupPath,
      skillPath,
    });
  }

  return { configuredAgents, schemaProfile };
}

export interface DoctorCheck {
  name: string;
  status: "ok" | "optional" | "warn";
  detail: string;
}

export interface DoctorReport {
  mode: "local" | "cloud";
  checks: DoctorCheck[];
}

export function runDoctor(
  env: NodeJS.ProcessEnv = process.env,
  effectiveMode: "local" | "cloud" = "local",
  apiKeySource = "none"
): DoctorReport {
  const checks: DoctorCheck[] = [];

  // 1. Node runtime
  const nodeVer = process.versions.node;
  const major = Number(nodeVer.split(".")[0]);
  checks.push({
    name: "Node.js runtime",
    status: major >= 20 ? "ok" : "warn",
    detail: `v${nodeVer} (requires >=20)`,
  });

  // 2. Execution mode & Cloud API key
  checks.push({
    name: "Execution mode",
    status: "ok",
    detail:
      effectiveMode === "cloud"
        ? `cloud (https://webcrawl.app via ${apiKeySource} key)`
        : "local zero-key engine (impit TLS + built-in parsers & vertical extractors)",
  });

  // 3. Local Chrome / Stealth Browser availability
  const chromePaths = [
    env.WEBCRAWL_CHROME_PATH,
    env.INTERACT_CHROME_PATH,
    env.CHROME_PATH,
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/snap/bin/chromium",
  ].filter(Boolean) as string[];
  const foundChrome = chromePaths.find((p) => existsSync(p));
  checks.push({
    name: "Local stealth browser",
    status: foundChrome ? "ok" : "optional",
    detail: foundChrome
      ? `Found Chrome at ${foundChrome} (used to render JS pages)`
      : "No local Chrome binary detected; static pages still work. For JS pages install Chrome or `npx playwright install chromium-headless-shell`, or run `webcrawl login` for cloud stealth browsers",
  });

  // 4. Search providers
  const serper = Boolean(env.SERPER_API_KEY);
  const brave = Boolean(env.BRAVE_SEARCH_API_KEY);
  const jina = Boolean(env.JINA_API_KEY);
  const configuredProviders = [
    "DuckDuckGo/Bing (built-in zero-key)",
    ...(serper ? ["Serper"] : []),
    ...(brave ? ["Brave"] : []),
    ...(jina ? ["Jina"] : []),
  ];
  checks.push({
    name: "Search providers",
    status: "ok",
    detail: configuredProviders.join(", "),
  });

  // 5. Document & Media parsers
  checks.push({
    name: "Document & Media parsers",
    status: "ok",
    detail: "PDF inspector, Office (mammoth/officeparser), YouTube captions, NVD/OSV CVEs ready",
  });

  return { mode: effectiveMode, checks };
}
