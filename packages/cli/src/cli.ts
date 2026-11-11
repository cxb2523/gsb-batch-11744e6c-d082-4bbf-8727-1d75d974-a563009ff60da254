import { execFile } from "node:child_process";
import crypto from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import {
  WebcrawlClient,
  WebcrawlError,
  configPath,
  describeError,
  readConfigFile,
  resolveConfig,
  writeConfigFile,
} from "@webcrawl/client";
import {
  formatCrawl,
  formatCredits,
  formatMap,
  formatMonitor,
  formatRerank,
  formatScrape,
  formatSearch,
  formatTargets,
} from "./format.js";
import {
  SUPPORTED_AGENTS,
  runDoctor,
  runSetup,
  type SupportedAgentId,
} from "./setup.js";

export interface Io {
  out: (s: string) => void;
  err: (s: string) => void;
  /** Whole stdin as text (only called when needed). */
  readStdin: () => Promise<string>;
  isTTY: boolean;
}

export interface Deps {
  env?: NodeJS.ProcessEnv;
  fetch?: typeof fetch;
  /** Config file path override (tests). */
  configFile?: string;
  /** Browser opener override (tests). */
  openUrl?: (url: string) => void;
  /** Home directory override for `webcrawl setup` tests. */
  homeDir?: string;
  /** Working directory override for `webcrawl setup` tests. */
  cwd?: string;
}

export const HELP = `Webcrawl Anything: search, scrape, parse and crawl any target on the internet

Usage: webcrawl <command> [options]

Commands
  search <query>      Search the web or verticals. -c category, --sub, -n limit, --site <domain>
  scrape <url>        Inspect a URL (website, SPA, PDF, Office, YouTube, GitHub, ArXiv, llms.txt)
  map <url>           List a site's URLs. --filter <text>, -n limit
  crawl <url>         Read several pages. -n max pages (default 5, max 25)
  extract <url>       Structured JSON. --prompt <text> or --schema <file.json>
  rerank <query>      Rank documents. --doc <text> (repeatable), --file <path>, or lines on stdin. -n top
  monitor [subcmd]    Watch pages/sites: create <url...>, list, get <id>, check <id>, pause <id>, resume <id>, delete <id>
  targets             List all supported crawl & search targets and their requirements
  categories          List search categories and vertical filters
  setup               Register Webcrawl MCP server and Agent Skill (Claude, Cursor, Codex, Gemini, Windsurf)
  doctor              Check local crawl engine, parsers, stealth browser, and cloud configuration
  login / signup      Create an account or sign in in your browser (default), or --email <addr> [--code <6-digit>], or --key <key>
  whoami              Show execution mode (local vs cloud), account email, key source, and credit balance

Options
  --mode <m>          Execution mode: auto (default: local without key, cloud with key), local, or cloud
  --email <addr>      Email address for CLI account creation / OTP sign-in (assigns 1,000 free credits)
  --code <6-digit>    6-digit email verification code from \`webcrawl login --email <addr>\`
  --name <name>       Optional display name when creating an account with \`--email\`
  --web               Sign in via browser OAuth (default for login; no need to pass it)
  --json              Print the raw JSON response
  --api-key <key>     Override WEBCRAWL_API_KEY
  --url <base>        Override WEBCRAWL_URL (default https://webcrawl.app)
  --country, --city   Where to search from (default: this machine's timezone)
  --no-cache          Skip cached pages (scrape)
  --scope <s|u|w>     Monitor scope: page (default), urls, or site
  --interval <mins>   Monitor check interval in minutes (default 60)
  --watch-for <text>  What to watch for (e.g. "Pricing tiers and discounts")
  --condition <expr>  Trigger rule expression (e.g. 'price < 50', 'content contains "In Stock"')
  --notify-email <e>  Alert email address when triggered (or 'true' for account email)
  --webhook <url>     Alert webhook URL when triggered
  --agent <name>      Target agent for setup: claude, cursor, codex, gemini, windsurf, or all (repeatable)
  --schema-profile    MCP schema profile for setup: compact (default) or full
  -v, --version       Print the installed package version
  -h, --help

Config order: flags, then WEBCRAWL_API_KEY / WEBCRAWL_URL / WEBCRAWL_MODE, then ~/.config/webcrawl/config.json`;

const OPTIONS = {
  json: { type: "boolean" },
  help: { type: "boolean", short: "h" },
  version: { type: "boolean", short: "v" },
  "api-key": { type: "string" },
  url: { type: "string" },
  mode: { type: "string" },
  category: { type: "string", short: "c" },
  sub: { type: "string" },
  limit: { type: "string", short: "n" },
  site: { type: "string", multiple: true },
  country: { type: "string" },
  city: { type: "string" },
  filter: { type: "string" },
  prompt: { type: "string" },
  schema: { type: "string" },
  doc: { type: "string", multiple: true },
  file: { type: "string" },
  key: { type: "string" },
  email: { type: "string" },
  code: { type: "string" },
  name: { type: "string" },
  web: { type: "boolean" },
  "no-wait": { type: "boolean" },
  "no-cache": { type: "boolean" },
  content: { type: "boolean" },
  scope: { type: "string" },
  interval: { type: "string" },
  "watch-for": { type: "string" },
  condition: { type: "string" },
  "notify-email": { type: "string" },
  webhook: { type: "string" },
  agent: { type: "string", multiple: true },
  "schema-profile": { type: "string" },
} as const;

class UsageError extends Error {}

/** Installed `webcrawl` version, read from package.json at runtime. */
export function packageVersion(): string {
  const pkgPath = join(dirname(fileURLToPath(import.meta.url)), "..", "package.json");
  const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { version?: string };
  if (!pkg.version) {
    throw new Error("package.json is missing a version field");
  }
  return pkg.version;
}

function int(v: string | undefined, name: string): number | undefined {
  if (v === undefined) {return undefined;}
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1) {throw new UsageError(`${name} must be a positive whole number`);}
  return n;
}

async function promptLine(io: Io, promptText: string): Promise<string> {
  if (!io.isTTY) {
    return (await io.readStdin()).trim();
  }
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((resolve) => {
    rl.question(promptText, (a) => {
      rl.close();
      resolve(a.trim());
    });
  });
}

async function readKeyInteractively(io: Io): Promise<string> {
  return promptLine(io, "Paste your API key (wc_live_…): ");
}

function openBrowserUrl(url: string): void {
  const cmd =
    process.platform === "darwin"
      ? "open"
      : process.platform === "win32"
        ? "cmd"
        : "xdg-open";
  const args = process.platform === "win32" ? ["/c", "start", "", url] : [url];
  try {
    execFile(cmd, args, () => {
      // ignore browser launch errors in headless environments
    });
  } catch {
    // ignore
  }
}

const esc = (s: string): string =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/** Self-contained (no network assets) page served on the loopback callback. */
export function callbackPage(opts: {
  kind: "success" | "error" | "info";
  title: string;
  body: string;
  email?: string;
  credits?: string;
  tryIt?: string;
}): string {
  const tone = opts.kind === "success" ? "#157f3b" : opts.kind === "error" ? "#b42318" : "#6236e8";
  const icon =
    opts.kind === "success"
      ? `<path class="mk" d="M20 33l8 8 16-17"/>`
      : opts.kind === "error"
        ? `<path class="mk" d="M23 23l18 18M41 23L23 41"/>`
        : `<path class="mk" d="M32 22v14M32 42v.5"/>`;
  const chips = [opts.email ? `<span class="chip">${esc(opts.email)}</span>` : "", opts.credits ? `<span class="chip hot">${esc(opts.credits)}</span>` : ""].join("");
  const dots = Array.from({ length: 14 }, (_, i) => `<i style="--a:${i * 25.7}deg;--d:${70 + (i % 3) * 18}px;--t:${(i % 5) * 0.06}s"></i>`).join("");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(opts.title)}</title>
<style>
:root{--tone:${tone}}*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;color:#1b1631;font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,sans-serif;background:#fbfaf8}
main{width:100%;max-width:440px;text-align:center;background:#fff;border:1px solid #e2ddd5;border-radius:16px;padding:36px 32px 28px;box-shadow:0 1px 2px #1b16310d,0 12px 32px #1b16310f;animation:rise .5s cubic-bezier(.2,.8,.2,1) both}
.brand{display:flex;align-items:center;justify-content:center;gap:8px;font-weight:600;letter-spacing:-.035em;color:#1b1631;margin-bottom:26px}.brand svg{width:26px;height:26px}
.badge{position:relative;width:96px;height:96px;margin:0 auto 18px}
.badge svg.ring{width:96px;height:96px;overflow:visible}
.ring circle{fill:color-mix(in srgb,var(--tone) 12%,transparent);stroke:var(--tone);stroke-width:2.5;stroke-dasharray:190;stroke-dashoffset:190;animation:draw .7s .1s ease-out forwards}
.mk{fill:none;stroke:var(--tone);stroke-width:4.5;stroke-linecap:round;stroke-linejoin:round;stroke-dasharray:60;stroke-dashoffset:60;animation:draw .45s .6s ease-out forwards}
.burst{position:absolute;inset:0;pointer-events:none}.burst i{position:absolute;left:50%;top:50%;width:6px;height:6px;margin:-3px;border-radius:50%;background:var(--tone);opacity:0;transform:rotate(var(--a)) translateY(0);animation:pop .9s calc(.7s + var(--t)) ease-out forwards}
h1{font-size:22px;margin:0 0 6px;letter-spacing:-.02em}p{margin:0 0 18px;color:#4a4460}
.chips{display:flex;gap:8px;justify-content:center;flex-wrap:wrap;margin-bottom:20px}
.chip{font-size:12.5px;padding:4px 10px;border-radius:999px;background:#f6f4f0;border:1px solid #e2ddd5;color:#4a4460}.chip.hot{background:#f1ecff;border-color:#d9ccff;color:#4f24cf}
.try{text-align:left;background:#f6f4f0;border:1px solid #efebe5;border-radius:10px;padding:12px 14px;margin-bottom:18px}
.trow{display:flex;align-items:center;justify-content:space-between;margin-bottom:4px}.trow small{margin:0!important}
.copy{font:600 12px/1 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;padding:6px 10px;border-radius:7px;border:1px solid #e2ddd5;background:#fff;color:#4a4460;cursor:pointer}.copy:hover{border-color:#6236e8;color:#4f24cf}
.try code{user-select:all;-webkit-user-select:all;cursor:text}
.try small{display:block;color:#5e5873;margin-bottom:4px;font-size:12px;text-transform:uppercase;letter-spacing:.08em}
.try code{font:13px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;color:#4f24cf;word-break:break-all}.try code:before{content:"$ ";color:#7d7690}
.foot{font-size:13px;color:#5e5873;margin:0}
@keyframes rise{from{opacity:0;transform:translateY(14px) scale(.98)}}
@keyframes draw{to{stroke-dashoffset:0}}
@keyframes pop{0%{opacity:1}100%{opacity:0;transform:rotate(var(--a)) translateY(calc(var(--d) * -1)) scale(.3)}}
@media (prefers-reduced-motion:reduce){*{animation-duration:.01s!important;animation-delay:0s!important}}
</style></head><body><main>
<div class="brand"><svg viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="7" fill="#1b1631"/><g stroke-linejoin="round" stroke-linecap="round" fill="none" stroke-width="3"><path d="M5 21.5L16 27.5L27 21.5" stroke="#8a80b8"/><path d="M5 16L16 22L27 16" stroke="#c9b8ff"/></g><path d="M16 4.5L27 10.5L16 16.5L5 10.5Z" fill="#8b6cff" stroke="#8b6cff" stroke-width="2" stroke-linejoin="round"/></svg>Webcrawl</div>
<div class="badge"><svg class="ring" viewBox="0 0 64 64" aria-hidden="true"><circle cx="32" cy="32" r="30"/>${icon}</svg>${opts.kind === "success" ? `<div class="burst">${dots}</div>` : ""}</div>
<h1>${esc(opts.title)}</h1><p>${opts.body}</p>
${chips ? `<div class="chips">${chips}</div>` : ""}
${opts.tryIt ? `<div class="try"><div class="trow"><small>Try it now</small><button type="button" class="copy" id="cp">Copy</button></div><code id="cmd">${esc(opts.tryIt)}</code></div>
<script>(function(){var b=document.getElementById("cp"),c=document.getElementById("cmd");if(!b||!c)return;var t=c.textContent;function done(){b.textContent="Copied";setTimeout(function(){b.textContent="Copy"},1500)}function fb(){var r=document.createRange();r.selectNodeContents(c);var s=getSelection();s.removeAllRanges();s.addRange(r);try{document.execCommand("copy");done()}catch(e){}}b.onclick=function(){if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(t).then(done,fb)}else{fb()}}})()</script>` : ""}
<p class="foot">You can close this tab and return to your terminal.</p>
</main></body></html>`;
}

async function runWebOAuthLogin(
  baseUrl: string,
  fetchImpl: typeof fetch,
  io: Io,
  openUrl: (url: string) => void = openBrowserUrl
): Promise<{ apiKey: string; email?: string; creditsRemaining?: number; creditsLimit?: number; plan?: string }> {
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  const state = crypto.randomBytes(16).toString("base64url");

  return new Promise((resolve, reject) => {
    const server = createServer();
    const timeout = setTimeout(() => {
      server.close();
      reject(new Error("Browser sign-in timed out after 180 seconds."));
    }, 180_000);

    server.listen(0, "127.0.0.1", async () => {
      try {
        const addr = server.address();
        const port = typeof addr === "object" && addr ? addr.port : 0;
        const redirectUri = `http://127.0.0.1:${port}/callback`;

        const regRes = await fetchImpl(`${baseUrl}/oauth/register`, {
          method: "POST",
          headers: { "content-type": "application/json", accept: "application/json" },
          body: JSON.stringify({
            client_name: "Webcrawl Anything CLI",
            redirect_uris: [redirectUri],
          }),
        });
        if (!regRes.ok) {
          throw new Error(`Could not register CLI OAuth client (HTTP ${regRes.status}). Try \`webcrawl login --email <you@domain.com>\`.`);
        }
        const { client_id: clientId } = (await regRes.json()) as { client_id: string };
        const authUrl = `${baseUrl}/oauth/authorize?${new URLSearchParams({
          response_type: "code",
          client_id: clientId,
          redirect_uri: redirectUri,
          code_challenge: challenge,
          code_challenge_method: "S256",
          state,
        }).toString()}`;

        io.out(
          [
            "Open this URL in your browser to create your webcrawl.app account or sign in (1,000 free monthly credits):",
            `  ${authUrl}`,
            "",
            "Waiting for browser authorization...",
          ].join("\n") + "\n"
        );
        openUrl(authUrl);

        let handled = false;
        server.on("request", async (req, res) => {
          try {
            const u = new URL(req.url || "/", redirectUri);
            if (u.pathname !== "/callback") {
              res.writeHead(404).end("Not found");
              return;
            }
            const code = u.searchParams.get("code");
            const returnedState = u.searchParams.get("state");
            if (handled) {
              // Browser retry / prefetch of the same callback: the code is single-use, so never exchange it twice.
              res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
              res.end(callbackPage({ kind: "info", title: "Already received", body: "This sign-in link was already used. Your terminal has everything it needs." }));
              return;
            }
            const oauthError = u.searchParams.get("error");
            if (oauthError && returnedState === state) {
              handled = true;
              res.writeHead(400, { "content-type": "text/html; charset=utf-8" });
              res.end(callbackPage({ kind: "error", title: "Sign-in cancelled", body: "You chose not to connect the CLI. Run <b>webcrawl login</b> whenever you want to try again." }));
              clearTimeout(timeout);
              server.close();
              reject(new Error(`OAuth authorization failed: ${oauthError}.`));
              return;
            }
            if (!code || returnedState !== state) {
              // Stray or forged request: reject it but keep waiting for the real callback.
              res.writeHead(400, { "content-type": "text/html; charset=utf-8" });
              res.end(callbackPage({ kind: "error", title: "Link not recognised", body: "This sign-in link does not match the one your terminal is waiting for. Run <b>webcrawl login</b> again for a fresh link." }));
              return;
            }
            handled = true;

            const tokenRes = await fetchImpl(`${baseUrl}/oauth/token`, {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
              body: new URLSearchParams({
                grant_type: "authorization_code",
                code,
                client_id: clientId,
                redirect_uri: redirectUri,
                code_verifier: verifier,
              }).toString(),
            });
            if (!tokenRes.ok) {
              const detail = (await tokenRes.json().catch(() => ({}))) as { error?: string; error_description?: string };
              const reason = detail.error_description || detail.error;
              res.writeHead(400, { "content-type": "text/html; charset=utf-8" });
              res.end(callbackPage({ kind: "error", title: "Sign-in failed", body: "Webcrawl could not finish signing you in. Your terminal has the details. Run <b>webcrawl login</b> to try again." }));
              throw new Error(
                `OAuth token exchange failed (HTTP ${tokenRes.status}${reason ? `: ${reason}` : ""}). Run \`webcrawl login\` again, or use \`webcrawl login --email <you@domain.com>\`.`
              );
            }
            const tokenData = (await tokenRes.json()) as { access_token: string };
            let finalKey = tokenData.access_token;

            const authedClient = new WebcrawlClient({
              baseUrl,
              apiKey: finalKey,
              fetch: fetchImpl,
              userAgent: "webcrawl-cli/1.2",
            });
            try {
              const keyRes = await authedClient.request<{ success: boolean; apiKey?: string }>(
                "POST",
                "/v1/account/keys",
                { name: "CLI API Key" }
              );
              if (keyRes.apiKey) {
                finalKey = keyRes.apiKey;
              }
            } catch {
              // keep OAuth access_token (`wc_mcp_...`) which is also accepted on all /v1/* endpoints
            }
            const meRes = await authedClient.me().catch(() => undefined);
            res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
            const u2 = meRes?.user;
            res.end(
              callbackPage({
                kind: "success",
                title: "You're connected",
                body: "Webcrawl CLI is signed in. Search, read and crawl the web from your terminal or your agent.",
                email: u2?.email,
                credits:
                  u2?.creditsRemaining !== undefined && u2?.creditsLimit !== undefined
                    ? `${u2.creditsRemaining.toLocaleString("en-US")} / ${u2.creditsLimit.toLocaleString("en-US")} credits`
                    : undefined,
                tryIt: 'webcrawl search "best ramen in shibuya"',
              })
            );
            clearTimeout(timeout);
            server.close();
            resolve({
              apiKey: finalKey,
              email: meRes?.user?.email,
              creditsRemaining: meRes?.user?.creditsRemaining,
              creditsLimit: meRes?.user?.creditsLimit,
              plan: meRes?.user?.plan,
            });
          } catch (err) {
            clearTimeout(timeout);
            server.close();
            reject(err);
          }
        });
      } catch (err) {
        clearTimeout(timeout);
        server.close();
        reject(err);
      }
    });
  });
}

type BackendClient = Pick<
  WebcrawlClient,
  "baseUrl" | "search" | "scrape" | "parse" | "run" | "map" | "crawl" | "extract" | "rerank" | "categories" | "targets" | "usage"
>;

async function resolveBackendClient(
  cfg: ReturnType<typeof resolveConfig>,
  deps: Deps
): Promise<BackendClient> {
  // When a custom fetch mock is injected (e.g. unit tests) or effectiveMode is cloud, use WebcrawlClient
  if (cfg.effectiveMode === "cloud" || deps.fetch) {
    return new WebcrawlClient({
      apiKey: cfg.apiKey,
      baseUrl: cfg.baseUrl,
      fetch: deps.fetch,
      userAgent: "webcrawl-cli/0.1",
    });
  }
  try {
    const packagedSpec = ["./core/local-engine.js"].join("");
    const fallbackSpec = ["..", "..", "..", "src", "local-engine.js"].join("/");
    const localMod = (await import(packagedSpec).catch(() => import(fallbackSpec))) as {
      createLocalEngineClient: () => BackendClient;
    };
    return localMod.createLocalEngineClient();
  } catch {
    return new WebcrawlClient({
      apiKey: cfg.apiKey,
      baseUrl: cfg.baseUrl,
      fetch: deps.fetch,
      userAgent: "webcrawl-cli/0.1",
    });
  }
}

export async function main(argv: string[], io: Io, deps: Deps = {}): Promise<number> {
  const env = deps.env ?? process.env;
  let parsed;
  try {
    parsed = parseArgs({ args: argv, options: OPTIONS, allowPositionals: true });
  } catch (e) {
    io.err(`${e instanceof Error ? e.message : String(e)}\nRun \`webcrawl --help\`.\n`);
    return 2;
  }
  const { values: v, positionals } = parsed;
  const [cmd, ...rest] = positionals;
  if (v.version) {
    io.out(`${packageVersion()}\n`);
    return 0;
  }
  if (v.help || !cmd || cmd === "help") {
    io.out(`${HELP}\n`);
    return cmd || v.help ? 0 : 2;
  }

  const file = deps.configFile ?? configPath(env);
  const cfg = resolveConfig(
    { apiKey: v["api-key"], baseUrl: v.url, mode: v.mode },
    env,
    readConfigFile(file)
  );
  const client = await resolveBackendClient(cfg, deps);
  const arg = rest.join(" ").trim();
  const need = (what: string) => {
    if (!arg) {throw new UsageError(`Missing ${what}. Usage: webcrawl ${cmd} <${what}>`);}
    return arg;
  };
  const emit = (res: Record<string, unknown>, pretty: string) => {
    if (v.json) {
      io.out(`${JSON.stringify(res, null, 2)}\n`);
      return;
    }
    io.out(`${pretty}\n`);
    const credits = formatCredits(res);
    if (credits) {io.err(`[${credits}]\n`);}
  };

  const METERED_COMMANDS = new Set(["search", "scrape", "map", "crawl", "extract", "rerank", "monitor"]);
  if (
    METERED_COMMANDS.has(cmd) &&
    (cfg.effectiveMode === "cloud" || cmd === "monitor") &&
    !cfg.apiKey &&
    !deps.fetch
  ) {
    const authHelp = [
      "webcrawl: Cloud mode requires a logged-in webcrawl.app account so credits can be attributed to your user (1,000 free monthly credits on signup).",
      "",
      "Create an account or sign in from the CLI:",
      "  1. Email OTP (agent & terminal friendly):",
      "     webcrawl login --email <you@domain.com>",
      "     webcrawl login --email <you@domain.com> --code <6-digit-code>",
      "  2. Browser OAuth redirect:",
      "     webcrawl login",
      "  3. Or run in zero-key local mode:",
      `     webcrawl --mode local ${cmd} ${rest.join(" ")}`,
    ].join("\n");
    if (v.json) {
      io.out(
        `${JSON.stringify(
          {
            success: false,
            error: "authentication_required",
            message: "Cloud mode requires a logged-in webcrawl.app account (1,000 free monthly credits on signup).",
            loginCommands: {
              sendOtp: "webcrawl login --email <you@domain.com>",
              verifyOtp: "webcrawl login --email <you@domain.com> --code <6-digit-code>",
              browserRedirect: "webcrawl login",
              signupUrl: `${cfg.baseUrl}/?signup=cli`,
            },
          },
          null,
          2
        )}\n`
      );
    } else {
      io.err(`${authHelp}\n`);
    }
    return 1;
  }

  try {
    switch (cmd) {
      case "search": {
        const res = await client.search({
          query: need("query"),
          category: v.category,
          subcategory: v.sub,
          limit: int(v.limit, "--limit"),
          sites: v.site,
          country: v.country,
          city: v.city,
          scrapeContent: v.content,
        });
        if (res.success === false && !v.json) {
          io.err(`${formatSearch(res)}\n`);
          return 1;
        }
        emit(res, formatSearch(res));
        return res.success === false ? 1 : 0;
      }
      case "scrape": {
        const res = await client.scrape({ url: need("url"), formats: ["markdown"], noCache: v["no-cache"] });
        // Blocked pages come back as success:false: report on stderr and exit 1, not empty content.
        if (res.success === false && !v.json) {
          io.err(`${formatScrape(res)}\n`);
          return 1;
        }
        emit(res, formatScrape(res));
        return res.success === false ? 1 : 0;
      }
      case "map": {
        const res = await client.map({ url: need("url"), search: v.filter, limit: int(v.limit, "--limit") });
        emit(res, formatMap(res));
        return 0;
      }
      case "crawl": {
        const res = await client.crawl({ url: need("url"), maxPages: int(v.limit, "--limit") });
        emit(res, formatCrawl(res));
        return 0;
      }
      case "extract": {
        let schema: Record<string, unknown> | undefined;
        if (v.schema) {
          try {
            schema = JSON.parse(readFileSync(v.schema, "utf8")) as Record<string, unknown>;
          } catch (e) {
            throw new UsageError(`Could not read schema ${v.schema}: ${e instanceof Error ? e.message : String(e)}`);
          }
        }
        const res = await client.extract({ url: need("url"), prompt: v.prompt, schema });
        if (res.success === false && !v.json) {
          const msg =
            typeof res.error === "string" && res.error.trim()
              ? res.error
              : JSON.stringify(res.data ?? res, null, 2);
          io.err(`${msg}\n`);
          return 1;
        }
        emit(res, JSON.stringify(res.data ?? res, null, 2));
        return res.success === false ? 1 : 0;
      }
      case "rerank": {
        const query = need("query");
        let docs = v.doc ?? [];
        if (v.file) {
          docs = docs.concat(readFileSync(v.file, "utf8").split(/\r?\n/).filter(Boolean));
        }
        if (!docs.length && !io.isTTY) {
          docs = (await io.readStdin()).split(/\r?\n/).filter(Boolean);
        }
        if (!docs.length) {throw new UsageError("No documents. Pass --doc, --file, or pipe lines on stdin.");}
        const res = await client.rerank({ query, documents: docs, topK: int(v.limit, "--limit") });
        emit(res, formatRerank(res));
        return 0;
      }
      case "monitor": {
        const cloudClient = new WebcrawlClient({
          apiKey: cfg.apiKey,
          baseUrl: cfg.baseUrl,
          fetch: deps.fetch,
          userAgent: "webcrawl-cli/1.3",
        });
        const first = (rest[0] ?? "").trim();
        const subcommands = new Set([
          "list",
          "ls",
          "create",
          "add",
          "watch",
          "get",
          "inspect",
          "check",
          "pause",
          "resume",
          "delete",
          "rm",
        ]);
        const sub = !first
          ? "list"
          : subcommands.has(first.toLowerCase())
            ? first.toLowerCase()
            : "create";
        const subArgs = subcommands.has(first.toLowerCase()) ? rest.slice(1) : rest;
        const requireMonitorId = (actionName: string): string => {
          const id = (subArgs[0] ?? "").trim();
          if (!id) {
            throw new UsageError(`Missing monitor id. Usage: webcrawl monitor ${actionName} <id>`);
          }
          return id;
        };

        if (sub === "list" || sub === "ls") {
          const res = await cloudClient.monitors();
          emit(res, formatMonitor(res));
          return 0;
        }
        if (sub === "get" || sub === "inspect") {
          const res = await cloudClient.getMonitor(requireMonitorId(sub));
          emit(res, formatMonitor(res));
          return 0;
        }
        if (sub === "check") {
          const res = await cloudClient.checkMonitor(requireMonitorId("check"));
          emit(res, formatMonitor(res));
          return 0;
        }
        if (sub === "pause" || sub === "resume") {
          const id = requireMonitorId(sub);
          const notifyEmailRaw = v["notify-email"];
          const res = await cloudClient.updateMonitor({
            id,
            status: sub === "pause" ? "paused" : "active",
            name: v.name,
            intervalMinutes: int(v.interval, "--interval"),
            watchFor: v["watch-for"],
            condition: v.condition,
            notifyEmail:
              notifyEmailRaw === undefined
                ? undefined
                : notifyEmailRaw === "true"
                  ? true
                  : notifyEmailRaw,
            webhookUrl: v.webhook,
          });
          emit(res, formatMonitor(res));
          return 0;
        }
        if (sub === "delete" || sub === "rm") {
          const res = await cloudClient.deleteMonitor(requireMonitorId(sub));
          emit(res, formatMonitor(res));
          return 0;
        }

        // create / add / watch / `webcrawl monitor <url...>`
        const urls = subArgs.map((s) => s.trim()).filter(Boolean);
        if (!urls.length) {
          throw new UsageError(
            "Missing URL to watch. Usage: webcrawl monitor <url> [--scope page|urls|site] [--watch-for <text>] [--condition <expr>]"
          );
        }
        const rawScope = (v.scope ?? (urls.length > 1 ? "urls" : "page")).toLowerCase();
        if (rawScope !== "page" && rawScope !== "urls" && rawScope !== "site") {
          throw new UsageError(`Invalid --scope "${v.scope}". Expected page, urls, or site.`);
        }
        const notifyEmailRaw = v["notify-email"];
        const res = await cloudClient.createMonitor({
          url: urls[0],
          urls: rawScope === "urls" || urls.length > 1 ? urls : undefined,
          mode: rawScope,
          maxPages: int(v.limit, "--limit"),
          name: v.name,
          intervalMinutes: int(v.interval, "--interval"),
          watchFor: v["watch-for"],
          condition: v.condition,
          notifyEmail:
            notifyEmailRaw === undefined
              ? undefined
              : notifyEmailRaw === "true"
                ? true
                : notifyEmailRaw,
          webhookUrl: v.webhook,
        });
        emit(res, formatMonitor(res));
        return 0;
      }
      case "categories": {
        const res = await client.categories();
        emit(res, JSON.stringify(res, null, 2));
        return 0;
      }
      case "targets": {
        const res = await client.targets();
        emit(res, formatTargets(res));
        return 0;
      }
      case "setup": {
        const rawAgents = v.agent ?? [];
        let agents: SupportedAgentId[] | undefined;
        if (rawAgents.includes("all")) {
          agents = SUPPORTED_AGENTS.map((a) => a.id);
        } else if (rawAgents.length) {
          const valid = new Set<string>(SUPPORTED_AGENTS.map((a) => a.id));
          for (const a of rawAgents) {
            if (!valid.has(a)) {
              throw new UsageError(
                `Unknown agent "${a}". Supported: ${SUPPORTED_AGENTS.map((x) => x.id).join(", ")}, all`
              );
            }
          }
          agents = rawAgents as SupportedAgentId[];
        }
        const schemaProfile = v["schema-profile"] === "full" ? "full" : "compact";
        const setupRes = runSetup({
          agents,
          schemaProfile,
          apiKey: cfg.apiKey,
          baseUrl: cfg.source.baseUrl !== "default" ? cfg.baseUrl : undefined,
          homeDir: deps.homeDir,
          cwd: deps.cwd,
        });
        const prettyLines = [
          `Webcrawl Anything agent setup complete (MCP schema profile: ${setupRes.schemaProfile}):`,
          ...setupRes.configuredAgents.map(
            (a) =>
              `  ✓ ${a.name}\n    MCP:   ${a.mcpConfigPath}${a.backupPath ? ` (backup: ${a.backupPath})` : ""}\n    Skill: ${a.skillPath}`
          ),
          "",
          "Restart your agent to load the `webcrawl` MCP server and `webcrawl-anything` skill.",
        ].join("\n");
        emit({ success: true, ...setupRes }, prettyLines);
        return 0;
      }
      case "doctor": {
        const report = runDoctor(env, cfg.effectiveMode, cfg.source.apiKey);
        const prettyLines = [
          `Webcrawl Anything Doctor (mode: ${report.mode})`,
          ...report.checks.map((c) => {
            const badge = c.status === "ok" ? "✓" : c.status === "optional" ? "○" : "!";
            return `  ${badge} ${c.name.padEnd(26)} ${c.detail}`;
          }),
        ].join("\n");
        emit({ success: true, ...report }, prettyLines);
        return 0;
      }
      case "login":
      case "signup": {
        const authClient = new WebcrawlClient({
          baseUrl: cfg.baseUrl,
          fetch: deps.fetch,
          userAgent: "webcrawl-cli/1.2",
        });

        // 1. Browser OAuth PKCE redirect (default for `webcrawl login`; `--web` kept for compatibility)
        if (v.web || (!v.email && !v.key)) {
          const webRes = await runWebOAuthLogin(cfg.baseUrl, deps.fetch ?? globalThis.fetch, io, deps.openUrl);
          const existing = readConfigFile(file);
          writeConfigFile(
            { ...existing, apiKey: webRes.apiKey, ...(v.url ? { baseUrl: v.url } : {}) },
            file
          );
          const payload = {
            success: true,
            method: "web_oauth",
            email: webRes.email,
            plan: webRes.plan ?? "free",
            creditsRemaining: webRes.creditsRemaining ?? 1000,
            creditsLimit: webRes.creditsLimit ?? 1000,
            configFile: file,
          };
          emit(
            payload,
            [
              `✓ Authenticated${webRes.email ? ` as ${webRes.email}` : ""} (${payload.plan} plan · ${payload.creditsRemaining} credits remaining of ${payload.creditsLimit}).`,
              `Saved API key to ${file}.`,
            ].join("\n")
          );
          return 0;
        }

        // 2. Email OTP account creation / sign-in (`webcrawl login --email <addr> [--code <6-digit>]`)
        if (v.email) {
          const email = v.email.trim();
          let code = v.code?.trim();
          if (!code) {
            const otpRes = await authClient.sendOtp(email);
            if (!otpRes.success) {
              throw new WebcrawlError("bad_request", otpRes.error || "Could not send verification code.");
            }
            if (otpRes.devCode && !io.isTTY) {
              code = otpRes.devCode;
            } else if (io.isTTY && !v["no-wait"]) {
              io.err(`Sent a 6-digit verification code to ${email} (expires in 10 minutes).\n`);
              code = await promptLine(io, `Enter the 6-digit code sent to ${email}: `);
            } else {
              const stepPayload = {
                success: true,
                step: "otp_sent",
                email: otpRes.email,
                expiresInSeconds: otpRes.expiresInSeconds,
                nextCommand: `webcrawl login --email ${email} --code <6-digit-code>`,
                browserFallbackUrl: `${cfg.baseUrl}/?signup=cli&email=${encodeURIComponent(email)}`,
              };
              emit(
                stepPayload,
                [
                  `Verification code sent to ${otpRes.email} (expires in ${Math.round(otpRes.expiresInSeconds / 60)} minutes).`,
                  `Ask the user for the 6-digit code from their email, then complete sign-in with:`,
                  `  webcrawl login --email ${email} --code <6-digit-code>`,
                  `Or redirect the user to sign in on the web: ${stepPayload.browserFallbackUrl}`,
                ].join("\n")
              );
              return 0;
            }
          }

          const verified = await authClient.verifyOtp({ email, code, name: v.name });
          if (!verified.success || !verified.apiKey) {
            throw new WebcrawlError(
              "auth",
              verified.error || "Could not verify the 6-digit code."
            );
          }
          const existing = readConfigFile(file);
          writeConfigFile(
            { ...existing, apiKey: verified.apiKey, ...(v.url ? { baseUrl: v.url } : {}) },
            file
          );
          const u = verified.user;
          const payload = {
            success: true,
            isNewUser: verified.isNewUser ?? false,
            email: u?.email ?? email,
            plan: u?.plan ?? "free",
            creditsRemaining: u?.creditsRemaining ?? 1000,
            creditsLimit: u?.creditsLimit ?? 1000,
            configFile: file,
          };
          emit(
            payload,
            [
              `✓ ${verified.isNewUser ? "Created webcrawl.app account" : "Signed in"} as ${payload.email} (${payload.plan} plan · ${payload.creditsRemaining} credits remaining of ${payload.creditsLimit}).`,
              `Saved API key (${verified.apiKey.slice(0, 8)}…${verified.apiKey.slice(-4)}) to ${file}.`,
            ].join("\n")
          );
          return 0;
        }

        // 3. Direct API key (`webcrawl login --key wc_live_...` or interactive paste)
        const key = v.key?.trim() ?? (await readKeyInteractively(io)).trim();
        if (!key) {throw new UsageError("No key provided. Pass --key <wc_live_...> or --email <you@domain.com>, or run `webcrawl login` to sign in via your browser.");}
        const existing = readConfigFile(file);
        writeConfigFile({ ...existing, apiKey: key, ...(v.url ? { baseUrl: v.url } : {}) }, file);
        io.out(`Saved your key to ${file}.\n`);
        return 0;
      }
      case "whoami": {
        const masked = cfg.apiKey ? `${cfg.apiKey.slice(0, 8)}…${cfg.apiKey.slice(-4)}` : "none";
        const lines = [
          `endpoint: ${cfg.baseUrl} (${cfg.source.baseUrl})`,
          `mode:     ${cfg.effectiveMode} (${cfg.source.mode})`,
          `key:      ${masked}${cfg.apiKey ? ` (${cfg.source.apiKey})` : ". Run `webcrawl login` to sign in via your browser (or `--email <you@domain.com>`), or set WEBCRAWL_API_KEY (local mode works with zero key)."}`,
        ];
        if (cfg.apiKey) {
          const u = await client.usage();
          if (v.json) {
            io.out(`${JSON.stringify({ endpoint: cfg.baseUrl, mode: cfg.effectiveMode, keySource: cfg.source.apiKey, usage: u }, null, 2)}\n`);
            return 0;
          }
          const userObj = (u.user ?? {}) as Record<string, unknown>;
          if (typeof userObj.email === "string") {
            lines.push(`account:  ${userObj.email} (${userObj.plan ?? "free"} plan)`);
          }
          const credits = (u.credits ?? u) as Record<string, unknown>;
          if (typeof credits.remaining === "number") {
            lines.push(`credits:  ${credits.remaining} remaining of ${credits.limit ?? "?"}`);
          }
        }
        io.out(`${lines.join("\n")}\n`);
        return 0;
      }
      default:
        throw new UsageError(`Unknown command "${cmd}".`);
    }
  } catch (e) {
    if (e instanceof UsageError) {
      io.err(`${e.message}\nRun \`webcrawl --help\`.\n`);
      return 2;
    }
    if (e instanceof WebcrawlError) {
      io.err(`webcrawl: ${describeError(e, cfg.baseUrl)}\n`);
      return 1;
    }
    io.err(`webcrawl: ${e instanceof Error ? e.message : String(e)}\n`);
    return 1;
  }
}
