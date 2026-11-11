/**
 * Local Chrome renderer (JS pages the native fetch ladder cannot hydrate).
 *
 * Primary driver is Chrome DevTools Protocol:
 * launch headless Chrome, navigate, wait until the DOM is content-ready
 * (load + stable main-content text / mutation-idle, rejecting loading
 * placeholders), then read `documentElement.outerHTML`.
 *
 * dump-dom is a last-resort fallback: Chrome 156 hangs on dump-dom with a
 * fresh profile, which used to look like a successful scrape of the
 * unrendered nav shell. Every attempt has a hard timeout and a process-group
 * kill. Playwright's chrome-headless-shell is discovered automatically when
 * present.
 */
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChromeConnectError, renderUrlViaCdp } from "./chrome-cdp.js";
import {
  DUMP_MAX_BYTES,
  chromeDumpDomArgs,
  discoverChromeBinaries,
  killProcessGroup,
  resolveChromeConnectTimeoutMs,
  resolveChromeTimeoutMs,
  type ChromeHeadlessMode,
} from "./chrome-launch.js";

export {
  DEFAULT_CONNECT_TIMEOUT_MS,
  DEFAULT_TIMEOUT_MS,
  VIRTUAL_TIME_MS,
  discoverChromeBinaries,
  findPlaywrightHeadlessShell,
  installedChromePath,
  isLocalChromeAvailable,
  parseDevToolsActivePort,
  chromeCdpArgs,
  chromeDumpDomArgs,
  killProcessGroup,
  resolveChromeConnectTimeoutMs,
  resolveChromeTimeoutMs,
  type ChromeHeadlessMode,
} from "./chrome-launch.js";
export { ChromeConnectError } from "./chrome-cdp.js";

export interface ChromeRenderAttempt {
  ok: boolean;
  method: string;
  ms: number;
  error?: string;
}

export interface ChromeRenderResult {
  html: string | null;
  method?: string;
  error?: string;
  attempts: ChromeRenderAttempt[];
}

type AttemptKind = { driver: "cdp" | "dump-dom"; headless: ChromeHeadlessMode };

function attemptPlan(binary: string): AttemptKind[] {
  const isShell = /headless[-_]?shell/i.test(binary);
  if (isShell) {
    return [
      { driver: "cdp", headless: "shell" },
      { driver: "dump-dom", headless: "shell" },
    ];
  }
  return [
    { driver: "cdp", headless: "new" },
    { driver: "cdp", headless: "old" },
    { driver: "dump-dom", headless: "old" },
    { driver: "dump-dom", headless: "new" },
  ];
}

function methodName(binary: string, kind: AttemptKind): string {
  const base = binary.split(/[/\\]/).pop() || binary;
  return `${kind.driver}/${kind.headless} (${base})`;
}

/**
 * Render `url` in local Chrome and return the hydrated HTML, or null when
 * Chrome is missing, times out, or produces nothing.
 */
export async function renderViaLocalChrome(
  url: string,
  opts: { timeoutMs?: number; connectTimeoutMs?: number; binaries?: string[] } = {}
): Promise<string | null> {
  const result = await renderViaLocalChromeDetailed(url, opts);
  return result.html;
}

/**
 * Same as `renderViaLocalChrome` but with the attempt log and an actionable
 * error when every driver fails. Callers that need to report honest JS-render
 * failures should use this.
 */
export async function renderViaLocalChromeDetailed(
  url: string,
  opts: { timeoutMs?: number; connectTimeoutMs?: number; binaries?: string[] } = {}
): Promise<ChromeRenderResult> {
  const binaries = opts.binaries?.length ? opts.binaries : discoverChromeBinaries();
  if (binaries.length === 0) {
    return {
      html: null,
      error:
        "No local Chrome/Chromium binary found. Install Chrome, set WEBCRAWL_CHROME_PATH, " +
        "or run `npx playwright install chromium-headless-shell`. See `webcrawl doctor`.",
      attempts: [],
    };
  }
  const budgetMs = resolveChromeTimeoutMs(opts.timeoutMs);
  const connectTimeoutMs = resolveChromeConnectTimeoutMs(opts.connectTimeoutMs);
  const started = Date.now();
  const attempts: ChromeRenderAttempt[] = [];
  let lastError = "local Chrome produced no content";

  for (const binary of binaries) {
    let hungConnect = false;
    for (const kind of attemptPlan(binary)) {
      const remaining = budgetMs - (Date.now() - started);
      if (remaining < 1_200) break;
      // A process that launched but never answered CDP will hang dump-dom too.
      if (kind.driver === "dump-dom" && hungConnect) continue;
      const method = methodName(binary, kind);
      const attemptBudget =
        kind.driver === "cdp"
          ? Math.min(remaining, kind.headless === "new" ? 12_000 : 8_000)
          : Math.min(remaining, 6_000);
      const t0 = Date.now();
      try {
        const html =
          kind.driver === "cdp"
            ? (await renderUrlViaCdp(binary, url, {
                timeoutMs: attemptBudget,
                connectTimeoutMs: Math.min(connectTimeoutMs, remaining),
                headless: kind.headless,
              })).html
            : await dumpDom(binary, url, kind.headless, attemptBudget);
        const ms = Date.now() - t0;
        if (html && html.length > 100) {
          attempts.push({ ok: true, method, ms });
          return { html, method, attempts };
        }
        lastError = `${method} returned empty HTML`;
        attempts.push({ ok: false, method, ms, error: lastError });
      } catch (err) {
        const ms = Date.now() - t0;
        lastError = `${method}: ${err instanceof Error ? err.message : String(err)}`;
        attempts.push({ ok: false, method, ms, error: lastError });
        if (err instanceof ChromeConnectError && err.hung) hungConnect = true;
      }
    }
  }

  return {
    html: null,
    error:
      `JavaScript rendering failed (${lastError}). ` +
      "Chrome hung, timed out, or produced no content. Install Chrome, point WEBCRAWL_CHROME_PATH " +
      "at chrome-headless-shell (`npx playwright install chromium-headless-shell`), " +
      "run `webcrawl login` and retry with `--mode cloud`, or set WEBCRAWL_RENDER_URL.",
    attempts,
  };
}

async function dumpDom(
  chrome: string,
  url: string,
  headless: ChromeHeadlessMode,
  timeoutMs: number
): Promise<string> {
  let profile = "";
  try {
    profile = mkdtempSync(join(tmpdir(), "wc-chrome-"));
  } catch {
    throw new Error("could not create Chrome profile directory");
  }
  const args = chromeDumpDomArgs({
    profile,
    headless,
    url,
    timeoutMs,
    binaryPath: chrome,
  });
  try {
    return await new Promise<string>((resolve, reject) => {
      let settled = false;
      const done = (err: Error | null, value?: string) => {
        if (settled) return;
        settled = true;
        if (err) reject(err);
        else resolve(value ?? "");
      };
      let child: ReturnType<typeof spawn>;
      try {
        child = spawn(chrome, args, {
          stdio: ["ignore", "pipe", "pipe"],
          detached: true,
        });
      } catch (err) {
        done(err instanceof Error ? err : new Error(String(err)));
        return;
      }
      const chunks: Buffer[] = [];
      let bytes = 0;
      let idle: ReturnType<typeof setTimeout> | null = null;
      const finish = (err: Error | null) => {
        clearTimeout(timer);
        if (idle) clearTimeout(idle);
        killProcessGroup(child.pid, child);
        if (err) {
          done(err);
          return;
        }
        const text = Buffer.concat(chunks).toString("utf8");
        done(null, text.trim());
      };
      const timer = setTimeout(() => {
        if (bytes > 100) finish(null);
        else finish(new Error(`dump-dom timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      child.stdout?.on("data", (c: Buffer) => {
        if (bytes >= DUMP_MAX_BYTES) return;
        const take = c.subarray(0, DUMP_MAX_BYTES - bytes);
        chunks.push(take);
        bytes += take.length;
        // Chrome 156 often prints the DOM then never exits (`--dump-dom` hang).
        if (idle) clearTimeout(idle);
        idle = setTimeout(() => {
          if (bytes > 40) finish(null);
        }, 400);
      });
      child.on("error", (err) => {
        clearTimeout(timer);
        if (idle) clearTimeout(idle);
        done(err);
      });
      child.on("close", () => {
        clearTimeout(timer);
        if (idle) clearTimeout(idle);
        if (bytes === 0) {
          done(new Error("dump-dom produced no stdout"));
          return;
        }
        const text = Buffer.concat(chunks).toString("utf8");
        done(null, text.trim().length > 0 ? text : "");
      });
    });
  } finally {
    try {
      rmSync(profile, { recursive: true, force: true });
    } catch {
      /* leftover profile is in /tmp */
    }
  }
}
