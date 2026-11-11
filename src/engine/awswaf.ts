/**
 * AWS WAF challenge handling (local prototype).
 *
 * `webcrawl`'s bot-check detector (`isAntiBotChallenge`) only matches
 * Cloudflare and Vercel Security Checkpoint signatures. AWS WAF serves
 * its invisible JS challenge as **HTTP 202** with an empty `<title>` and
 * none of those markers, so such pages come back as
 * `Empty page (HTTP 202)` with `blocked: false` and never reach the
 * stealth browser. This module adds the missing detection plus a local
 * stealth-routing path so those pages can be solved and read anyway.
 *
 * Detection markers are layered (no single one is proof):
 *   - status 202 (documented Challenge interstitial status)
 *   - `awsWafCookieDomainList` / `AwsWafIntegration` (documented JS API)
 *   - `aws-waf-token` cookie reference
 *   - `<div id="challenge-container">` + `/__challenge_<id>/.../challenge.js`
 *
 * The detection itself now lives in the shared detector
 * (`isAwsWafChallenge` in `./fetcher.js`, also folded into
 * `isAntiBotChallenge`); this module re-exports it and adds the local
 * stealth-routing path so challenge pages can be solved and read anyway.
 */
import { fetchWithTlsImpersonation, isAntiBotChallenge, isAwsWafChallenge } from "./fetcher.js";
import { fastHtmlToMarkdown } from "./markdown.js";

export { isAwsWafChallenge };

/** True when a fetch response is any known bot check (upstream detector + AWS WAF). */
export function isBlockedLike(html: string, status?: number): boolean {
  return isAntiBotChallenge(html ?? "", status ?? 200) || isAwsWafChallenge(html ?? "", status);
}

export interface AwsWafPage {
  url: string;
  title: string;
  markdown: string;
  linksCount: number;
  cached: false;
  cacheLayer: "miss";
  structuredData: null;
  statusCode?: number;
  blocked?: boolean;
  error?: string;
  awsWaf?: boolean;
  stealth?: boolean;
}

const MAC_CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const CHALLENGE_TIMEOUT_MS = 45_000;

/** Waits for a dynamically-installed playwright-core (avoids a hard dep). */
async function loadPlaywrightCore(): Promise<{ chromium: { launch(opts: Record<string, unknown>): Promise<BrowserLike> } }> {
  // Non-literal specifier: playwright-core stays a soft, runtime-only dependency
  // so `tsc --noEmit` passes without the package installed.
  const specifier = "playwright-core";
  return (await import(specifier)) as never;
}

/** Minimal shape of a Playwright browser/context/page this module needs. */
interface BrowserLike {
  newContext(opts?: Record<string, unknown>): Promise<ContextLike>;
  close(): Promise<void>;
}
interface ContextLike {
  addInitScript(script: string): Promise<void>;
  newPage(): Promise<PageLike>;
}
interface PageLike {
  goto(url: string, opts?: Record<string, unknown>): Promise<unknown>;
  content(): Promise<string>;
  url(): string;
  title(): Promise<string>;
  waitForTimeout(ms: number): Promise<void>;
  waitForLoadState(state: string, opts?: Record<string, unknown>): Promise<void>;
  on(event: string, handler: (r: any) => void): void;
  mainFrame(): unknown;
}

function chromePath(): string | undefined {
  return process.env.INTERACT_CHROME_PATH || MAC_CHROME;
}

/**
 * Opens `url` in a real local Chromium, waits out the AWS WAF challenge
 * (the interstitial reloads itself once `AwsWafIntegration.getToken()`
 * resolves), then returns the rendered page as a CrawledPage-shaped result.
 * Never fabricates content: a page still showing the challenge comes back
 * `blocked: true` with an honest error.
 */
export async function awsWafStealthFetch(url: string, opts: { timeoutMs?: number } = {}): Promise<AwsWafPage> {
  const fail = (error: string, blocked = true): AwsWafPage => ({
    url,
    title: url,
    markdown: "",
    linksCount: 0,
    cached: false,
    cacheLayer: "miss",
    structuredData: null,
    blocked,
    error,
    awsWaf: true,
    stealth: true,
  });
  const { chromium } = await loadPlaywrightCore();
  const executablePath = chromePath();
  const browser = await chromium.launch({
    executablePath,
    headless: true,
    args: [
      "--no-sandbox",
      "--disable-gpu",
      "--disable-dev-shm-usage",
      "--no-first-run",
      "--no-default-browser-check",
      // Hide navigator.webdriver, which bot checks look for.
      "--disable-blink-features=AutomationControlled",
      `--window-size=1280,800`,
    ],
  });
  try {
    const ctx = await browser.newContext({
      userAgent:
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
      viewport: { width: 1280, height: 800 },
      locale: "en-US",
    });
    await ctx.addInitScript("Object.defineProperty(Navigator.prototype,'webdriver',{get:()=>false});");
    const page = await ctx.newPage();
    let navStatus: number | null = null;
    page.on("response", (r: { request(): { isNavigationRequest(): boolean }; frame(): unknown; status(): number }) => {
      try {
        if (r.request().isNavigationRequest() && r.frame() === page.mainFrame()) navStatus = r.status();
      } catch {}
    });
    // The interstitial reloads itself after getToken(); domcontentloaded +
    // marker polling survives that reload race.
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: Math.min(30_000, opts.timeoutMs ?? 30_000) });
    const deadline = Date.now() + (opts.timeoutMs ?? CHALLENGE_TIMEOUT_MS);
    let html = "";
    for (;;) {
      html = await page.content().catch(() => "");
      if (!isAwsWafChallenge(html) && !isAntiBotChallenge(html, 200)) break;
      if (Date.now() > deadline) break;
      await page.waitForTimeout(700).catch(() => {});
    }
    try {
      await page.waitForLoadState("networkidle", { timeout: 2500 });
    } catch {}
    html = await page.content().catch(() => html);
    if (isAwsWafChallenge(html) || isAntiBotChallenge(html, 200)) {
      return { ...fail("Still blocked by the site's AWS WAF challenge in local stealth mode"), statusCode: navStatus ?? undefined };
    }
    const finalUrl = page.url();
    const parsed = fastHtmlToMarkdown(html, finalUrl || url, { retainImages: "all" });
    if (parsed.markdown.length === 0) {
      return {
        ...fail(`Empty page after challenge (HTTP ${navStatus ?? "?"})`, false),
        statusCode: navStatus ?? undefined,
      };
    }
    return {
      url,
      title: parsed.title || finalUrl || url,
      markdown: parsed.markdown,
      linksCount: parsed.links.length,
      cached: false,
      cacheLayer: "miss",
      structuredData: null,
      statusCode: navStatus ?? 200,
      awsWaf: true,
      stealth: true,
    };
  } finally {
    await browser.close().catch(() => {});
  }
}

/**
 * Reads one page: plain TLS-impersonated fetch first; when the site answers
 * with an AWS WAF challenge (which the upstream detector misses), routes
 * through the local stealth browser instead.
 */
export async function crawlPageWithAwsWaf(url: string, opts: { bypassCache?: boolean; stealthTimeoutMs?: number } = {}): Promise<AwsWafPage> {
  const fetched = await fetchWithTlsImpersonation(url, 12_000);
  if (!isAwsWafChallenge(fetched.html, fetched.status)) {
    const parsed = fastHtmlToMarkdown(fetched.html, url, { retainImages: "all" });
    return {
      url,
      title: parsed.title || url,
      markdown: parsed.markdown,
      linksCount: parsed.links.length,
      cached: false,
      cacheLayer: "miss",
      structuredData: null,
      statusCode: fetched.status,
      ...(parsed.markdown.length === 0 ? { error: `Empty page (HTTP ${fetched.status})` } : {}),
    };
  }
  console.info("[awswaf] challenge detected, routing through local stealth browser", { url, status: fetched.status });
  return awsWafStealthFetch(url, { timeoutMs: opts.stealthTimeoutMs });
}
