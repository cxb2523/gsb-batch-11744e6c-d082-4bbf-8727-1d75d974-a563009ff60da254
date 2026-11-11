/**
 * Stealth mode: read pages a bot check refuses to plain HTTP clients.
 *
 * One real Chromium session (the interact browser: Vercel Sandbox in prod,
 * local Playwright in dev) opens the entry page, waits until the check clears,
 * then reads every requested URL with that cleared session. Raw documents
 * (robots.txt, sitemaps) are read with fetch() from inside the page so they
 * carry the same cookies, IP and TLS fingerprint as the browser.
 *
 * Never fabricates content: a page still showing a check comes back `blocked`.
 */
import { isAntiBotChallenge } from "./fetcher.js";
import { setDomainCookie, setDomainUserAgent } from "./fetcher.js";
import { cookieHeaderFrom, getWarmSession, saveWarmSession, WARM_TTL_MS, type CookieLike } from "./session.js";
import { remoteStealthProvider, type RemoteProvider } from "../interact/remote.js";

export interface StealthDoc {
  url: string;
  ok: boolean;
  status?: number | null;
  contentType?: string;
  body?: string;
  finalUrl?: string;
  title?: string;
  blocked?: boolean;
  error?: string;
}

export interface StealthResult {
  /** True when the entry page passed the bot check. */
  solved: boolean;
  entry: StealthDoc | null;
  docs: StealthDoc[];
  durationMs: number;
  error?: string;
  /** Set when a remote provider (e.g. Browser Use) hosted the browser. */
  provider?: RemoteProvider;
  /** Provider charge for the session in USD, when it reported one. */
  providerCostUsd?: number;
}

export interface StealthItem {
  url: string;
  /** Read as a raw document (robots.txt, sitemap XML) instead of rendering it. */
  raw?: boolean;
}

/**
 * True when a real browser can run here: our own (sandbox in prod, local
 * Playwright in dev) or a remote provider. A remote browser still needs the
 * sandbox or local Playwright to run the step script against it.
 */
export async function stealthAvailable(): Promise<boolean> {
  if (process.env.WEBCRAWL_STEALTH === "false") return false;
  const { interactBrowserAvailable } = await import("../interact/driver.js");
  return interactBrowserAvailable();
}

/** True when this fetched document is a bot check, not the real content. */
export function isBlockedResponse(status: number | null | undefined, body: string): boolean {
  return isAntiBotChallenge(body ?? "", status ?? 200);
}

/**
 * Opens `entryUrl` in a real browser, waits for the bot check to clear, then
 * reads `items` in order through that session. One browser per call.
 */
export async function stealthFetch(
  entryUrl: string,
  items: StealthItem[],
  opts: {
    budgetMs?: number;
    solveMs?: number;
    followSitemaps?: number;
    /** Allow the paid remote provider. Off for unbilled (anonymous) runs. Default true. */
    remote?: boolean;
    /** Keep the solved session warm (sandbox left running + cookies saved) for repeat queries. */
    keepWarm?: boolean;
    /** Tier P2: egress the stealth browser through this residential proxy URL. */
    proxy?: string;
  } = {}
): Promise<StealthResult> {
  const t0 = Date.now();
  if (!(await stealthAvailable())) {
    return { solved: false, entry: null, docs: [], durationMs: 0, error: "Stealth browser not configured" };
  }
  const { startBrowser, runBrowserStep, stopBrowser } = await import("../interact/driver.js");
  const provider = opts.remote === false ? null : remoteStealthProvider();
  const domain = hostOf(entryUrl);
  const proxyUrl = opts.proxy ?? null;
  let proxyUser = "";
  let proxyPass = "";
  if (proxyUrl) {
    try {
      const parsed = new URL(proxyUrl);
      proxyUser = decodeURIComponent(parsed.username);
      proxyPass = decodeURIComponent(parsed.password);
    } catch {
      /* bad proxy URL: browser launch will surface the error */
    }
  }
  // A warm session for this domain means the challenge is already solved: short
  // solve budget. A cold solve needs the full budget. Proxy runs never reuse
  // warm sessions (their cookies were earned from a datacenter egress IP).
  const hadWarm = provider || proxyUrl ? null : await getWarmSession(domain).catch(() => null);
  const tag = provider ? { provider } : { warm: Boolean(hadWarm) };
  let handle: Awaited<ReturnType<typeof startBrowser>> | null = null;
  // Filled in by `finally` once the provider reports the session cost.
  const out: { result?: StealthResult } = {};
  let capturedCookies: { name: string; value: string; domain?: string; path?: string; expires?: number }[] = [];
  let capturedUa = "";
  try {
    const budgetMs = opts.budgetMs ?? 90_000;
    handle = await startBrowser({
      timeoutMs: Math.min(5 * 60_000, budgetMs + 90_000),
      remote: provider,
      domain: provider || proxyUrl ? undefined : domain,
      proxy: proxyUrl ?? undefined,
    });
    const res = await runBrowserStep(handle, {
      type: "fetchMany",
      entry: entryUrl,
      items: items.slice(0, 40),
      budgetMs,
      solveMs: hadWarm ? Math.min(opts.solveMs ?? 20_000, 8_000) : (opts.solveMs ?? 20_000),
      followSitemaps: opts.followSitemaps ?? 0,
      ...(proxyUser ? { proxyUser, proxyPass, proxyByteCap: 6_000_000 } : {}),
    });
    if (!res.ok) {
      out.result = { solved: false, entry: null, docs: [], durationMs: 0, error: res.error || "Stealth browser step failed", ...tag };
    } else {
      const value = (res.data?.value ?? {}) as {
        entry?: StealthDoc | null;
        docs?: StealthDoc[];
        solved?: boolean;
        userAgent?: string;
        cookies?: { name: string; value: string; domain?: string; path?: string; expires?: number }[];
      };
      capturedCookies = Array.isArray(value.cookies) ? value.cookies : [];
      capturedUa = value.userAgent ?? "";
      if (capturedUa) setDomainUserAgent(domain, capturedUa);
      if (capturedCookies.length > 0) {
        setDomainCookie(domain, cookieHeaderFrom(capturedCookies));
      }
      out.result = {
        solved: Boolean(value.solved),
        entry: value.entry ?? null,
        docs: Array.isArray(value.docs) ? value.docs : [],
        durationMs: 0,
        ...tag,
      };
    }
  } catch (err) {
    out.result = { solved: false, entry: null, docs: [], durationMs: 0, error: err instanceof Error ? err.message : String(err), ...tag };
  } finally {
    const solved = out.result?.solved === true;
    const keepWarm = !provider && solved && (opts.keepWarm ?? true) && Boolean(handle && handle.kind === "sandbox" && capturedUa);
    const cost = handle
      ? await stopBrowser(handle, {
          keepWarm,
          domain,
          userAgent: capturedUa,
          cookieHeader: capturedCookies.length > 0 ? cookieHeaderFrom(capturedCookies) : "",
        }).catch(() => null)
      : null;
    if (out.result && cost) out.result.providerCostUsd = cost.costUsd;
    if (!keepWarm && solved && capturedCookies.length > 0) {
      // Even without a warm sandbox, remember the solved cookies for replay on
      // the lightweight tier (UA-paired; rejection there just escalates).
      await saveWarmSession({ domain, sandboxId: "", userAgent: capturedUa, cookieHeader: cookieHeaderFrom(capturedCookies), expiresAt: Date.now() + WARM_TTL_MS })
        .catch(() => {});
    }
    console.info("[stealth] session result", {
      domain,
      solved,
      warm: Boolean(hadWarm),
      keepWarm,
      cookieCount: capturedCookies.length,
      durationMs: Date.now() - t0,
    });
  }
  const result = out.result!;
  result.durationMs = Date.now() - t0;
  if (provider) {
    console.info("[stealth] remote session", {
      provider,
      solved: result.solved,
      docs: result.docs.length,
      costUsd: result.providerCostUsd,
      durationMs: result.durationMs,
      error: result.error,
    });
  }
  return result;
}

/** Hostname of a URL, or "" when unparseable. */
function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

/** Extracts `<loc>` entries from a sitemap or sitemap index. */
export function parseSitemapLocs(xml: string): { pages: string[]; sitemaps: string[] } {
  const pages: string[] = [];
  const sitemaps: string[] = [];
  const isIndex = /<sitemapindex[\s>]/i.test(xml);
  for (const m of xml.matchAll(/<loc>\s*(?:<!\[CDATA\[)?([^<\]]+?)(?:\]\]>)?\s*<\/loc>/gi)) {
    const loc = m[1]
      .trim()
      .replace(/&amp;/g, "&")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"')
      .replace(/&#39;|&apos;/g, "'");
    if (isIndex || /\.xml(\.gz)?(\?|$)/i.test(loc)) sitemaps.push(loc);
    else pages.push(loc);
  }
  return { pages, sitemaps };
}

/** Sitemap URLs declared in robots.txt. */
export function sitemapsFromRobots(robots: string): string[] {
  return Array.from(robots.matchAll(/^\s*Sitemap:\s*(\S+)/gim)).map((m) => m[1].trim());
}

/**
 * Finds a blocked site's pages through one stealth session: robots.txt and the
 * usual sitemap paths, following robots-declared and child sitemaps in the same
 * session. Also returns the rendered entry page so its links count when there
 * is no sitemap.
 */
export async function stealthDiscover(
  entryUrl: string,
  opts: { budgetMs?: number; sitemapUrls?: string[]; remote?: boolean } = {}
): Promise<{
  solved: boolean;
  sitemapPages: string[];
  sitemapsRead: string[];
  entry: StealthDoc | null;
  durationMs: number;
  error?: string;
  providerCostUsd?: number;
}> {
  const origin = new URL(entryUrl).origin;
  const first = await stealthFetch(
    entryUrl,
    [
      ...(opts.sitemapUrls ?? []).map((url) => ({ url, raw: true })),
      { url: `${origin}/robots.txt`, raw: true },
      { url: `${origin}/sitemap.xml`, raw: true },
      { url: `${origin}/sitemap_index.xml`, raw: true },
      { url: `${origin}/sitemap-index.xml`, raw: true },
    ],
    { budgetMs: opts.budgetMs ?? 75_000, followSitemaps: 12, remote: opts.remote }
  );
  const { pages, sitemapsRead } = collectSitemapPages(first.docs);
  return {
    solved: first.solved,
    sitemapPages: pages,
    sitemapsRead,
    entry: first.entry,
    durationMs: first.durationMs,
    ...(first.error ? { error: first.error } : {}),
    ...(first.providerCostUsd !== undefined ? { providerCostUsd: first.providerCostUsd } : {}),
  };
}

/** Page URLs from every readable sitemap among `docs` (robots.txt and blocked docs are skipped). */
export function collectSitemapPages(docs: StealthDoc[]): { pages: string[]; sitemapsRead: string[] } {
  const pages = new Set<string>();
  const sitemapsRead: string[] = [];
  for (const doc of docs) {
    if (!doc.ok || !doc.body || doc.blocked || (doc.status ?? 200) >= 400) continue;
    if (/\/robots\.txt(\?|$)/i.test(doc.url) || !doc.body.includes("<loc>")) continue;
    sitemapsRead.push(doc.url);
    for (const u of parseSitemapLocs(doc.body).pages) pages.add(u);
  }
  return { pages: Array.from(pages), sitemapsRead };
}
