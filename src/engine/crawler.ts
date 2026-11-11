import { buildPathScope } from "./path-scope.js";
import { followSafely } from "./safe-url.js";
import { AdaptiveConcurrency, parseRobots, sleep, withRetries, type RobotsRules } from "./crawl-policy.js";
import { escalateToSandboxOrBrowser } from "../sandbox.js";
import {
  getCachedMap,
  getCachedMapAsync,
  getCachedPage,
  getCachedPageAsync,
  setCachedMap,
  setCachedPage,
  sha256,
} from "./cache.js";
import {
  fetchWithTlsImpersonation,
  getBrowserHeaders,
  isAntiBotChallenge,
} from "./fetcher.js";
import {
  decodeHtmlEntities,
  extractLinksFromHtml,
  fastHtmlToMarkdown,
} from "./markdown.js";
import {
  extractByPromptAndSchema,
  hasCustomExtractRequest,
} from "../extract/structured.js";

export interface MapWebsiteOptions {
  /** Only crawl the exact root/target domain (default: true when includeSubdomains is false and selectedDomains is empty) */
  onlyRootDomain?: boolean;
  /** Also crawl subdomains of the allowed domain(s), e.g. docs.example.com (default: false) */
  includeSubdomains?: boolean;
  /** Explicit allowlist of domains/subdomains (supports exact hosts like "docs.example.com" or wildcards like "*.example.com") */
  selectedDomains?: string[];
  /** Maximum number of discovered URLs to return (default: 5000) */
  limit?: number;
  /** Maximum number of HTML pages to fetch during multi-hop BFS crawl when sitemap is missing (default: 250) */
  maxCrawlPages?: number;
  /** Alias for maxCrawlPages */
  maxCrawl?: number;
  /** Maximum BFS hop depth from the entry URL (default: 8) */
  maxDepth?: number;
  /** Only keep URLs whose path matches one of these (prefix, `*` wildcards, trailing `$`). */
  includePaths?: string[];
  /** Drop URLs whose path matches any of these. Wins over includePaths. */
  excludePaths?: string[];
  /** Stay under the start URL's path when no includePaths are given (default: true). */
  restrictToSubpath?: boolean;
  /** Sitemaps to read first (e.g. a site whose sitemap is not at /sitemap.xml). */
  sitemapUrls?: string[];
  /** Overall map timeout in milliseconds (default: 25000) */
  timeoutMs?: number;
  /** Bypass 24-hour map cache (default: false) */
  bypassCache?: boolean;
  /** When a bot check blocks plain requests, find pages through a real browser (default: true) */
  stealth?: boolean;
  /** Time budget for the stealth browser session (default: 75000) */
  stealthBudgetMs?: number;
  /** Allow the paid remote stealth provider (default true). Off for unbilled runs. */
  remoteStealth?: boolean;
}

export async function mapWebsiteUrls(
  targetUrl: string,
  options: MapWebsiteOptions = {}
): Promise<{
  success: boolean;
  links: string[];
  latencyMs: number;
  source: string;
  cached?: boolean;
  cacheLayer?: "memory" | "disk" | "postgres" | "miss";
  pagesCrawled?: number;
  /** The site answered plain requests with a bot check. */
  blocked?: boolean;
  /** Pages were found through the stealth browser. */
  stealth?: boolean;
  /** What a remote stealth provider charged for discovery, in USD. */
  stealthCostUsd?: number;
  scope?: {
    onlyRootDomain: boolean;
    includeSubdomains: boolean;
    selectedDomains: string[];
    maxCrawlPages: number;
    maxDepth: number;
    includePaths: string[];
    excludePaths: string[];
  };
}> {
  const start = performance.now();
  const limit = Math.max(1, options.limit ?? 5000);
  const maxCrawlPages = Math.max(
    1,
    options.maxCrawlPages ?? options.maxCrawl ?? 250
  );
  const maxDepth = Math.max(1, options.maxDepth ?? 8);
  const timeoutMs = options.timeoutMs ?? 25_000;
  const bypassCache = Boolean(options.bypassCache);

  const rawSelectedDomains = (options.selectedDomains ?? [])
    .map((d) =>
      d
        .trim()
        .toLowerCase()
        .replace(/^https?:\/\//, "")
        .replace(/\/.*$/, "")
    )
    .filter(Boolean);

  // If `onlyRootDomain: true` is explicitly passed, it overrides `includeSubdomains`
  const includeSubdomains =
    options.onlyRootDomain === true
      ? false
      : Boolean(options.includeSubdomains);
  const onlyRootDomain =
    options.onlyRootDomain ??
    (!includeSubdomains && rawSelectedDomains.length === 0);

  const base = new URL(targetUrl);
  const normalizedTarget = base.toString().replace(/\/$/, "") || base.origin;
  const baseHost = base.hostname.toLowerCase().replace(/^www\./, "");

  const pathScope = buildPathScope(targetUrl, {
    includePaths: options.includePaths,
    excludePaths: options.excludePaths,
    restrictToSubpath: options.restrictToSubpath,
  });

  const scopeSignature = `${normalizedTarget}::${pathScope.signature}::root=${onlyRootDomain}::sub=${includeSubdomains}::sel=${rawSelectedDomains.slice().sort().join(",")}::lim=${limit}::maxCrawl=${maxCrawlPages}::depth=${maxDepth}::sm=${(options.sitemapUrls ?? []).join(",")}`;

  if (!bypassCache) {
    const cached = await getCachedMapAsync(scopeSignature);
    if (cached) {
      return {
        success: true,
        links: cached.links.slice(0, limit),
        latencyMs: Math.round(performance.now() - start),
        source: `${cached.source} (${cached.cacheLayer || "24h"}-cache)`,
        cached: true,
        cacheLayer: cached.cacheLayer || "memory",
        pagesCrawled: cached.pagesCrawled,
        scope: {
          onlyRootDomain,
          includeSubdomains,
          selectedDomains: rawSelectedDomains,
          maxCrawlPages,
          maxDepth,
          includePaths: pathScope.includes,
          excludePaths: pathScope.excludes,
        },
      };
    }
  }

  const allowedHosts = new Set<string>();
  const wildcardSuffixes: string[] = [];

  if (rawSelectedDomains.length > 0) {
    for (const domain of rawSelectedDomains) {
      if (domain.startsWith("*.")) {
        const suffix = domain.slice(2).replace(/^www\./, "");
        if (suffix) {
          wildcardSuffixes.push(suffix);
          allowedHosts.add(suffix);
        }
      } else {
        allowedHosts.add(domain.replace(/^www\./, ""));
      }
    }
  } else {
    allowedHosts.add(baseHost);
  }

  const origin = base.origin;
  const discovered = new Set<string>();

  const isAllowedUrl = (candidate: string): boolean => {
    try {
      const u = new URL(candidate, origin);
      if (u.protocol !== "http:" && u.protocol !== "https:") {
        return false;
      }
      const candHost = u.hostname.toLowerCase().replace(/^www\./, "");

      let hostMatch = allowedHosts.has(candHost);

      if (!hostMatch && wildcardSuffixes.length > 0) {
        for (const suffix of wildcardSuffixes) {
          if (candHost === suffix || candHost.endsWith(`.${suffix}`)) {
            hostMatch = true;
            break;
          }
        }
      }

      if (!hostMatch && includeSubdomains && !onlyRootDomain) {
        for (const h of allowedHosts) {
          if (candHost.endsWith(`.${h}`)) {
            hostMatch = true;
            break;
          }
        }
      }

      if (!hostMatch) {
        return false;
      }
      // Skip binary/static assets
      if (
        /\.(png|jpg|jpeg|gif|svg|webp|ico|pdf|zip|tar|gz|css|js|mjs|map|woff2?|ttf|eot|mp4|mp3|wav|avi|mov|xml|json)$/i.test(
          u.pathname
        )
      ) {
        return false;
      }
      return pathScope.allows(u.toString());
    } catch {
      return false;
    }
  };

  const normalizeUrl = (raw: string, baseUrl = origin): string | null => {
    try {
      const u = new URL(raw, baseUrl);
      u.hash = "";
      // Strip tracking query params (`utm_*`, `ref`, `fbclid`, `gclid`) so BFS doesn't loop on marketing tags
      for (const key of Array.from(u.searchParams.keys())) {
        if (/^(utm_|fbclid|gclid|msclkid|_ga|_gl|ref$)/i.test(key)) {
          u.searchParams.delete(key);
        }
      }
      const normalized = u.toString().replace(/\/$/, "") || origin;
      return isAllowedUrl(normalized) ? normalized : null;
    } catch {
      return null;
    }
  };

  let robots: RobotsRules = parseRobots(null);
  let robotsBlocked = 0;
  const addUrl = (raw: string, baseUrl = origin): string | null => {
    if (discovered.size >= limit) {
      return null;
    }
    const normalized = normalizeUrl(raw, baseUrl);
    if (normalized) {
      if (!robots.allows(normalized)) {
        robotsBlocked++;
        return null;
      }
      discovered.add(normalized);
      return normalized;
    }
    return null;
  };

  addUrl(targetUrl);

  // Race sitemap discovery (root + subpath) + root HTML link discovery in parallel
  const sitemapCandidates = new Set<string>([
    `${origin}/sitemap.xml`,
    `${origin}/sitemap_index.xml`,
    `${origin}/sitemap-index.xml`,
  ]);
  if (base.pathname && base.pathname !== "/") {
    const cleanSubpath = base.pathname.replace(/\/$/, "");
    sitemapCandidates.add(`${origin}${cleanSubpath}/sitemap.xml`);
  }

  // Set when the site answers with a bot check instead of content.
  let blockedByBotCheck = false;
  let sawThrottle = false;
  const fetchTextFast = async (
    url: string,
    maxMs = 4500
  ): Promise<string | null> => {
    try {
      const res = await withRetries(() => fetchWithTlsImpersonation(url, maxMs), { retries: 1 });
      if (res.status === 429 || res.status === 503) sawThrottle = true;
      if (isAntiBotChallenge(res.html, res.status)) {
        blockedByBotCheck = true;
        return null;
      }
      if (res.status < 200 || res.status >= 400) {
        return null;
      }
      return res.html;
    } catch {
      return null;
    }
  };

  const userSitemaps = (options.sitemapUrls ?? []).slice(0, 5);
  const [robotsTxt, rootHtml, defaultSitemapXml, ...userSitemapXmls] = await Promise.all([
    fetchTextFast(`${origin}/robots.txt`, 2500),
    fetchTextFast(targetUrl, 4500),
    fetchTextFast(`${origin}/sitemap.xml`, 4500),
    ...userSitemaps.map((u) => fetchTextFast(u, 6000)),
  ]);

  // Detect canonical domain from `<link rel="canonical" href="...">` only when selectedDomains is not restricting hosts
  if (rootHtml && rawSelectedDomains.length === 0) {
    const canonicalMatch = rootHtml.match(
      /<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']+)["']/i
    );
    if (canonicalMatch?.[1]) {
      try {
        const canonUrl = new URL(canonicalMatch[1], origin);
        const canonHost = canonUrl.hostname.toLowerCase().replace(/^www\./, "");
        if (!onlyRootDomain || canonHost === baseHost) {
          allowedHosts.add(canonHost);
        }
        sitemapCandidates.add(`${canonUrl.origin}/sitemap.xml`);
        sitemapCandidates.add(`${canonUrl.origin}/sitemap-index.xml`);
        sitemapCandidates.add(`${canonUrl.origin}/sitemap_index.xml`);
      } catch {
        // ignore invalid canonical URL
      }
    }
  }

  robots = parseRobots(robotsTxt);
  if (robotsTxt) {
    const matches = robotsTxt.matchAll(/^Sitemap:\s*(.+)$/gim);
    for (const m of matches) {
      const smUrl = m[1].trim();
      if (smUrl) {
        sitemapCandidates.add(smUrl);
      }
    }
  }

  let foundSitemap = false;
  const parseSitemapXml = async (xml: string, depth = 0): Promise<void> => {
    if (depth > 3 || discovered.size >= limit) {
      return;
    }
    const locMatches = Array.from(
      xml.matchAll(/<loc>\s*(?:<!\[CDATA\[)?([^<\]]+?)(?:\]\]>)?\s*<\/loc>/gi)
    );
    const subSitemaps: string[] = [];

    for (const m of locMatches) {
      const loc = decodeHtmlEntities(m[1].trim());
      if (
        loc.endsWith(".xml") ||
        loc.endsWith(".xml.gz") ||
        loc.includes("sitemap")
      ) {
        subSitemaps.push(loc);
      } else {
        addUrl(loc);
      }
      if (discovered.size >= limit) {
        break;
      }
    }

    if (
      subSitemaps.length > 0 &&
      discovered.size < limit &&
      performance.now() - start < timeoutMs * 0.75
    ) {
      const childXmls = await Promise.all(
        subSitemaps.slice(0, 10).map((u) => fetchTextFast(u, 3500))
      );
      for (const childXml of childXmls) {
        if (childXml) {
          await parseSitemapXml(childXml, depth + 1);
        }
      }
    }
  };

  // Sitemaps the caller named come first; they usually list exactly the pages wanted.
  for (const xml of userSitemapXmls) {
    if (xml && xml.includes("<loc>")) {
      foundSitemap = true;
      await parseSitemapXml(xml, 0);
    }
  }
  if (foundSitemap) {
    // Caller's sitemap answered: skip guessing at default locations.
  } else if (defaultSitemapXml && defaultSitemapXml.includes("<loc>")) {
    foundSitemap = true;
    await parseSitemapXml(defaultSitemapXml, 0);
  } else {
    const extraSitemaps = Array.from(sitemapCandidates).filter(
      (u) => u !== `${origin}/sitemap.xml`
    );
    if (extraSitemaps.length > 0) {
      const xmls = await Promise.all(
        extraSitemaps.slice(0, 5).map((u) => fetchTextFast(u, 3500))
      );
      for (const xml of xmls) {
        if (xml && xml.includes("<loc>")) {
          foundSitemap = true;
          await parseSitemapXml(xml, 0);
        }
      }
    }
  }

  // Track BFS queue and visited pages for full-website crawling
  const visited = new Set<string>([normalizedTarget]);
  const bfsQueue: Array<{ url: string; depth: number }> = [];
  let pagesCrawled = 0;

  const ingestHtmlPage = (pageUrl: string, html: string, depth: number) => {
    pagesCrawled++;
    // Warm the 24-hour page scrape cacheopportunistically while crawling!
    const parsed = fastHtmlToMarkdown(html, pageUrl, { retainImages: "all" });
    if (parsed.markdown.length > 0) {
      setCachedPage(pageUrl, "all", {
        title: parsed.title,
        markdown: parsed.markdown,
        links: parsed.links,
        statusCode: 200,
        contentHash: sha256(parsed.markdown),
      });
    }
    const pageLinks = extractLinksFromHtml(html, pageUrl);
    for (const rawLink of pageLinks) {
      const added = addUrl(rawLink, pageUrl);
      if (added && !visited.has(added) && depth + 1 <= maxDepth) {
        visited.add(added);
        bfsQueue.push({ url: added, depth: depth + 1 });
      }
    }
  };

  if (rootHtml) {
    ingestHtmlPage(normalizedTarget, rootHtml, 0);
  }

  // Bot check in the way (e.g. Vercel Security Checkpoint, Cloudflare): pass it
  // once in a real browser and read robots.txt + sitemaps through that session.
  let stealthUsed = false;
  let stealthCostUsd: number | undefined;
  if (blockedByBotCheck && !foundSitemap && options.stealth !== false) {
    const { stealthAvailable, stealthDiscover } = await import("./stealth.js");
    if (await stealthAvailable()) {
      stealthUsed = true;
      const found = await stealthDiscover(targetUrl, {
        budgetMs: Math.max(30_000, options.stealthBudgetMs ?? 75_000),
        sitemapUrls: userSitemaps,
        remote: options.remoteStealth,
      });
      stealthCostUsd = found.providerCostUsd;
      for (const u of found.sitemapPages) addUrl(u);
      if (found.sitemapPages.length > 0) foundSitemap = true;
      const entry = found.entry;
      if (entry?.body && !entry.blocked) {
        // Links from the rendered entry page count when there is no sitemap.
        for (const rawLink of extractLinksFromHtml(entry.body, entry.finalUrl || targetUrl)) {
          addUrl(rawLink, entry.finalUrl || targetUrl);
        }
      }
      console.info("[map] stealth discovery", {
        url: targetUrl,
        solved: found.solved,
        sitemapsRead: found.sitemapsRead.length,
        sitemapPages: found.sitemapPages.length,
        discovered: discovered.size,
        durationMs: found.durationMs,
        error: found.error,
      });
    }
  }

  // If sitemap is missing and static HTML on root page found < 2 internal links (e.g. client-rendered SPA or WAF),
  // escalate the root page to @vercel/sandbox / headless browser to hydrate the DOM links!
  // Skipped after stealth ran: it already tried a real browser on this site.
  if (!foundSitemap && discovered.size <= 2 && !stealthUsed) {
    const escalated = await escalateToSandboxOrBrowser(targetUrl, {
      retainImages: "all",
      timeoutMs: Math.min(12_000, timeoutMs),
    });
    if (escalated && escalated.links.length > 0 && !isAntiBotChallenge(escalated.html, 200)) {
      pagesCrawled++;
      setCachedPage(normalizedTarget, "all", {
        title: escalated.title,
        markdown: escalated.markdown,
        links: escalated.links,
        statusCode: escalated.statusCode,
        contentHash: sha256(escalated.markdown),
      });
      for (const rawLink of escalated.links) {
        const added = addUrl(rawLink, normalizedTarget);
        if (added && !visited.has(added)) {
          visited.add(added);
          bfsQueue.push({ url: added, depth: 1 });
        }
      }
    }
  }

  // Multi-hop concurrent BFS crawl across the website when sitemap is missing (or yielded < 15 links)
  const concurrency = new AdaptiveConcurrency(1, 12, 6);
  if (!foundSitemap || discovered.size < 15) {
    while (
      bfsQueue.length > 0 &&
      discovered.size < limit &&
      pagesCrawled < maxCrawlPages &&
      performance.now() - start < timeoutMs * 0.88
    ) {
      const remainingCrawlBudget = Math.max(0, maxCrawlPages - pagesCrawled);
      if (remainingCrawlBudget === 0) {
        break;
      }
      const wave = bfsQueue.splice(
        0,
        Math.min(concurrency.current, remainingCrawlBudget)
      );
      sawThrottle = false;
      const htmlResults = await Promise.all(
        wave.map(async (item) => {
          // Check if page is already in L1/L2/L3 Postgres 24-hour cache
          const cachedPage = await getCachedPageAsync(item.url, "all");
          if (cachedPage && cachedPage.links.length > 0) {
            return { item, cachedLinks: cachedPage.links, html: null };
          }
          const html = await fetchTextFast(item.url, 3200);
          return { item, cachedLinks: null, html };
        })
      );

      concurrency.record({
        ok: htmlResults.filter((r) => r.cachedLinks || r.html).length,
        failed: htmlResults.filter((r) => !r.cachedLinks && !r.html).length,
        throttled: sawThrottle,
      });
      if (robots.crawlDelayMs > 0 || sawThrottle) {
        await sleep(Math.min(robots.crawlDelayMs || 1000, 3000));
      }

      for (const { item, cachedLinks, html } of htmlResults) {
        if (discovered.size >= limit || pagesCrawled >= maxCrawlPages) {
          break;
        }
        if (cachedLinks) {
          pagesCrawled++;
          for (const rawLink of cachedLinks) {
            const added = addUrl(rawLink, item.url);
            if (added && !visited.has(added) && item.depth + 1 <= maxDepth) {
              visited.add(added);
              bfsQueue.push({ url: added, depth: item.depth + 1 });
            }
          }
        } else if (html) {
          ingestHtmlPage(item.url, html, item.depth);
        }
      }
    }
  }

  const finalLinks = Array.from(discovered).slice(0, limit);
  const source = `${foundSitemap ? "sitemap+html" : "bfs-full-crawl"}${stealthUsed ? "+stealth" : ""}`;

  // A blocked map that found nothing is not cached, so the next run tries again.
  if (finalLinks.length > 1 || (pagesCrawled > 0 && !blockedByBotCheck)) {
    setCachedMap(scopeSignature, {
      links: finalLinks,
      source,
      pagesCrawled,
    });
  }

  return {
    success: true,
    links: finalLinks,
    latencyMs: Math.round(performance.now() - start),
    source,
    cached: false,
    pagesCrawled,
    blocked: blockedByBotCheck,
    stealth: stealthUsed,
    ...(stealthCostUsd !== undefined ? { stealthCostUsd } : {}),
    scope: {
      onlyRootDomain,
      includeSubdomains,
      selectedDomains: rawSelectedDomains,
      maxCrawlPages,
      maxDepth,
      includePaths: pathScope.includes,
      excludePaths: pathScope.excludes,
    },
  };
}

/**
 * Ultra-fast HTTP status batch check for `websiteDeletedPages.ts`.
 * Checks if URLs return 404/410 without downloading/rendering full markdown!
 */
export async function checkUrlsStatusBatch(
  urls: string[],
  timeoutMs = 8000
): Promise<Array<{ url: string; statusCode: number; ok: boolean }>> {
  return Promise.all(
    urls.map(async (url) => {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        const hop = (method: "HEAD" | "GET") => (hopUrl: string) =>
          fetch(hopUrl, {
            method,
            headers: getBrowserHeaders(hopUrl),
            redirect: "manual",
            signal: controller.signal,
          }).then((r) => ({
            status: r.status,
            headers: { location: r.headers.get("location") ?? "" } as Record<string, string>,
            ok: r.ok,
            body: r.body,
          }));
        // Try HEAD first, fallback to GET if 405/403; every redirect hop is SSRF-checked
        let { res } = await followSafely(url, hop("HEAD"));
        if (res.status === 405 || res.status === 403) {
          ({ res } = await followSafely(url, hop("GET")));
          await res.body?.cancel().catch(() => undefined);
        }
        clearTimeout(timer);
        return {
          url,
          statusCode: res.status,
          ok: res.ok,
        };
      } catch {
        return {
          url,
          statusCode: 0,
          ok: false,
        };
      }
    })
  );
}

/**
 * Extracts structured JSON from a URL.
 * Honours `prompt` / `schema` when provided; otherwise falls back to
 * `{ app_name, product_features }` from title and headings.
 */
export async function extractWebsiteData(
  url: string,
  options: {
    prompt?: string;
    schema?: Record<string, unknown>;
    openaiApiKey?: string;
    bypassCache?: boolean;
    /** Already-extracted content (e.g. a parsed PDF); skips the HTML fetch and cache. */
    markdown?: string;
    /** Source HTML when the caller already fetched the page (quote cards, JSON-LD). */
    html?: string;
  } = {}
): Promise<Record<string, unknown> & {
  cached?: boolean;
  cacheLayer?: "memory" | "disk" | "postgres" | "miss";
}> {
  const custom = hasCustomExtractRequest(options.prompt, options.schema);
  if (!custom && !options.bypassCache && !options.markdown) {
    const cachedPage = await getCachedPageAsync(url, "all");
    if (
      cachedPage?.structuredData &&
      typeof cachedPage.structuredData.app_name === "string" &&
      Array.isArray(cachedPage.structuredData.product_features)
    ) {
      return {
        app_name: cachedPage.structuredData.app_name,
        product_features: cachedPage.structuredData.product_features.map(String),
        cached: true,
        cacheLayer: cachedPage.cacheLayer || "postgres",
      };
    }
  }

  let title = "";
  let markdown = "";
  let html = options.html ?? "";
  let links: string[] = [];
  const existingPage = !options.bypassCache && !options.markdown
    ? await getCachedPageAsync(url, "all")
    : undefined;

  if (options.markdown) {
    markdown = options.markdown;
    title = url.split("/").pop() || url;
  } else if (existingPage && existingPage.markdown.length > 0) {
    title = existingPage.title;
    markdown = existingPage.markdown;
    links = existingPage.links;
  } else {
    const { res } = await followSafely(url, (hopUrl) =>
      fetch(hopUrl, {
        headers: getBrowserHeaders(hopUrl),
        redirect: "manual",
        signal: AbortSignal.timeout(8000),
      }).then((r) => ({
        status: r.status,
        headers: { location: r.headers.get("location") ?? "" } as Record<string, string>,
        text: () => r.text(),
      }))
    );
    html = await res.text();
    const parsed = fastHtmlToMarkdown(html, url);
    title = parsed.title;
    markdown = parsed.markdown;
    links = parsed.links;
  }

  const cacheMeta = () => ({
    cached: Boolean(existingPage),
    cacheLayer: existingPage?.cacheLayer || ("miss" as const),
  });

  // If OPENAI_API_KEY is available, use gpt-4o-mini for structured JSON extraction
  const apiKey = options.openaiApiKey || process.env.OPENAI_API_KEY;
  if (apiKey) {
    try {
      const schemaHint = options.schema
        ? `Return a JSON object matching this JSON Schema:\n${JSON.stringify(options.schema)}`
        : options.prompt
          ? `Return JSON that satisfies this request: ${options.prompt}`
          : 'Extract the application/website name and a list of key product features as JSON: {"app_name": string, "product_features": string[]}.';
      const llmRes = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          model: "gpt-4o-mini",
          response_format: { type: "json_object" },
          messages: [
            {
              role: "system",
              content: schemaHint,
            },
            {
              role: "user",
              content: `${options.prompt ? `${options.prompt}\n\n` : ""}URL: ${url}\nTitle: ${title}\n\nContent:\n${markdown.slice(0, 12000)}`,
            },
          ],
          temperature: 0,
        }),
        signal: AbortSignal.timeout(10000),
      });
      if (llmRes.ok) {
        const json = (await llmRes.json()) as {
          choices?: Array<{ message?: { content?: string } }>;
        };
        const content = json.choices?.[0]?.message?.content;
        if (content) {
          const parsed = JSON.parse(content) as Record<string, unknown>;
          const usable = custom
            ? parsed && typeof parsed === "object" && !Array.isArray(parsed)
            : Boolean(parsed.app_name && Array.isArray(parsed.product_features));
          if (usable) {
            const structuredResult = custom
              ? parsed
              : {
                  app_name: String(parsed.app_name),
                  product_features: (parsed.product_features as unknown[]).map(String),
                };
            setCachedPage(url, "all", {
              title,
              markdown,
              links,
              structuredData: structuredResult,
              statusCode: 200,
              contentHash: sha256(markdown),
            });
            return { ...structuredResult, ...cacheMeta() };
          }
        }
      }
    } catch {
      // Fall through to deterministic heuristic extraction
    }
  }

  if (custom) {
    const shaped = extractByPromptAndSchema(html, markdown, options.prompt, options.schema);
    if (shaped) {
      setCachedPage(url, "all", {
        title,
        markdown,
        links,
        structuredData: shaped,
        statusCode: 200,
        contentHash: sha256(markdown),
      });
      return { ...shaped, ...cacheMeta() };
    }
    // Honour the caller's schema/prompt: never substitute the generic
    // `{ app_name, product_features }` object when they asked for something else.
    return { ...cacheMeta() };
  }

  // Deterministic fast extraction from Title, Meta Description, and H2/H3/List headings (<5ms)
  const cleanAppName =
    title.split(/\s+[-|\u2014–:]\s+/)[0]?.trim() ||
    new URL(url).hostname.replace(/^www\./, "").split(".")[0];

  const features = new Set<string>();
  const headingMatches = markdown.matchAll(/^#{2,3}\s+([^\n]+)/gm);
  for (const m of headingMatches) {
    const h = m[1].replace(/\[([^\]]+)\]\([^)]+\)/g, "$1").trim();
    if (
      h.length > 4 &&
      h.length < 90 &&
      !/^(cookie|privacy|terms|contact|sign in|login|faq)/i.test(h)
    ) {
      features.add(h);
    }
    if (features.size >= 10) {
      break;
    }
  }

  if (features.size < 3) {
    const bulletMatches = markdown.matchAll(/^- ([^\n]+)/gm);
    for (const m of bulletMatches) {
      const b = m[1].replace(/\[([^\]]+)\]\([^)]+\)/g, "$1").trim();
      if (b.length > 8 && b.length < 100) {
        features.add(b);
      }
      if (features.size >= 8) {
        break;
      }
    }
  }

  const structuredResult = {
    app_name: cleanAppName,
    product_features:
      features.size > 0
        ? Array.from(features)
        : [`${cleanAppName} core platform`, "Documentation & Knowledge Base"],
  };

  setCachedPage(url, "all", {
    title,
    markdown,
    links,
    structuredData: structuredResult,
    statusCode: 200,
    contentHash: sha256(markdown),
  });

  return {
    ...structuredResult,
    ...cacheMeta(),
  };
}

/**
 * Full-website multi-page crawler (`POST /v1/crawl`) backed by the shared 3-tier
 * L1 Memory -> L2 Disk -> L3 Postgres URL store (`crawled_pages`).
 * Pages already stored in Postgres for this website are served directly without re-crawling!
 */
export async function crawlWebsitePages(
  targetUrl: string,
  options: {
    maxPages?: number;
    includeSubdomains?: boolean;
    onlyRootDomain?: boolean;
    bypassCache?: boolean;
    extractStructured?: boolean;
    timeoutMs?: number;
  } = {}
): Promise<{
  success: boolean;
  rootUrl: string;
  pagesCount: number;
  cachedPagesCount: number;
  postgresHits: number;
  latencyMs: number;
  pages: CrawledPage[];
}> {
  const start = performance.now();
  const maxPages = Math.min(25, Math.max(1, options.maxPages ?? 5));
  const bypassCache = Boolean(options.bypassCache);
  const timeoutMs = options.timeoutMs ?? 20_000;

  const mapRes = await mapWebsiteUrls(targetUrl, {
    limit: Math.max(maxPages * 3, 25),
    maxCrawlPages: maxPages,
    includeSubdomains: options.includeSubdomains,
    onlyRootDomain: options.onlyRootDomain,
    bypassCache,
    timeoutMs: Math.min(12_000, timeoutMs),
    // Sync crawl: the durable workflow handles stealth; this path must stay fast.
    stealth: false,
  });

  const targetLinks = mapRes.links.slice(0, maxPages);
  if (targetLinks.length === 0) {
    targetLinks.push(targetUrl);
  }

  let cachedPagesCount = 0;
  let postgresHits = 0;

  const pages = await Promise.all(
    targetLinks.map(async (pageUrl) => {
      const page = await crawlPage(pageUrl, {
        bypassCache,
        extractStructured: options.extractStructured,
      });
      if (page.cached) {
        cachedPagesCount += 1;
        if (page.cacheLayer === "postgres") postgresHits += 1;
      }
      return page;
    })
  );

  return {
    success: true,
    rootUrl: targetUrl,
    pagesCount: pages.length,
    cachedPagesCount,
    postgresHits,
    latencyMs: Math.round(performance.now() - start),
    pages,
  };
}

export interface CrawledPage {
  url: string;
  title: string;
  markdown: string;
  linksCount: number;
  cached: boolean;
  cacheLayer: "memory" | "disk" | "postgres" | "miss";
  structuredData?: Record<string, unknown> | null;
  statusCode?: number;
  error?: string;
  /** The site served a bot check instead of this page. */
  blocked?: boolean;
  /** Read through the stealth browser. */
  stealth?: boolean;
  /** Remote provider that hosted the stealth browser (billed with a surcharge). */
  stealthProvider?: string;
}

/** True for markdown converted from a bot-check page (old cache entries). */
export function isChallengeMarkdown(title: string, markdown: string): boolean {
  if (/blocked by network security/i.test(`${title}\n${markdown}`)) {
    return true;
  }
  const t = `${title}\n${markdown.slice(0, 600)}`.toLowerCase();
  return (
    t.includes("vercel security checkpoint") ||
    t.includes("we're verifying your browser") ||
    t.includes("just a moment...") ||
    t.includes("attention required! | cloudflare") ||
    t.includes("checking your browser before accessing")
  );
}

/**
 * Re-reads blocked pages through one stealth browser session. Pages that come
 * back clean are cached and returned as content; pages still blocked keep
 * `blocked: true` and an honest error.
 */
export async function crawlPagesStealth(
  entryUrl: string,
  urls: string[],
  options: { extractStructured?: boolean; budgetMs?: number; remote?: boolean } = {}
): Promise<{ pages: CrawledPage[]; solved: boolean; durationMs: number; error?: string; provider?: string; providerCostUsd?: number }> {
  const { stealthFetch } = await import("./stealth.js");
  const res = await stealthFetch(
    entryUrl,
    urls.map((url) => ({ url })),
    { budgetMs: options.budgetMs ?? 120_000, remote: options.remote }
  );
  const byUrl = new Map(res.docs.map((d) => [d.url, d]));
  const pages = urls.map((url): CrawledPage => {
    const doc = byUrl.get(url);
    const fail = (error: string, blocked = true): CrawledPage => ({
      url,
      title: url,
      markdown: "",
      linksCount: 0,
      cached: false,
      cacheLayer: "miss",
      structuredData: null,
      statusCode: doc?.status ?? undefined,
      blocked,
      stealth: true,
      error,
    });
    if (!doc) return fail(res.error ? `Stealth mode failed: ${res.error}` : "Stealth mode did not reach this page");
    if (!doc.ok) return fail(doc.error || "Stealth mode could not open this page");
    if (doc.blocked || isAntiBotChallenge(doc.body ?? "", doc.status ?? 200)) {
      return fail("Still blocked by the site's bot check in stealth mode");
    }
    const parsed = fastHtmlToMarkdown(doc.body ?? "", doc.finalUrl || url, { retainImages: "all" });
    if (parsed.markdown.length === 0) return fail(`Empty page (HTTP ${doc.status ?? "?"})`, false);
    const title = parsed.title || doc.title || url;
    let structuredData: Record<string, unknown> | null = null;
    if (options.extractStructured) {
      const headings = Array.from(parsed.markdown.matchAll(/^#{1,3}\s+([^\n]+)/gm))
        .map((m) => m[1].trim())
        .slice(0, 8);
      structuredData = { title, headings, wordCount: parsed.markdown.split(/\s+/).filter(Boolean).length };
    }
    setCachedPage(url, "all", {
      title,
      markdown: parsed.markdown,
      links: parsed.links,
      structuredData,
      statusCode: doc.status ?? 200,
      contentHash: sha256(parsed.markdown),
    });
    return {
      url,
      title,
      markdown: parsed.markdown,
      linksCount: parsed.links.length,
      cached: false,
      cacheLayer: "miss",
      structuredData,
      statusCode: doc.status ?? 200,
      stealth: true,
      ...(res.provider ? { stealthProvider: res.provider } : {}),
    };
  });
  return {
    pages,
    solved: res.solved,
    durationMs: res.durationMs,
    ...(res.error ? { error: res.error } : {}),
    ...(res.provider ? { provider: res.provider } : {}),
    ...(res.providerCostUsd !== undefined ? { providerCostUsd: res.providerCostUsd } : {}),
  };
}

/**
 * Fetches one page for a crawl: cache first (unless bypassed), then a
 * TLS-impersonated fetch. Never throws; failures come back with `error`.
 * Used by `crawlWebsitePages` and by the durable crawl workflow (one call per page).
 */
export async function crawlPage(
  pageUrl: string,
  options: { bypassCache?: boolean; extractStructured?: boolean; timeoutMs?: number } = {}
): Promise<CrawledPage> {
  if (!options.bypassCache) {
    const cached = await getCachedPageAsync(pageUrl, "all");
    // Older entries may hold a bot-check page; treat those as a miss.
    if (cached && cached.markdown.length > 0 && !isChallengeMarkdown(cached.title, cached.markdown)) {
      return {
        url: pageUrl,
        title: cached.title,
        markdown: cached.markdown,
        linksCount: cached.links.length,
        cached: true,
        cacheLayer: cached.cacheLayer || "postgres",
        structuredData: cached.structuredData ?? null,
      };
    }
  }

  try {
    const { looksLikeBinaryUrl, fetchAndParse } = await import("../parse/fetch.js");
    if (looksLikeBinaryUrl(pageUrl)) {
      const file = await fetchAndParse(pageUrl, {
        timeoutMs: Math.max(options.timeoutMs ?? 6000, 30_000),
        bypassCache: options.bypassCache,
        // Crawls are bulk: keep OCR bounded per file.
        maxOcrPages: 20,
      });
      if (file) {
        const { result } = file;
        return {
          url: pageUrl,
          title: result.title || pageUrl,
          markdown: result.markdown,
          linksCount: 0,
          cached: result.cached,
          cacheLayer: result.cacheLayer,
          structuredData: { parse: { ...result.meta, contentHash: result.contentHash } },
          statusCode: file.resource.status,
          ...(result.markdown.length === 0
            ? { error: result.meta.warnings[0] || "No content extracted from file" }
            : {}),
        };
      }
    }
    const fetched = await fetchWithTlsImpersonation(pageUrl, options.timeoutMs ?? 6000);
    if (isAntiBotChallenge(fetched.html, fetched.status)) {
      // Never return, cache or bill the bot-check page as content.
      return {
        url: pageUrl,
        title: pageUrl,
        markdown: "",
        linksCount: 0,
        cached: false,
        cacheLayer: "miss",
        structuredData: null,
        statusCode: fetched.status,
        blocked: true,
        error: `Blocked by the site's bot check (HTTP ${fetched.status})`,
      };
    }
    const parsed = fastHtmlToMarkdown(fetched.html, pageUrl, { retainImages: "all" });
    let structuredData: Record<string, unknown> | null = null;
    if (options.extractStructured) {
      const headings = Array.from(parsed.markdown.matchAll(/^#{1,3}\s+([^\n]+)/gm))
        .map((m) => m[1].trim())
        .slice(0, 8);
      structuredData = {
        title: parsed.title,
        headings,
        wordCount: parsed.markdown.split(/\s+/).filter(Boolean).length,
      };
    }
    if (parsed.markdown.length > 0) {
      setCachedPage(pageUrl, "all", {
        title: parsed.title,
        markdown: parsed.markdown,
        links: parsed.links,
        structuredData,
        statusCode: fetched.status,
        contentHash: sha256(parsed.markdown),
      });
    }
    return {
      url: pageUrl,
      title: parsed.title,
      markdown: parsed.markdown,
      linksCount: parsed.links.length,
      cached: false,
      cacheLayer: "miss",
      structuredData,
      statusCode: fetched.status,
      ...(parsed.markdown.length === 0 ? { error: `Empty page (HTTP ${fetched.status})` } : {}),
    };
  } catch (err) {
    return {
      url: pageUrl,
      title: pageUrl,
      markdown: "",
      linksCount: 0,
      cached: false,
      cacheLayer: "miss",
      structuredData: null,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}
