import {
  decodeHtmlEntities,
  fetchWithTlsImpersonation,
} from "../engine/index.js";
import {
  cveSeverityLabel,
  extractCveIdsFromText,
  extractDomainHost,
  extractGhsaIdsFromText,
  extractOfferFromSerpSnippet,
  parseBingShoppingHtml,
  parseNvdResponse,
  parseOsvVuln,
  parsePriceString,
  type CveRecord,
  type ProductOffer,
} from "../extract/index.js";
import {
  CVE_STORE_SINCE,
  getCachedCves,
  getCachedQuery,
  refreshStaleCves,
  rememberQuery,
  searchCachedCves,
} from "../extract/cve-cache.js";
import type {
  RawCandidateDocument,
  SearchEngineSource,
  UserLocationContext,
} from "../ranker/index.js";
import {
  ddgRegion,
  planEngines,
  resolveCategory,
  type SearchRequest,
} from "./catalog.js";

/**
 * Wikipedia only helps for entity / definition queries ("retrieval augmented
 * generation", "what is rag"). For intent queries ("best X under 500",
 * "A vs B", "how to ...") it injects off-topic pages (songs, unrelated topics).
 */
export function isEntityQuery(q: string): boolean {
  const t = q.trim().toLowerCase();
  if (/^(what is|what are|who is|who was|define|meaning of)\b/.test(t)) {
    return true;
  }
  if (
    /\b(how|why|best|top|vs|versus|cheap|cheapest|review|reviews|price|pricing|near|latest|this week|today|buy|under|over|to)\b|\d/.test(
      t
    )
  ) {
    return false;
  }
  return t.split(/\s+/).filter(Boolean).length <= 4;
}

/**
 * Stage 1: Hedged Multi-Engine Native Federation with Early-Exit Quorum.
 * Fires all native zero-key search engines concurrently and exits as soon as a fast
 * quorum (at least 2 engines + >= limit results + 80ms grace window) finishes,
 * preventing any single slow engine from inflating tail latency.
 */
export async function fetchHedgedNativeFederation(
  rawQuery: string,
  localizedQuery: string,
  perEngineLimit: number,
  req: SearchRequest,
  userLocation: UserLocationContext,
  quorumTimeoutMs: number,
  targetSites: string[],
  onOffer: (offer: ProductOffer) => void,
  onCve?: (cve: CveRecord) => void
): Promise<RawCandidateDocument[]> {
  if (req.provider && req.provider !== "auto") {
    const q =
      targetSites.length > 0 && targetSites.length <= 3
        ? `${localizedQuery} ${targetSites.map((h) => `site:${h}`).join(" OR ")}`
        : localizedQuery;
    switch (req.provider) {
      case "jina":
        return fetchJinaSearch(q, perEngineLimit, req);
      case "serper":
        return fetchSerperApi(q, perEngineLimit, req);
      case "brave":
        return fetchBraveSearchApi(q, perEngineLimit);
      case "ddg":
        return fetchDuckDuckGoLiteOnly(q, perEngineLimit, userLocation);
    }
  }

  const collected: RawCandidateDocument[] = [];
  let completedPrimaryEngines = 0;
  let totalCompletedEngines = 0;

  const category = resolveCategory(req);
  const plan = planEngines(category, req.filters).filter(
    (e) =>
      e !== "wikipedia" ||
      req.filters?.engines?.includes("wikipedia") ||
      isEntityQuery(rawQuery)
  );
  let completedShoppingEngine = !plan.includes("bing-shopping");
  // News: the quorum must include the actual news engine, not just general web results.
  let completedNewsEngine = !(category === "news" && plan.includes("google-news-rss"));
  if (!completedNewsEngine) {
    quorumTimeoutMs = Math.max(quorumTimeoutMs, 4200);
  }
  // Security: structured CVE records come from NVD (~1.2s per request, two for keyword
  // searches), so the quorum waits for it instead of exiting on web results alone.
  let completedNvdEngine = !plan.includes("nvd");
  if (!completedNvdEngine) {
    quorumTimeoutMs = Math.max(quorumTimeoutMs, 9000);
  }
  // Academic: wait for the ArXiv + OpenAlex scholarly paper APIs before exiting quorum.
  let completedArxivEngine = !(category === "academic" && plan.includes("arxiv"));
  if (!completedArxivEngine) {
    quorumTimeoutMs = Math.max(quorumTimeoutMs, 4500);
  }
  const siteHintQuery =
    targetSites.length > 0 && targetSites.length <= 3
      ? `${localizedQuery} ${targetSites.join(" ")}`
      : localizedQuery;

  const factories: Partial<
    Record<
      SearchEngineSource,
      { primary: boolean; run: () => Promise<RawCandidateDocument[]> }
    >
  > = {
    "bing-shopping": {
      primary: true,
      run: () =>
        fetchBingShoppingNative(
          rawQuery,
          perEngineLimit,
          userLocation,
          targetSites,
          onOffer
        ),
    },
    "google-shopping": {
      primary: true,
      run: () =>
        fetchGoogleShoppingProvider(
          rawQuery,
          localizedQuery,
          perEngineLimit,
          userLocation,
          targetSites,
          onOffer
        ),
    },
    "brave-native": {
      primary: true,
      run: () =>
        fetchBraveNativeSerp(siteHintQuery, perEngineLimit, userLocation),
    },
    "ddg-lite": {
      primary: true,
      run: () =>
        fetchDuckDuckGoLiteOnly(siteHintQuery, perEngineLimit, userLocation),
    },
    "google-news-rss": {
      primary: category === "news",
      run: () =>
        fetchGoogleNewsSearchRss(
          localizedQuery,
          Math.min(perEngineLimit, category === "shopping" ? 4 : 10),
          userLocation,
          req.lang,
          category === "news" ? 4000 : 2000
        ),
    },
    wikipedia: {
      primary: false,
      run: () => fetchWikipediaOpenSearch(localizedQuery, Math.min(perEngineLimit, 5)),
    },
    "hn-algolia": {
      primary: false,
      run: () => fetchHackerNewsAlgolia(localizedQuery, perEngineLimit),
    },
    "bing-rss": {
      primary: false,
      run: () => fetchBingWebRss(localizedQuery, perEngineLimit),
    },
    arxiv: {
      primary: category === "academic",
      run: () => fetchArxivApi(rawQuery, Math.max(perEngineLimit, 8)),
    },
    // Vulnerability databases use the raw query: localisation hints ("in Australia") break id/keyword lookups.
    nvd: { primary: true, run: () => fetchNvdApi(rawQuery, perEngineLimit, onCve) },
    osv: { primary: false, run: () => fetchOsvApi(rawQuery, perEngineLimit, onCve) },
  };
  const tasks: Array<{
    name: SearchEngineSource;
    primary: boolean;
    promise: Promise<RawCandidateDocument[]>;
  }> = [];
  const timed = (
    name: string,
    p: Promise<RawCandidateDocument[]>
  ): Promise<RawCandidateDocument[]> => {
    if (!process.env.DEBUG_SEARCH_TIMING) {
      return p;
    }
    const t0 = performance.now();
    return p.then(
      (r) => {
        console.log(`[timing] engine=${name} ms=${Math.round(performance.now() - t0)} n=${r.length}`);
        return r;
      },
      (e) => {
        console.log(`[timing] engine=${name} ms=${Math.round(performance.now() - t0)} ERR=${String(e?.message ?? e).slice(0, 80)}`);
        throw e;
      }
    );
  };
  for (const name of plan) {
    const f = factories[name];
    if (f) {
      tasks.push({ name, primary: f.primary, promise: timed(name, f.run()) });
    }
  }

  if (process.env.SERPER_API_KEY) {
    tasks.push({
      name: "serper",
      primary: true,
      promise: timed("serper", fetchSerperApi(localizedQuery, perEngineLimit, req)),
    });
  }

  if (process.env.BRAVE_SEARCH_API_KEY) {
    tasks.push({
      name: "brave-api",
      primary: true,
      promise: timed("brave-api", fetchBraveSearchApi(localizedQuery, perEngineLimit)),
    });
  }

  await new Promise<void>((resolve) => {
    let settled = false;
    let graceTimer: ReturnType<typeof setTimeout> | null = null;
    const hardTimer = setTimeout(() => {
      if (!settled) {
        settled = true;
        resolve();
      }
    }, quorumTimeoutMs);

    const checkQuorum = () => {
      if (settled) {
        return;
      }
      if (totalCompletedEngines >= tasks.length) {
        settled = true;
        clearTimeout(hardTimer);
        if (graceTimer) {
          clearTimeout(graceTimer);
        }
        resolve();
        return;
      }
      const uniqueCount = new Set(collected.map((c) => canonicalSearchUrl(c.url)).filter(Boolean)).size;
      const fillTarget = Math.max(1, req.limit ?? 5);
      // Early-exit quorum: at least 1 primary web engine + 2 total engines + enough
      // *unique* URLs to fill `limit` (not just Wikipedia's 2 hits).
      if (
        completedShoppingEngine &&
        completedNewsEngine &&
        completedNvdEngine &&
        completedArxivEngine &&
        completedPrimaryEngines >= 1 &&
        totalCompletedEngines >= 2 &&
        uniqueCount >= fillTarget &&
        !graceTimer
      ) {
        graceTimer = setTimeout(() => {
          if (!settled) {
            settled = true;
            clearTimeout(hardTimer);
            resolve();
          }
        }, 90);
      }
    };

    for (const task of tasks) {
      task.promise
        .then((items) => {
          if (items.length > 0) {
            collected.push(...items);
            if (task.primary) {
              completedPrimaryEngines++;
            }
          }
        })
        .catch(() => {
          // ignore engine error
        })
        .finally(() => {
          if (task.name === "bing-shopping") {
            completedShoppingEngine = true;
          }
          if (task.name === "google-news-rss") {
            completedNewsEngine = true;
          }
          if (task.name === "nvd") {
            completedNvdEngine = true;
          }
          if (task.name === "arxiv") {
            completedArxivEngine = true;
          }
          totalCompletedEngines++;
          checkQuorum();
        });
    }
  });

  // Fallback: the free engines are scraped and can be blocked or rate limited. When they
  // come back thin, fill in from a keyed search provider so the caller still gets an answer.
  const uniqueUrls = new Set(collected.map((c) => c.url).filter(Boolean));
  if (uniqueUrls.size < JINA_FALLBACK_MIN_URLS && process.env.JINA_API_KEY) {
    const t0 = performance.now();
    const jina = await fetchJinaSearch(localizedQuery, perEngineLimit, req);
    if (process.env.DEBUG_SEARCH_TIMING) {
      console.log(`[timing] engine=jina(fallback) ms=${Math.round(performance.now() - t0)} n=${jina.length}`);
    }
    collected.push(...jina);
  }

  // HTML SERPs (DDG, Brave) are frequently challenge/429 pages. When they
  // yield nothing *or come back thinner than `limit`*, fill from keyless APIs
  // (Wikipedia, HN Algolia, Bing RSS, DDG Instant Answer) with retry/backoff.
  const fillTarget = Math.max(1, req.limit ?? 5);
  const uniqueAfter = new Set(collected.map((c) => canonicalSearchUrl(c.url)).filter(Boolean));
  if (uniqueAfter.size < fillTarget && (!req.provider || req.provider === "auto")) {
    const extras = await fetchKeylessSearchFallbacks(localizedQuery, Math.max(fillTarget, perEngineLimit));
    collected.push(...extras);
  }

  return collected;
}

/** Below this many unique URLs from the free engines, the keyed search fallback runs. */
export const JINA_FALLBACK_MIN_URLS = 3;

/** True when a scraped SERP is a bot-check / captcha rather than results. */
export function isSerpChallengeHtml(html: string, status = 200): boolean {
  if (status === 403 || status === 429 || status === 503) return true;
  const lower = String(html ?? "").slice(0, 8000).toLowerCase();
  return (
    lower.includes("bots use duckduckgo") ||
    lower.includes("anomaly-modal") ||
    lower.includes("please complete the following challenge") ||
    lower.includes("schedule a captcha") ||
    lower.includes("flagged as being suspicious") ||
    lower.includes("enable javascript to function")
  );
}

export const EMPTY_SEARCH_ERROR =
  "Keyless search engines returned no results (DuckDuckGo and Brave often serve a bot challenge). " +
  "Tried Wikipedia, Hacker News, Bing RSS, and DuckDuckGo Instant Answer as well. " +
  "Set BRAVE_SEARCH_API_KEY, SERPER_API_KEY, or JINA_API_KEY, or retry later.";

/** Canonical URL for search dedupe (host lowercased, trailing slash / tracking params stripped). */
export function canonicalSearchUrl(raw: string | undefined): string {
  if (!raw) return "";
  try {
    const u = new URL(raw);
    u.hash = "";
    u.hostname = u.hostname.toLowerCase();
    for (const key of [...u.searchParams.keys()]) {
      if (/^(utm_|ref|fbclid|gclid|mc_)/i.test(key)) u.searchParams.delete(key);
    }
    let path = u.pathname.replace(/\/+$/, "") || "/";
    u.pathname = path;
    return u.toString();
  } catch {
    return raw.replace(/\/+$/, "").toLowerCase();
  }
}

/** Round-robin merge so one source (e.g. Wikipedia) cannot fill `-n` by itself. */
export function mergeSearchCandidates(
  groups: RawCandidateDocument[][],
  limit: number
): RawCandidateDocument[] {
  const seen = new Set<string>();
  const out: RawCandidateDocument[] = [];
  const queues = groups.map((g) => [...g]);
  let progressed = true;
  while (out.length < limit && progressed) {
    progressed = false;
    for (const q of queues) {
      while (q.length > 0) {
        const item = q.shift()!;
        const key = canonicalSearchUrl(item.url);
        if (!key || seen.has(key)) continue;
        seen.add(key);
        out.push(item);
        progressed = true;
        break;
      }
      if (out.length >= limit) break;
    }
  }
  return out;
}

export async function withRetry<T>(
  fn: () => Promise<T>,
  opts: { retries?: number; delayMs?: number; isEmpty?: (v: T) => boolean } = {}
): Promise<T> {
  const retries = opts.retries ?? 1;
  const delayMs = opts.delayMs ?? 250;
  const isEmpty = opts.isEmpty ?? ((v: T) => (Array.isArray(v) ? v.length === 0 : !v));
  let last = await fn();
  for (let i = 0; i < retries && isEmpty(last); i++) {
    await new Promise((r) => setTimeout(r, delayMs * (i + 1)));
    last = await fn();
  }
  return last;
}

/** Parse Bing's `format=rss` web-search feed into candidate docs. */
export function parseBingWebRss(xml: string, limit: number): RawCandidateDocument[] {
  const items: RawCandidateDocument[] = [];
  const itemRe = /<item>([\s\S]*?)<\/item>/gi;
  let match: RegExpExecArray | null;
  while ((match = itemRe.exec(xml)) !== null && items.length < limit) {
    const block = match[1];
    const title = decodeHtmlEntities(
      (block.match(/<title>([\s\S]*?)<\/title>/i)?.[1] || "")
        .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
        .trim()
    );
    const link = (block.match(/<link>([\s\S]*?)<\/link>/i)?.[1] || "")
      .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
      .trim();
    const description = decodeHtmlEntities(
      (block.match(/<description>([\s\S]*?)<\/description>/i)?.[1] || "")
        .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
        .replace(/<[^>]+>/g, " ")
        .replace(/\s+/g, " ")
        .trim()
    );
    if (!title || !link.startsWith("http")) continue;
    items.push({
      title,
      url: link,
      description: description || title,
      engine: "bing-rss",
      engineRank: items.length + 1,
    });
  }
  return items;
}

async function fetchBingWebRss(query: string, limit: number): Promise<RawCandidateDocument[]> {
  try {
    const rssUrl = `https://www.bing.com/search?format=rss&q=${encodeURIComponent(query)}`;
    const res = await fetch(rssUrl, {
      headers: {
        Accept: "application/rss+xml, application/xml, text/xml;q=0.9, */*;q=0.8",
        "User-Agent": "Mozilla/5.0 (compatible; WebCrawl/1.4; +https://webcrawl.app)",
      },
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return [];
    const xml = await res.text();
    if (!xml.includes("<item>")) return [];
    return parseBingWebRss(xml, limit);
  } catch {
    return [];
  }
}

/**
 * Last-resort keyless engines used when DDG/Brave HTML SERPs come back empty
 * or thinner than `limit`. Wikipedia OpenSearch, HN Algolia, Bing RSS, and
 * DuckDuckGo Instant Answer do not require a JS challenge or API key.
 */
export async function fetchKeylessSearchFallbacks(
  query: string,
  limit: number
): Promise<RawCandidateDocument[]> {
  const per = Math.max(limit, 5);
  const empty = (v: RawCandidateDocument[]) => v.length === 0;
  const run = () =>
    Promise.all([
      withRetry(() => fetchHackerNewsAlgolia(query, per), { retries: 1, delayMs: 280, isEmpty: empty }),
      withRetry(() => fetchWikipediaOpenSearch(query, per), { retries: 1, delayMs: 280, isEmpty: empty }),
      withRetry(() => fetchBingWebRss(query, per), { retries: 1, delayMs: 280, isEmpty: empty }),
      withRetry(() => fetchDuckDuckGoInstantAnswer(query, per), { retries: 1, delayMs: 280, isEmpty: empty }),
    ]);
  let groups = await run();
  if (groups.every((g) => g.length === 0)) {
    await new Promise((r) => setTimeout(r, 400));
    groups = await run();
  }
  return mergeSearchCandidates(groups, Math.max(limit, 8));
}

/** DuckDuckGo Instant Answer API — keyless JSON, unrelated to the HTML SERP challenge. */
export async function fetchDuckDuckGoInstantAnswer(
  query: string,
  limit: number
): Promise<RawCandidateDocument[]> {
  try {
    const url = `https://api.duckduckgo.com/?q=${encodeURIComponent(query)}&format=json&no_redirect=1&no_html=1&skip_disambig=1`;
    const res = await fetch(url, {
      headers: {
        Accept: "application/json",
        "User-Agent": "WebCrawl/1.4 (https://webcrawl.app; search@webcrawl.app)",
      },
      signal: AbortSignal.timeout(2500),
    });
    if (!res.ok) return [];
    const json = (await res.json()) as {
      Heading?: string;
      AbstractURL?: string;
      AbstractText?: string;
      AbstractSource?: string;
      Results?: Array<{ FirstURL?: string; Text?: string }>;
      RelatedTopics?: unknown;
    };
    const items: RawCandidateDocument[] = [];
    const push = (title: string, href: string, description: string) => {
      if (!href.startsWith("http") || items.length >= limit) return;
      if (items.some((i) => canonicalSearchUrl(i.url) === canonicalSearchUrl(href))) return;
      items.push({
        title: title || href,
        url: href,
        description: description || title,
        engine: "ddg-lite",
        engineRank: items.length + 1,
      });
    };
    if (json.AbstractURL && (json.Heading || json.AbstractText)) {
      push(
        json.Heading || json.AbstractSource || json.AbstractURL,
        json.AbstractURL,
        json.AbstractText || ""
      );
    }
    for (const row of json.Results ?? []) {
      if (row.FirstURL && row.Text) push(row.Text, row.FirstURL, row.Text);
    }
    const walk = (node: unknown) => {
      if (items.length >= limit) return;
      if (Array.isArray(node)) {
        for (const n of node) walk(n);
        return;
      }
      if (!node || typeof node !== "object") return;
      const rec = node as { FirstURL?: string; Text?: string; Topics?: unknown };
      if (rec.FirstURL && rec.Text) push(rec.Text, rec.FirstURL, rec.Text);
      if (rec.Topics) walk(rec.Topics);
    };
    walk(json.RelatedTopics);
    return items;
  } catch {
    return [];
  }
}

export async function fetchJinaSearch(
  query: string,
  limit: number,
  req?: { country?: string; lang?: string }
): Promise<RawCandidateDocument[]> {
  const key = process.env.JINA_API_KEY;
  if (!key) {
    return [];
  }
  try {
    const res = await fetch("https://s.jina.ai/", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${key}`,
        Accept: "application/json",
        "Content-Type": "application/json",
        // Titles, URLs and descriptions only: page bodies cost more tokens and we rank on snippets.
        "X-Respond-With": "no-content",
      },
      body: JSON.stringify({
        q: query,
        num: limit,
        ...(req?.country ? { gl: req.country } : {}),
        ...(req?.lang ? { hl: req.lang } : {}),
      }),
      signal: AbortSignal.timeout(3500),
    });
    if (!res.ok) {
      return [];
    }
    const json = (await res.json()) as {
      data?: Array<{ title?: string; url?: string; description?: string; date?: string }>;
    };
    return (json.data || [])
      .filter((item) => item.url)
      .slice(0, limit)
      .map((item, idx) => ({
        title: item.title || "",
        url: item.url || "",
        description: item.description || "",
        publishedDate: item.date,
        engine: "jina" as const,
        engineRank: idx + 1,
      }));
  } catch {
    return [];
  }
}

/**
 * 0A. Bing Shopping Native Provider (`bing-shopping`) via Impit Chrome TLS impersonation.
 * Parses embedded `CustomData` JSON + `<li class="br-item">` seller/rating cards with zero API keys and zero headless browsers (~400ms).
 * When `targetSites` is set (e.g. `["jbhifi.com.au", "amazon.com.au"]`), queries per-site in parallel so even bot-gated retailers return live prices and direct product URLs.
 */
export async function fetchBingShoppingNative(
  rawQuery: string,
  limit: number,
  userLocation?: UserLocationContext,
  targetSites?: string[],
  onOffer?: (offer: ProductOffer) => void
): Promise<RawCandidateDocument[]> {
  try {
    const rawCc = (userLocation?.country || "us").toLowerCase();
    const cc = rawCc === "eu" ? "de" : rawCc === "uk" ? "gb" : rawCc;
    const queries =
      targetSites && targetSites.length > 0
        ? targetSites.slice(0, 4).map((site) => `${rawQuery} ${site}`)
        : [rawQuery];

    const items: RawCandidateDocument[] = [];
    const seenUrls = new Set<string>();

    await Promise.all(
      queries.map(async (q) => {
        try {
          const url = `https://www.bing.com/shop?q=${encodeURIComponent(q)}&cc=${encodeURIComponent(cc)}`;
          const res = await fetchWithTlsImpersonation(url, 2400);
          if (res.status !== 200 || !res.html) {
            return;
          }

          const offers = parseBingShoppingHtml(res.html, userLocation?.country);
          for (const offer of offers) {
            onOffer?.(offer);
            if (seenUrls.has(offer.url)) {
              continue;
            }
            seenUrls.add(offer.url);
            const descParts = [
              `${offer.rawPrice} (${offer.currency}) at ${offer.vendor}`,
              offer.rating ? `Rating: ${offer.rating}/5` : "",
              offer.freeShipping ? "Free shipping" : "",
              offer.title,
            ].filter(Boolean);
            items.push({
              title: `${offer.title} - ${offer.rawPrice} (${offer.vendor})`,
              url: offer.url,
              description: descParts.join(" · "),
              engine: "bing-shopping",
              engineRank: items.length + 1,
            });
          }
        } catch {
          // Ignore individual site query timeout
        }
      })
    );

    return items.slice(0, Math.max(limit * 2, 16));
  } catch {
    return [];
  }
}

/**
 * 0B. Google Shopping Provider (`google-shopping`).
 * Tier 1: Serper `/shopping` endpoint when `SERPER_API_KEY` is configured.
 * Tier 2 (Zero-key fallback): Shopping-intent Brave query ("<query> buy price") with snippet price extraction.
 */
export async function fetchGoogleShoppingProvider(
  rawQuery: string,
  localizedQuery: string,
  limit: number,
  userLocation?: UserLocationContext,
  targetSites?: string[],
  onOffer?: (offer: ProductOffer) => void
): Promise<RawCandidateDocument[]> {
  const serperKey = process.env.SERPER_API_KEY;
  if (serperKey) {
    try {
      const gl = (userLocation?.country || "us").toLowerCase();
      const q =
        targetSites && targetSites.length > 0
          ? `${rawQuery} ${targetSites.slice(0, 3).join(" OR ")}`
          : rawQuery;
      const res = await fetch("https://google.serper.dev/shopping", {
        method: "POST",
        headers: {
          "X-API-KEY": serperKey,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ q, gl, num: Math.min(limit * 2, 20) }),
        signal: AbortSignal.timeout(2200),
      });
      if (res.ok) {
        const json = (await res.json()) as {
          shopping?: Array<{
            title?: string;
            source?: string;
            link?: string;
            price?: string;
            delivery?: string;
            imageUrl?: string;
            rating?: number;
            ratingCount?: number;
          }>;
        };
        const items: RawCandidateDocument[] = [];
        for (const entry of json.shopping ?? []) {
          if (!entry.link || !entry.title) {
            continue;
          }
          const parsedPrice = parsePriceString(
            entry.price,
            userLocation?.country
          );
          const domain = extractDomainHost(entry.link);
          if (parsedPrice && domain) {
            onOffer?.({
              title: entry.title,
              vendor: entry.source || domain,
              domain,
              url: entry.link,
              price: parsedPrice.price,
              rawPrice: parsedPrice.rawPrice,
              currency: parsedPrice.currency,
              availability: "in_stock",
              ...(entry.rating ? { rating: entry.rating } : {}),
              ...(entry.ratingCount ? { reviewCount: entry.ratingCount } : {}),
              ...(entry.delivery
                ? {
                    freeShipping: /free/i.test(entry.delivery),
                    shippingNote: entry.delivery,
                  }
                : {}),
              ...(entry.imageUrl ? { imageUrl: entry.imageUrl } : {}),
              source: "google-shopping",
            });
          }
          items.push({
            title: entry.price
              ? `${entry.title} - ${entry.price}`
              : entry.title,
            url: entry.link,
            description: [
              entry.price,
              entry.source,
              entry.delivery,
              entry.title,
            ]
              .filter(Boolean)
              .join(" · "),
            engine: "google-shopping",
            engineRank: items.length + 1,
          });
        }
        if (items.length > 0) {
          return items.slice(0, limit);
        }
      }
    } catch {
      // Fall through to zero-key shopping query
    }
  }

  // Zero-key shopping intent query to capture price-aggregator and retailer pages
  try {
    const shoppingQuery =
      targetSites && targetSites.length > 0
        ? `${rawQuery} ${targetSites.slice(0, 3).join(" ")} price`
        : `${localizedQuery} price buy`;
    const [braveCandidates, ddgCandidates] = await Promise.all([
      fetchBraveNativeSerp(shoppingQuery, limit, userLocation),
      fetchDuckDuckGoLiteOnly(shoppingQuery, limit, userLocation),
    ]);
    const candidates = [...braveCandidates, ...ddgCandidates];
    for (const c of candidates) {
      c.engine = "google-shopping";
      const snippetOffer = extractOfferFromSerpSnippet(
        c.title,
        c.description,
        c.url,
        userLocation?.country
      );
      if (snippetOffer) {
        onOffer?.(snippetOffer);
      }
    }
    return candidates;
  } catch {
    return [];
  }
}

/**
 * 1. Brave Search Native HTML parser via Impit Chrome TLS impersonation (`search.brave.com/search`).
 * Independent web index with zero API keys required.
 */
export async function fetchBraveNativeSerp(
  query: string,
  limit: number,
  userLocation?: UserLocationContext
): Promise<RawCandidateDocument[]> {
  try {
    const rawCc = (userLocation?.country || "").toLowerCase();
    // Brave Search supports specific 2-letter country codes; map 'eu' or unsupported codes safely
    const braveCc = rawCc === "eu" ? "" : rawCc === "uk" ? "gb" : rawCc;
    const countryParam =
      braveCc && braveCc.length === 2
        ? `&country=${encodeURIComponent(braveCc)}`
        : "";
    const url = `https://search.brave.com/search?q=${encodeURIComponent(
      query
    )}&source=web${countryParam}`;
    const res = await fetchWithTlsImpersonation(url, 2200);
    if (res.status !== 200 || !res.html || isSerpChallengeHtml(res.html, res.status)) {
      return [];
    }

    const html = res.html;
    const items: RawCandidateDocument[] = [];
    const seen = new Set<string>();

    // Brave organic web results use `data-type="web"` blocks or `<a href="https://..." class="... l1 ...">`
    const snippetBlocks = html.split(/data-type=["']web["']/i).slice(1);

    for (const block of snippetBlocks) {
      if (items.length >= limit) {
        break;
      }
      const linkMatch = block.match(
        /<a[^>]+href=["'](https?:\/\/(?!(?:search|cdn\.search|imgs\.search)\.brave\.com)[^"']+)["'][^>]*>([\s\S]*?)<\/a>/i
      );
      if (!linkMatch) {
        continue;
      }
      const rawUrl = linkMatch[1].trim();
      if (seen.has(rawUrl)) {
        continue;
      }

      const titleMatch =
        block.match(
          /class=["'][^"']*title[^"']*["'][^>]*>([\s\S]*?)<\/div>/i
        ) ||
        block.match(
          /<div[^>]+class=["'][^"']*heading[^"']*["'][^>]*>([\s\S]*?)<\/div>/i
        );
      const rawTitle = titleMatch ? titleMatch[1] : linkMatch[2];
      const title = decodeHtmlEntities(
        rawTitle
          .replace(/<[^>]+>/g, " ")
          .replace(/\s+/g, " ")
          .trim()
      );

      const descMatch =
        block.match(
          /class=["'][^"']*snippet-description[^"']*["'][^>]*>([\s\S]*?)<\/div>/i
        ) ||
        block.match(
          /class=["'][^"']*generic-snippet[^"']*["'][^>]*>([\s\S]*?)<\/div>/i
        );
      const description = decodeHtmlEntities(
        (descMatch ? descMatch[1] : "")
          .replace(/<[^>]+>/g, " ")
          .replace(/\s+/g, " ")
          .trim()
      );

      if (title && rawUrl.startsWith("http")) {
        seen.add(rawUrl);
        items.push({
          title,
          url: rawUrl,
          description: description || title,
          engine: "brave-native",
          engineRank: items.length + 1,
        });
      }
    }

    // Fallback generic anchor + description extraction if Brave's DOM class varied
    if (items.length === 0) {
      const anchorRegex =
        /<a[^>]+href=["'](https?:\/\/(?!(?:search|cdn\.search|imgs\.search)\.brave\.com)[^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
      let m: RegExpExecArray | null;
      while ((m = anchorRegex.exec(html)) !== null && items.length < limit) {
        const linkUrl = m[1].trim();
        if (seen.has(linkUrl)) {
          continue;
        }
        const text = decodeHtmlEntities(
          m[2]
            .replace(/<[^>]+>/g, " ")
            .replace(/\s+/g, " ")
            .trim()
        );
        if (
          text.length < 12 ||
          /^(Ask|All|Images|News|Videos|Maps|Goggles)$/i.test(text)
        ) {
          continue;
        }
        seen.add(linkUrl);
        items.push({
          title: text,
          url: linkUrl,
          description: text,
          engine: "brave-native",
          engineRank: items.length + 1,
        });
      }
    }

    return items;
  } catch {
    return [];
  }
}

/**
 * 2. DuckDuckGo Lite / HTML SERP via Impit Chrome TLS impersonation.
 */
async function fetchDuckDuckGoLiteOnly(
  query: string,
  limit: number,
  userLocation?: UserLocationContext
): Promise<RawCandidateDocument[]> {
  const seenUrls = new Set<string>();
  const items: RawCandidateDocument[] = [];

  const addResult = (title: string, url: string, description: string) => {
    const cleanUrl = unwrapRedirectUrl(url);
    if (
      !cleanUrl.startsWith("http") ||
      cleanUrl.includes("duckduckgo.com/y.js") ||
      seenUrls.has(cleanUrl)
    ) {
      return;
    }
    seenUrls.add(cleanUrl);
    items.push({
      title: decodeHtmlEntities(
        title
          .replace(/<[^>]+>/g, "")
          .replace(/\s+/g, " ")
          .trim()
      ),
      url: cleanUrl,
      description: decodeHtmlEntities(
        description
          .replace(/<[^>]+>/g, "")
          .replace(/\s+/g, " ")
          .trim()
      ),
      engine: "ddg-lite",
      engineRank: items.length + 1,
    });
  };

  try {
    const countryCode = (userLocation?.country || "").toUpperCase();
    const kl = ddgRegion(countryCode, undefined);
    const klParam = kl ? `&kl=${encodeURIComponent(kl)}` : "";
    const endpoints = [
      `https://lite.duckduckgo.com/lite/?q=${encodeURIComponent(query)}${klParam}`,
      `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}${klParam}`,
    ];
    for (const endpoint of endpoints) {
      if (items.length >= limit) break;
      try {
        const liteRes = await fetchWithTlsImpersonation(endpoint, 2200);
        if (!liteRes?.html || isSerpChallengeHtml(liteRes.html, liteRes.status)) {
          continue;
        }
        const html = liteRes.html;
        const linkMatches = Array.from(
          html.matchAll(
            /<a\s+[^>]*href=["']([^"']+)["'][^>]*class=["']result-link["'][^>]*>([\s\S]*?)<\/a>|<a\s+[^>]*class=["']result-link["'][^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi
          )
        );
        const snippetMatches = Array.from(
          html.matchAll(
            /<td\s+[^>]*class=["']result-snippet["'][^>]*>([\s\S]*?)<\/td>/gi
          )
        );

        for (let i = 0; i < linkMatches.length && items.length < limit; i++) {
          const m = linkMatches[i];
          const rawUrl = m[1] || m[3] || "";
          const rawTitle = m[2] || m[4] || "";
          const rawSnippet = snippetMatches[i]?.[1] || "";
          addResult(rawTitle, rawUrl, rawSnippet);
        }
        if (items.length > 0) break;
      } catch {
        // try the next DDG HTML endpoint
      }
    }
  } catch {
    // ignore
  }

  return items;
}

/**
 * 3. Google News Search RSS (`news.google.com/rss/search`) with dynamic edition localization (`gl`, `hl`, `ceid`).
 */
export async function fetchGoogleNewsSearchRss(
  query: string,
  limit: number,
  userLocation?: UserLocationContext,
  lang = "en",
  timeoutMs = 2000
): Promise<RawCandidateDocument[]> {
  try {
    const rawGl = (userLocation?.country || "US").toUpperCase();
    const gl = rawGl === "EU" || rawGl === "UK" ? "GB" : rawGl;
    const cleanLang = (lang || "en").toLowerCase().split("-")[0];
    const hl = `${cleanLang}-${gl}`;
    const ceid = `${gl}:${cleanLang}`;
    const rssUrl = `https://news.google.com/rss/search?q=${encodeURIComponent(
      query
    )}&hl=${encodeURIComponent(hl)}&gl=${encodeURIComponent(gl)}&ceid=${encodeURIComponent(
      ceid
    )}`;
    const res = await fetchWithTlsImpersonation(rssUrl, timeoutMs);
    if (res.status !== 200 || !res.html.includes("<item>")) {
      return [];
    }
    const items: RawCandidateDocument[] = [];
    const itemRegex = /<item>([\s\S]*?)<\/item>/gi;
    let match: RegExpExecArray | null;
    while (
      (match = itemRegex.exec(res.html)) !== null &&
      items.length < limit
    ) {
      const block = match[1];
      const title = decodeHtmlEntities(
        (block.match(/<title>([\s\S]*?)<\/title>/i)?.[1] || "")
          .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
          .trim()
      );
      const link = (block.match(/<link>([\s\S]*?)<\/link>/i)?.[1] || "").trim();
      const source = decodeHtmlEntities(
        (block.match(/<source[^>]*>([\s\S]*?)<\/source>/i)?.[1] || "").trim()
      );
      const pubDate = (
        block.match(/<pubDate>([\s\S]*?)<\/pubDate>/i)?.[1] || ""
      ).trim();
      const rawDesc = decodeHtmlEntities(
        block.match(/<description>([\s\S]*?)<\/description>/i)?.[1] || ""
      )
        .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
        .replace(/<[^>]+>/g, " ")
        .replace(/\s+/g, " ")
        .trim();
      if (title && link) {
        items.push({
          title,
          url: link,
          description: [source ? `[${source}]` : "", pubDate, rawDesc]
            .filter(Boolean)
            .join(" - "),
          publishedDate: pubDate || undefined,
          engine: "google-news-rss",
          engineRank: items.length + 1,
        });
      }
    }
    return items;
  } catch {
    return [];
  }
}

/**
 * 4. Wikipedia OpenSearch API (`en.wikipedia.org/w/api.php`) for high-authority entity grounding.
 */
async function fetchWikipediaOpenSearch(
  query: string,
  limit: number
): Promise<RawCandidateDocument[]> {
  try {
    const cleanQuery = query.replace(/\([^)]*\)|-?site:\S+/g, "").trim();
    if (!cleanQuery) {
      return [];
    }
    const url = `https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch=${encodeURIComponent(
      cleanQuery
    )}&srlimit=${limit}&format=json`;
    const res = await fetch(url, {
      headers: {
        "User-Agent":
          "WebCrawl/1.0 (https://webcrawl.app; search@webcrawl.app)",
        Accept: "application/json",
      },
      signal: AbortSignal.timeout(2200),
    });
    if (!res.ok) {
      return [];
    }
    const json = (await res.json()) as {
      query?: {
        search?: Array<{
          title?: string;
          snippet?: string;
          timestamp?: string;
        }>;
      };
    };
    const hits = json.query?.search || [];
    return hits.slice(0, limit).map((hit, idx) => {
      const title = (hit.title || "").trim();
      const slug = encodeURIComponent(title.replace(/\s+/g, "_"));
      const snippet = decodeHtmlEntities(
        (hit.snippet || "")
          .replace(/<[^>]+>/g, " ")
          .replace(/\s+/g, " ")
          .trim()
      );
      return {
        title: `${title} - Wikipedia`,
        url: `https://en.wikipedia.org/wiki/${slug}`,
        description: snippet,
        publishedDate: hit.timestamp,
        engine: "wikipedia" as const,
        engineRank: idx + 1,
      };
    });
  } catch {
    return [];
  }
}

/**
 * 5. HackerNews Algolia API (`hn.algolia.com/api/v1/search`) for ultra-fast tech & developer search.
 */
async function fetchHackerNewsAlgolia(
  query: string,
  limit: number
): Promise<RawCandidateDocument[]> {
  try {
    const cleanQuery = query.replace(/\([^)]*\)|-?site:\S+/g, "").trim();
    const url = `https://hn.algolia.com/api/v1/search?query=${encodeURIComponent(
      cleanQuery
    )}&tags=story&hitsPerPage=${limit}`;
    const res = await fetch(url, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(2200),
    });
    if (!res.ok) {
      return [];
    }
    const json = (await res.json()) as {
      hits?: Array<{
        title?: string;
        url?: string;
        objectID?: string;
        points?: number;
        num_comments?: number;
        created_at?: string;
      }>;
    };
    const items: RawCandidateDocument[] = [];
    for (const hit of json.hits || []) {
      if (items.length >= limit) {
        break;
      }
      const targetUrl =
        hit.url ||
        (hit.objectID
          ? `https://news.ycombinator.com/item?id=${hit.objectID}`
          : "");
      if (!targetUrl || !hit.title) {
        continue;
      }
      items.push({
        title: hit.title,
        url: targetUrl,
        description: `${hit.title} (Hacker News: ${hit.points ?? 0} points, ${
          hit.num_comments ?? 0
        } comments)`,
        publishedDate: hit.created_at,
        engine: "hn-algolia",
        engineRank: items.length + 1,
      });
    }
    return items;
  } catch {
    return [];
  }
}

/**
 * 6. ArXiv API (`export.arxiv.org/api/query`) + OpenAlex Scholarly Works API
 * for scientific, ML/AI, biomedical, and peer-reviewed research paper search.
 */
export function buildArxivSearchQuery(rawQuery: string): string {
  const clean = rawQuery
    .replace(/\([^)]*\)|-?site:\S+/g, " ")
    .replace(/["'`]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (!clean) {
    return "all:machine+learning";
  }
  const arxivIdMatch = clean.match(/\b(\d{4}\.\d{4,5}(?:v\d+)?)\b/i);
  if (arxivIdMatch) {
    return `id:${encodeURIComponent(arxivIdMatch[1])}`;
  }
  const stop = new Set(["the", "and", "for", "with", "from", "paper", "papers", "arxiv", "research"]);
  const words = clean
    .split(/\s+/)
    .map((w) => w.replace(/[^a-zA-Z0-9.-]/g, ""))
    .filter((w) => w.length >= 2 && !stop.has(w.toLowerCase()))
    .slice(0, 6);
  if (words.length <= 1) {
    return `all:${encodeURIComponent(words[0] || clean)}`;
  }
  return words.map((w) => `all:${encodeURIComponent(w)}`).join("+AND+");
}

async function fetchOpenAlexPapers(
  query: string,
  limit: number
): Promise<RawCandidateDocument[]> {
  try {
    const clean = query.replace(/\([^)]*\)|-?site:\S+/g, " ").replace(/\s+/g, " ").trim();
    if (!clean) {
      return [];
    }
    const url = `https://api.openalex.org/works?search=${encodeURIComponent(
      clean
    )}&per-page=${Math.min(limit, 8)}`;
    const res = await fetch(url, {
      headers: { "user-agent": "webcrawl-anything/1.2 (mailto:support@webcrawl.app)" },
      signal: AbortSignal.timeout(2800),
    });
    if (!res.ok) {
      return [];
    }
    const data = (await res.json()) as {
      results?: Array<{
        title?: string;
        doi?: string;
        publication_date?: string;
        publication_year?: number;
        cited_by_count?: number;
        primary_location?: {
          landing_page_url?: string;
          pdf_url?: string;
          source?: { display_name?: string };
        };
        open_access?: { oa_url?: string };
        authorships?: Array<{ author?: { display_name?: string } }>;
        abstract_inverted_index?: Record<string, number[]>;
      }>;
    };
    const works = Array.isArray(data.results) ? data.results : [];
    const items: RawCandidateDocument[] = [];
    for (const w of works) {
      if (items.length >= limit) {
        break;
      }
      const title = (w.title || "").replace(/\s+/g, " ").trim();
      const targetUrl =
        w.primary_location?.landing_page_url ||
        w.open_access?.oa_url ||
        w.doi ||
        "";
      if (!title || !targetUrl) {
        continue;
      }
      const authors = (w.authorships || [])
        .map((a) => a.author?.display_name)
        .filter((n): n is string => Boolean(n))
        .slice(0, 4)
        .join(", ");
      let abstractText = "";
      if (w.abstract_inverted_index && typeof w.abstract_inverted_index === "object") {
        const pairs: Array<[number, string]> = [];
        for (const [word, positions] of Object.entries(w.abstract_inverted_index)) {
          if (Array.isArray(positions)) {
            for (const pos of positions) {
              pairs.push([pos, word]);
            }
          }
        }
        pairs.sort((a, b) => a[0] - b[0]);
        abstractText = pairs.map((p) => p[1]).join(" ");
      }
      const venue = w.primary_location?.source?.display_name;
      const pdfUrl = w.primary_location?.pdf_url || w.open_access?.oa_url;
      const metaParts = [
        authors ? `Authors: ${authors}` : "",
        venue ? `Venue: ${venue}` : "",
        typeof w.cited_by_count === "number" ? `Citations: ${w.cited_by_count}` : "",
        pdfUrl ? `PDF: ${pdfUrl}` : "",
      ].filter(Boolean);
      const description = [metaParts.join(" · "), abstractText]
        .filter(Boolean)
        .join(" — ")
        .slice(0, 460);
      items.push({
        title: `[Paper] ${title}`,
        url: targetUrl,
        description: description || title,
        publishedDate:
          w.publication_date ||
          (w.publication_year ? `${w.publication_year}-01-01` : undefined),
        engine: "arxiv",
        engineRank: items.length + 1,
      });
    }
    return items;
  } catch {
    return [];
  }
}

export async function fetchArxivApi(
  query: string,
  limit: number
): Promise<RawCandidateDocument[]> {
  const arxivPromise = (async (): Promise<RawCandidateDocument[]> => {
    try {
      const searchExpr = buildArxivSearchQuery(query);
      const url = `https://export.arxiv.org/api/query?search_query=${searchExpr}&start=0&max_results=${Math.max(
        limit,
        6
      )}`;
      const res = await fetch(url, {
        headers: { "user-agent": "webcrawl-anything/1.2 (https://webcrawl.app)" },
        signal: AbortSignal.timeout(3500),
      });
      if (!res.ok) {
        return [];
      }
      const xml = await res.text();
      const entries = xml.match(/<entry>([\s\S]*?)<\/entry>/gi) || [];
      const items: RawCandidateDocument[] = [];

      for (const entry of entries) {
        if (items.length >= limit) {
          break;
        }
        const title = decodeHtmlEntities(
          (entry.match(/<title>([\s\S]*?)<\/title>/i)?.[1] || "")
            .replace(/\s+/g, " ")
            .trim()
        );
        const rawIdUrl = (entry.match(/<id>([\s\S]*?)<\/id>/i)?.[1] || "").trim();
        const idUrl = rawIdUrl.replace(/^http:\/\/arxiv\.org\//i, "https://arxiv.org/");
        const summary = decodeHtmlEntities(
          (entry.match(/<summary>([\s\S]*?)<\/summary>/i)?.[1] || "")
            .replace(/\s+/g, " ")
            .trim()
        );
        const published = (
          entry.match(/<published>([\s\S]*?)<\/published>/i)?.[1] || ""
        ).trim();
        const authorMatches = Array.from(
          entry.matchAll(/<author>[\s\S]*?<name>([\s\S]*?)<\/name>[\s\S]*?<\/author>/gi)
        )
          .map((m) => decodeHtmlEntities(m[1].trim()))
          .filter(Boolean)
          .slice(0, 4);
        const pdfLink =
          entry.match(/<link[^>]+title=["']pdf["'][^>]+href=["']([^"']+)["']/i)?.[1] ||
          idUrl.replace("/abs/", "/pdf/");

        if (title && idUrl) {
          const metaPrefix = [
            authorMatches.length ? `Authors: ${authorMatches.join(", ")}` : "",
            pdfLink ? `PDF: ${pdfLink.replace(/^http:\/\//i, "https://")}` : "",
          ]
            .filter(Boolean)
            .join(" · ");
          items.push({
            title: `[arXiv] ${title}`,
            url: idUrl,
            description: (metaPrefix ? `${metaPrefix} — ${summary}` : summary).slice(0, 460),
            publishedDate: published || undefined,
            engine: "arxiv",
            engineRank: items.length + 1,
          });
        }
      }
      return items;
    } catch {
      return [];
    }
  })();

  const [arxivItems, openAlexItems] = await Promise.all([
    arxivPromise,
    fetchOpenAlexPapers(query, Math.max(4, Math.ceil(limit / 2))),
  ]);

  const combined: RawCandidateDocument[] = [];
  const seen = new Set<string>();
  for (const item of [...arxivItems, ...openAlexItems]) {
    const key = item.url.toLowerCase().replace(/v\d+$/, "");
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    combined.push({ ...item, engineRank: combined.length + 1 });
  }
  return combined.slice(0, Math.max(limit, 8));
}

const NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_TIMEOUT_MS = 4000;

function nvdHeaders(): Record<string, string> {
  const key = process.env.NVD_API_KEY;
  return key ? { apiKey: key } : {};
}

/** Words that describe the search, not the product, stripped before an NVD keyword search. */
const VULN_NOISE =
  /\b(cves?|vulns?|vulnerabilit(?:y|ies)|security|advisor(?:y|ies)|exploits?|exploited|critical|high|latest|recent|new|known|list|of|for|in|the|and|bugs?|issues?|patch(?:es)?|20\d\d)\b/gi;

export function nvdKeywordFromQuery(query: string): string {
  return query
    .replace(/\([^)]*\)|-?site:\S+/g, " ")
    .replace(VULN_NOISE, " ")
    .replace(/[^\w.\- ]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function cveToCandidate(r: CveRecord, engine: "nvd" | "osv", rank: number): RawCandidateDocument {
  const label = cveSeverityLabel(r);
  const product = r.affected?.[0]
    ? `${r.affected[0].vendor ? `${r.affected[0].vendor} ` : ""}${r.affected[0].product}`
    : undefined;
  return {
    title: [r.id, label ? `(${label})` : "", product ? `- ${product}` : "", r.title && !product ? `- ${r.title}` : ""]
      .filter(Boolean)
      .join(" "),
    url: r.url,
    description: r.summary.slice(0, 420),
    publishedDate: r.published,
    engine,
    engineRank: rank,
  };
}

/**
 * Exact CVE ids, cache first: hits come from Postgres (stale ones refresh in the
 * background), and only misses go to NVD, one request each, capped at `cap`.
 * Used for query ids and page-mentioned ids. Write-back happens in the pipeline
 * once NVD and OSV records are merged.
 */
export async function fetchNvdByIds(ids: string[], cap = 3): Promise<CveRecord[]> {
  if (ids.length === 0) return [];
  const cached = await getCachedCves(ids);
  const have = new Set(
    cached.records.flatMap((c) => [c.id, ...(c.aliases ?? [])].map((x) => x.toUpperCase()))
  );
  const missing = ids.filter((id) => !have.has(id.toUpperCase()));
  refreshStaleCves(cached.stale, cached.records, (s) => fetchNvdLiveByIds(s, s.length));
  const live = missing.length ? await fetchNvdLiveByIds(missing, cap) : [];
  return [...cached.records, ...live];
}

async function fetchNvdLiveByIds(ids: string[], cap: number): Promise<CveRecord[]> {
  const out: CveRecord[] = [];
  await Promise.all(
    ids.slice(0, cap).map(async (id) => {
      try {
        const res = await fetch(`${NVD_API}?cveId=${encodeURIComponent(id)}`, {
          headers: nvdHeaders(),
          signal: AbortSignal.timeout(NVD_TIMEOUT_MS),
        });
        if (res.ok) out.push(...parseNvdResponse(await res.json()));
      } catch {
        // rate limited or slow: the caller falls back to OSV + web results
      }
    })
  );
  return out;
}

/**
 * 7. NVD CVE API 2.0. Exact ids use `cveId`; anything else uses `keywordSearch`.
 * NVD returns keyword matches oldest-first, so when there are more matches than we
 * want, a second request fetches the newest page (`startIndex = total - n`).
 */
async function fetchNvdApi(
  query: string,
  limit: number,
  onCve?: (cve: CveRecord) => void
): Promise<RawCandidateDocument[]> {
  try {
    const ids = extractCveIdsFromText(query, 5);
    let records: CveRecord[] = [];
    if (ids.length > 0) {
      records = await fetchNvdByIds(ids, 5);
    } else {
      const kw = nvdKeywordFromQuery(query);
      if (!kw) return [];
      const n = Math.min(Math.max(limit, 5), 20);
      records = (await cachedKeywordResult(kw)) ?? (await fetchNvdKeywordLive(kw, n));
    }
    records.forEach((r) => onCve?.(r));
    return records.slice(0, limit).map((r, i) => cveToCandidate(r, "nvd", i + 1));
  } catch {
    return [];
  }
}

const byPublishedDesc = (a: CveRecord, b: CveRecord) =>
  (b.published ?? "").localeCompare(a.published ?? "");

/**
 * Keyword answered within QUERY_TTL_MS: replay its id list from the cache. Returns
 * null (go live) unless nearly every id is still cached, so a partial row set never
 * masks NVD's full answer. Ids outside the stored window (pre-2020) are never cached,
 * so they count as expected misses.
 */
async function cachedKeywordResult(kw: string): Promise<CveRecord[] | null> {
  const ids = await getCachedQuery(kw);
  if (!ids) return null;
  const storable = ids.filter((id) => Number(id.match(/^CVE-(\d{4})-/)?.[1]) >= CVE_STORE_SINCE);
  if (storable.length === 0) return ids.length === 0 ? [] : null;
  const cached = await getCachedCves(storable);
  if (cached.records.length < Math.ceil(storable.length * 0.8)) return null;
  refreshStaleCves(cached.stale, cached.records, (s) => fetchNvdLiveByIds(s, s.length));
  return cached.records.sort(byPublishedDesc);
}

/** NVD keywordSearch (newest page), remembered per keyword; FTS over the cache if NVD fails. */
async function fetchNvdKeywordLive(kw: string, n: number): Promise<CveRecord[]> {
  const base = `${NVD_API}?keywordSearch=${encodeURIComponent(kw)}`;
  const first = await fetch(`${base}&resultsPerPage=${n}`, {
    headers: nvdHeaders(),
    signal: AbortSignal.timeout(NVD_TIMEOUT_MS),
  }).catch(() => null);
  if (!first?.ok) {
    // Rate limited (403/503) or slow: serve what earlier searches cached.
    return (await searchCachedCves(kw, n)).sort(byPublishedDesc);
  }
  const body = await first.json();
  const total = Number(body?.totalResults ?? 0);
  let records = parseNvdResponse(body);
  if (total > n) {
    const latest = await fetch(`${base}&resultsPerPage=${n}&startIndex=${total - n}`, {
      headers: nvdHeaders(),
      signal: AbortSignal.timeout(NVD_TIMEOUT_MS),
    }).catch(() => null);
    if (latest?.ok) records = parseNvdResponse(await latest.json());
  }
  records.sort(byPublishedDesc);
  rememberQuery(kw, records.map((r) => r.id));
  return records;
}

const OSV_ECOSYSTEMS: Record<string, string> = {
  npm: "npm",
  node: "npm",
  pypi: "PyPI",
  pip: "PyPI",
  python: "PyPI",
  go: "Go",
  golang: "Go",
  maven: "Maven",
  java: "Maven",
  cargo: "crates.io",
  crates: "crates.io",
  rust: "crates.io",
  rubygems: "RubyGems",
  gem: "RubyGems",
  ruby: "RubyGems",
  nuget: "NuGet",
  packagist: "Packagist",
  composer: "Packagist",
  php: "Packagist",
  hex: "Hex",
  pub: "Pub",
};

/** "lodash npm vulnerabilities" -> { name: "lodash", ecosystem: "npm" } */
export function osvPackageFromQuery(query: string): { name: string; ecosystem: string } | null {
  const words = nvdKeywordFromQuery(query).split(" ").filter(Boolean);
  const ecoIdx = words.findIndex((w) => OSV_ECOSYSTEMS[w.toLowerCase()]);
  if (ecoIdx < 0) return null;
  const name = words.filter((_, i) => i !== ecoIdx && !/^(package|library|module|crate)s?$/i.test(words[i]))[0];
  return name ? { name, ecosystem: OSV_ECOSYSTEMS[words[ecoIdx].toLowerCase()] } : null;
}

/**
 * 8. OSV (`api.osv.dev`): exact CVE/GHSA ids, or `package + ecosystem` queries.
 * Adds ecosystem package ranges and fixed versions that NVD's CPE data lacks.
 */
async function fetchOsvApi(
  query: string,
  limit: number,
  onCve?: (cve: CveRecord) => void
): Promise<RawCandidateDocument[]> {
  try {
    const ids = [...extractCveIdsFromText(query, 3), ...extractGhsaIdsFromText(query, 3)];
    let records: CveRecord[] = [];
    if (ids.length > 0) {
      const got = await Promise.all(
        ids.slice(0, 4).map(async (id) => {
          const res = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, {
            signal: AbortSignal.timeout(3000),
          }).catch(() => null);
          return res?.ok ? parseOsvVuln(await res.json()) : null;
        })
      );
      records = got.filter((r): r is CveRecord => r !== null);
    } else {
      const pkg = osvPackageFromQuery(query);
      if (!pkg) return [];
      const res = await fetch("https://api.osv.dev/v1/query", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ package: pkg }),
        signal: AbortSignal.timeout(3000),
      });
      if (!res.ok) return [];
      const body = await res.json();
      records = ((body?.vulns ?? []) as unknown[])
        .map((v) => parseOsvVuln(v as Record<string, unknown>))
        .filter((r): r is CveRecord => r !== null)
        .sort((a, b) => (b.published ?? "").localeCompare(a.published ?? ""))
        .slice(0, Math.max(limit, 10));
    }
    records.forEach((r) => onCve?.(r));
    return records.slice(0, limit).map((r, i) => cveToCandidate(r, "osv", i + 1));
  } catch {
    return [];
  }
}

async function fetchSerperApi(
  effectiveQuery: string,
  limit: number,
  req: SearchRequest
): Promise<RawCandidateDocument[]> {
  try {
    const res = await fetch("https://google.serper.dev/search", {
      method: "POST",
      headers: {
        "X-API-KEY": process.env.SERPER_API_KEY || "",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        q: effectiveQuery,
        num: limit,
        ...(req.country ? { gl: req.country } : {}),
        ...(req.lang ? { hl: req.lang } : {}),
        ...(req.tbs ? { tbs: req.tbs } : {}),
      }),
      signal: AbortSignal.timeout(2000),
    });
    if (!res.ok) {
      return [];
    }
    const json = (await res.json()) as {
      organic?: Array<{
        title?: string;
        link?: string;
        snippet?: string;
        date?: string;
      }>;
    };
    return (json.organic || []).slice(0, limit).map((item, idx) => ({
      title: item.title || "",
      url: item.link || "",
      description: item.snippet || "",
      publishedDate: item.date,
      engine: "serper" as const,
      engineRank: idx + 1,
    }));
  } catch {
    return [];
  }
}

async function fetchBraveSearchApi(
  effectiveQuery: string,
  limit: number
): Promise<RawCandidateDocument[]> {
  try {
    const u = new URL("https://api.search.brave.com/res/v1/web/search");
    u.searchParams.set("q", effectiveQuery);
    u.searchParams.set("count", String(limit));
    const res = await fetch(u.toString(), {
      headers: {
        Accept: "application/json",
        "X-Subscription-Token": process.env.BRAVE_SEARCH_API_KEY || "",
      },
      signal: AbortSignal.timeout(2000),
    });
    if (!res.ok) {
      return [];
    }
    const json = (await res.json()) as {
      web?: {
        results?: Array<{
          title?: string;
          url?: string;
          description?: string;
          page_age?: string;
        }>;
      };
    };
    return (json.web?.results || []).slice(0, limit).map((item, idx) => ({
      title: item.title || "",
      url: item.url || "",
      description: item.description || "",
      publishedDate: item.page_age,
      engine: "brave-api" as const,
      engineRank: idx + 1,
    }));
  } catch {
    return [];
  }
}

function unwrapRedirectUrl(rawUrl: string): string {
  let cleaned = rawUrl.replace(/&amp;/g, "&").trim();
  if (cleaned.startsWith("//")) {
    cleaned = `https:${cleaned}`;
  }
  if (
    cleaned.includes("duckduckgo.com/y.js") ||
    cleaned.includes("duckduckgo.com/duckduckgo-help-pages")
  ) {
    return "";
  }
  if (cleaned.includes("uddg=")) {
    try {
      const parsed = new URL(cleaned, "https://duckduckgo.com");
      const uddg = parsed.searchParams.get("uddg");
      if (uddg) {
        return decodeURIComponent(uddg);
      }
    } catch {
      // ignore
    }
  }
  return cleaned;
}
