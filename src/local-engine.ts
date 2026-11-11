/**
 * Zero-key Local Execution Engine for Webcrawl Anything.
 *
 * Implements the exact same method surface as `WebcrawlClient` (`search`, `scrape`,
 * `parse`, `map`, `crawl`, `extract`, `rerank`, `categories`, `targets`) in-process
 * using the shared `src/engine/`, `src/search/`, `src/parse/`, `src/extract/`,
 * `src/ranker/`, and `src/targets/` pipeline.
 *
 * Every community improvement to extractors, parsers, or targets in `src/` immediately
 * powers both this local engine (`npx webcrawl`) and the hosted `webcrawl.app` API.
 */
import {
  extractWebsiteData,
  fastHtmlToMarkdown,
  fetchWithTlsImpersonation,
  getCachedPageAsync,
  isChallengeMarkdown,
  isLocalChromeAvailable,
  mapWebsiteUrls,
  renderViaLocalChromeDetailed,
  setCachedPage,
  sha256,
} from "./engine.js";
import {
  isDomainRenderNeeded,
  markDomainRenderNeeded,
} from "./engine/session.js";
import { isRenderProviderEnabled, renderViaProvider } from "./engine/render.js";
import {
  fetchResource,
  isAntiBotChallenge,
  lastFetchTier,
  needsBrowserEscalation,
} from "./engine/fetcher.js";
import { parseFile, publicParseMeta } from "./parse/index.js";
import { isBinaryContentType, looksLikeBinaryUrl } from "./parse/fetch.js";
import { maxDownloadBytes } from "./parse/limits.js";
import { parseYouTubeCached, youtubeVideoId } from "./parse/youtube.js";
import { rankDocuments, type RawCandidateDocument } from "./ranker.js";
import { getSearchCategoriesCatalog, searchWeb } from "./search.js";
import { inspectTarget, listTargets, resolveTarget } from "./targets.js";
import {
  hasCustomExtractRequest,
  isEmptyExtractResult,
} from "./extract/structured.js";

export interface LocalEngineBackend {
  readonly baseUrl: string;
  search(p: Record<string, unknown>): Promise<Record<string, unknown>>;
  scrape(p: { url: string; formats?: Array<"markdown" | "links" | "html">; noCache?: boolean }): Promise<Record<string, unknown>>;
  parse(p: Record<string, unknown>): Promise<Record<string, unknown>>;
  run(id: string): Promise<Record<string, unknown>>;
  map(p: { url: string; limit?: number; search?: string }): Promise<Record<string, unknown>>;
  crawl(p: { url: string; maxPages?: number; extractStructured?: boolean }): Promise<Record<string, unknown>>;
  extract(p: { url: string; prompt?: string; schema?: Record<string, unknown> }): Promise<Record<string, unknown>>;
  rerank(p: { query: string; documents: Array<string | Record<string, unknown>>; topK?: number }): Promise<Record<string, unknown>>;
  categories(): Promise<Record<string, unknown>>;
  targets(): Promise<Record<string, unknown>>;
  usage(): Promise<Record<string, unknown>>;
}

/** Lowercased hostname of a URL (memo key for the Tier R render memo). */
function safeDomainOf(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

/**
 * Scrape result for a page the site refused (bot check, 403/429/503).
 * `success: false` with no markdown, so callers never mistake the block page
 * for content. Exported for unit tests.
 */
export function blockedScrapeResult(
  url: string,
  statusCode: number,
  tier: string,
  latencyMs: number,
  reason?: string
): Record<string, unknown> {
  const error =
    reason ??
    (`Blocked by the site's bot check (HTTP ${statusCode}). No content was returned. ` +
      "Retry with `--mode cloud` (hosted stealth browser), or self-host a render provider via WEBCRAWL_RENDER_URL.");
  return {
    success: false,
    mode: "local",
    url,
    blocked: true,
    statusCode,
    error,
    title: url,
    markdown: "",
    links: [],
    data: { url, title: url, markdown: "", links: [] },
    evidence: { tier, blocked: true, statusCode, latencyMs, limitations: [error] },
  };
}

/**
 * JS page whose renderer failed. `success: false` so callers never treat the
 * unrendered nav shell as content (v1.4.3 smoke test: 114 chars of nav with
 * success:true after Chrome hung on --dump-dom).
 */
export function jsRenderFailedResult(
  url: string,
  statusCode: number,
  tier: string,
  latencyMs: number,
  reason: string
): Record<string, unknown> {
  return {
    success: false,
    mode: "local",
    url,
    blocked: false,
    needsJs: true,
    statusCode,
    error: reason,
    title: url,
    markdown: "",
    links: [],
    data: { url, title: url, markdown: "", links: [] },
    evidence: {
      tier,
      blocked: false,
      needsJs: true,
      statusCode,
      latencyMs,
      limitations: [reason],
    },
  };
}

/** Shells shorter than this are unrendered JS / empty pages and must not be cached as content. */
export const MIN_CACHEABLE_MARKDOWN = 200;

/** Attach source HTML when the caller asked for the `html` format. */
export function withOptionalHtml(
  result: Record<string, unknown>,
  html: string | undefined,
  formats?: Array<"markdown" | "links" | "html">
): Record<string, unknown> {
  if (!formats?.includes("html") || !html) return result;
  const data =
    result.data && typeof result.data === "object" && !Array.isArray(result.data)
      ? (result.data as Record<string, unknown>)
      : {};
  return { ...result, html, data: { ...data, html } };
}

/** Structured extract payload: custom prompt/schema → only those fields, no `target` sidecar. */
export function extractOutputData(
  extracted: Record<string, unknown>,
  opts: { prompt?: string; schema?: Record<string, unknown>; target?: unknown }
): Record<string, unknown> {
  if (hasCustomExtractRequest(opts.prompt, opts.schema)) return extracted;
  return {
    ...extracted,
    ...(opts.target ? { target: opts.target } : {}),
  };
}

function nativeScrapeTier(): string {
  const t = lastFetchTier();
  return t === "impersonate" || t === "proxy-impersonate" ? t : "impit-tls";
}

function emptyPageError(statusCode: number): string {
  return (
    `Page returned no readable content (HTTP ${statusCode}). ` +
    "The site may be blocking automated clients or serving a client-rendered shell. " +
    "Retry with `--mode cloud` (hosted stealth browser), or self-host a render provider via WEBCRAWL_RENDER_URL."
  );
}

interface RenderedLocalPage {
  title: string;
  markdown: string;
  html: string;
  links: string[];
  tier: string;
}

function defaultJsRenderError(): string {
  return (
    "Page needs JavaScript rendering; local Chrome was not available or produced no content. " +
    "Install Chrome (see `webcrawl doctor`), point WEBCRAWL_CHROME_PATH at chrome-headless-shell " +
    "(`npx playwright install chromium-headless-shell`), run `webcrawl login` and retry with `--mode cloud`, " +
    "or self-host a render provider via WEBCRAWL_RENDER_URL."
  );
}

/**
 * JS / challenge shell → render provider, then local Chrome (CDP, then dump-dom),
 * then stealth. Returns null when no renderer produced real content.
 */
async function escalateJsRender(
  url: string
): Promise<{ page: RenderedLocalPage | null; error?: string }> {
  const errors: string[] = [];
  if (isRenderProviderEnabled()) {
    const rendered = await renderViaProvider(url);
    if (rendered && rendered.markdown.trim().length >= 40) {
      return {
        page: {
          title: rendered.title,
          markdown: rendered.markdown,
          html: "",
          links: [],
          tier: "render",
        },
      };
    }
    errors.push("render provider produced no content");
  }
  if (isLocalChromeAvailable()) {
    const chrome = await renderViaLocalChromeDetailed(url);
    if (chrome.html && chrome.html.length > 100) {
      const parsed = fastHtmlToMarkdown(chrome.html, url);
      if (
        parsed.markdown.trim().length > 40 &&
        !isAntiBotChallenge(chrome.html, 200) &&
        !isChallengeMarkdown(parsed.title, parsed.markdown)
      ) {
        return { page: { ...parsed, html: chrome.html, tier: "browser" } };
      }
      errors.push(
        chrome.method
          ? `${chrome.method} rendered HTML but markdown was still a shell`
          : "local Chrome rendered HTML but markdown was still a shell"
      );
    } else if (chrome.error) {
      errors.push(chrome.error);
    } else {
      errors.push("local Chrome produced no content");
    }
  } else {
    errors.push("no local Chrome/Chromium binary");
  }
  try {
    const { stealthAvailable } = await import("./engine/stealth.js");
    const { escalateToSandboxOrBrowser, isChallengeResult } = await import("./sandbox.js");
    if (await stealthAvailable()) {
      const esc = await escalateToSandboxOrBrowser(url, { browser: true, timeoutMs: 25_000 });
      if (
        esc &&
        esc.markdown.trim().length > 40 &&
        !isChallengeResult(esc.html, esc.markdown, esc.statusCode)
      ) {
        return {
          page: {
            title: esc.title,
            markdown: esc.markdown,
            html: esc.html,
            links: esc.links,
            tier: esc.tier,
          },
        };
      }
      errors.push("stealth browser produced no content");
    }
  } catch {
    /* stealth optional */
  }
  return { page: null, error: errors.filter(Boolean).join("; ") || defaultJsRenderError() };
}

/**
 * Apply `map --filter` / `search` after discovery, then honour `-n` / `limit`.
 * Matching is a case-insensitive substring of the URL. Exported for unit tests.
 */
export function filterMappedLinks(
  links: string[],
  search?: string,
  limit = 100
): string[] {
  const cap = Math.max(1, limit);
  const needle = search?.trim().toLowerCase();
  const filtered = needle
    ? links.filter((l) => l.toLowerCase().includes(needle))
    : links;
  return filtered.slice(0, cap);
}

/** How many URLs to discover before applying `--filter`, so a small `-n` cannot hide matches. */
const MAP_FILTER_DISCOVER_LIMIT = 5000;

export function createLocalEngineClient(): LocalEngineBackend {
  return {
    baseUrl: "local://engine",

    async search(p: Record<string, unknown>): Promise<Record<string, unknown>> {
      const query = String(p.query ?? "").trim();
      const category = typeof p.category === "string" ? p.category : undefined;
      const subcategory = typeof p.subcategory === "string" ? p.subcategory : undefined;
      const limit = typeof p.limit === "number" ? p.limit : 5;
      const country = typeof p.country === "string" ? p.country : undefined;
      const city = typeof p.city === "string" ? p.city : undefined;
      const sites = Array.isArray(p.sites) ? p.sites.map(String) : undefined;
      const scrapeContent = Boolean(p.scrapeContent);

      const res = await searchWeb({
        query,
        category: category as never,
        subcategory,
        limit,
        country,
        city,
        filters: sites?.length ? { sites } : undefined,
        scrapeOptions: scrapeContent ? { formats: ["markdown"] } : undefined,
      });

      const resolved = resolveTarget({ query, category });
      return {
        ...res,
        success: res.success !== false,
        mode: "local",
        target: {
          id: resolved.plugin.id,
          name: resolved.plugin.name,
          confidence: resolved.match.confidence,
        },
      };
    },

    async scrape(p: {
      url: string;
      formats?: Array<"markdown" | "links" | "html">;
      noCache?: boolean;
    }): Promise<Record<string, unknown>> {
      const targetUrl = /^https?:\/\//i.test(p.url) ? p.url : `https://${p.url}`;
      const start = Date.now();

      // 1. Check if YouTube URL
      if (youtubeVideoId(targetUrl)) {
        const yt = await parseYouTubeCached(targetUrl, { bypassCache: p.noCache });
        return {
          success: true,
          mode: "local",
          url: targetUrl,
          title: yt.title,
          markdown: yt.markdown,
          data: {
            url: targetUrl,
            title: yt.title,
            markdown: yt.markdown,
            metadata: { parse: publicParseMeta(yt) },
          },
          evidence: {
            targetId: "youtube-media",
            tier: "native-parser",
            contentHash: yt.contentHash,
            latencyMs: Date.now() - start,
            sourceUrl: targetUrl,
            matchedSignals: ["youtube:captions"],
            limitations: yt.meta.warnings,
          },
        };
      }

      // 2. Check if binary document URL (PDF, DOCX, XLSX, PPTX)
      if (looksLikeBinaryUrl(targetUrl)) {
        const fetched = await fetchResource(targetUrl, { maxBytes: maxDownloadBytes() });
        if (isBinaryContentType(fetched.contentType) || looksLikeBinaryUrl(fetched.url)) {
          const parsed = await parseFile(
            { bytes: fetched.body, contentType: fetched.contentType, fileName: fetched.url },
            { bypassCache: p.noCache }
          );
          return {
            success: true,
            mode: "local",
            url: fetched.url,
            title: parsed.title,
            markdown: parsed.markdown,
            data: {
              url: fetched.url,
              title: parsed.title,
              markdown: parsed.markdown,
              metadata: { parse: publicParseMeta(parsed) },
            },
            evidence: {
              targetId: "pdf-office",
              tier: parsed.meta.method === "ocr" ? "ocr" : "native-parser",
              contentHash: parsed.contentHash,
              latencyMs: Date.now() - start,
              sourceUrl: fetched.url,
              matchedSignals: [`parse:${parsed.meta.kind}:${parsed.meta.method}`],
              limitations: parsed.meta.warnings,
            },
          };
        }
      }

      // 3. Check local cache first
      if (!p.noCache) {
        const cached = await getCachedPageAsync(targetUrl, "none");
        // Entries written before blocked pages stopped being cached may hold a
        // bot-check page: treat those as a miss and fetch again. Thin shells
        // (header-only JS pages) must also miss so local Chrome can hydrate them.
        if (
          cached &&
          !isChallengeMarkdown(cached.title, cached.markdown) &&
          cached.markdown.trim().length >= MIN_CACHEABLE_MARKDOWN
        ) {
          const targetInspection = await inspectTarget({
            url: targetUrl,
            markdown: cached.markdown,
          });
          return {
            success: true,
            mode: "local",
            url: targetUrl,
            title: cached.title,
            markdown: cached.markdown,
            links: cached.links,
            cached: true,
            data: {
              url: targetUrl,
              title: cached.title,
              markdown: cached.markdown,
              links: cached.links,
              structured: targetInspection.structured,
            },
            evidence: {
              ...targetInspection.evidence,
              tier: "cache",
              contentHash: cached.contentHash,
              latencyMs: Date.now() - start,
            },
          };
        }
      }

      // 4. Fetch with TLS impersonation (impit) + target-aware extraction.
      //    Tier R: memoized render-needed domains skip the native ladder
      //    entirely when a render provider is configured — cache (step 3)
      //    already absorbed repeats, so the provider is the next best hop.
      const renderDomain = safeDomainOf(targetUrl);
      if (isRenderProviderEnabled() && (await isDomainRenderNeeded(renderDomain))) {
        const rendered = await renderViaProvider(targetUrl);
        if (rendered) {
          const renderHash = sha256(rendered.markdown);
          setCachedPage(targetUrl, "none", {
            title: rendered.title,
            markdown: rendered.markdown,
            links: [],
            statusCode: 200,
            contentHash: renderHash,
          });
          return {
            success: true,
            mode: "local",
            url: targetUrl,
            title: rendered.title || targetUrl,
            markdown: rendered.markdown,
            links: [],
            data: {
              url: targetUrl,
              title: rendered.title || targetUrl,
              markdown: rendered.markdown,
              links: [],
            },
            evidence: {
              targetId: "render-provider",
              tier: "render",
              contentHash: renderHash,
              latencyMs: Date.now() - start,
              sourceUrl: rendered.sourceUrl,
              matchedSignals: ["render:provider"],
              limitations: rendered.warnings,
            },
          };
        }
        // Provider failed on a memo'd domain: fall through to the native
        // ladder — the memo may be stale or the provider flaky.
      }

      const fetched = await fetchWithTlsImpersonation(targetUrl);
      const parsed = fastHtmlToMarkdown(fetched.html, targetUrl);
      let title = parsed.title;
      let markdown = parsed.markdown;
      let links = parsed.links;
      let html = fetched.html;
      const blocked = isAntiBotChallenge(html, fetched.status);
      const needsRender = needsBrowserEscalation(fetched.status, html, markdown);
      const nativeTier = nativeScrapeTier();

      //    JS shell / challenge: memoize the domain and escalate to a renderer
      //    (hosted provider, local Chrome CDP, then stealth). Never cache
      //    the unrendered shell, and never report the shell as success:true.
      if (needsRender) {
        await markDomainRenderNeeded(renderDomain);
        // 403/429/503 is already a refusal — don't spend a Chrome launch on the block page.
        const escalated =
          blocked && fetched.status >= 400
            ? { page: null, error: undefined as string | undefined }
            : await escalateJsRender(targetUrl);
        const rendered = escalated.page;
        if (rendered) {
          const renderHash = sha256(rendered.markdown);
          if (rendered.markdown.trim().length >= MIN_CACHEABLE_MARKDOWN) {
            setCachedPage(targetUrl, "none", {
              title: rendered.title,
              markdown: rendered.markdown,
              links: rendered.links,
              statusCode: 200,
              contentHash: renderHash,
            });
          }
          return withOptionalHtml(
            {
              success: true,
              mode: "local",
              url: targetUrl,
              title: rendered.title || targetUrl,
              markdown: rendered.markdown,
              links: rendered.links,
              data: {
                url: targetUrl,
                title: rendered.title || targetUrl,
                markdown: rendered.markdown,
                links: rendered.links,
              },
              evidence: {
                targetId: rendered.tier === "render" ? "render-provider" : "web-spa",
                tier: rendered.tier,
                contentHash: renderHash,
                latencyMs: Date.now() - start,
                sourceUrl: targetUrl,
                matchedSignals: rendered.tier === "browser" ? ["render:local-chrome"] : [`render:${rendered.tier}`],
              },
            },
            rendered.html,
            p.formats
          );
        }
        if (blocked) {
          return blockedScrapeResult(
            targetUrl,
            fetched.status,
            nativeTier,
            Date.now() - start
          );
        }
        return jsRenderFailedResult(
          targetUrl,
          fetched.status,
          nativeTier,
          Date.now() - start,
          escalated.error || (!markdown.trim() ? emptyPageError(fetched.status) : defaultJsRenderError())
        );
      }

      if (blocked || !markdown.trim()) {
        return blockedScrapeResult(
          targetUrl,
          fetched.status,
          nativeTier,
          Date.now() - start,
          blocked ? undefined : emptyPageError(fetched.status)
        );
      }

      const contentHash = sha256(markdown || html);
      if (markdown.trim().length >= MIN_CACHEABLE_MARKDOWN) {
        setCachedPage(targetUrl, "none", {
          title,
          markdown,
          links,
          statusCode: fetched.status,
          contentHash,
        });
      }

      const targetInspection = await inspectTarget({
        url: targetUrl,
        html,
        markdown,
      });

      return withOptionalHtml(
        {
          success: true,
          mode: "local",
          url: targetUrl,
          title: title || targetInspection.title || targetUrl,
          markdown: targetInspection.markdown || markdown,
          links,
          data: {
            url: targetUrl,
            title: title || targetInspection.title || targetUrl,
            markdown: targetInspection.markdown || markdown,
            links,
            structured: targetInspection.structured,
          },
          evidence: {
            ...targetInspection.evidence,
            tier: nativeTier,
            contentHash,
            latencyMs: Date.now() - start,
          },
        },
        html,
        p.formats
      );
    },

    async parse(p: Record<string, unknown>): Promise<Record<string, unknown>> {
      const url = typeof p.url === "string" ? p.url : undefined;
      if (url && youtubeVideoId(url)) {
        const yt = await parseYouTubeCached(url, {
          language: typeof p.language === "string" ? p.language : undefined,
          bypassCache: Boolean(p.noCache),
        });
        return {
          success: true,
          mode: "local",
          title: yt.title,
          markdown: yt.markdown,
          metadata: { parse: publicParseMeta(yt) },
        };
      }

      let bytes = p.bytes instanceof Uint8Array ? p.bytes : undefined;
      let contentType = typeof p.contentType === "string" ? p.contentType : undefined;
      let fileName = typeof p.fileName === "string" ? p.fileName : url;

      if (!bytes && typeof p.base64 === "string") {
        bytes = new Uint8Array(Buffer.from(p.base64, "base64"));
      }
      if (!bytes && url) {
        const fetched = await fetchResource(url, { maxBytes: maxDownloadBytes() });
        bytes = fetched.body;
        contentType = contentType ?? fetched.contentType;
        fileName = fileName ?? fetched.url;
      }
      if (!bytes) {
        throw new Error("parse requires `url`, `bytes`, or `base64`");
      }

      const parsed = await parseFile(
        { bytes, contentType, fileName },
        {
          ocr: (p.ocr as "auto" | "force" | "off" | undefined) ?? "auto",
          pages: Array.isArray(p.pages) ? p.pages.map(Number) : undefined,
          language: typeof p.language === "string" ? p.language : undefined,
          bypassCache: Boolean(p.noCache),
        }
      );

      return {
        success: true,
        mode: "local",
        title: parsed.title,
        markdown: parsed.markdown,
        metadata: { parse: publicParseMeta(parsed) },
      };
    },

    async run(id: string): Promise<Record<string, unknown>> {
      return {
        success: false,
        mode: "local",
        id,
        status: "not_found",
        error: "Background runs require cloud mode (`webcrawl login` or WEBCRAWL_API_KEY).",
      };
    },

    async map(p: { url: string; limit?: number; search?: string }): Promise<Record<string, unknown>> {
      const targetUrl = /^https?:\/\//i.test(p.url) ? p.url : `https://${p.url}`;
      const limit = Math.max(1, p.limit ?? 100);
      const needle = p.search?.trim();
      // Discover first (widely when filtering), then apply search and limit so
      // `map --filter webhooks -n 10` can still find /webhooks/* URLs that are
      // not among the first 10 sitemap entries (#11).
      const mapped = await mapWebsiteUrls(targetUrl, {
        limit: needle ? Math.max(limit, MAP_FILTER_DISCOVER_LIMIT) : limit,
      });
      const links = filterMappedLinks(mapped.links, needle, limit);
      return {
        success: true,
        mode: "local",
        url: targetUrl,
        links,
        source: mapped.source,
        total: links.length,
      };
    },

    async crawl(p: { url: string; maxPages?: number }): Promise<Record<string, unknown>> {
      const targetUrl = /^https?:\/\//i.test(p.url) ? p.url : `https://${p.url}`;
      const maxPages = Math.min(25, Math.max(1, p.maxPages ?? 5));
      const mapped = await mapWebsiteUrls(targetUrl, { limit: maxPages * 3 });
      const urls = Array.from(new Set([targetUrl, ...mapped.links])).slice(0, maxPages);

      const pages: Array<Record<string, unknown>> = [];
      for (const u of urls) {
        try {
          const scraped = await this.scrape({ url: u });
          pages.push({
            url: scraped.url ?? u,
            title: scraped.title ?? u,
            markdown: scraped.markdown ?? "",
            evidence: scraped.evidence,
          });
        } catch {
          // continue crawling remaining pages
        }
      }

      return {
        success: true,
        mode: "local",
        url: targetUrl,
        total: pages.length,
        data: pages,
        pages,
      };
    },

    async extract(p: {
      url: string;
      prompt?: string;
      schema?: Record<string, unknown>;
    }): Promise<Record<string, unknown>> {
      const targetUrl = /^https?:\/\//i.test(p.url) ? p.url : `https://${p.url}`;
      // Scrape first (local Chrome / render provider) so JS pages yield rendered HTML, not the shell.
      const scraped = (await this.scrape({
        url: targetUrl,
        formats: ["markdown", "html"],
        noCache: true,
      })) as {
        success?: boolean;
        blocked?: boolean;
        needsJs?: boolean;
        error?: string;
        markdown?: string;
        html?: string;
        title?: string;
        data?: { structured?: Record<string, unknown>; markdown?: string; title?: string; html?: string };
      };
      let markdown = (scraped.data && scraped.data.markdown) || scraped.markdown || "";
      let html = (scraped.data && scraped.data.html) || scraped.html || "";
      if (scraped.blocked || scraped.success === false) {
        // Bot-blocked pages stay failures. A JS shell whose Chrome render failed
        // can still yield structured data from JSON islands once script tags are
        // stripped for card matching — never from `document.write` templates.
        if (scraped.needsJs && scraped.blocked !== true) {
          try {
            const fetched = await fetchWithTlsImpersonation(targetUrl);
            html = fetched.html || html;
            const parsedShell = fastHtmlToMarkdown(html, targetUrl);
            markdown = parsedShell.markdown || markdown;
          } catch {
            /* keep whatever scrape returned */
          }
        } else {
          return {
            success: false,
            blocked: true,
            mode: "local",
            url: targetUrl,
            data: {},
            error: scraped.error || emptyPageError(200),
            evidence: {
              tier: lastFetchTier(),
              sourceUrl: targetUrl,
              limitations: [String(scraped.error || emptyPageError(200))],
            },
          };
        }
      }

      const targetInspection = await inspectTarget({
        url: targetUrl,
        html,
        markdown,
      });
      const siteData = await extractWebsiteData(targetUrl, {
        prompt: p.prompt,
        schema: p.schema,
        markdown,
        html,
        bypassCache: true,
      });
      const { cached: _c, cacheLayer: _l, ...extracted } = siteData;
      const data = extractOutputData(extracted, {
        prompt: p.prompt,
        schema: p.schema,
        target: targetInspection.structured,
      });
      if (hasCustomExtractRequest(p.prompt, p.schema) && isEmptyExtractResult(data)) {
        const error =
          "Extraction produced no data matching the prompt/schema. " +
          "If this is a JS-rendered page, install Chrome (see `webcrawl doctor`) and retry; " +
          "empty objects are not reported as success.";
        return {
          success: false,
          mode: "local",
          url: targetUrl,
          data: {},
          error,
          evidence: {
            ...targetInspection.evidence,
            limitations: [
              ...((targetInspection.evidence?.limitations as string[] | undefined) ?? []),
              error,
            ],
          },
        };
      }
      return {
        success: true,
        mode: "local",
        url: targetUrl,
        data,
        evidence: targetInspection.evidence,
      };
    },

    async rerank(p: {
      query: string;
      documents: Array<string | Record<string, unknown>>;
      topK?: number;
    }): Promise<Record<string, unknown>> {
      const candidates: RawCandidateDocument[] = p.documents.map((doc, idx) => {
        if (typeof doc === "string") {
          return {
            url: `doc://${idx + 1}`,
            title: doc.slice(0, 80),
            description: doc,
            markdown: doc,
            sourceEngine: "direct" as const,
          };
        }
        const text = String(doc.text ?? doc.description ?? doc.markdown ?? doc.title ?? "");
        return {
          url: String(doc.url ?? `doc://${idx + 1}`),
          title: String(doc.title ?? text.slice(0, 80)),
          description: text,
          markdown: text,
          sourceEngine: "direct" as const,
        };
      });

      const ranked = await rankDocuments(p.query, candidates, {
        topK: p.topK ?? candidates.length,
      });

      return {
        success: true,
        mode: "local",
        results: ranked.results.map((r) => ({
          url: r.url,
          title: r.title,
          description: r.description,
          score: r.score,
          scoreBreakdown: r.scoreBreakdown,
        })),
      };
    },

    async categories(): Promise<Record<string, unknown>> {
      return {
        success: true,
        mode: "local",
        ...getSearchCategoriesCatalog(),
      };
    },

    async targets(): Promise<Record<string, unknown>> {
      return {
        success: true,
        mode: "local",
        targets: listTargets().map((t) => ({
          id: t.id,
          name: t.name,
          category: t.category,
          returns: t.returns,
          requirements: t.requirements,
          examples: t.examples,
        })),
      };
    },

    async usage(): Promise<Record<string, unknown>> {
      return {
        success: true,
        mode: "local",
        plan: "open-source-local",
        note: "Running locally with zero API key. Set WEBCRAWL_API_KEY or run `webcrawl login` to use webcrawl.app cloud stealth browsers and global cache.",
      };
    },
  };
}
