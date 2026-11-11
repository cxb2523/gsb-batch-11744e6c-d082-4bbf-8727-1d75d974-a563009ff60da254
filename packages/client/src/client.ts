import { DEFAULT_BASE_URL } from "./config.js";
import { WebcrawlError, kindForStatus } from "./errors.js";
import type {
  ApiResponse,
  CrawlParams,
  ExtractParams,
  MapParams,
  MonitorParams,
  MonitorResponse,
  MonitorUpdateParams,
  ParseParams,
  ParseResponse,
  RerankParams,
  ScrapeParams,
  SearchParams,
  SearchResponse,
} from "./types.js";

export interface ClientOptions {
  apiKey?: string;
  baseUrl?: string;
  /** Per-request timeout in ms. Default 60s. */
  timeoutMs?: number;
  fetch?: typeof fetch;
  userAgent?: string;
  /** IANA timezone sent as `X-User-Timezone` so results are local. Defaults to this machine's. */
  timezone?: string;
}

function localTimezone(): string | undefined {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  } catch {
    return undefined;
  }
}

function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("base64");}
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));}
  return btoa(s);
}

const compact = <T extends Record<string, unknown>>(o: T): Partial<T> =>
  Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as Partial<T>;

export class WebcrawlClient {
  readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly hasCustomFetch: boolean;
  private readonly userAgent: string;
  private readonly timezone?: string;

  constructor(opts: ClientOptions = {}) {
    this.baseUrl = (opts.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    this.apiKey = opts.apiKey;
    this.timeoutMs = opts.timeoutMs ?? 60_000;
    this.fetchImpl = opts.fetch ?? globalThis.fetch;
    this.hasCustomFetch = Boolean(opts.fetch);
    this.userAgent = opts.userAgent ?? "webcrawl-client/0.1";
    this.timezone = opts.timezone ?? localTimezone();
  }

  async request<T = ApiResponse>(
    method: "GET" | "POST" | "PATCH" | "DELETE",
    path: string,
    body?: unknown
  ): Promise<T> {
    const headers: Record<string, string> = {
      accept: "application/json",
      "user-agent": this.userAgent,
    };
    if (this.apiKey) {headers.authorization = `Bearer ${this.apiKey}`;}
    if (this.timezone) {headers["x-user-timezone"] = this.timezone;}
    if (body !== undefined) {headers["content-type"] = "application/json";}

    let res: Response;
    try {
      res = await this.fetchImpl(`${this.baseUrl}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (e) {
      const name = e instanceof Error ? e.name : "";
      if (name === "TimeoutError" || name === "AbortError") {
        throw new WebcrawlError("timeout", `Request to ${path} timed out after ${this.timeoutMs}ms`);
      }
      throw new WebcrawlError("network", e instanceof Error ? e.message : String(e));
    }

    const text = await res.text();
    let json: unknown;
    try {
      json = text ? JSON.parse(text) : {};
    } catch {
      json = { error: text.slice(0, 300) };
    }

    if (!res.ok) {
      const obj = (json && typeof json === "object" ? json : {}) as Record<string, unknown>;
      const retry = Number(res.headers.get("retry-after"));
      throw new WebcrawlError(
        kindForStatus(res.status),
        typeof obj.error === "string" ? obj.error : `HTTP ${res.status}`,
        { status: res.status, retryAfter: Number.isFinite(retry) && retry > 0 ? retry : undefined, body: json }
      );
    }
    return json as T;
  }

  async search(p: SearchParams): Promise<SearchResponse> {
    const { sites, scrapeContent, ...rest } = p;
    const rawCat = (p.category || "").trim().toLowerCase();
    const rawSub = (p.subcategory || "").trim().toLowerCase();
    const isAcademic =
      rawCat === "academic" ||
      rawCat === "paper" ||
      rawCat === "papers" ||
      rawCat === "research" ||
      rawCat === "arxiv" ||
      rawCat === "scholar" ||
      rawCat === "scholarly" ||
      rawSub === "arxiv" ||
      rawSub === "papers" ||
      rawSub === "ml" ||
      rawSub === "pubmed" ||
      rawSub === "math";

    const proxyPromise = this.request<SearchResponse>("POST", "/v1/search", {
      ...compact({ ...rest, ...(isAcademic ? { category: "academic" } : {}) }),
      ...(sites?.length ? { filters: { sites } } : {}),
      ...(scrapeContent ? { scrapeOptions: { formats: ["markdown"] } } : {}),
    });

    if (!isAcademic || this.hasCustomFetch) {
      return proxyPromise;
    }

    const limit = p.limit ?? 5;
    if (!this.apiKey) {
      const scholarlyItems = await fetchAcademicPapersForClient(this.fetchImpl, p.query, limit);
      return {
        success: true,
        category: "academic",
        results: scholarlyItems.slice(0, limit),
      };
    }

    const [proxyRes, scholarlyItems] = await Promise.all([
      proxyPromise.catch(() => ({ success: true, results: [] as Array<Record<string, unknown>> })),
      fetchAcademicPapersForClient(this.fetchImpl, p.query, limit),
    ]);

    if (!scholarlyItems.length) {
      return proxyRes;
    }
    const existing = Array.isArray(proxyRes.results) ? proxyRes.results : [];
    const merged: Array<Record<string, unknown>> = [];
    const seen = new Set<string>();
    for (const item of [...scholarlyItems, ...existing]) {
      const url = typeof item.url === "string" ? item.url.toLowerCase().replace(/v\d+$/, "") : "";
      if (!url || seen.has(url)) {
        continue;
      }
      seen.add(url);
      merged.push(item);
      if (merged.length >= limit) {
        break;
      }
    }
    return {
      ...proxyRes,
      success: true,
      category: "academic",
      results: merged,
    };
  }

  scrape(p: ScrapeParams): Promise<ApiResponse> {
    return this.request("POST", "/v1/scrape", compact({ url: p.url, formats: p.formats, noCache: p.noCache }));
  }

  /** PDF, DOCX/XLSX/PPTX, image or audio/video to Markdown. Long files: pass `async: true` and poll `run()`. */
  parse(p: ParseParams): Promise<ParseResponse> {
    const { bytes, noCache, ...rest } = p;
    if (!p.url && !bytes && !p.base64) {
      throw new WebcrawlError("bad_request", "parse needs `url`, `bytes` or `base64`");
    }
    const base64 = bytes ? bytesToBase64(bytes) : p.base64;
    return this.request("POST", "/v1/parse", compact({ ...rest, base64, ...(noCache ? { noCache: true } : {}) }));
  }

  /** Status, trace and (when finished) result of an async run. */
  run(id: string): Promise<ApiResponse> {
    return this.request("GET", `/v1/runs/${encodeURIComponent(id)}`);
  }

  map(p: MapParams): Promise<ApiResponse> {
    return this.request("POST", "/v1/map", compact({ ...p }));
  }

  crawl(p: CrawlParams): Promise<ApiResponse> {
    return this.request("POST", "/v1/crawl", compact({ ...p, maxPages: p.maxPages === undefined ? undefined : Math.min(25, Math.max(1, p.maxPages)) }));
  }

  extract(p: ExtractParams): Promise<ApiResponse> {
    return this.request("POST", "/v1/extract", compact({ ...p }));
  }

  rerank(p: RerankParams): Promise<ApiResponse> {
    return this.request("POST", "/v1/rerank", compact({ ...p }));
  }

  categories(): Promise<ApiResponse> {
    return this.request("GET", "/v1/search/categories");
  }

  async targets(): Promise<ApiResponse> {
    try {
      return await this.request("GET", "/v1/targets");
    } catch (e) {
      if (!this.hasCustomFetch && e instanceof WebcrawlError && (e.status === 404 || e.status === 405)) {
        return { success: true, count: BUILTIN_CLIENT_TARGETS.length, targets: BUILTIN_CLIENT_TARGETS };
      }
      throw e;
    }
  }

  usage(): Promise<ApiResponse> {
    return this.request("GET", "/v1/account/usage");
  }

  /** List all web monitors on the account. */
  monitors(): Promise<MonitorResponse> {
    return this.request("GET", "/v1/monitors");
  }

  /** Fetch a single web monitor by ID, including its latest snapshot and per-URL state. */
  getMonitor(id: string): Promise<MonitorResponse> {
    return this.request("GET", `/v1/monitors/${encodeURIComponent(id)}`);
  }

  /** Create a new web monitor (single page, multi-URL list, or whole website section) and run its initial check. */
  createMonitor(p: MonitorParams): Promise<MonitorResponse> {
    const primaryUrl = p.url ?? p.urls?.[0];
    if (!primaryUrl) {
      throw new WebcrawlError("bad_request", "createMonitor requires `url` or non-empty `urls`");
    }
    return this.request(
      "POST",
      "/v1/monitors",
      compact({
        ...p,
        url: primaryUrl,
        maxPages: p.maxPages === undefined ? undefined : Math.min(25, Math.max(1, p.maxPages)),
      })
    );
  }

  /** Trigger an immediate live check on an existing web monitor, evaluating its condition and diffing against the prior snapshot. */
  checkMonitor(id: string): Promise<MonitorResponse> {
    return this.request("POST", `/v1/monitors/${encodeURIComponent(id)}/check`, {});
  }

  /** Update a monitor's status (`active` | `paused`), interval, watch goal, trigger condition, or notification channels. */
  updateMonitor(p: MonitorUpdateParams): Promise<MonitorResponse> {
    const { id, ...rest } = p;
    if (!id) {
      throw new WebcrawlError("bad_request", "updateMonitor requires `id`");
    }
    return this.request("PATCH", `/v1/monitors/${encodeURIComponent(id)}`, compact(rest));
  }

  /** Delete a web monitor by ID. */
  deleteMonitor(id: string): Promise<MonitorResponse> {
    if (!id) {
      throw new WebcrawlError("bad_request", "deleteMonitor requires `id`");
    }
    return this.request("DELETE", `/v1/monitors/${encodeURIComponent(id)}`);
  }

  /** Send a 6-digit OTP verification code to an email address to sign up or log in (provisions 1,000 free monthly credits). */
  sendOtp(email: string): Promise<{
    success: boolean;
    email: string;
    expiresInSeconds: number;
    transport?: string;
    devCode?: string;
    error?: string;
  }> {
    return this.request("POST", "/v1/auth/otp/send", { email: email.trim() });
  }

  /** Verify a 6-digit OTP code, creating the user account (with 1,000 monthly credits) if new, and return a `wc_live_...` API key. */
  async verifyOtp(params: {
    email: string;
    code: string;
    name?: string;
  }): Promise<{
    success: boolean;
    isNewUser?: boolean;
    apiKey?: string;
    sessionToken?: string;
    user?: {
      id: string;
      email: string;
      name?: string | null;
      plan: string;
      creditsLimit: number;
      creditsUsed: number;
      creditsRemaining: number;
    };
    error?: string;
  }> {
    const res = await this.request<{
      success: boolean;
      isNewUser?: boolean;
      apiKey?: string;
      sessionToken?: string;
      user?: {
        id: string;
        email: string;
        name?: string | null;
        plan: string;
        creditsLimit: number;
        creditsUsed: number;
        creditsRemaining: number;
      };
      error?: string;
    }>("POST", "/v1/auth/otp/verify", {
      email: params.email.trim(),
      code: params.code.trim(),
      ...(params.name ? { name: params.name.trim() } : {}),
    });

    if (res.success && !res.apiKey && res.sessionToken) {
      try {
        const sessionClient = new WebcrawlClient({
          baseUrl: this.baseUrl,
          apiKey: res.sessionToken,
          fetch: this.fetchImpl,
          userAgent: this.userAgent,
        });
        const keyRes = await sessionClient.request<{
          success: boolean;
          apiKey?: string;
        }>("POST", "/v1/account/keys", { name: "CLI API Key" });
        if (keyRes.apiKey) {
          res.apiKey = keyRes.apiKey;
        }
      } catch {
        // Fallback to sessionToken if key creation fails
        res.apiKey = res.sessionToken;
      }
    }
    return res;
  }

  /** Fetch authenticated user profile & remaining credit balance. */
  me(): Promise<{
    success: boolean;
    authenticated: boolean;
    user?: {
      id: string;
      email: string;
      name?: string | null;
      plan: string;
      creditsLimit: number;
      creditsUsed: number;
      creditsRemaining: number;
    };
  }> {
    return this.request("GET", "/v1/auth/me");
  }
}

const decodeXmlEntities = (s: string): string =>
  s
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");

async function fetchAcademicPapersForClient(
  fetchImpl: typeof fetch,
  rawQuery: string,
  limit: number
): Promise<Array<Record<string, unknown>>> {
  const clean = rawQuery
    .replace(/\([^)]*\)|-?site:\S+/g, " ")
    .replace(/["'`]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (!clean) {
    return [];
  }
  const arxivIdMatch = clean.match(/\b(\d{4}\.\d{4,5}(?:v\d+)?)\b/i);
  const stop = new Set(["the", "and", "for", "with", "from", "paper", "papers", "arxiv", "research"]);
  const words = clean
    .split(/\s+/)
    .map((w) => w.replace(/[^a-zA-Z0-9.-]/g, ""))
    .filter((w) => w.length >= 2 && !stop.has(w.toLowerCase()))
    .slice(0, 6);
  const searchExpr = arxivIdMatch
    ? `id:${encodeURIComponent(arxivIdMatch[1])}`
    : words.length <= 1
      ? `all:${encodeURIComponent(words[0] || clean)}`
      : words.map((w) => `all:${encodeURIComponent(w)}`).join("+AND+");

  const arxivPromise = (async (): Promise<Array<Record<string, unknown>>> => {
    try {
      const url = `https://export.arxiv.org/api/query?search_query=${searchExpr}&start=0&max_results=${Math.max(
        limit,
        6
      )}`;
      const res = await fetchImpl(url, {
        headers: { "user-agent": "webcrawl-anything/1.2 (https://webcrawl.app)" },
        signal: AbortSignal.timeout(4000),
      });
      if (!res.ok) {
        return [];
      }
      const xml = await res.text();
      const entries = xml.match(/<entry>([\s\S]*?)<\/entry>/gi) || [];
      const out: Array<Record<string, unknown>> = [];
      for (const entry of entries) {
        if (out.length >= limit) {
          break;
        }
        const title = decodeXmlEntities(
          (entry.match(/<title>([\s\S]*?)<\/title>/i)?.[1] || "").replace(/\s+/g, " ").trim()
        );
        const rawIdUrl = (entry.match(/<id>([\s\S]*?)<\/id>/i)?.[1] || "").trim();
        const idUrl = rawIdUrl.replace(/^http:\/\/arxiv\.org\//i, "https://arxiv.org/");
        const summary = decodeXmlEntities(
          (entry.match(/<summary>([\s\S]*?)<\/summary>/i)?.[1] || "").replace(/\s+/g, " ").trim()
        );
        const published = (entry.match(/<published>([\s\S]*?)<\/published>/i)?.[1] || "").trim();
        const authors = Array.from(
          entry.matchAll(/<author>[\s\S]*?<name>([\s\S]*?)<\/name>[\s\S]*?<\/author>/gi)
        )
          .map((m) => decodeXmlEntities(m[1].trim()))
          .filter(Boolean)
          .slice(0, 4);
        const pdfUrl = (
          entry.match(/<link[^>]+title=["']pdf["'][^>]+href=["']([^"']+)["']/i)?.[1] ||
          idUrl.replace("/abs/", "/pdf/")
        ).replace(/^http:\/\//i, "https://");
        if (title && idUrl) {
          const metaPrefix = [
            authors.length ? `Authors: ${authors.join(", ")}` : "",
            pdfUrl ? `PDF: ${pdfUrl}` : "",
          ]
            .filter(Boolean)
            .join(" · ");
          out.push({
            title: `[arXiv] ${title}`,
            url: idUrl,
            description: (metaPrefix ? `${metaPrefix} — ${summary}` : summary).slice(0, 460),
            publishedDate: published || undefined,
            sources: ["arxiv"],
          });
        }
      }
      return out;
    } catch {
      return [];
    }
  })();

  const openAlexPromise = (async (): Promise<Array<Record<string, unknown>>> => {
    try {
      const url = `https://api.openalex.org/works?search=${encodeURIComponent(
        clean
      )}&per-page=${Math.min(limit, 6)}`;
      const res = await fetchImpl(url, {
        headers: { "user-agent": "webcrawl-anything/1.2 (mailto:support@webcrawl.app)" },
        signal: AbortSignal.timeout(3200),
      });
      if (!res.ok) {
        return [];
      }
      const data = (await res.json()) as {
        results?: Array<{
          title?: string;
          doi?: string;
          publication_date?: string;
          cited_by_count?: number;
          primary_location?: {
            landing_page_url?: string;
            pdf_url?: string;
            source?: { display_name?: string };
          };
          open_access?: { oa_url?: string };
          authorships?: Array<{ author?: { display_name?: string } }>;
        }>;
      };
      const out: Array<Record<string, unknown>> = [];
      for (const w of data.results || []) {
        if (out.length >= limit) {
          break;
        }
        const title = (w.title || "").replace(/\s+/g, " ").trim();
        const targetUrl =
          w.primary_location?.landing_page_url || w.open_access?.oa_url || w.doi || "";
        if (!title || !targetUrl) {
          continue;
        }
        const authors = (w.authorships || [])
          .map((a) => a.author?.display_name)
          .filter((n): n is string => Boolean(n))
          .slice(0, 4)
          .join(", ");
        const venue = w.primary_location?.source?.display_name;
        const pdfUrl = w.primary_location?.pdf_url || w.open_access?.oa_url;
        const desc = [
          authors ? `Authors: ${authors}` : "",
          venue ? `Venue: ${venue}` : "",
          typeof w.cited_by_count === "number" ? `Citations: ${w.cited_by_count}` : "",
          pdfUrl ? `PDF: ${pdfUrl}` : "",
        ]
          .filter(Boolean)
          .join(" · ");
        out.push({
          title: `[Paper] ${title}`,
          url: targetUrl,
          description: desc || title,
          publishedDate: w.publication_date,
          sources: ["arxiv"],
        });
      }
      return out;
    } catch {
      return [];
    }
  })();

  const [arxivItems, openAlexItems] = await Promise.all([arxivPromise, openAlexPromise]);
  return [...arxivItems, ...openAlexItems];
}

const BUILTIN_CLIENT_TARGETS = [
  {
    id: "llms-txt",
    name: "llms.txt & AI Documentation Indexes",
    returns: "Structured sections, doc links, summaries, and full markdown manifest for LLM context ingestion",
    requirements: "Built-in zero-key markdown manifest parser",
  },
  {
    id: "github",
    name: "GitHub Repositories, Issues & Releases",
    returns: "Repository metadata, stars/forks, topics, language, issue/PR threads, release notes, and README markdown",
    requirements: "Built-in zero-key HTML/JSON inspector via impit TLS fetch",
  },
  {
    id: "arxiv",
    name: "ArXiv & Academic Research Papers",
    returns: "Paper title, authors, abstract, primary subject, DOI, submission date, and direct PDF link",
    requirements: "Built-in ArXiv + OpenAlex paper search (-c academic) and abstract/PDF parser",
  },
  {
    id: "youtube-media",
    name: "YouTube Videos, Audio & Media Files",
    returns: "Timestamped transcript Markdown, video title/channel/duration metadata, and spoken audio transcription",
    requirements: "Built-in zero-key YouTube multi-client caption extractor",
  },
  {
    id: "pdf-office",
    name: "PDFs & Office Documents (DOCX, XLSX, PPTX)",
    returns: "Page-numbered Markdown, tables, native text extraction, automatic OCR on scanned pages",
    requirements: "Built-in (PDF inspector, pdf-parse, mammoth, officeparser, tesseract.js)",
  },
  {
    id: "cve",
    name: "Security Advisories & CVEs (NVD / OSV / CISA KEV)",
    returns: "Structured CVERecord with CVSS v3.1/v4.0 score, severity, CWEs, affected/fixed versions, and CISA KEV status",
    requirements: "Built-in live NVD 2.0 + OSV.dev + CISA KEV enrichment (-c security --sub cve)",
  },
  {
    id: "shopping",
    name: "Shopping & Multi-Retailer Product Offers",
    returns: "AggregatedProduct & ProductOffer records with price, currency, stock availability, retailer, rating, and reviews",
    requirements: "Zero-key local HTML/JSON-LD product extractor (-c shopping)",
  },
  {
    id: "travel",
    name: "Flights & Hotels",
    returns: "Structured FlightOffer & HotelListing items with price, currency, airline/stops or star/guest rating",
    requirements: "Zero-key local search + schema.org extractor (-c flights / -c hotels)",
  },
  {
    id: "real-estate",
    name: "Real Estate & Local Business Listings",
    returns: "PropertyListing (bedrooms, bathrooms, parking, suburb) & BusinessListing (phone, address, rating, hours)",
    requirements: "Zero-key local extractor (-c real-estate --sub buy|rent|sold / -c business)",
  },
  {
    id: "web",
    name: "Websites, Docs & Single-Page Apps (SPAs)",
    returns: "Clean Markdown, title, metadata, canonical links, content hash, and evidence source tier",
    requirements: "Zero-key local (impit TLS impersonation + local Chrome) or webcrawl.app cloud stealth browsers",
  },
];

export function createClient(opts: ClientOptions = {}): WebcrawlClient {
  return new WebcrawlClient(opts);
}
