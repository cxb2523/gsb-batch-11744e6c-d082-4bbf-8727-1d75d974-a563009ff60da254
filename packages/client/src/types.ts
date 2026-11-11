/** Fields every API response may carry. Responses are intentionally loose: the API grows faster than this client. */
export interface CreditInfo {
  charged?: number;
  used?: number;
  remaining?: number;
  limit?: number;
}

export interface ApiResponse {
  success?: boolean;
  credits?: CreditInfo;
  [key: string]: unknown;
}

export interface Location {
  country?: string;
  region?: string;
  city?: string;
  timezone?: string;
}

export interface SearchParams extends Location {
  query: string;
  category?: string;
  subcategory?: string;
  limit?: number;
  /** Restrict to these domains. */
  sites?: string[];
  includeDomains?: string[];
  excludeDomains?: string[];
  /** Time filter, e.g. `qdr:w`. */
  tbs?: string;
  scrapeContent?: boolean;
}

export interface SearchResponse extends ApiResponse {
  results?: Array<{ title?: string; url?: string; description?: string; markdown?: string }>;
  data?: unknown;
  offers?: unknown[];
  products?: unknown[];
  listings?: unknown[];
  flights?: unknown[];
  hotels?: unknown[];
  businesses?: unknown[];
  /** Structured CVE records (category "security"): id, cvssScore, severity, affected, fixed versions, kev, references. */
  cves?: unknown[];
}

export interface ScrapeParams {
  url: string;
  formats?: Array<"markdown" | "links" | "html">;
  noCache?: boolean;
}

/** Parse a file (PDF, Office, image, audio/video) from a URL, raw bytes or base64. */
export interface ParseParams {
  /** File URL. Provide one of `url`, `bytes` or `base64`. */
  url?: string;
  /** Raw file bytes (sent as base64 JSON). */
  bytes?: Uint8Array;
  base64?: string;
  fileName?: string;
  contentType?: string;
  /** `auto` OCRs only scanned pages; `force` OCRs every page; `off` never OCRs. */
  ocr?: "auto" | "force" | "off";
  /** 1-indexed PDF pages to read. */
  pages?: number[];
  maxOcrPages?: number;
  /** ISO-639-1 hint for transcription. */
  language?: string;
  /** WebVTT/SRT captions to use instead of transcribing. */
  captions?: string;
  describeVideo?: boolean;
  /** Run as a durable job (returns a run id), for big PDFs and long media. */
  async?: boolean;
  noCache?: boolean;
}

export interface ParseMetadata {
  kind?: string;
  method?: "native" | "ocr" | "vision" | "transcript";
  pages?: number;
  pagesOcr?: number[];
  pagesSkipped?: Array<{ page: number; reason: string }>;
  durationSeconds?: number;
  warnings?: string[];
}

export interface ParseResponse extends ApiResponse {
  title?: string;
  markdown?: string;
  /** Present when the parse runs as a durable job. */
  id?: string;
  status?: string;
  statusUrl?: string;
  metadata?: { parse?: ParseMetadata; [key: string]: unknown };
}

export interface MapParams {
  url: string;
  limit?: number;
  search?: string;
}

export interface CrawlParams {
  url: string;
  maxPages?: number;
  extractStructured?: boolean;
}

export interface ExtractParams {
  url: string;
  prompt?: string;
  schema?: Record<string, unknown>;
}

export type RerankDocument = string | { title?: string; url?: string; text?: string; description?: string };

export interface RerankParams {
  query: string;
  documents: RerankDocument[];
  topK?: number;
}

export type MonitorScopeMode = "page" | "urls" | "site";

export interface MonitorParams {
  /** Primary URL to watch (or site root URL when `mode: "site"`). */
  url?: string;
  /** Multiple URLs to watch when `mode: "urls"`. */
  urls?: string[];
  /** Watch scope: single `"page"` (default), `"urls"` list, or whole `"site"`. */
  mode?: MonitorScopeMode;
  /** Max pages to sample in `"site"` mode (1..25, default 5). */
  maxPages?: number;
  /** Optional friendly name for the watch. */
  name?: string;
  /** Poll interval in minutes (5..10080, default 60). */
  intervalMinutes?: number;
  /** Natural-language focus describing what to watch for (e.g. "Pricing tiers and discounts"). */
  watchFor?: string;
  /** Trigger condition expression (e.g. `'price < 50'`, `'content contains "In Stock"'`) or condition AST object. */
  condition?: string | Record<string, unknown>;
  /** Email address to alert when triggered, or `true` to use the signed-in account email. */
  notifyEmail?: string | boolean;
  /** HTTPS webhook URL to POST when triggered. */
  webhookUrl?: string;
}

export interface MonitorUpdateParams {
  id: string;
  name?: string | null;
  status?: "active" | "paused";
  intervalMinutes?: number;
  watchFor?: string | null;
  condition?: string | Record<string, unknown> | null;
  notifyEmail?: string | boolean | null;
  webhookUrl?: string | null;
  urls?: string[];
  maxPages?: number;
}

export interface MonitorRecord {
  id: string;
  name?: string | null;
  mode?: MonitorScopeMode;
  url: string;
  urls?: string[];
  maxPages?: number;
  watchFor?: string | null;
  condition?: Record<string, unknown> | null;
  conditionJev?: string | null;
  notifyEmail?: string | null;
  webhookUrl?: string | null;
  intervalMinutes: number;
  status: "active" | "paused";
  lastContentHash?: string | null;
  lastTitle?: string | null;
  lastSnapshot?: string | null;
  lastDiffSummary?: string | null;
  lastConditionMet?: boolean | null;
  lastNotificationStatus?: string | null;
  changeCount?: number;
  lastCheckedAt?: string | null;
  lastChangeDetectedAt?: string | null;
  createdAt?: string;
  [key: string]: unknown;
}

export interface MonitorResponse extends ApiResponse {
  monitor?: MonitorRecord;
  monitors?: MonitorRecord[];
  initialCheck?: Record<string, unknown>;
  check?: Record<string, unknown>;
  notifications?: Record<string, unknown>;
  deleted?: boolean;
}
