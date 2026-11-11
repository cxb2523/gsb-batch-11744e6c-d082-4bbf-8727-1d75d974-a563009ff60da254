/**
 * Pluggable Target & Extractor Registry types for Webcrawl Anything.
 *
 * Modeled on Reverse Engineer Anything (REA): every target declares what it can
 * inspect, its local/cloud prerequisites, how to match URLs or search queries,
 * and returns structured results paired with verifiable Evidence & Provenance.
 */

export type TargetCategory =
  | "web"
  | "documents"
  | "media"
  | "commerce"
  | "travel"
  | "real-estate"
  | "local"
  | "security"
  | "developer"
  | "academic";

export type TargetTier =
  | "cache"
  | "static"
  | "impit-tls"
  | "impersonate"
  | "proxy-impersonate"
  | "cloudflare"
  | "stealth-browser"
  | "sandbox"
  | "native-parser"
  | "ocr"
  | "api";

export interface TargetEvidence {
  /** Which target plugin handled the inspection */
  targetId: string;
  /** Transport or parser tier used to acquire the content */
  tier: TargetTier;
  /** SHA-256 of the raw content or canonical payload */
  contentHash?: string;
  /** End-to-end execution latency in milliseconds */
  latencyMs?: number;
  /** Canonical URL or upstream endpoint inspected */
  sourceUrl?: string;
  /** DOM selectors, JSON-LD blocks, API endpoints, or regex rules that matched */
  matchedSignals: string[];
  /** Explicit limitations, unverified fields, or skipped sections (REA-style honesty) */
  limitations: string[];
}

export interface TargetMatch {
  matched: boolean;
  confidence: number; // 0..1
  reason?: string;
  extractedParams?: Record<string, string>;
}

export interface TargetInspectInput {
  url?: string;
  query?: string;
  html?: string;
  markdown?: string;
  bytes?: Uint8Array;
  contentType?: string;
  countryCode?: string;
}

export interface TargetInspectResult<T = unknown> {
  targetId: string;
  targetName: string;
  category: TargetCategory;
  title?: string;
  markdown?: string;
  structured?: T;
  evidence: TargetEvidence;
}

export interface CrawlTargetPlugin<T = unknown> {
  /** Unique slug (e.g. "web-spa", "pdf-office", "youtube", "shopping", "github", "arxiv", "cve") */
  id: string;
  /** Human-readable target name for `webcrawl targets` and README table */
  name: string;
  /** Category grouping */
  category: TargetCategory;
  /** One-line summary of what Webcrawl returns for this target (REA table column 2) */
  returns: string;
  /** Local/cloud requirements & guide note (REA table column 3) */
  requirements: string;
  /** Example URLs or queries for CLI / agent discovery */
  examples: string[];
  /** Fast synchronous check whether a URL or search query targets this plugin */
  matches(input: { url?: string; query?: string; contentType?: string; category?: string }): TargetMatch;
  /** Extract structured data + evidence from already-fetched HTML/text/bytes */
  extract?(input: TargetInspectInput): Promise<TargetInspectResult<T>> | TargetInspectResult<T>;
}
