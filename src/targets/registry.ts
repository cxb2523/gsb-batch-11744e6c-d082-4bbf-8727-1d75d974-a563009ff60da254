/**
 * Unified Target & Extractor Registry for Webcrawl Anything.
 *
 * Wraps every built-in vertical extractor (`src/extract/*`), binary/media parser (`src/parse/*`),
 * multi-tier web crawler (`src/engine/*`), and developer target (`src/targets/developer.ts`)
 * behind a single discoverable interface with REA-style Evidence & Provenance.
 */
import crypto from "node:crypto";
import {
  extractBusinessListingsFromHtml,
  extractCveIdsFromText,
  extractFlightOffersFromHtml,
  extractHotelListingsFromHtml,
  extractOffersFromHtml,
  extractPropertyListingsFromHtml,
  groupOffersIntoProducts,
} from "../extract/index.js";
import { fastHtmlToMarkdown } from "../engine/markdown.js";
import { BINARY_KINDS, detectFileKind } from "../parse/detect.js";
import { youtubeVideoId } from "../parse/youtube.js";
import {
  arxivTargetPlugin,
  githubTargetPlugin,
  llmsTxtTargetPlugin,
} from "./developer.js";
import type {
  CrawlTargetPlugin,
  TargetInspectInput,
  TargetInspectResult,
  TargetMatch,
} from "./types.js";

function sha256(content: string): string {
  return crypto.createHash("sha256").update(content).digest("hex");
}

export const webSpaTargetPlugin: CrawlTargetPlugin = {
  id: "web-spa",
  name: "Websites, SPAs & Anti-Bot Pages",
  category: "web",
  returns: "Clean Markdown, title, outbound links, JSON-LD / OpenGraph metadata, and tier provenance",
  requirements: "Built-in impit TLS impersonation; optional local Chrome/Playwright or webcrawl.app cloud stealth for Cloudflare/DataDome",
  examples: [
    "npx webcrawl scrape https://news.ycombinator.com",
    "npx webcrawl crawl https://docs.stripe.com -n 10",
  ],
  matches({ url }) {
    if (url && /^https?:\/\//i.test(url)) {
      return { matched: true, confidence: 0.5, reason: "Generic HTTP/HTTPS web URL" };
    }
    return { matched: false, confidence: 0 };
  },
  extract(input: TargetInspectInput): TargetInspectResult {
    const html = input.html ?? "";
    const url = input.url ?? "https://example.com";
    const { title, markdown, links } = fastHtmlToMarkdown(html, url);
    const matchedSignals = ["html:fast-markdown"];
    const limitations: string[] = [];
    if (!markdown.trim()) {
      limitations.push("Static HTML contained no readable body text; enable browser/stealth escalation for client-rendered SPA");
    }
    return {
      targetId: "web-spa",
      targetName: "Websites, SPAs & Anti-Bot Pages",
      category: "web",
      title,
      markdown,
      structured: { title, linkCount: links.length, links: links.slice(0, 50) },
      evidence: {
        targetId: "web-spa",
        tier: "static",
        contentHash: sha256(html),
        sourceUrl: url,
        matchedSignals,
        limitations,
      },
    };
  },
};

export const pdfOfficeTargetPlugin: CrawlTargetPlugin = {
  id: "pdf-office",
  name: "PDFs & Office Documents (DOCX, XLSX, PPTX)",
  category: "documents",
  returns: "Page-numbered Markdown, tables, native text extraction, automatic OCR on scanned pages, and skipped-page diagnostics",
  requirements: "Built-in PDF inspector, mammoth, and officeparser; optional OCR provider for scanned pages",
  examples: [
    "npx webcrawl scrape https://arxiv.org/pdf/1706.03762.pdf",
  ],
  matches({ url, contentType }) {
    if (url || contentType) {
      const { kind } = detectFileKind({ contentType, fileName: url });
      if (kind === "pdf" || kind === "docx" || kind === "xlsx" || kind === "pptx") {
        return { matched: true, confidence: 0.99, reason: `Detected ${kind.toUpperCase()} document` };
      }
    }
    return { matched: false, confidence: 0 };
  },
};

export const youtubeMediaTargetPlugin: CrawlTargetPlugin = {
  id: "youtube-media",
  name: "YouTube Videos, Audio & Media Files",
  category: "media",
  returns: "Timestamped transcript Markdown, video title/channel/duration metadata, and spoken audio transcription",
  requirements: "Built-in zero-key YouTube multi-client caption extractor; optional audio transcription provider for raw MP3/MP4",
  examples: [
    "npx webcrawl scrape https://www.youtube.com/watch?v=dQw4w9WgXcQ",
  ],
  matches({ url, contentType }) {
    if (url && youtubeVideoId(url)) {
      return { matched: true, confidence: 0.99, reason: "YouTube video URL" };
    }
    if (url || contentType) {
      const { kind } = detectFileKind({ contentType, fileName: url });
      if (kind === "audio" || kind === "video" || (BINARY_KINDS.has(kind) && kind === "image")) {
        return { matched: true, confidence: 0.95, reason: `Detected ${kind} media resource` };
      }
    }
    return { matched: false, confidence: 0 };
  },
};

export const shoppingTargetPlugin: CrawlTargetPlugin = {
  id: "shopping",
  name: "E-Commerce Products & Multi-Retailer Offers",
  category: "commerce",
  returns: "Normalized prices, currency, stock availability, seller ratings, free-shipping flags, and grouped product comparisons",
  requirements: "Built-in JSON-LD Product/Offer, OpenGraph, and SERP shopping card extractors",
  examples: [
    "npx webcrawl search \"Sony WH-1000XM5 headphones\" -c shopping",
  ],
  matches({ category, query, url }) {
    if (category === "shopping") {
      return { matched: true, confidence: 0.99, reason: "Shopping search category" };
    }
    if (url && /\b(amazon\.|ebay\.|walmart\.|bestbuy\.|jbhifi\.|shopify)/i.test(url)) {
      return { matched: true, confidence: 0.85, reason: "Retailer product domain" };
    }
    if (query && /\b(buy|price|cheapest|deal|in stock|review)\b/i.test(query)) {
      return { matched: true, confidence: 0.65, reason: "Commercial shopping query intent" };
    }
    return { matched: false, confidence: 0 };
  },
  extract(input: TargetInspectInput): TargetInspectResult {
    const html = input.html ?? "";
    const url = input.url ?? "https://example.com";
    const offers = extractOffersFromHtml(html, url, input.countryCode);
    const products = groupOffersIntoProducts(offers, input.query ?? "");
    const matchedSignals = offers.map((o) => `offer:${o.source}`);
    const limitations = offers.length === 0 ? ["No JSON-LD Product/Offer or OpenGraph price tags found on page"] : [];
    return {
      targetId: "shopping",
      targetName: "E-Commerce Products & Multi-Retailer Offers",
      category: "commerce",
      structured: { offers, products },
      evidence: {
        targetId: "shopping",
        tier: "static",
        contentHash: sha256(html),
        sourceUrl: url,
        matchedSignals: Array.from(new Set(matchedSignals)),
        limitations,
      },
    };
  },
};

export const flightsTargetPlugin: CrawlTargetPlugin = {
  id: "flights",
  name: "Airline Routes, Fares & Schedules",
  category: "travel",
  returns: "Origin/destination IATA codes, airline, price, cabin class, stops, duration, and trip type",
  requirements: "Built-in IATA route parser, JSON-LD FlightReservation, and fare table extractor",
  examples: [
    "npx webcrawl search \"flights SYD to SFO non-stop\" -c flights",
  ],
  matches({ category, query }) {
    if (category === "flights") {
      return { matched: true, confidence: 0.99, reason: "Flights search category" };
    }
    if (query && /\b(flights?|airfare|non-stop|round-trip|[A-Z]{3}\s+to\s+[A-Z]{3})\b/i.test(query)) {
      return { matched: true, confidence: 0.8, reason: "Flight route query intent" };
    }
    return { matched: false, confidence: 0 };
  },
  extract(input: TargetInspectInput): TargetInspectResult {
    const html = input.html ?? "";
    const url = input.url ?? "https://example.com";
    const flights = extractFlightOffersFromHtml(html, url, input.countryCode);
    return {
      targetId: "flights",
      targetName: "Airline Routes, Fares & Schedules",
      category: "travel",
      structured: { flights },
      evidence: {
        targetId: "flights",
        tier: "static",
        contentHash: sha256(html),
        sourceUrl: url,
        matchedSignals: flights.length > 0 ? ["dom:flight-offers"] : [],
        limitations: flights.length === 0 ? ["No structured flight fares found in static HTML"] : [],
      },
    };
  },
};

export const hotelsTargetPlugin: CrawlTargetPlugin = {
  id: "hotels",
  name: "Hotels, Stays & Nightly Rates",
  category: "travel",
  returns: "Hotel name, nightly rate, star rating, guest review score, neighbourhood, and amenities",
  requirements: "Built-in LodgingBusiness / Hotel JSON-LD and booking card extractor",
  examples: [
    "npx webcrawl search \"boutique hotels in Tokyo Shinjuku\" -c hotels",
  ],
  matches({ category, query, url }) {
    if (category === "hotels") {
      return { matched: true, confidence: 0.99, reason: "Hotels search category" };
    }
    if (url && /\b(booking\.com|expedia\.|hotels\.com|airbnb\.)/i.test(url)) {
      return { matched: true, confidence: 0.85, reason: "Hospitality domain" };
    }
    if (query && /\b(hotels?|resort|nightly rate|check-in|accommodation)\b/i.test(query)) {
      return { matched: true, confidence: 0.75, reason: "Hotel search query intent" };
    }
    return { matched: false, confidence: 0 };
  },
  extract(input: TargetInspectInput): TargetInspectResult {
    const html = input.html ?? "";
    const url = input.url ?? "https://example.com";
    const hotels = extractHotelListingsFromHtml(html, url, input.countryCode);
    return {
      targetId: "hotels",
      targetName: "Hotels, Stays & Nightly Rates",
      category: "travel",
      structured: { hotels },
      evidence: {
        targetId: "hotels",
        tier: "static",
        contentHash: sha256(html),
        sourceUrl: url,
        matchedSignals: hotels.length > 0 ? ["dom:hotel-listings"] : [],
        limitations: hotels.length === 0 ? ["No structured hotel listings found in static HTML"] : [],
      },
    };
  },
};

export const realEstateTargetPlugin: CrawlTargetPlugin = {
  id: "real-estate",
  name: "Real Estate & Property Listings",
  category: "real-estate",
  returns: "Property address, price/rent period, bedrooms, bathrooms, parking, land size, and listing type (sale/rent/sold)",
  requirements: "Built-in RealEstateListing / Residence JSON-LD and property portal DOM extractor",
  examples: [
    "npx webcrawl search \"3 bedroom house in Austin TX\" -c real-estate --sub buy",
  ],
  matches({ category, query, url }) {
    if (category === "real-estate") {
      return { matched: true, confidence: 0.99, reason: "Real estate search category" };
    }
    if (url && /\b(zillow\.com|realtor\.com|redfin\.com|domain\.com\.au|realestate\.com\.au|rightmove\.co\.uk)/i.test(url)) {
      return { matched: true, confidence: 0.9, reason: "Real estate portal domain" };
    }
    if (query && /\b(for sale|for rent|bedrooms?| townhouses?|apartments?)\b/i.test(query)) {
      return { matched: true, confidence: 0.7, reason: "Real estate query intent" };
    }
    return { matched: false, confidence: 0 };
  },
  extract(input: TargetInspectInput): TargetInspectResult {
    const html = input.html ?? "";
    const url = input.url ?? "https://example.com";
    const listings = extractPropertyListingsFromHtml(html, url, input.countryCode);
    return {
      targetId: "real-estate",
      targetName: "Real Estate & Property Listings",
      category: "real-estate",
      structured: { listings },
      evidence: {
        targetId: "real-estate",
        tier: "static",
        contentHash: sha256(html),
        sourceUrl: url,
        matchedSignals: listings.length > 0 ? ["dom:property-listings"] : [],
        limitations: listings.length === 0 ? ["No structured property cards found in static HTML"] : [],
      },
    };
  },
};

export const localBusinessTargetPlugin: CrawlTargetPlugin = {
  id: "local-business",
  name: "Local Businesses, Clinics & Services",
  category: "local",
  returns: "Business name, phone, street address, opening hours, rating, review count, and price range",
  requirements: "Built-in LocalBusiness schema.org & contact block extractor",
  examples: [
    "npx webcrawl search \"24 hour emergency vet in Melbourne\" -c business",
  ],
  matches({ category }) {
    if (category === "business") {
      return { matched: true, confidence: 0.99, reason: "Local business search category" };
    }
    return { matched: false, confidence: 0 };
  },
  extract(input: TargetInspectInput): TargetInspectResult {
    const html = input.html ?? "";
    const url = input.url ?? "https://example.com";
    const businesses = extractBusinessListingsFromHtml(html, url);
    return {
      targetId: "local-business",
      targetName: "Local Businesses, Clinics & Services",
      category: "local",
      structured: { businesses },
      evidence: {
        targetId: "local-business",
        tier: "static",
        contentHash: sha256(html),
        sourceUrl: url,
        matchedSignals: businesses.length > 0 ? ["dom:local-business"] : [],
        limitations: businesses.length === 0 ? ["No LocalBusiness JSON-LD or contact card found"] : [],
      },
    };
  },
};

export const cveSecurityTargetPlugin: CrawlTargetPlugin = {
  id: "cve-security",
  name: "CVEs, GHSA Advisories & Exploit Catalogs",
  category: "security",
  returns: "CVE/GHSA IDs, CVSS v3/v4 score & vector, severity, CWEs, affected package ranges, fixed versions, and CISA KEV status",
  requirements: "Built-in NVD 2.0 + OSV.dev advisory correlator and page vulnerability parser (zero API key required)",
  examples: [
    "npx webcrawl search \"CVE-2024-3094 xz utils\" -c security",
    "npx webcrawl search \"nextjs middleware auth bypass cve\" -c security",
  ],
  matches({ category, query, url }) {
    if (category === "security") {
      return { matched: true, confidence: 0.99, reason: "Security search category" };
    }
    const text = `${url ?? ""} ${query ?? ""}`;
    if (/\b(CVE-\d{4}-\d{4,7}|GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4})\b/i.test(text)) {
      return { matched: true, confidence: 0.98, reason: "CVE or GHSA identifier detected" };
    }
    return { matched: false, confidence: 0 };
  },
  extract(input: TargetInspectInput): TargetInspectResult {
    const text = input.markdown ?? input.html ?? input.query ?? "";
    const cveIds = extractCveIdsFromText(text);
    return {
      targetId: "cve-security",
      targetName: "CVEs, GHSA Advisories & Exploit Catalogs",
      category: "security",
      structured: { cveIds },
      evidence: {
        targetId: "cve-security",
        tier: "api",
        contentHash: sha256(text),
        sourceUrl: input.url,
        matchedSignals: cveIds.map((id) => `cve:${id}`),
        limitations: cveIds.length === 0 ? ["No explicit CVE-YYYY-NNNN identifier found in text"] : [],
      },
    };
  },
};

/** Default ordered registry of all built-in targets (specific targets first, generic web-spa last). */
export const BUILTIN_TARGETS: CrawlTargetPlugin[] = [
  llmsTxtTargetPlugin,
  githubTargetPlugin,
  arxivTargetPlugin,
  youtubeMediaTargetPlugin,
  pdfOfficeTargetPlugin,
  cveSecurityTargetPlugin,
  shoppingTargetPlugin,
  flightsTargetPlugin,
  hotelsTargetPlugin,
  realEstateTargetPlugin,
  localBusinessTargetPlugin,
  webSpaTargetPlugin,
];

const customTargets = new Map<string, CrawlTargetPlugin>();

/** Register a custom or community target plugin at runtime. */
export function registerTarget(plugin: CrawlTargetPlugin): void {
  customTargets.set(plugin.id, plugin);
}

/** List all registered target plugins (community overrides + built-ins). */
export function listTargets(): CrawlTargetPlugin[] {
  const byId = new Map<string, CrawlTargetPlugin>();
  for (const t of customTargets.values()) {
    byId.set(t.id, t);
  }
  for (const t of BUILTIN_TARGETS) {
    if (!byId.has(t.id)) {
      byId.set(t.id, t);
    }
  }
  return Array.from(byId.values());
}

export function getTargetById(id: string): CrawlTargetPlugin | undefined {
  return customTargets.get(id) ?? BUILTIN_TARGETS.find((t) => t.id === id);
}

/** Resolve the highest-confidence target plugin for a URL, query, or category. */
export function resolveTarget(input: {
  url?: string;
  query?: string;
  contentType?: string;
  category?: string;
}): { plugin: CrawlTargetPlugin; match: TargetMatch } {
  let bestPlugin: CrawlTargetPlugin = webSpaTargetPlugin;
  let bestMatch: TargetMatch = { matched: true, confidence: 0.1, reason: "Fallback web target" };

  for (const plugin of listTargets()) {
    const m = plugin.matches(input);
    if (m.matched && m.confidence > bestMatch.confidence) {
      bestPlugin = plugin;
      bestMatch = m;
    }
  }
  return { plugin: bestPlugin, match: bestMatch };
}

/** Run target-aware extraction on HTML/text and attach REA-style Evidence & Provenance. */
export async function inspectTarget(
  input: TargetInspectInput & { targetId?: string; category?: string }
): Promise<TargetInspectResult> {
  const start = Date.now();
  const plugin = input.targetId
    ? (getTargetById(input.targetId) ?? webSpaTargetPlugin)
    : resolveTarget({
        url: input.url,
        query: input.query,
        contentType: input.contentType,
        category: input.category,
      }).plugin;

  if (plugin.extract) {
    const res = await plugin.extract(input);
    res.evidence.latencyMs = Date.now() - start;
    return res;
  }

  const fallback = await webSpaTargetPlugin.extract!(input);
  fallback.targetId = plugin.id;
  fallback.targetName = plugin.name;
  fallback.category = plugin.category;
  fallback.evidence.targetId = plugin.id;
  fallback.evidence.latencyMs = Date.now() - start;
  return fallback;
}
