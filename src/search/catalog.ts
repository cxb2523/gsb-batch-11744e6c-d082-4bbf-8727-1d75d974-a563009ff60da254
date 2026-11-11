import {
  extractDomainHost,
  type AggregatedProduct,
  type BusinessListing,
  type CveRecord,
  type FlightOffer,
  type HotelListing,
  type ProductOffer,
  type PropertyListing,
} from "../extract/index.js";
import type {
  DecisionModelId,
  DocumentScoreBreakdown,
  SearchEngineSource,
  UserLocationContext,
} from "../ranker/index.js";

export type {
  AggregatedProduct,
  BusinessListing,
  CveRecord,
  FlightOffer,
  HotelListing,
  ProductOffer,
  PropertyListing,
} from "../extract/index.js";

export interface SearchAgentFilters {
  /** Restrict to these engines (overrides the category's default engine plan) */
  engines?: SearchEngineSource[];
  excludeEngines?: SearchEngineSource[];
  /** Prefer domains on the user's country-code TLD and demote other country TLDs */
  preferLocalDomains?: boolean;
  /** How to localize the upstream query: add city, country, region, or nothing. Default "auto" = per category policy */
  localizeBy?: "auto" | "city" | "country" | "region" | "none";
  mustIncludeTerms?: string[];
  excludeTerms?: string[];
  boostTerms?: string[];
  includeDomains?: string[];
  excludeDomains?: string[];
  /** Target specific retailer domains or URLs (e.g. ["jbhifi.com.au", "amazon.com.au"]) */
  sites?: string[];
  /** Enable structured product/offer extraction & grouping (default: true when category === "shopping") */
  productMode?: boolean;
  /** Allow headless browser / sandbox escalation on bot-gated candidate product pages (default: false) */
  allowBrowserEscalation?: boolean;
  /** Free-text ranking instruction passed to the decision model */
  customInstruction?: string;
  /** When true, mustIncludeTerms / excludeTerms hard-drop candidates instead of only lowering scores */
  strict?: boolean;
}

export const SEARCH_PROVIDER_CHOICES = ["auto", "ddg", "jina", "serper", "brave"] as const;
export type SearchProviderChoice = (typeof SEARCH_PROVIDER_CHOICES)[number];
/** Providers that bill an extra credit when they serve the search. */
export const PAID_SEARCH_PROVIDERS: ReadonlySet<string> = new Set(["jina", "serper", "brave"]);
export const SEARCH_PROVIDER_ENV_KEYS: Record<string, string> = {
  jina: "JINA_API_KEY",
  serper: "SERPER_API_KEY",
  brave: "BRAVE_SEARCH_API_KEY",
};

export interface SearchRequest {
  query: string;
  limit?: number;
  tbs?: string;
  lang?: string;
  country?: string;
  region?: string;
  city?: string;
  timezone?: string;
  location?: string | UserLocationContext;
  /** Any category string; see GET /v1/search/categories for the built-in catalog */
  category?: string;
  /** Any subcategory string(s) within the category */
  subcategory?: string | string[];
  /** Legacy multi-category list; first entry is used when `category` is unset */
  categories?: string[];
  filters?: SearchAgentFilters;
  includeDomains?: string[];
  excludeDomains?: string[];
  bypassCache?: boolean;
  /**
   * Pick one search provider and skip the default multi-engine pipeline.
   * `auto` (default) uses the free engines and falls back to a keyed provider when results are thin.
   */
  provider?: SearchProviderChoice;
  rankOptions?: {
    useDecisionModel?: boolean;
    decisionModel?: DecisionModelId;
    decisionTimeoutMs?: number;
    quorumTimeoutMs?: number;
    maxPerDomain?: number;
  };
  scrapeOptions?: {
    formats?: Array<"markdown" | "links" | "html">;
    retainImages?: "all" | "none";
    scrapeTimeoutMs?: number;
  };
}

export interface SearchResultItem {
  title: string;
  url: string;
  canonicalUrl?: string;
  description: string;
  markdown?: string;
  links?: string[];
  publishedDate?: string;
  score?: number;
  rank?: number;
  sources?: SearchEngineSource[];
  highlights?: string[];
  scoreBreakdown?: DocumentScoreBreakdown;
  offer?: ProductOffer;
  listings?: PropertyListing[];
  flights?: FlightOffer[];
  hotels?: HotelListing[];
  businesses?: BusinessListing[];
  /** CVE records this page is the record for, or mentions (category === "security") */
  cves?: CveRecord[];
}

export interface SearchResponse {
  success: boolean;
  data: SearchResultItem[];
  /** Structured product clusters with normalized multi-vendor offers and lowest-price `bestOffer` (populated by default when category === "shopping" or filters.productMode === true) */
  products?: AggregatedProduct[];
  /** Flat list of all extracted product offers across engines and candidate pages */
  offers?: ProductOffer[];
  /** Structured real-estate property listings with address, price, beds/baths/parking, propertyType, portal, and agency (populated when category === "real-estate") */
  listings?: PropertyListing[];
  /** Structured flight offers with airline, origin, destination, duration, stops, cabinClass, and fare price (populated when category === "flights") */
  flights?: FlightOffer[];
  /** Structured hotel and accommodation listings with nightly rate, star/guest ratings, address, and amenities (populated when category === "hotels") */
  hotels?: HotelListing[];
  /** Structured business and company listings with category, address, phone, rating, hours, and website (populated when category === "business") */
  businesses?: BusinessListing[];
  /** Structured CVE records from NVD and OSV: CVSS score and severity, CWE, affected products and versions, fixed versions, CISA KEV flag, dates and references (populated when category === "security") */
  cves?: CveRecord[];
  provider: "native-federated" | "brave" | "serper" | "jina" | "ddg-edge";
  /** Set when a keyless search returns no hits (engines blocked or empty). */
  error?: string;
  /** Set when the primary engines came back thin and a paid fallback engine filled in. */
  fallback?: "jina";
  cached?: boolean;
  latencyMs: number;
  userLocation?: UserLocationContext;
  rankingMetrics?: {
    totalCandidates: number;
    uniqueCandidates: number;
    lexicalLatencyMs: number;
    decisionLatencyMs: number;
    totalRankingLatencyMs: number;
    decisionModelUsed: string | null;
    enginesContributing: SearchEngineSource[];
  };
}

export interface CategoryDefinition {
  description: string;
  engines: SearchEngineSource[];
  /** Where to localize the upstream query by default */
  localizeBy: "city" | "country" | "none";
  preferLocalDomains: boolean;
  subcategories: Record<string, { description: string }>;
}

/** Declarative category catalog. Categories/subcategories passed by agents are free-form; this is only the default engine plan. */
export const SEARCH_CATEGORY_CATALOG: Record<string, CategoryDefinition> = {
  general: {
    description: "Broad web search across general-purpose engines.",
    engines: ["brave-native", "ddg-lite", "wikipedia", "hn-algolia", "bing-rss"],
    localizeBy: "none",
    preferLocalDomains: false,
    subcategories: {
      reference: { description: "Encyclopedic / reference answers" },
      howto: { description: "Guides and tutorials" },
    },
  },
  news: {
    description:
      "Recent news and current events, localized to the user's news edition (country).",
    engines: ["google-news-rss", "brave-native", "ddg-lite"],
    // Never append the city: "paris" + "Sydney" turns a news query into flights.
    // Google News localizes through its edition (gl/hl/ceid) instead.
    localizeBy: "none",
    preferLocalDomains: true,
    subcategories: {
      local: { description: "Local news" },
      world: { description: "International news" },
      business: { description: "Business and finance news" },
      sports: { description: "Sports news" },
    },
  },
  shopping: {
    description:
      "Product-oriented shopping search with live multi-retailer prices, normalized offers, and bestOffer comparison, localized to the user's country.",
    engines: ["bing-shopping", "google-shopping", "brave-native", "ddg-lite"],
    localizeBy: "country",
    preferLocalDomains: true,
    subcategories: {
      deals: { description: "Discounts and promotions" },
      "price-comparison": { description: "Compare prices across retailers" },
      reviews: { description: "Product reviews" },
    },
  },
  "real-estate": {
    description:
      "Real-estate property search with structured listings (address, price, bedrooms, bathrooms, parking, property type, agency, and portal URL), localized to the user's city/country.",
    engines: ["brave-native", "ddg-lite"],
    localizeBy: "city",
    preferLocalDomains: true,
    subcategories: {
      buy: { description: "Properties for sale" },
      rent: { description: "Properties for rent / lease" },
      sold: { description: "Recently sold properties and sale prices" },
      commercial: { description: "Commercial real estate" },
      land: { description: "Vacant land and house-and-land packages" },
    },
  },
  flights: {
    description:
      "Flight search with structured fare offers (airline, origin, destination, duration, stops, cabin class, and fare price), localized to the user's country.",
    engines: ["brave-native", "ddg-lite"],
    localizeBy: "country",
    preferLocalDomains: true,
    subcategories: {
      "one-way": { description: "One-way flight fares" },
      "round-trip": { description: "Round-trip / return flight fares" },
      nonstop: { description: "Direct / nonstop flights" },
      "business-class": {
        description: "Business and first class cabin fares",
      },
      "cheap-flights": {
        description: "Low-cost carriers and budget flight deals",
      },
      status: { description: "Live flight status, schedules, and routes" },
    },
  },
  hotels: {
    description:
      "Hotel and accommodation search with structured nightly rates, star & guest ratings, review counts, address, and amenities, localized to the user's city/country.",
    engines: ["brave-native", "ddg-lite"],
    localizeBy: "city",
    preferLocalDomains: true,
    subcategories: {
      luxury: { description: "5-star luxury hotels and resorts" },
      budget: { description: "Budget hotels, motels, and hostels" },
      resorts: { description: "Beach, ski, and spa resorts" },
      apartments: {
        description: "Serviced apartments, suites, and vacation rentals",
      },
      "pet-friendly": { description: "Pet-friendly hotels and stays" },
      "last-minute": { description: "Last-minute hotel deals" },
    },
  },
  business: {
    description:
      "Local business, service provider, restaurant, and company directory search with structured contact details, address, ratings, opening hours, and website.",
    engines: ["brave-native", "ddg-lite"],
    localizeBy: "city",
    preferLocalDomains: true,
    subcategories: {
      local: { description: "Local shops, trades, and neighborhood services" },
      restaurants: {
        description: "Restaurants, cafes, bars, and dining",
      },
      services: {
        description:
          "Home and professional services (plumbers, electricians, cleaners)",
      },
      b2b: { description: "B2B vendors, SaaS companies, and agencies" },
      "company-profile": {
        description: "Company headquarters, leadership, and corporate info",
      },
      healthcare: {
        description: "Doctors, dentists, clinics, and medical practices",
      },
      legal: { description: "Law firms, solicitors, and legal services" },
    },
  },
  academic: {
    description: "Research papers, ArXiv preprints, and scholarly literature.",
    engines: ["arxiv"],
    localizeBy: "none",
    preferLocalDomains: false,
    subcategories: {
      papers: { description: "Preprints and peer-reviewed research papers" },
      arxiv: { description: "ArXiv preprints in CS, AI/ML, physics, and mathematics" },
      ml: { description: "Machine learning, AI, and NLP conference papers (NeurIPS, ICML, ICLR, ACL)" },
      pubmed: { description: "Biomedical and life-sciences literature (PubMed / PMC)" },
      math: { description: "Mathematics, statistics, and theoretical physics papers" },
    },
  },
  tech: {
    description: "Software, developer and technology content.",
    engines: ["brave-native", "ddg-lite", "wikipedia", "hn-algolia"],
    localizeBy: "none",
    preferLocalDomains: false,
    subcategories: {
      code: { description: "Code and documentation" },
      discussion: { description: "Developer discussions" },
    },
  },
  security: {
    description:
      "Vulnerabilities and security advisories. Returns structured CVE records (CVSS, affected and fixed versions, KEV) from NVD and OSV.",
    engines: ["nvd", "osv", "brave-native", "ddg-lite"],
    localizeBy: "none",
    preferLocalDomains: false,
    subcategories: {
      cve: { description: "CVE records by id, product or package (e.g. CVE-2024-3094, openssl, lodash npm)" },
      advisories: { description: "Vendor and GitHub security advisories" },
      exploits: { description: "Exploitation reports and proof-of-concept write-ups" },
    },
  },
};

export function resolveCategory(req: SearchRequest): string {
  const raw = (req.category || req.categories?.[0] || "").trim().toLowerCase();
  if (
    raw === "realestate" ||
    raw === "real_estate" ||
    raw === "property" ||
    raw === "properties" ||
    raw === "housing" ||
    raw === "homes" ||
    raw === "rentals"
  ) {
    return "real-estate";
  }
  if (
    raw === "flight" ||
    raw === "flights" ||
    raw === "airfare" ||
    raw === "airlines" ||
    raw === "airline"
  ) {
    return "flights";
  }
  if (
    raw === "hotel" ||
    raw === "hotels" ||
    raw === "accommodation" ||
    raw === "lodging" ||
    raw === "stays" ||
    raw === "resorts"
  ) {
    return "hotels";
  }
  if (
    raw === "business" ||
    raw === "businesses" ||
    raw === "local-business" ||
    raw === "local_business" ||
    raw === "company" ||
    raw === "companies" ||
    raw === "directory" ||
    raw === "restaurants"
  ) {
    return "business";
  }
  if (
    raw === "academic" ||
    raw === "paper" ||
    raw === "papers" ||
    raw === "research" ||
    raw === "arxiv" ||
    raw === "scholar" ||
    raw === "scholarly" ||
    raw === "science"
  ) {
    return "academic";
  }
  if (
    raw === "cve" ||
    raw === "cves" ||
    raw === "vulnerability" ||
    raw === "vulnerabilities" ||
    raw === "vuln" ||
    raw === "vulns" ||
    raw === "infosec" ||
    raw === "advisories"
  ) {
    return "security";
  }
  if (raw && raw !== "general") {
    return raw;
  }
  // Auto-detect vertical intent when category is omitted or "general"
  const q = (req.query || "").toLowerCase();
  if (/\b(cve-\d{4}-\d{4,7}|ghsa(?:-[a-z0-9]{4}){3})\b/.test(q)) {
    return "security";
  }
  if (
    /\b(houses?|homes?|apartments?|flats?|townhouses?|units?|villas?|condos?|duplex(?:es)?|land|property|properties|real\s+estate)\b/.test(
      q
    ) &&
    /\b(for\s+sale|for\s+rent|to\s+rent|for\s+lease|sold|recently\s+sold|buy|rent|rental|auction|bedroom|bed)\b/.test(
      q
    )
  ) {
    return "real-estate";
  }
  if (
    /\b(flights?\s+(?:from|to|between)|cheap\s+flights?|direct\s+flights?|nonstop\s+flights?|airfare|round[\s-]trip\s+flights?|one[\s-]way\s+flights?|fly\s+from)\b/.test(
      q
    )
  ) {
    return "flights";
  }
  if (
    /\b(hotels?\s+in|best\s+hotels?|cheap\s+hotels?|luxury\s+hotels?|resorts?\s+in|where\s+to\s+stay\s+in|boutique\s+hotels?|5[\s-]star\s+hotels?|accommodation\s+in)\b/.test(
      q
    )
  ) {
    return "hotels";
  }
  if (
    /\b(best\s+(?:restaurants?|cafes?|coffee\s+shops?|plumbers?|electricians?|dentists?|lawyers?|mechanics?|gyms?|salons?|barbers?|accountants?|clinics?)\s+(?:in|near)|near\s+me|opening\s+hours|phone\s+number\s+for)\b/.test(
      q
    )
  ) {
    return "business";
  }
  return raw || "general";
}

export function planEngines(
  category: string,
  filters?: SearchAgentFilters
): SearchEngineSource[] {
  const base = (
    SEARCH_CATEGORY_CATALOG[category] ?? SEARCH_CATEGORY_CATALOG.general
  ).engines;
  let plan = filters?.engines?.length ? [...filters.engines] : [...base];
  if (filters?.excludeEngines?.length) {
    const excluded = filters.excludeEngines;
    plan = plan.filter((e) => !excluded.includes(e));
  }
  return plan;
}

/** DuckDuckGo region param (`kl`) derived from ISO-3166 country + language. */
export function ddgRegion(country?: string, lang?: string): string | undefined {
  if (!country || country.length !== 2) {
    return undefined;
  }
  const cc = country.toLowerCase();
  const DDG_REGION_MAP: Record<string, string> = {
    eu: "wt-wt",
    gb: "uk-en",
    uk: "uk-en",
    au: "au-en",
    us: "us-en",
    ca: "ca-en",
    nz: "nz-en",
    ie: "ie-en",
    sg: "sg-en",
    in: "in-en",
    vn: "vn-en",
    my: "my-en",
    ph: "ph-en",
    hk: "hk-tzh",
    de: "de-de",
    fr: "fr-fr",
    es: "es-es",
    it: "it-it",
    nl: "nl-nl",
    pl: "pl-pl",
    se: "se-sv",
    no: "no-no",
    dk: "dk-da",
    fi: "fi-fi",
    pt: "pt-pt",
    ch: "ch-de",
    at: "at-de",
    be: "be-fr",
    jp: "jp-jp",
    kr: "kr-kr",
    th: "th-en",
    id: "id-en",
  };
  if (lang) {
    const cleanLang = lang.toLowerCase().slice(0, 2);
    return `${cc === "gb" ? "uk" : cc}-${cleanLang}`;
  }
  return DDG_REGION_MAP[cc] || `${cc}-en`;
}

export function getSearchCategoriesCatalog() {
  return {
    categories: Object.entries(SEARCH_CATEGORY_CATALOG).map(([id, def]) => ({
      id,
      ...def,
      subcategories: Object.entries(def.subcategories).map(([sid, s]) => ({
        id: sid,
        ...s,
      })),
    })),
    notes:
      "`category` and `subcategory` accept any string; unknown categories fall back to the general engine plan.",
    filters: {
      engines: "SearchEngineSource[]: override engine plan",
      excludeEngines: "SearchEngineSource[]",
      preferLocalDomains: "boolean",
      localizeBy: "auto | city | country | region | none",
      mustIncludeTerms: "string[]",
      excludeTerms: "string[]",
      boostTerms: "string[]",
      includeDomains:
        "string[]: post-fetch host allowlist (supports subdomains)",
      excludeDomains:
        "string[]: post-fetch host blocklist (supports subdomains)",
      sites:
        "string[]: target specific retailer domains or URLs (e.g. ['jbhifi.com.au', 'amazon.com.au'])",
      productMode:
        "boolean: return structured products[] and offers[] with prices (default true for category='shopping')",
      allowBrowserEscalation:
        "boolean: allow headless browser escalation on blocked candidate pages (default false)",
      customInstruction: "string: ranking hint for decision model",
      strict:
        "boolean: hard-drop results that miss mustIncludeTerms or match excludeTerms (default false = score penalty only)",
    },
  };
}

export function normalizeHostList(domainsOrUrls?: string[]): string[] {
  if (!domainsOrUrls?.length) {
    return [];
  }
  const out: string[] = [];
  for (const raw of domainsOrUrls) {
    const trimmed = (raw || "").trim().toLowerCase();
    if (!trimmed) {
      continue;
    }
    if (trimmed.includes("://")) {
      const h = extractDomainHost(trimmed);
      if (h) {
        out.push(h);
      }
    } else {
      const h = trimmed
        .replace(/^www\./i, "")
        .split("/")[0]
        .trim();
      if (h) {
        out.push(h);
      }
    }
  }
  return Array.from(new Set(out));
}

export function hostMatchesAny(
  urlOrHost: string,
  allowedHosts: string[]
): boolean {
  if (!allowedHosts.length) {
    return true;
  }
  const host = urlOrHost.includes("://")
    ? extractDomainHost(urlOrHost)
    : urlOrHost.replace(/^www\./i, "").toLowerCase();
  if (!host) {
    return false;
  }
  return allowedHosts.some(
    (target) => host === target || host.endsWith(`.${target}`)
  );
}

const COUNTRY_NAME_TO_CODE: Record<string, string> = {
  australia: "AU",
  "united states": "US",
  usa: "US",
  "united kingdom": "GB",
  uk: "GB",
  britain: "GB",
  england: "GB",
  europe: "EU",
  "european union": "EU",
  india: "IN",
  singapore: "SG",
  vietnam: "VN",
  "viet nam": "VN",
  germany: "DE",
  france: "FR",
  italy: "IT",
  spain: "ES",
  netherlands: "NL",
  switzerland: "CH",
  sweden: "SE",
  norway: "NO",
  denmark: "DK",
  poland: "PL",
  ireland: "IE",
  austria: "AT",
  belgium: "BE",
  portugal: "PT",
  finland: "FI",
  canada: "CA",
  "new zealand": "NZ",
  japan: "JP",
  "south korea": "KR",
  korea: "KR",
  thailand: "TH",
  malaysia: "MY",
  indonesia: "ID",
  philippines: "PH",
  "hong kong": "HK",
  taiwan: "TW",
  uae: "AE",
  "united arab emirates": "AE",
};

function normalizeCountryInput(raw?: string): {
  code?: string;
  countryName?: string;
  cityHint?: string;
} {
  if (!raw || !raw.trim()) {
    return {};
  }
  const clean = raw.trim();
  if (clean.length === 2) {
    const upper = clean.toUpperCase();
    return {
      code: upper === "UK" ? "GB" : upper,
      ...(upper === "EU" ? { countryName: "Europe" } : {}),
      ...(upper === "SG" ? { cityHint: "Singapore" } : {}),
    };
  }
  const mapped = COUNTRY_NAME_TO_CODE[clean.toLowerCase()];
  if (mapped) {
    return {
      code: mapped,
      countryName: clean,
      ...(mapped === "SG" ? { cityHint: "Singapore" } : {}),
    };
  }
  return {};
}

export function resolveUserLocation(req: SearchRequest): UserLocationContext {
  const loc: UserLocationContext = {};

  if (typeof req.location === "string" && req.location.trim()) {
    const parts = req.location
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    if (parts.length === 1) {
      const norm = normalizeCountryInput(parts[0]);
      if (norm.code) {
        loc.country = norm.code;
        if (norm.countryName) {
          loc.countryName = norm.countryName;
        }
        if (norm.cityHint && !loc.city) {
          loc.city = norm.cityHint;
        }
      } else {
        loc.city = parts[0];
      }
    } else if (parts.length === 2) {
      loc.city = parts[0];
      const norm = normalizeCountryInput(parts[1]);
      loc.country = norm.code || parts[1];
      if (norm.countryName) {
        loc.countryName = norm.countryName;
      }
    } else if (parts.length >= 3) {
      loc.city = parts[0];
      loc.region = parts[1];
      const norm = normalizeCountryInput(parts[parts.length - 1]);
      loc.country = norm.code || parts[parts.length - 1];
      if (norm.countryName) {
        loc.countryName = norm.countryName;
      }
    }
  } else if (req.location && typeof req.location === "object") {
    Object.assign(loc, req.location);
  }

  if (req.country) {
    const norm = normalizeCountryInput(req.country);
    loc.country = norm.code || req.country.trim().toUpperCase();
    if (norm.countryName && !loc.countryName) {
      loc.countryName = norm.countryName;
    }
    if (norm.cityHint && !loc.city && !req.city) {
      loc.city = norm.cityHint;
    }
  }
  if (req.region) {
    loc.region = req.region.trim();
  }
  if (req.city) {
    loc.city = req.city.trim();
  }
  if (req.timezone) {
    loc.timezone = req.timezone.trim();
  }

  // Infer city from IANA timezone (e.g. "Australia/Sydney" -> Sydney) when nothing else is known
  if (loc.timezone && !loc.city && !loc.country && loc.timezone.includes("/")) {
    loc.city = loc.timezone.split("/").pop()?.replace(/_/g, " ");
  }

  return loc;
}
