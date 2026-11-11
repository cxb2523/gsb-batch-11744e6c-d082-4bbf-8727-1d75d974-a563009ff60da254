import type {
  RawCandidateDocument,
  SearchEngineSource,
  SearchFilterContext,
  UserLocationContext,
} from "./types.js";

const ENGINE_WEIGHTS: Record<SearchEngineSource, number> = {
  "google-shopping": 1.38,
  "bing-shopping": 1.35,
  serper: 1.35,
  "brave-api": 1.3,
  jina: 1.3,
  "brave-native": 1.25,
  "ddg-lite": 1.15,
  "bing-rss": 1.12,
  "google-news-rss": 1.05,
  wikipedia: 1.1,
  "hn-algolia": 1.0,
  arxiv: 1.05,
  // Authoritative vulnerability databases: rank their record pages above write-ups.
  nvd: 1.4,
  osv: 1.3,
};

const STOPWORDS = new Set([
  "a",
  "an",
  "and",
  "are",
  "as",
  "at",
  "be",
  "by",
  "for",
  "from",
  "has",
  "he",
  "in",
  "is",
  "it",
  "its",
  "of",
  "on",
  "or",
  "that",
  "the",
  "to",
  "was",
  "were",
  "will",
  "with",
  "what",
  "when",
  "where",
  "who",
  "why",
  "how",
  "can",
  "we",
  "you",
  "your",
  "this",
  "these",
  "those",
  "into",
  "about",
  "over",
  "after",
  "before",
]);

const TRACKING_PARAMS = new Set([
  "utm_source",
  "utm_medium",
  "utm_campaign",
  "utm_term",
  "utm_content",
  "fbclid",
  "gclid",
  "msclkid",
  "mc_cid",
  "mc_eid",
  "ref",
  "ref_src",
]);

/**
 * Canonicalize a URL for cross-engine deduplication and RRF fusion.
 */
export function canonicalizeUrl(rawUrl: string): string {
  try {
    const u = new URL(rawUrl.trim());
    u.hash = "";
    u.hostname = u.hostname.toLowerCase().replace(/^www\./, "");
    for (const key of Array.from(u.searchParams.keys())) {
      if (
        TRACKING_PARAMS.has(key.toLowerCase()) ||
        key.toLowerCase().startsWith("utm_")
      ) {
        u.searchParams.delete(key);
      }
    }
    if (u.pathname.length > 1 && u.pathname.endsWith("/")) {
      u.pathname = u.pathname.slice(0, -1);
    }
    return u.toString();
  } catch {
    return rawUrl.trim();
  }
}

/**
 * Fast 32-bit FNV-1a integer hash for zero-allocation token/trigram comparison.
 */
export function fnv1a32(str: string): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
}

/**
 * Ultra-fast Porter-style suffix stripper for English IR normalization.
 */
export function stemToken(word: string): string {
  if (word.length <= 3) {
    return word;
  }
  let w = word;
  if (w.endsWith("ies") && w.length > 4) {
    return w.slice(0, -3) + "y";
  }
  if (w.endsWith("es") && w.length > 4 && /(ches|shes|xes|zes|ses)$/.test(w)) {
    return w.slice(0, -2);
  }
  if (
    w.endsWith("s") &&
    !w.endsWith("ss") &&
    !w.endsWith("us") &&
    !w.endsWith("is")
  ) {
    w = w.slice(0, -1);
  }
  if (w.endsWith("ing") && w.length > 5) {
    w = w.slice(0, -3);
  } else if (w.endsWith("ed") && w.length > 4) {
    w = w.slice(0, -2);
  } else if (w.endsWith("ational") && w.length > 8) {
    w = w.slice(0, -5) + "e";
  } else if (w.endsWith("tion") && w.length > 6) {
    w = w.slice(0, -3);
  } else if (w.endsWith("ment") && w.length > 6) {
    w = w.slice(0, -4);
  } else if (w.endsWith("ness") && w.length > 6) {
    w = w.slice(0, -4);
  } else if (w.endsWith("ly") && w.length > 5) {
    w = w.slice(0, -2);
  }
  return w;
}

export interface TokenizedText {
  tokens: string[];
  hashes: Uint32Array;
  freqMap: Map<number, number>;
  trigramSet: Set<number>;
}

export function tokenizeAndHash(
  text: string,
  includeTrigrams = false
): TokenizedText {
  const normalized = text
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, " ")
    .split(/[\s-]+/)
    .filter((t) => t.length >= 2 && !STOPWORDS.has(t));

  const tokens = normalized.map(stemToken);
  const hashes = new Uint32Array(tokens.length);
  const freqMap = new Map<number, number>();
  const trigramSet = new Set<number>();

  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i];
    const h = fnv1a32(tok);
    hashes[i] = h;
    freqMap.set(h, (freqMap.get(h) ?? 0) + 1);

    if (includeTrigrams) {
      const padded = `^${tok}$`;
      for (let j = 0; j <= padded.length - 3; j++) {
        trigramSet.add(fnv1a32(padded.slice(j, j + 3)));
      }
    }
  }

  return { tokens, hashes, freqMap, trigramSet };
}

/**
 * Stage 2: Weighted Reciprocal Rank Fusion (W-RRF) across heterogeneous engines.
 * Formula: RRF(d) = sum_{e in Engines} w_e / (k + rank_e(d))
 */
export function fuseWithWeightedRrf(
  rawCandidates: RawCandidateDocument[],
  rrfK = 60
): {
  merged: Array<{
    doc: RawCandidateDocument;
    canonicalUrl: string;
    sources: SearchEngineSource[];
    engineRanks: Partial<Record<SearchEngineSource, number>>;
    rrfRaw: number;
  }>;
  enginesContributing: SearchEngineSource[];
} {
  const byUrl = new Map<
    string,
    {
      doc: RawCandidateDocument;
      canonicalUrl: string;
      sources: SearchEngineSource[];
      engineRanks: Partial<Record<SearchEngineSource, number>>;
      rrfRaw: number;
    }
  >();
  const engineSet = new Set<SearchEngineSource>();

  rawCandidates.forEach((cand, idx) => {
    const canonical = canonicalizeUrl(cand.url || `doc:${idx}`);
    const engine: SearchEngineSource = cand.engine || "ddg-lite";
    const rank = cand.engineRank ?? idx + 1;
    const weight = ENGINE_WEIGHTS[engine] ?? 1.0;
    const rrfContribution = weight / (rrfK + rank);

    engineSet.add(engine);

    const existing = byUrl.get(canonical);
    if (!existing) {
      const sources = cand.sources
        ? Array.from(new Set([...cand.sources, engine]))
        : [engine];
      byUrl.set(canonical, {
        doc: { ...cand },
        canonicalUrl: canonical,
        sources,
        engineRanks: { ...(cand.engineRanks || {}), [engine]: rank },
        rrfRaw: rrfContribution,
      });
    } else {
      if (!existing.sources.includes(engine)) {
        existing.sources.push(engine);
      }
      const prevRank = existing.engineRanks[engine];
      if (prevRank === undefined || rank < prevRank) {
        existing.engineRanks[engine] = rank;
        existing.rrfRaw += rrfContribution;
      }
      // Keep richest title/description/markdown
      if ((cand.title?.length || 0) > (existing.doc.title?.length || 0)) {
        existing.doc.title = cand.title;
      }
      if (
        (cand.description?.length || 0) >
        (existing.doc.description?.length || 0)
      ) {
        existing.doc.description = cand.description;
      }
      if (
        cand.markdown &&
        (!existing.doc.markdown ||
          cand.markdown.length > existing.doc.markdown.length)
      ) {
        existing.doc.markdown = cand.markdown;
      }
      if (cand.publishedDate && !existing.doc.publishedDate) {
        existing.doc.publishedDate = cand.publishedDate;
      }
    }
  });

  // Apply multi-engine consensus bonus (+12% per additional independent search engine)
  const merged = Array.from(byUrl.values()).map((entry) => {
    const consensusMultiplier =
      1 + Math.min(entry.sources.length - 1, 4) * 0.12;
    return {
      ...entry,
      rrfRaw: entry.rrfRaw * consensusMultiplier,
    };
  });

  return {
    merged,
    enginesContributing: Array.from(engineSet),
  };
}

/**
 * Extract headings (H1-H3) from Markdown text for fielded BM25F scoring.
 */
export function extractMarkdownHeadings(markdown?: string): string {
  if (!markdown) {
    return "";
  }
  const matches = markdown.match(/^#{1,3}\s+.+$/gm);
  return matches ? matches.join(" ") : "";
}

/**
 * Stage 4a: ColBERT-inspired Subword + Token MaxSim Passage Scorer & Highlight Extractor.
 * Splits document into semantic blocks and computes maximum late-interaction similarity
 * per query token + minimum window proximity.
 */
export function computePassageMaxSimAndHighlights(
  queryTok: TokenizedText,
  rawQueryLower: string,
  doc: RawCandidateDocument,
  maxHighlights = 2
): { maxSimScore: number; highlights: string[] } {
  const sourceText = [doc.description || "", doc.markdown || ""]
    .filter(Boolean)
    .join("\n\n");
  if (!sourceText.trim() || queryTok.hashes.length === 0) {
    return {
      maxSimScore: 0,
      highlights: doc.description ? [doc.description.slice(0, 320)] : [],
    };
  }

  // Segment into semantic blocks (~150-500 chars) without ES2018 lookbehind
  const rawBlocks = sourceText
    .replace(/([.!?])\s+(?=[A-Z0-9#*\-[])/g, "$1\n\n")
    .split(/\n{2,}/g)
    .map((blk) => blk.replace(/\s+/g, " ").trim())
    .filter((blk) => blk.length >= 25);

  const blocks =
    rawBlocks.length > 0 ? rawBlocks.slice(0, 32) : [sourceText.slice(0, 500)];

  // Pre-build per-query-token trigram sets for subword matching
  const queryTokenTrigrams: Array<Set<number>> = queryTok.tokens.map((tok) => {
    const set = new Set<number>();
    const padded = `^${tok}$`;
    for (let j = 0; j <= padded.length - 3; j++) {
      set.add(fnv1a32(padded.slice(j, j + 3)));
    }
    return set;
  });

  const scoredBlocks: Array<{ text: string; score: number }> = [];

  for (const block of blocks) {
    const bTok = tokenizeAndHash(block, true);
    if (bTok.hashes.length === 0) {
      continue;
    }

    // ColBERT MaxSim: for each query term, find maximum similarity across all tokens in block
    let sumMaxSim = 0;
    for (let qi = 0; qi < queryTok.hashes.length; qi++) {
      const qHash = queryTok.hashes[qi];
      if (bTok.freqMap.has(qHash)) {
        // Exact stemmed token match = 1.0
        sumMaxSim += 1.0;
      } else {
        // Subword character 3-gram Dice overlap
        const qTris = queryTokenTrigrams[qi];
        if (qTris.size > 0) {
          let overlap = 0;
          for (const tri of qTris) {
            if (bTok.trigramSet.has(tri)) {
              overlap++;
            }
          }
          const subwordSim = overlap / qTris.size;
          if (subwordSim > 0.35) {
            sumMaxSim += subwordSim * 0.75;
          }
        }
      }
    }

    let blockScore = sumMaxSim / queryTok.hashes.length;
    if (
      rawQueryLower.length >= 4 &&
      block.toLowerCase().includes(rawQueryLower)
    ) {
      blockScore = Math.min(1, blockScore + 0.25);
    }

    scoredBlocks.push({ text: block, score: blockScore });
  }

  if (scoredBlocks.length === 0) {
    return {
      maxSimScore: 0,
      highlights: doc.description ? [doc.description.slice(0, 320)] : [],
    };
  }

  scoredBlocks.sort((a, b) => b.score - a.score);
  const top1 = scoredBlocks[0].score;
  const top2 = scoredBlocks[1]?.score ?? top1;
  // KeyB2+ style Top-1 + Top-2 block aggregation
  const maxSimScore = Math.min(1, top1 * 0.7 + top2 * 0.3);

  const highlights: string[] = [];
  for (const b of scoredBlocks) {
    if (highlights.length >= maxHighlights) {
      break;
    }
    const clipped = b.text.length > 360 ? `${b.text.slice(0, 357)}...` : b.text;
    if (!highlights.includes(clipped)) {
      highlights.push(clipped);
    }
  }

  return { maxSimScore, highlights };
}

/**
 * Stage 4b: Exact phrase, ordered bigram, and minimum window proximity score.
 */
export function computeProximityAndExactScore(
  queryTok: TokenizedText,
  rawQueryLower: string,
  titleTok: TokenizedText,
  descTok: TokenizedText,
  rawTitleLower: string,
  rawDescLower: string
): number {
  if (queryTok.hashes.length === 0) {
    return 0;
  }
  let score = 0;

  // 1. Exact phrase match in title or description
  if (rawQueryLower.length >= 3) {
    if (rawTitleLower.includes(rawQueryLower)) {
      score += 0.55;
    }
    if (rawDescLower.includes(rawQueryLower)) {
      score += 0.3;
    }
  }

  // 2. Ordered query bi-grams in title + description
  if (queryTok.hashes.length >= 2) {
    const combined = new Uint32Array(
      titleTok.hashes.length + descTok.hashes.length
    );
    combined.set(titleTok.hashes, 0);
    combined.set(descTok.hashes, titleTok.hashes.length);

    let matchedBigrams = 0;
    const totalBigrams = queryTok.hashes.length - 1;
    for (let qi = 0; qi < totalBigrams; qi++) {
      const h1 = queryTok.hashes[qi];
      const h2 = queryTok.hashes[qi + 1];
      for (let ci = 0; ci < combined.length - 1; ci++) {
        if (
          combined[ci] === h1 &&
          (combined[ci + 1] === h2 || combined[ci + 2] === h2)
        ) {
          matchedBigrams++;
          break;
        }
      }
    }
    score += 0.35 * (matchedBigrams / totalBigrams);
  } else {
    // Single-term query: check title hit
    if (titleTok.freqMap.has(queryTok.hashes[0])) {
      score += 0.5;
    }
  }

  return Math.min(1, score);
}

/**
 * Extract effective publisher/domain key for domain diversity.
 * For Google News RSS redirect URLs (`news.google.com/rss/articles/...`), extracts the
 * actual publisher (`[Publisher]` or `- Publisher` suffix) so distinct news outlets
 * aren't collapsed under `news.google.com`, while true same-publisher pages share a key.
 */
export function extractPublisherDomainKey(
  canonicalUrl: string,
  title: string,
  description: string
): string {
  try {
    const u = new URL(canonicalUrl);
    const host = u.hostname.toLowerCase().replace(/^www\./, "");
    if (host === "news.google.com" && u.pathname.includes("/rss/articles/")) {
      const bracketMatch = description.match(/^\[([^\]]+)\]/);
      if (bracketMatch?.[1]) {
        return `publisher:${bracketMatch[1].trim().toLowerCase()}`;
      }
      const dashMatch = title.match(/\s[-|]\s([^-|]+)$/);
      if (dashMatch?.[1]) {
        return `publisher:${dashMatch[1].trim().toLowerCase()}`;
      }
    }
    return host;
  } catch {
    return canonicalUrl;
  }
}

/**
 * Compute token-set Jaccard + containment similarity in [0, 1] between two candidates
 * to detect near-duplicate headlines or syndicated wire stories.
 */
export function computeTokenSimilarity(
  setA: Set<number>,
  setB: Set<number>
): number {
  if (setA.size === 0 || setB.size === 0) {
    return 0;
  }
  let intersection = 0;
  for (const h of setA) {
    if (setB.has(h)) {
      intersection++;
    }
  }
  if (intersection === 0) {
    return 0;
  }
  const union = setA.size + setB.size - intersection;
  const jaccard = intersection / union;
  const minContainment = intersection / Math.min(setA.size, setB.size);
  return jaccard * 0.6 + minContainment * 0.4;
}

const regionDisplayNames =
  typeof Intl !== "undefined" && typeof Intl.DisplayNames === "function"
    ? new Intl.DisplayNames(["en"], { type: "region" })
    : null;

/**
 * Dynamically resolve an ISO 3166-1 alpha-2 country code (e.g. "AU", "GB", "JP", "BR")
 * into its full English name ("Australia", "United Kingdom", "Japan", "Brazil") using
 * standard runtime Intl.DisplayNames: zero hardcoded country tables.
 */
export function resolveCountryDisplayName(
  countryCode?: string
): string | undefined {
  if (!countryCode) {
    return undefined;
  }
  const clean = countryCode.trim().toUpperCase();
  if (clean.length !== 2) {
    return countryCode.trim();
  }
  if (clean === "EU") {
    return "Europe";
  }
  try {
    return regionDisplayNames?.of(clean) || clean;
  } catch {
    return clean;
  }
}

const EU_CCTLDS = new Set([
  "eu",
  "de",
  "fr",
  "it",
  "es",
  "nl",
  "be",
  "at",
  "ie",
  "pt",
  "fi",
  "se",
  "dk",
  "pl",
  "cz",
  "hu",
  "ro",
  "gr",
  "ch",
  "no",
  "uk",
  "gb",
]);

/**
 * Stage 4d: Dynamic Geolocation & Filter Affinity score in [0, 1].
 * Zero hardcoded retailer/city/country lists:
 * - Resolves country display name dynamically via `Intl.DisplayNames`
 * - Matches any 2-letter ccTLD algorithmically (`.${cc}`, `.com.${cc}`, `.co.${cc}`, `.org.${cc}`, `.net.${cc}`, `.gov.${cc}`)
 * - Penalizes foreign 2-letter ccTLDs when `preferLocalDomains` or user country is set
 * - Evaluates dynamic `userLocation` (`city`, `region`, `countryName`) and agent `filterContext` (`boostTerms`, `mustIncludeTerms`, `excludeTerms`)
 */
export function computeGeoAffinityScore(
  doc: RawCandidateDocument,
  canonicalUrl: string,
  userLocation?: UserLocationContext,
  filterContext?: SearchFilterContext
): number {
  const hasGeo = Boolean(
    userLocation &&
    (userLocation.country || userLocation.city || userLocation.region)
  );
  const hasFilterTerms = Boolean(
    filterContext?.boostTerms?.length ||
    filterContext?.mustIncludeTerms?.length ||
    filterContext?.excludeTerms?.length ||
    filterContext?.subcategory
  );
  if (!hasGeo && !hasFilterTerms) {
    return 0.5;
  }

  let score = 0.4;
  const countryCode = (userLocation?.country || "").trim().toUpperCase();
  const countryLower = countryCode.toLowerCase();
  const countryNameLower = (
    userLocation?.countryName ||
    resolveCountryDisplayName(countryCode) ||
    ""
  )
    .trim()
    .toLowerCase();
  const cityLower = (userLocation?.city || "").trim().toLowerCase();
  const regionLower = (userLocation?.region || "").trim().toLowerCase();
  const combinedText =
    `${doc.title || ""} ${doc.description || ""} ${canonicalUrl}`.toLowerCase();

  // 1. Algorithmic ccTLD check from ISO-3166 alpha-2 country code (no hardcoded TLD list)
  if (countryLower.length === 2) {
    try {
      const host = new URL(canonicalUrl).hostname
        .toLowerCase()
        .replace(/^www\./, "");
      const topLabel = host.split(".").pop() || "";
      // Note: 'uk' vs 'gb' is standard ISO-3166 / IANA ccTLD alias
      const matchesLocalCcTld =
        topLabel === countryLower ||
        (countryLower === "gb" && topLabel === "uk") ||
        (countryLower === "uk" && topLabel === "gb") ||
        (countryLower === "eu" && EU_CCTLDS.has(topLabel));

      if (matchesLocalCcTld) {
        score += 0.42;
      } else if (
        topLabel.length === 2 &&
        topLabel !== "io" &&
        topLabel !== "ai" &&
        topLabel !== "co" &&
        topLabel !== "tv" &&
        topLabel !== "me" &&
        topLabel !== "app"
      ) {
        // Foreign country-code TLD penalty when user has a different country
        score -= filterContext?.preferLocalDomains ? 0.28 : 0.16;
      }
    } catch {
      // ignore
    }
  }

  // 2. Dynamic city / region / country name match in document text or URL
  if (cityLower && cityLower.length >= 2 && combinedText.includes(cityLower)) {
    score += 0.32;
  }
  if (
    regionLower &&
    regionLower.length >= 2 &&
    combinedText.includes(regionLower)
  ) {
    score += 0.15;
  }
  if (
    countryNameLower &&
    countryNameLower.length >= 2 &&
    combinedText.includes(countryNameLower)
  ) {
    score += 0.22;
  }

  // 3. Dynamic subcategory / boostTerms / excludeTerms affinity
  const subcats = Array.isArray(filterContext?.subcategory)
    ? filterContext?.subcategory
    : filterContext?.subcategory
      ? [filterContext.subcategory]
      : [];
  for (const sub of subcats) {
    const cleanSub = sub.replace(/[-_]/g, " ").trim().toLowerCase();
    if (cleanSub && combinedText.includes(cleanSub)) {
      score += 0.14;
    }
  }

  if (filterContext?.boostTerms?.length) {
    for (const term of filterContext.boostTerms) {
      const t = term.trim().toLowerCase();
      if (t && combinedText.includes(t)) {
        score += 0.12;
      }
    }
  }

  return Math.max(0, Math.min(1, score));
}

/**
 * Stage 4c: Freshness & Domain Authority score.
 */
export function computeFreshnessAndAuthorityScore(
  doc: RawCandidateDocument,
  canonicalUrl: string
): number {
  let score = 0.5;

  // Clean URL structure & shallow depth bonus
  try {
    const u = new URL(canonicalUrl);
    if (u.protocol === "https:") {
      score += 0.08;
    }
    const segments = u.pathname.split("/").filter(Boolean);
    if (segments.length <= 2) {
      score += 0.1;
    } else if (segments.length >= 5) {
      score -= 0.08;
    }

    // High-signal documentation / technical / primary domains
    if (
      /\.(edu|gov|org)$/.test(u.hostname) ||
      /(github\.com|arxiv\.org|wikipedia\.org|developer\.mozilla\.org|vercel\.com|docs\.)/.test(
        u.hostname
      )
    ) {
      score += 0.14;
    }

    // Primary vulnerability sources (CVE records, advisories, vendor security bulletins)
    if (
      /(^|\.)(nvd\.nist\.gov|cve\.org|cve\.mitre\.org|osv\.dev|cisa\.gov)$/.test(u.hostname) ||
      (u.hostname === "github.com" && /^\/advisories\//.test(u.pathname)) ||
      /\/(security|advisories|security-advisories|vulnerabilities)(\/|$)/i.test(u.pathname)
    ) {
      score += 0.12;
    }
  } catch {
    // ignore
  }

  // Temporal freshness signal (2026 / 2025 or recent pubDate)
  const combinedMeta = `${doc.publishedDate || ""} ${doc.title || ""} ${doc.description || ""}`;
  if (/\b2026\b/.test(combinedMeta)) {
    score += 0.18;
  } else if (/\b2025\b/.test(combinedMeta)) {
    score += 0.1;
  }

  if (doc.publishedDate) {
    const parsedMs = Date.parse(doc.publishedDate);
    if (!Number.isNaN(parsedMs)) {
      const ageDays = Math.max(
        0,
        (Date.now() - parsedMs) / (1000 * 60 * 60 * 24)
      );
      if (ageDays <= 7) {
        score += 0.18;
      } else if (ageDays <= 30) {
        score += 0.12;
      } else if (ageDays <= 180) {
        score += 0.06;
      }
    }
  }

  return Math.max(0, Math.min(1, score));
}
