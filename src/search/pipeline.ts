import {
  fastHtmlToMarkdown,
  fetchWithTlsImpersonation,
  getCachedPage,
  setCachedPage,
  sha256,
} from "../engine/index.js";
import {
  dedupeBusinessListings,
  dedupeFlightOffers,
  dedupeHotelListings,
  dedupePropertyListings,
  extractBusinessListingFromSerpResult,
  extractBusinessListingsFromHtml,
  extractBusinessListingsWithScaleDown,
  extractDomainHost,
  extractFlightOfferFromSerpResult,
  extractFlightOffersFromHtml,
  extractFlightOffersWithScaleDown,
  extractHotelListingFromSerpResult,
  extractHotelListingsFromHtml,
  extractHotelListingsWithScaleDown,
  extractOfferFromSerpSnippet,
  extractOffersFromHtml,
  extractPropertyListingFromSerpResult,
  extractPropertyListingsFromHtml,
  extractPropertyListingsWithScaleDown,
  groupOffersIntoProducts,
  type AggregatedProduct,
  type BusinessListing,
  type CveRecord,
  type FlightOffer,
  type HotelListing,
  type ProductOffer,
  type PropertyListing,
  extractCveIdsFromText,
  mergeCveRecords,
  normalizeCveId,
  sortCveRecords,
} from "../extract/index.js";
import {
  rankDocuments,
  resolveCountryDisplayName,
  type DecisionModelId,
  type SearchFilterContext,
} from "../ranker/index.js";
import {
  browserEscalationAvailable,
  escalateToSandboxOrBrowser,
} from "../sandbox.js";

const HOTEL_OTA_HOSTS = [
  "booking.com",
  "agoda.com",
  "hotels.com",
  "expedia.com",
  "expedia.com.au",
  "tripadvisor.com",
  "tripadvisor.com.au",
  "trivago.com",
  "kayak.com",
  "trip.com",
];

function isHotelOta(url: string): boolean {
  return hostMatchesAny(url, HOTEL_OTA_HOSTS);
}
import {
  hostMatchesAny,
  normalizeHostList,
  resolveCategory,
  resolveUserLocation,
  SEARCH_CATEGORY_CATALOG,
  type SearchRequest,
  type SearchResponse,
  type SearchResultItem,
} from "./catalog.js";
import {
  EMPTY_SEARCH_ERROR,
  fetchHedgedNativeFederation,
  fetchJinaSearch,
  fetchNvdByIds,
} from "./providers.js";
import { runInBackground, upsertCves } from "../extract/cve-cache.js";

const searchCache = new Map<
  string,
  {
    data: SearchResultItem[];
    products?: AggregatedProduct[];
    offers?: ProductOffer[];
    listings?: PropertyListing[];
    flights?: FlightOffer[];
    hotels?: HotelListing[];
    businesses?: BusinessListing[];
    cves?: CveRecord[];
    provider: SearchResponse["provider"];
    rankingMetrics?: SearchResponse["rankingMetrics"];
    expiresAt: number;
  }
>();
const SEARCH_CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours warm edge cache

/**
 * High-speed Native Multi-Engine Web Search + 5-Stage Document & Decision Model Reranker (`/v1/search` & `/api/v1/search`).
 * Uses Hedged Quorum Racing + Weighted Reciprocal Rank Fusion (W-RRF) + Fielded BM25F+ + ColBERT Subword MaxSim +
 * Vercel AI Gateway Decision Models (`baseten/mammoth-1` & `convaiinnovations/laya`).
 */
export async function searchWeb(req: SearchRequest): Promise<SearchResponse> {
  const start = performance.now();
  const limit = Math.min(Math.max(req.limit ?? 5, 1), 25);

  const effectiveQuery = req.query.trim();
  const targetSites = normalizeHostList([
    ...(req.filters?.sites ?? []),
    ...(req.includeDomains ?? []),
    ...(req.filters?.includeDomains ?? []),
  ]);
  const excludedHosts = normalizeHostList([
    ...(req.excludeDomains ?? []),
    ...(req.filters?.excludeDomains ?? []),
  ]);

  const userLocation = resolveUserLocation(req);
  const hasGeo = Boolean(
    userLocation.country || userLocation.city || userLocation.region
  );

  const category = resolveCategory(req);
  const filters = req.filters;
  const productMode =
    filters?.productMode !== undefined
      ? Boolean(filters.productMode)
      : category === "shopping";
  const allowBrowserEscalation = Boolean(filters?.allowBrowserEscalation);
  const catDef =
    SEARCH_CATEGORY_CATALOG[category] ?? SEARCH_CATEGORY_CATALOG.general;
  const countryName =
    resolveCountryDisplayName(userLocation.country) || userLocation.country;
  const localizeBy =
    filters?.localizeBy && filters.localizeBy !== "auto"
      ? filters.localizeBy
      : catDef.localizeBy;
  const qLower = effectiveQuery.toLowerCase();
  const queryAlreadyHasPlace =
    Boolean(
      userLocation.city && qLower.includes(userLocation.city.toLowerCase())
    ) || Boolean(countryName && qLower.includes(countryName.toLowerCase()));
  const geoSuffix =
    localizeBy === "city"
      ? userLocation.city || countryName || ""
      : localizeBy === "country"
        ? countryName || userLocation.city || ""
        : localizeBy === "region"
          ? userLocation.region || countryName || ""
          : "";
  const localizedSearchQuery =
    geoSuffix && !queryAlreadyHasPlace && hasGeo
      ? `${effectiveQuery} ${geoSuffix}`.trim()
      : effectiveQuery;
  const filterContext: SearchFilterContext = {
    category,
    subcategory: req.subcategory,
    preferLocalDomains:
      filters?.preferLocalDomains ?? catDef.preferLocalDomains,
    boostTerms: filters?.boostTerms,
    mustIncludeTerms: filters?.mustIncludeTerms,
    excludeTerms: filters?.excludeTerms,
    customInstruction: filters?.customInstruction,
  };

  const useDecisionModel = req.rankOptions?.useDecisionModel !== false;
  const decisionModel: DecisionModelId =
    req.rankOptions?.decisionModel ?? "auto";

  const cacheKey = JSON.stringify({
    q: localizedSearchQuery,
    country: userLocation.country,
    city: userLocation.city,
    limit,
    tbs: req.tbs,
    category,
    subcategory: req.subcategory,
    filters: req.filters,
    targetSites,
    excludedHosts,
    productMode,
    provider: req.provider ?? "auto",
    useDecisionModel,
    decisionModel,
    scrape: Boolean(req.scrapeOptions?.formats?.length),
  });

  if (!req.bypassCache) {
    const cached = searchCache.get(cacheKey);
    if (cached && Date.now() < cached.expiresAt) {
      return {
        success: true,
        data: cached.data,
        ...(cached.products ? { products: cached.products } : {}),
        ...(cached.offers ? { offers: cached.offers } : {}),
        ...(cached.listings ? { listings: cached.listings } : {}),
        ...(cached.flights ? { flights: cached.flights } : {}),
        ...(cached.hotels ? { hotels: cached.hotels } : {}),
        ...(cached.businesses ? { businesses: cached.businesses } : {}),
        ...(cached.cves ? { cves: cached.cves } : {}),
        provider: cached.provider,
        cached: true,
        latencyMs: Math.round(performance.now() - start),
        ...(hasGeo ? { userLocation } : {}),
        rankingMetrics: cached.rankingMetrics,
      };
    }
  }

  const perEngineLimit = Math.min(Math.max(limit + 4, 8), 15);
  // Must outlast DDG/Brave impersonation (2200ms) so a slow SERP is not cut off
  // after Wikipedia's 2 hits — the v1.4.3 keyless-search failure mode.
  const quorumTimeoutMs = req.rankOptions?.quorumTimeoutMs ?? 2800;

  // Stage 1: Hedged Multi-Engine Native Federation
  const collectedOffers: ProductOffer[] = [];
  const offerByUrl = new Map<string, ProductOffer>();
  const recordOffer = (offer: ProductOffer) => {
    if (
      targetSites.length > 0 &&
      !hostMatchesAny(offer.domain || offer.url, targetSites)
    ) {
      return;
    }
    if (
      excludedHosts.length > 0 &&
      hostMatchesAny(offer.domain || offer.url, excludedHosts)
    ) {
      return;
    }
    collectedOffers.push(offer);
    if (offer.url && !offerByUrl.has(offer.url)) {
      offerByUrl.set(offer.url, offer);
    }
  };

  // Security: structured CVE records streamed from the NVD / OSV engines.
  const collectedCves: CveRecord[] = [];
  const recordCve = (cve: CveRecord) => {
    collectedCves.push(cve);
  };

  // Hotels: a parallel OTA-biased pass so booking sites (photos, nightly rates,
  // review scores) are in the candidate pool, not only travel articles.
  const otaPass =
    category === "hotels" && targetSites.length === 0
      ? fetchHedgedNativeFederation(
          `${effectiveQuery} booking.com agoda`,
          `${localizedSearchQuery} booking.com agoda`,
          perEngineLimit,
          req,
          userLocation,
          quorumTimeoutMs,
          [],
          recordOffer
        ).catch(() => [] as Awaited<ReturnType<typeof fetchHedgedNativeFederation>>)
      : Promise.resolve([]);
  const [mainCandidates, otaCandidates] = await Promise.all([
    fetchHedgedNativeFederation(
      effectiveQuery,
      localizedSearchQuery,
      perEngineLimit,
      req,
      userLocation,
      quorumTimeoutMs,
      targetSites,
      recordOffer,
      recordCve
    ),
    otaPass,
  ]);
  const mainUrls = new Set(mainCandidates.map((c) => c.url));
  const rawCandidatesUnfiltered = [
    ...mainCandidates,
    ...otaCandidates.filter(
      (c) => c.url && isHotelOta(c.url) && !mainUrls.has(c.url)
    ),
  ];

  // Post-fetch host filtering for `sites`, `includeDomains`, and `excludeDomains` (never uses `-site:` which breaks Brave)
  const rawCandidates = rawCandidatesUnfiltered.filter((cand) => {
    if (!cand.url) {
      return false;
    }
    if (targetSites.length > 0 && !hostMatchesAny(cand.url, targetSites)) {
      return false;
    }
    if (excludedHosts.length > 0 && hostMatchesAny(cand.url, excludedHosts)) {
      return false;
    }
    return true;
  });

  // Stage 2: Pre-rank with W-RRF + Lexical BM25F+ so if content scraping is requested,
  // we only scrape the highest-value top candidate URLs.
  const wantsMarkdown = req.scrapeOptions?.formats?.includes("markdown");
  const wantsLinks = req.scrapeOptions?.formats?.includes("links");

  // Enrich any candidates that are ALREADY in our warm 24-hour pageCache for 0ms cost!
  const retainImages = req.scrapeOptions?.retainImages ?? "all";
  for (const cand of rawCandidates) {
    if (!cand.url) {
      continue;
    }
    const warm = getCachedPage(cand.url, retainImages);
    if (warm) {
      cand.markdown = warm.markdown;
      cand.links = warm.links;
    }
  }

  // Stage 3: Optional parallel content scraping (when `scrapeOptions.formats` includes "markdown" or "links")
  if ((wantsMarkdown || wantsLinks) && rawCandidates.length > 0) {
    const preRanked = await rankDocuments(localizedSearchQuery, rawCandidates, {
      topK: limit + 2,
      useDecisionModel: false,
      userLocation,
      filterContext,
    });
    const urlsToScrape = new Set(
      preRanked.results.slice(0, limit).map((r) => r.url)
    );
    const scrapeTimeoutMs = req.scrapeOptions?.scrapeTimeoutMs ?? 2500;

    await Promise.all(
      rawCandidates.map(async (item) => {
        if (!item.url || !urlsToScrape.has(item.url) || item.markdown) {
          return;
        }
        try {
          const res = await fetchWithTlsImpersonation(
            item.url,
            scrapeTimeoutMs
          );
          if (res.status < 200 || res.status >= 400 || !res.html) {
            return;
          }
          const parsed = fastHtmlToMarkdown(res.html, item.url, {
            retainImages,
          });
          setCachedPage(item.url, retainImages, {
            title: parsed.title || item.title,
            markdown: parsed.markdown,
            links: parsed.links,
            statusCode: res.status,
            contentHash: sha256(parsed.markdown),
          });
          if (wantsMarkdown) {
            item.markdown = parsed.markdown;
          }
          if (wantsLinks) {
            item.links = parsed.links;
          }
        } catch {
          // Keep SERP snippet if individual page times out
        }
      })
    );
  }

  // Stage 4 & 5: Full 5-Stage Document & Passage Ranking + Vercel AI Gateway Decision Model (`baseten/mammoth-1` / `convaiinnovations/laya`)
  let rankCandidates = rawCandidates;
  if (
    filters?.strict &&
    (filters.mustIncludeTerms?.length || filters.excludeTerms?.length)
  ) {
    const must = (filters.mustIncludeTerms ?? [])
      .map((t) => t.trim().toLowerCase())
      .filter(Boolean);
    const exclude = (filters.excludeTerms ?? [])
      .map((t) => t.trim().toLowerCase())
      .filter(Boolean);
    rankCandidates = rawCandidates.filter((c) => {
      const hay =
        `${c.title || ""} ${c.description || ""} ${c.url || ""} ${c.markdown || ""}`.toLowerCase();
      return (
        must.every((t) => hay.includes(t)) &&
        !exclude.some((t) => hay.includes(t))
      );
    });
  }

  // News: evergreen pages (Wikipedia, travel guides) out-score articles on entity
  // queries like "paris". Rank only dated articles when there are enough of them.
  if (category === "news") {
    const dated = rankCandidates.filter(
      (c) => c.publishedDate || c.engine === "google-news-rss"
    );
    if (dated.length >= Math.min(3, limit)) {
      rankCandidates = dated;
    }
  }

  const rankOpts = {
    topK: limit,
    useDecisionModel,
    decisionModel,
    decisionTimeoutMs: req.rankOptions?.decisionTimeoutMs ?? 1200,
    decisionTopN: Math.min(limit + 3, 12),
    maxPerDomain: req.rankOptions?.maxPerDomain,
    userLocation,
    filterContext,
  };
  let ranked = await rankDocuments(localizedSearchQuery, rankCandidates, rankOpts);

  // Thin result set after ranking and filtering: ask the keyed search provider once, then re-rank.
  const minResults = Math.min(3, limit);
  if (
    (!req.provider || req.provider === "auto") &&
    ranked.results.length < minResults &&
    process.env.JINA_API_KEY &&
    !rankCandidates.some((c) => c.engine === "jina")
  ) {
    const jinaQuery =
      targetSites.length > 0 && targetSites.length <= 3
        ? `${localizedSearchQuery} ${targetSites.map((h) => `site:${h}`).join(" OR ")}`
        : localizedSearchQuery;
    const jina = await fetchJinaSearch(jinaQuery, perEngineLimit, req);
    const filteredJina = jina.filter(
      (c) =>
        (targetSites.length === 0 || hostMatchesAny(c.url, targetSites)) &&
        (excludedHosts.length === 0 || !hostMatchesAny(c.url, excludedHosts))
    );
    if (filteredJina.length > 0) {
      const reranked = await rankDocuments(
        localizedSearchQuery,
        [...rankCandidates, ...filteredJina],
        rankOpts
      );
      if (reranked.results.length > ranked.results.length) {
        ranked = reranked;
      }
    }
  }

  // Stage 6 (Shopping Product Mode): Extract JSON-LD/OpenGraph/SERP offers from top ranked pages when needed,
  // with optional browser escalation on blocked candidate pages (`allowBrowserEscalation: true`).
  if (productMode) {
    for (const doc of ranked.results) {
      if (!offerByUrl.has(doc.url)) {
        const snippetOffer = extractOfferFromSerpSnippet(
          doc.title,
          doc.description,
          doc.url,
          userLocation.country
        );
        if (snippetOffer) {
          recordOffer(snippetOffer);
        }
      }
    }

    // Only probe top candidate pages for JSON-LD / OpenGraph if we still need more offers (< limit)
    const candidatesMissingOffer =
      collectedOffers.length >= limit
        ? []
        : ranked.results.filter((doc) => !offerByUrl.has(doc.url)).slice(0, 3);

    if (candidatesMissingOffer.length > 0) {
      await Promise.all(
        candidatesMissingOffer.map(async (doc) => {
          try {
            const res = await fetchWithTlsImpersonation(doc.url, 1800);
            let html = res.html || "";
            if (
              (!html || res.status === 403 || res.status === 503) &&
              allowBrowserEscalation
            ) {
              const esc = await escalateToSandboxOrBrowser(doc.url, {
                timeoutMs: 4500,
              });
              if (esc?.html) {
                html = esc.html;
              }
            }
            if (html) {
              const pageOffers = extractOffersFromHtml(
                html,
                doc.url,
                doc.title,
                userLocation.country
              );
              for (const o of pageOffers) {
                recordOffer(o);
              }
            }
          } catch {
            // Best-effort extraction
          }
        })
      );
    }
  }

  const products = productMode
    ? groupOffersIntoProducts(collectedOffers, effectiveQuery, limit)
    : undefined;

  const isRealEstate = category === "real-estate";
  const collectedListings: PropertyListing[] = [];
  const listingsByUrl = new Map<string, PropertyListing[]>();

  if (isRealEstate) {
    const seenPortalUrls = new Set<string>();
    const seenDomains = new Set<string>();
    const portalCandidates: Array<{
      url: string;
      title: string;
      description: string;
    }> = [];
    for (const doc of ranked.results.slice(0, Math.min(limit, 8))) {
      seenPortalUrls.add(doc.url);
      const dom = extractDomainHost(doc.url);
      if (dom) {
        seenDomains.add(dom);
      }
      portalCandidates.push(doc);
    }
    // Include additional organic SERP candidates from distinct domains so if 1-2 top domains
    // return 403/CAPTCHA on cloud datacenter IPs, other organic results still yield listings.
    for (const cand of rankCandidates) {
      if (portalCandidates.length >= 10) {
        break;
      }
      const dom = extractDomainHost(cand.url);
      if (!seenPortalUrls.has(cand.url) && dom && !seenDomains.has(dom)) {
        seenPortalUrls.add(cand.url);
        seenDomains.add(dom);
        portalCandidates.push(cand);
      }
    }
    const scrapedMarkdowns: Array<{ url: string; markdown: string }> = [];
    await Promise.all(
      portalCandidates.map(async (doc) => {
        const pageListings: PropertyListing[] = [];
        try {
          const fetched = await fetchWithTlsImpersonation(doc.url, 2600);
          if (
            fetched.status >= 200 &&
            fetched.status < 400 &&
            fetched.html.length > 500
          ) {
            const extracted = extractPropertyListingsFromHtml(
              fetched.html,
              doc.url,
              userLocation.country
            );
            pageListings.push(...extracted);
            if (extracted.length === 0) {
              const md = fastHtmlToMarkdown(fetched.html, doc.url, {
                retainImages: "none",
              }).markdown;
              if (md && md.length > 120) {
                scrapedMarkdowns.push({ url: doc.url, markdown: md });
              }
            }
          }
        } catch {
          // Best-effort extraction
        }

        if (pageListings.length === 0) {
          const fallback = extractPropertyListingFromSerpResult(
            doc.title,
            doc.description,
            doc.url,
            userLocation.country
          );
          if (fallback) {
            pageListings.push(fallback);
          }
        }

        if (pageListings.length > 0) {
          listingsByUrl.set(doc.url, pageListings.slice(0, 10));
          collectedListings.push(...pageListings);
        }
      })
    );

    // Tier-2 fallback: if deterministic JSON-state / JSON-LD extraction yielded fewer than 3 listings,
    // run `scaledown/scaledown-extract-1` ($0.05/1M input, $0 output) over scraped page markdown + SERP snippets.
    if (collectedListings.length < 3) {
      const combinedContext = [
        ...scrapedMarkdowns
          .slice(0, 3)
          .map((m) => `Source URL: ${m.url}\n${m.markdown.slice(0, 3500)}`),
        ...rankCandidates
          .slice(0, 10)
          .map((c) => `Result: ${c.title} | ${c.url}\n${c.description}`),
      ].join("\n\n");
      const primaryUrl =
        scrapedMarkdowns[0]?.url ||
        ranked.results[0]?.url ||
        "https://webcrawl.app";
      const scaledownListings = await extractPropertyListingsWithScaleDown(
        combinedContext,
        primaryUrl,
        userLocation.country,
        3000
      );
      if (scaledownListings.length > 0) {
        collectedListings.push(...scaledownListings);
      }
    }
  }

  const dedupedListings = isRealEstate
    ? dedupePropertyListings(collectedListings, Math.max(limit * 5, 25))
    : undefined;

  // Stage 6.5 (Flights, Hotels, Business Vertical Extraction)
  const isFlights = category === "flights";
  const isHotels = category === "hotels";
  const isBusiness = category === "business";

  const collectedFlights: FlightOffer[] = [];
  const flightsByUrl = new Map<string, FlightOffer[]>();
  const collectedHotels: HotelListing[] = [];
  const hotelsByUrl = new Map<string, HotelListing[]>();
  const collectedBusinesses: BusinessListing[] = [];
  const businessesByUrl = new Map<string, BusinessListing[]>();

  if (isFlights || isHotels || isBusiness) {
    const seenUrls = new Set<string>();
    const seenDomains = new Set<string>();
    const verticalCandidates: Array<{
      url: string;
      title: string;
      description: string;
    }> = [];
    // Hotels: booking sites carry photos, prices and ratings for many stays on one
    // page, so pull them into the probe set even when they rank below articles.
    if (isHotels) {
      const otaFirst = [...ranked.results, ...rankCandidates].filter(
        (c) => c.url && isHotelOta(c.url)
      );
      for (const cand of otaFirst) {
        if (verticalCandidates.length >= 4) {
          break;
        }
        const dom = extractDomainHost(cand.url);
        if (!seenUrls.has(cand.url) && dom && !seenDomains.has(dom)) {
          seenUrls.add(cand.url);
          seenDomains.add(dom);
          verticalCandidates.push(cand);
        }
      }
    }
    for (const doc of ranked.results.slice(0, Math.min(limit, 8))) {
      if (seenUrls.has(doc.url)) {
        continue;
      }
      seenUrls.add(doc.url);
      const dom = extractDomainHost(doc.url);
      if (dom) {
        seenDomains.add(dom);
      }
      verticalCandidates.push(doc);
    }
    for (const cand of rankCandidates) {
      if (verticalCandidates.length >= 10) {
        break;
      }
      const dom = extractDomainHost(cand.url);
      if (!seenUrls.has(cand.url) && dom && !seenDomains.has(dom)) {
        seenUrls.add(cand.url);
        seenDomains.add(dom);
        verticalCandidates.push(cand);
      }
    }

    const scrapedMarkdowns: Array<{ url: string; markdown: string }> = [];
    await Promise.all(
      verticalCandidates.map(async (doc) => {
        try {
          const fetched = await fetchWithTlsImpersonation(doc.url, 2400);
          // Blocked (403/429/202 challenge) or JS-only shell on a booking site:
          // retry once through the browser tier inside a fixed budget.
          if (
            isHotels &&
            isHotelOta(doc.url) &&
            (allowBrowserEscalation || browserEscalationAvailable()) &&
            (fetched.status === 202 ||
              fetched.status === 403 ||
              fetched.status === 429 ||
              fetched.status === 503 ||
              !/data-testid="title"|application\/ld\+json/i.test(fetched.html))
          ) {
            const esc = await escalateToSandboxOrBrowser(doc.url, {
              timeoutMs: 6000,
            }).catch(() => null);
            if (esc?.html && esc.html.length > 500) {
              fetched.status = 200;
              fetched.html = esc.html;
            }
          }
          if (
            fetched.status >= 200 &&
            fetched.status < 400 &&
            fetched.html.length > 500
          ) {
            if (isFlights) {
              const extracted = extractFlightOffersFromHtml(
                fetched.html,
                doc.url,
                userLocation.country,
                effectiveQuery
              );
              if (extracted.length > 0) {
                flightsByUrl.set(doc.url, extracted.slice(0, 10));
                collectedFlights.push(...extracted);
                return;
              }
            } else if (isHotels) {
              const extracted = extractHotelListingsFromHtml(
                fetched.html,
                doc.url,
                userLocation.country
              );
              if (extracted.length > 0) {
                hotelsByUrl.set(doc.url, extracted.slice(0, 10));
                collectedHotels.push(...extracted);
                return;
              }
            } else if (isBusiness) {
              const extracted = extractBusinessListingsFromHtml(
                fetched.html,
                doc.url,
                userLocation.country
              );
              if (extracted.length > 0) {
                businessesByUrl.set(doc.url, extracted.slice(0, 10));
                collectedBusinesses.push(...extracted);
                return;
              }
            }

            const md = fastHtmlToMarkdown(fetched.html, doc.url, {
              retainImages: "none",
            }).markdown;
            if (md && md.length > 120) {
              scrapedMarkdowns.push({ url: doc.url, markdown: md });
            }
          }
        } catch {
          // Best-effort extraction
        }

        // SERP snippet fallback
        if (isFlights) {
          const fallback = extractFlightOfferFromSerpResult(
            doc.title,
            doc.description,
            doc.url,
            userLocation.country,
            effectiveQuery
          );
          if (fallback) {
            flightsByUrl.set(doc.url, [fallback]);
            collectedFlights.push(fallback);
          }
        } else if (isHotels) {
          const fallback = extractHotelListingFromSerpResult(
            doc.title,
            doc.description,
            doc.url,
            userLocation.country
          );
          if (fallback) {
            hotelsByUrl.set(doc.url, [fallback]);
            collectedHotels.push(fallback);
          }
        } else if (isBusiness) {
          const fallback = extractBusinessListingFromSerpResult(
            doc.title,
            doc.description,
            doc.url,
            userLocation.country
          );
          if (fallback) {
            businessesByUrl.set(doc.url, [fallback]);
            collectedBusinesses.push(fallback);
          }
        }
      })
    );

    const combinedContext = [
      ...scrapedMarkdowns
        .slice(0, 3)
        .map((m) => `Source URL: ${m.url}\n${m.markdown.slice(0, 3500)}`),
      ...rankCandidates
        .slice(0, 10)
        .map((c) => `Result: ${c.title} | ${c.url}\n${c.description}`),
    ].join("\n\n");
    const primaryUrl =
      scrapedMarkdowns[0]?.url ||
      ranked.results[0]?.url ||
      "https://webcrawl.app";

    if (isFlights && collectedFlights.length < 3) {
      const sdFlights = await extractFlightOffersWithScaleDown(
        combinedContext,
        primaryUrl,
        userLocation.country,
        3000
      );
      if (sdFlights.length > 0) {
        collectedFlights.push(...sdFlights);
      }
    } else if (isHotels && collectedHotels.length < 3) {
      const sdHotels = await extractHotelListingsWithScaleDown(
        combinedContext,
        primaryUrl,
        userLocation.country,
        3000
      );
      if (sdHotels.length > 0) {
        collectedHotels.push(...sdHotels);
      }
    } else if (isBusiness && collectedBusinesses.length < 3) {
      const sdBusinesses = await extractBusinessListingsWithScaleDown(
        combinedContext,
        primaryUrl,
        userLocation.country,
        3000
      );
      if (sdBusinesses.length > 0) {
        collectedBusinesses.push(...sdBusinesses);
      }
    }
  }

  const dedupedFlights = isFlights
    ? dedupeFlightOffers(collectedFlights, Math.max(limit * 5, 25))
    : undefined;
  const dedupedHotels = isHotels
    ? dedupeHotelListings(collectedHotels, Math.max(limit * 5, 25))
    : undefined;
  const dedupedBusinesses = isBusiness
    ? dedupeBusinessListings(collectedBusinesses, Math.max(limit * 5, 25))
    : undefined;

  // Stage 6.6 (Security: structured CVE records)
  // API records first; then any CVE id a top-ranked page mentions that the APIs
  // did not return gets one NVD lookup (capped), so write-ups resolve to records.
  const isSecurity = category === "security";
  let dedupedCves: CveRecord[] | undefined;
  const cvesByUrl = new Map<string, CveRecord[]>();
  if (isSecurity) {
    const queryIds = extractCveIdsFromText(effectiveQuery, 5);
    const known = new Set(
      collectedCves.flatMap((c) => [c.id, ...(c.aliases ?? [])].map(normalizeCveId))
    );
    const pageIds = new Map<string, string[]>();
    for (const doc of ranked.results.slice(0, Math.max(limit, 5))) {
      const ids = extractCveIdsFromText(
        `${doc.title} ${doc.description} ${doc.markdown?.slice(0, 20000) ?? ""}`,
        6
      );
      if (ids.length) pageIds.set(doc.url, ids);
    }
    const missing = [
      ...new Set([...queryIds, ...[...pageIds.values()].flat()]),
    ].filter((id) => !known.has(id));
    if (missing.length > 0) {
      collectedCves.push(...(await fetchNvdByIds(missing, 3)));
    }
    dedupedCves = sortCveRecords(
      mergeCveRecords(collectedCves, Math.max(limit * 5, 25)),
      queryIds
    );
    // Incremental cache: store the merged NVD + OSV records after the response
    // (unchanged rows are skipped by the upsert's IS DISTINCT FROM guard).
    runInBackground(upsertCves(dedupedCves));
    const byId = new Map<string, CveRecord>();
    for (const c of dedupedCves) {
      for (const n of [c.id, ...(c.aliases ?? [])]) byId.set(normalizeCveId(n), c);
    }
    for (const c of dedupedCves) {
      cvesByUrl.set(c.url, [c]);
    }
    for (const [url, ids] of pageIds) {
      const recs = [
        ...new Set(ids.map((id) => byId.get(id)).filter((c): c is CveRecord => !!c)),
      ];
      if (recs.length && !cvesByUrl.has(url)) cvesByUrl.set(url, recs.slice(0, 5));
    }
  }

  const finalItems: SearchResultItem[] = ranked.results.map((doc) => {
    const matchedOffer = offerByUrl.get(doc.url);
    const matchedListings = listingsByUrl.get(doc.url);
    const matchedFlights = flightsByUrl.get(doc.url);
    const matchedHotels = hotelsByUrl.get(doc.url);
    const matchedBusinesses = businessesByUrl.get(doc.url);
    const matchedCves = cvesByUrl.get(doc.url);
    return {
      title: doc.title,
      url: doc.url,
      canonicalUrl: doc.canonicalUrl,
      description: doc.description,
      ...(wantsMarkdown && doc.markdown ? { markdown: doc.markdown } : {}),
      ...(wantsLinks && doc.links ? { links: doc.links } : {}),
      ...(doc.publishedDate ? { publishedDate: doc.publishedDate } : {}),
      score: doc.score,
      rank: doc.rank,
      sources: doc.sources,
      highlights: doc.highlights,
      scoreBreakdown: doc.scoreBreakdown,
      ...(matchedOffer ? { offer: matchedOffer } : {}),
      ...(matchedListings?.length ? { listings: matchedListings } : {}),
      ...(matchedFlights?.length ? { flights: matchedFlights } : {}),
      ...(matchedHotels?.length ? { hotels: matchedHotels } : {}),
      ...(matchedBusinesses?.length ? { businesses: matchedBusinesses } : {}),
      ...(matchedCves?.length ? { cves: matchedCves } : {}),
    };
  });

  // Charge the fallback surcharge only when a keyed-provider result actually reached the caller.
  // An explicitly chosen provider is not a fallback.
  const usedJinaFallback =
    (!req.provider || req.provider === "auto") &&
    finalItems.some((item) => item.sources?.includes("jina"));
  const engines = ranked.rankingMetrics.enginesContributing;
  const provider: SearchResponse["provider"] =
    engines.length > 1
      ? "native-federated"
      : engines.includes("serper")
        ? "serper"
        : engines.includes("jina")
          ? "jina"
          : engines.includes("brave-api") || engines.includes("brave-native")
            ? "brave"
            : engines.includes("ddg-lite")
              ? "ddg-edge"
              : "native-federated";

  const hasHits =
    finalItems.length > 0 ||
    (products && products.length > 0) ||
    (dedupedListings && dedupedListings.length > 0) ||
    (dedupedFlights && dedupedFlights.length > 0) ||
    (dedupedHotels && dedupedHotels.length > 0) ||
    (dedupedBusinesses && dedupedBusinesses.length > 0) ||
    (dedupedCves && dedupedCves.length > 0);

  if (hasHits) {
    searchCache.set(cacheKey, {
      data: finalItems,
      ...(products ? { products } : {}),
      ...(productMode ? { offers: collectedOffers } : {}),
      ...(dedupedListings ? { listings: dedupedListings } : {}),
      ...(dedupedFlights ? { flights: dedupedFlights } : {}),
      ...(dedupedHotels ? { hotels: dedupedHotels } : {}),
      ...(dedupedBusinesses ? { businesses: dedupedBusinesses } : {}),
      ...(dedupedCves ? { cves: dedupedCves } : {}),
      provider,
      rankingMetrics: ranked.rankingMetrics,
      expiresAt: Date.now() + SEARCH_CACHE_TTL_MS,
    });
  }

  if (!hasHits) {
    return {
      success: false,
      data: [],
      provider,
      error: EMPTY_SEARCH_ERROR,
      cached: false,
      latencyMs: Math.round(performance.now() - start),
      ...(hasGeo ? { userLocation } : {}),
      rankingMetrics: ranked.rankingMetrics,
    };
  }

  return {
    success: true,
    data: finalItems,
    ...(products ? { products } : {}),
    ...(productMode ? { offers: collectedOffers } : {}),
    ...(dedupedListings ? { listings: dedupedListings } : {}),
    ...(dedupedFlights ? { flights: dedupedFlights } : {}),
    ...(dedupedHotels ? { hotels: dedupedHotels } : {}),
    ...(dedupedBusinesses ? { businesses: dedupedBusinesses } : {}),
    ...(dedupedCves ? { cves: dedupedCves } : {}),
    provider,
    ...(usedJinaFallback ? { fallback: "jina" as const } : {}),
    cached: false,
    latencyMs: Math.round(performance.now() - start),
    ...(hasGeo ? { userLocation } : {}),
    rankingMetrics: ranked.rankingMetrics,
  };
}
