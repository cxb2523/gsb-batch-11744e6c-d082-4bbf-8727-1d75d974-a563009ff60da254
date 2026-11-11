import { extractDomainHost, parsePriceString } from "./currency.js";

export interface ProductOffer {
  title: string;
  vendor: string;
  domain: string;
  url: string;
  price: number;
  rawPrice: string;
  currency: string;
  availability?: "in_stock" | "out_of_stock" | "preorder" | "unknown";
  rating?: number;
  reviewCount?: number;
  freeShipping?: boolean;
  shippingNote?: string;
  imageUrl?: string;
  source:
    | "bing-shopping"
    | "google-shopping"
    | "json-ld"
    | "opengraph"
    | "serp-snippet";
}

export interface AggregatedProduct {
  name: string;
  bestOffer: ProductOffer;
  minPrice: number;
  maxPrice: number;
  currency: string;
  offerCount: number;
  vendors: string[];
  offers: ProductOffer[];
}

function normalizeAvailability(raw?: string): ProductOffer["availability"] {
  if (!raw) {
    return undefined;
  }
  const s = raw.toLowerCase();
  if (
    s.includes("instock") ||
    s.includes("in_stock") ||
    s.includes("in stock")
  ) {
    return "in_stock";
  }
  if (
    s.includes("outofstock") ||
    s.includes("out_of_stock") ||
    s.includes("sold out")
  ) {
    return "out_of_stock";
  }
  if (
    s.includes("preorder") ||
    s.includes("pre-order") ||
    s.includes("backorder")
  ) {
    return "preorder";
  }
  return "unknown";
}

/**
 * Extract structured ProductOffer items from Bing Shopping HTML (`CustomData` JSON + `<li class="br-item">` seller/rating DOM).
 */
export function parseBingShoppingHtml(
  html: string,
  countryCode?: string
): ProductOffer[] {
  if (!html) {
    return [];
  }

  const sellerByOfferId = new Map<
    string,
    {
      seller?: string;
      rating?: number;
      reviewCount?: number;
      freeShipping?: boolean;
    }
  >();

  const cardRegex =
    /<li[^>]+class=["'][^"']*\bbr-item\b[^"']*["'][^>]*data-offerId=["']([^"']+)["']([\s\S]*?)<\/li>/gi;
  let cardMatch: RegExpExecArray | null;
  while ((cardMatch = cardRegex.exec(html)) !== null) {
    const offerId = cardMatch[1];
    const body = cardMatch[2];
    const sellerRaw =
      (body.match(
        /class=["'][^"']*\bbr-seller(?:\s|["'])[^>]*>([\s\S]*?)<\/div>/i
      ) ||
        body.match(
          /class=["']l2_seller_lgfb[^"']*["'][^>]*title=["']([^"']+)["']/i
        ) ||
        [])[1]
        ?.replace(/<[^>]+>/g, "")
        .trim() || undefined;
    const ratingStr = (body.match(
      /class=["']rating-num["'][^>]*>([\d.]+)<\/div>/i
    ) || [])[1];
    const rating = ratingStr ? Number.parseFloat(ratingStr) : undefined;
    const freeShipping = /Free shipping/i.test(body);
    sellerByOfferId.set(offerId, {
      seller: sellerRaw,
      rating: Number.isFinite(rating) ? rating : undefined,
      freeShipping,
    });
  }

  const offers: ProductOffer[] = [];
  const seenKey = new Set<string>();
  const customDataRegex =
    /"CustomData":"(\{\\u0022MediaUrl\\u0022:[\s\S]*?\})"/g;
  let m: RegExpExecArray | null;

  while ((m = customDataRegex.exec(html)) !== null) {
    try {
      const unescaped = JSON.parse(`"${m[1]}"`) as string;
      const obj = JSON.parse(unescaped) as {
        MediaUrl?: string;
        PageUrl?: string;
        ToolTip?: string;
        GlobalOfferId?: string;
        Price?: string;
        Stars?: number;
      };
      if (!obj.PageUrl || !obj.ToolTip || !obj.Price) {
        continue;
      }
      const parsedPrice = parsePriceString(obj.Price, countryCode);
      if (!parsedPrice) {
        continue;
      }
      const domain = extractDomainHost(obj.PageUrl);
      if (!domain) {
        continue;
      }
      const extra = sellerByOfferId.get(String(obj.GlobalOfferId || "")) || {};
      const vendor = extra.seller || domain;
      const dedupeKey = `${domain}::${parsedPrice.price}::${obj.ToolTip.slice(0, 48).toLowerCase()}`;
      if (seenKey.has(dedupeKey)) {
        continue;
      }
      seenKey.add(dedupeKey);

      offers.push({
        title: obj.ToolTip.trim(),
        vendor,
        domain,
        url: obj.PageUrl,
        price: parsedPrice.price,
        rawPrice: parsedPrice.rawPrice,
        currency: parsedPrice.currency,
        availability: "in_stock",
        ...(extra.rating
          ? { rating: extra.rating }
          : obj.Stars && obj.Stars > 0
            ? { rating: obj.Stars }
            : {}),
        ...(extra.freeShipping
          ? { freeShipping: true, shippingNote: "Free shipping" }
          : {}),
        ...(obj.MediaUrl ? { imageUrl: obj.MediaUrl } : {}),
        source: "bing-shopping",
      });
    } catch {
      // Ignore malformed CustomData block
    }
  }

  return offers;
}

/**
 * Extract structured ProductOffer items from arbitrary retailer or price-aggregator HTML
 * using Schema.org JSON-LD (`Product`, `Offer`, `AggregateOffer`), OpenGraph `product:price:*`, and microdata.
 */
export function extractOffersFromHtml(
  html: string,
  pageUrl: string,
  fallbackTitle?: string,
  countryCode?: string
): ProductOffer[] {
  if (!html || !pageUrl) {
    return [];
  }
  const domain = extractDomainHost(pageUrl);
  if (!domain) {
    return [];
  }
  const offers: ProductOffer[] = [];
  const seen = new Set<string>();

  const pushOffer = (
    candidate: Omit<ProductOffer, "domain"> & { domain?: string }
  ) => {
    const d = candidate.domain || extractDomainHost(candidate.url) || domain;
    const key = `${d}::${candidate.price}::${candidate.url}`;
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    offers.push({ ...candidate, domain: d });
  };

  // 1. Schema.org JSON-LD (<script type="application/ld+json">)
  const ldRegex =
    /<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let ldMatch: RegExpExecArray | null;
  while ((ldMatch = ldRegex.exec(html)) !== null) {
    const rawJson = ldMatch[1].trim();
    if (!rawJson) {
      continue;
    }
    try {
      const parsed = JSON.parse(rawJson) as unknown;
      const visit = (
        node: unknown,
        inheritedTitle?: string,
        inheritedRating?: number
      ) => {
        if (!node || typeof node !== "object") {
          return;
        }
        if (Array.isArray(node)) {
          for (const item of node) {
            visit(item, inheritedTitle, inheritedRating);
          }
          return;
        }
        const rec = node as Record<string, unknown>;
        if (Array.isArray(rec["@graph"])) {
          visit(rec["@graph"], inheritedTitle, inheritedRating);
        }
        const typeVal = String(rec["@type"] || "").toLowerCase();
        const nodeName =
          typeof rec.name === "string" && rec.name.trim()
            ? rec.name.trim()
            : inheritedTitle || fallbackTitle || domain;
        const aggRatingObj = rec.aggregateRating as
          | Record<string, unknown>
          | undefined;
        const ratingVal =
          aggRatingObj &&
          (typeof aggRatingObj.ratingValue === "number" ||
            typeof aggRatingObj.ratingValue === "string")
            ? Number.parseFloat(String(aggRatingObj.ratingValue))
            : inheritedRating;

        if (typeVal.includes("product") && rec.offers) {
          visit(
            rec.offers,
            nodeName,
            Number.isFinite(ratingVal) ? ratingVal : undefined
          );
        } else if (
          typeVal.includes("offer") ||
          rec.price !== undefined ||
          rec.lowPrice !== undefined
        ) {
          const rawPrice = (rec.price ?? rec.lowPrice) as
            | string
            | number
            | undefined;
          const priceCurrency =
            typeof rec.priceCurrency === "string"
              ? rec.priceCurrency
              : undefined;
          const p = parsePriceString(rawPrice, countryCode, priceCurrency);
          if (p) {
            const offerUrl =
              typeof rec.url === "string" && rec.url.startsWith("http")
                ? rec.url
                : pageUrl;
            const sellerObj = rec.seller as Record<string, unknown> | undefined;
            const sellerName =
              sellerObj &&
              typeof sellerObj.name === "string" &&
              sellerObj.name.trim()
                ? sellerObj.name.trim()
                : extractDomainHost(offerUrl) || domain;
            pushOffer({
              title: nodeName,
              vendor: sellerName,
              url: offerUrl,
              price: p.price,
              rawPrice: p.rawPrice,
              currency: p.currency,
              availability: normalizeAvailability(
                typeof rec.availability === "string"
                  ? rec.availability
                  : undefined
              ),
              ...(Number.isFinite(ratingVal) ? { rating: ratingVal } : {}),
              source: "json-ld",
            });
          }
          if (Array.isArray(rec.offers)) {
            visit(rec.offers, nodeName, ratingVal);
          }
        }
      };
      visit(parsed, fallbackTitle);
    } catch {
      // Ignore malformed JSON-LD script
    }
  }

  // 2. OpenGraph / meta product price tags
  if (offers.length === 0) {
    const ogAmount = (html.match(
      /<meta[^>]+(?:property|name)=["'](?:product|og):price:amount["'][^>]+content=["']([^"']+)["']/i
    ) ||
      html.match(
        /<meta[^>]+content=["']([^"']+)["'][^>]+(?:property|name)=["'](?:product|og):price:amount["']/i
      ) ||
      html.match(/itemprop=["']price["'][^>]+content=["']([^"']+)["']/i) ||
      [])[1];
    const ogCurrency = (html.match(
      /<meta[^>]+(?:property|name)=["'](?:product|og):price:currency["'][^>]+content=["']([^"']+)["']/i
    ) ||
      html.match(
        /itemprop=["']priceCurrency["'][^>]+content=["']([^"']+)["']/i
      ) ||
      [])[1];

    if (ogAmount) {
      const p = parsePriceString(ogAmount, countryCode, ogCurrency);
      if (p) {
        pushOffer({
          title: fallbackTitle || domain,
          vendor: domain,
          url: pageUrl,
          price: p.price,
          rawPrice: p.rawPrice,
          currency: p.currency,
          source: "opengraph",
        });
      }
    }
  }

  return offers;
}

/**
 * Extract fallback price offer from a SERP result title/description when a snippet explicitly states a price
 * (e.g. "Buy Sony WH-1000XM5 from £173.49", "Sony WH-1000XM5 - $399.00 at JB Hi-Fi").
 */
export function extractOfferFromSerpSnippet(
  title: string,
  description: string,
  url: string,
  countryCode?: string
): ProductOffer | null {
  const combined = `${title} ${description}`;
  const prefixMatch = combined.match(
    /(?:from\s+|price\s+|now\s+|sale\s+|ab\s+)?((?:A\$|AU\$|NZ\$|CA\$|US\$|S\$|SG\$|HK\$|NT\$|Rs\.?|INR|SGD|EUR|GBP|USD|VND|RM|Rp\.?|\$|£|€|¥|₹|₫|฿|₱|₩)\s?\d[\d,.]*(?:\s*(?:crores?|cr|lakhs?|lacs?|tỷ|triệu))?)/i
  );
  const suffixMatch = !prefixMatch
    ? combined.match(
        /(\d[\d,.]*\s*(?:€|£|₫|₹|zł|kr|CHF|EUR|GBP|INR|SGD|VND|THB|MYR|IDR))\b/i
      )
    : null;
  const matchedRaw = prefixMatch?.[1] || suffixMatch?.[1];
  if (!matchedRaw) {
    return null;
  }
  const parsed = parsePriceString(matchedRaw, countryCode);
  if (!parsed) {
    return null;
  }
  const domain = extractDomainHost(url);
  if (!domain) {
    return null;
  }
  return {
    title: title.trim(),
    vendor: domain,
    domain,
    url,
    price: parsed.price,
    rawPrice: parsed.rawPrice,
    currency: parsed.currency,
    source: "serp-snippet",
  };
}

function normalizeProductNameTokens(title: string): string[] {
  const stop = new Set([
    "the",
    "and",
    "with",
    "for",
    "from",
    "buy",
    "new",
    "brand",
    "sealed",
    "official",
    "free",
    "shipping",
    "delivery",
    "sale",
    "deal",
    "deals",
    "price",
    "prices",
    "online",
    "australia",
    "uk",
    "usa",
  ]);
  return title
    .toLowerCase()
    .replace(/[^a-z0-9+]+/g, " ")
    .split(/\s+/)
    .filter((t) => t.length >= 2 && !stop.has(t));
}

function tokenJaccard(a: string[], b: string[]): number {
  if (a.length === 0 || b.length === 0) {
    return 0;
  }
  const setA = new Set(a);
  const setB = new Set(b);
  let inter = 0;
  for (const t of setA) {
    if (setB.has(t)) {
      inter++;
    }
  }
  const union = setA.size + setB.size - inter;
  return union > 0 ? inter / union : 0;
}

/**
 * Group extracted ProductOffer items into normalized AggregatedProduct clusters and compute `bestOffer` (lowest in-stock price).
 */
export function groupOffersIntoProducts(
  offers: ProductOffer[],
  query: string,
  maxProducts = 10
): AggregatedProduct[] {
  if (offers.length === 0) {
    return [];
  }

  const queryTokens = normalizeProductNameTokens(query);

  // Deduplicate identical (domain, price, url) offers
  const uniqueOffers: ProductOffer[] = [];
  const seen = new Set<string>();
  for (const o of offers) {
    const key = `${o.domain}::${o.price}::${o.url}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    uniqueOffers.push(o);
  }

  interface Cluster {
    name: string;
    tokens: string[];
    offers: ProductOffer[];
  }

  const clusters: Cluster[] = [];

  for (const offer of uniqueOffers) {
    const tokens = normalizeProductNameTokens(offer.title);
    let bestCluster: Cluster | null = null;
    let bestSim = 0;

    for (const c of clusters) {
      const sim = tokenJaccard(tokens, c.tokens);
      if (sim > bestSim) {
        bestSim = sim;
        bestCluster = c;
      }
    }

    if (bestCluster && bestSim >= 0.42) {
      bestCluster.offers.push(offer);
      if (
        offer.title.length < bestCluster.name.length &&
        offer.title.length >= 12
      ) {
        bestCluster.name = offer.title;
      }
    } else {
      clusters.push({
        name: offer.title,
        tokens,
        offers: [offer],
      });
    }
  }

  const products: AggregatedProduct[] = clusters.map((c) => {
    const sorted = [...c.offers].sort((a, b) => {
      const aOut = a.availability === "out_of_stock" ? 1 : 0;
      const bOut = b.availability === "out_of_stock" ? 1 : 0;
      if (aOut !== bOut) {
        return aOut - bOut;
      }
      return a.price - b.price;
    });
    const bestOffer = sorted[0];
    const prices = sorted.map((o) => o.price);
    const vendors = Array.from(new Set(sorted.map((o) => o.vendor)));
    return {
      name: c.name,
      bestOffer,
      minPrice: Math.min(...prices),
      maxPrice: Math.max(...prices),
      currency: bestOffer.currency,
      offerCount: sorted.length,
      vendors,
      offers: sorted,
    };
  });

  // Sort clusters by relevance to query tokens + multi-vendor offer count + lowest price
  products.sort((a, b) => {
    const relA = tokenJaccard(normalizeProductNameTokens(a.name), queryTokens);
    const relB = tokenJaccard(normalizeProductNameTokens(b.name), queryTokens);
    const scoreA = relA * 2 + Math.min(a.offerCount, 6) * 0.25;
    const scoreB = relB * 2 + Math.min(b.offerCount, 6) * 0.25;
    if (Math.abs(scoreB - scoreA) > 0.15) {
      return scoreB - scoreA;
    }
    return a.minPrice - b.minPrice;
  });

  return products.slice(0, maxProducts);
}
