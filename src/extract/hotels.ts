import {
  extractDomainHost,
  parsePriceString,
  resolveCurrencyCode,
} from "./currency.js";
import { normalizeIdentity, resultDedupeKey } from "./dedupe-key.js";
import { ldImage, resolveAbsoluteUrl } from "./real-estate.js";

export interface HotelListing {
  name: string;
  address?: string;
  city?: string;
  country?: string;
  pricePerNight?: number;
  priceText: string;
  currency?: string;
  starRating?: number;
  guestRating?: number;
  reviewCount?: number;
  amenities?: string[];
  roomType?: string;
  freeCancellation?: boolean;
  image?: string;
  latitude?: number;
  longitude?: number;
  url: string;
  provider: string;
  extractedVia:
    | "json-state"
    | "rsc-payload"
    | "json-ld"
    | "html-cards"
    | "scaledown-extract-1"
    | "serp-snippet";
}

const HOTEL_TYPES = new Set([
  "hotel",
  "lodgingbusiness",
  "resort",
  "hostel",
  "motel",
  "bedandbreakfast",
  "vacationrental",
  "hotelroom",
  "suite",
  "accommodation",
]);

export function parseHotelPrice(
  rawPrice: string | number | undefined | null,
  countryCode?: string,
  explicitCurrency?: string
): { pricePerNight?: number; priceText: string; currency: string } {
  const defaultCurrency = resolveCurrencyCode(explicitCurrency, countryCode);
  if (
    typeof rawPrice === "number" &&
    Number.isFinite(rawPrice) &&
    rawPrice >= 15 &&
    rawPrice <= 25_000
  ) {
    const rounded = Math.round(rawPrice);
    return {
      pricePerNight: rounded,
      priceText: `${defaultCurrency} $${rounded.toLocaleString("en-US")}/night`,
      currency: defaultCurrency,
    };
  }
  const text = String(rawPrice || "").trim();
  if (!text) {
    return { priceText: "Check Availability", currency: defaultCurrency };
  }
  const parsed = parsePriceString(text, countryCode, explicitCurrency, 25_000);
  if (parsed && parsed.price >= 15) {
    const rounded = Math.round(parsed.price);
    return {
      pricePerNight: rounded,
      priceText: `${parsed.currency} $${rounded.toLocaleString("en-US")}/night`,
      currency: parsed.currency,
    };
  }
  return { priceText: text, currency: defaultCurrency };
}

function extractAddressFields(addr: unknown): {
  address?: string;
  city?: string;
  country?: string;
} {
  if (!addr) {
    return {};
  }
  if (typeof addr === "string") {
    return { address: addr.trim() };
  }
  if (typeof addr === "object") {
    const a = addr as Record<string, unknown>;
    const street =
      typeof a.streetAddress === "string" ? a.streetAddress.trim() : "";
    const city =
      typeof a.addressLocality === "string"
        ? a.addressLocality.trim()
        : typeof a.city === "string"
          ? a.city.trim()
          : "";
    const region =
      typeof a.addressRegion === "string" ? a.addressRegion.trim() : "";
    const country =
      typeof a.addressCountry === "string"
        ? a.addressCountry.trim()
        : typeof (a.addressCountry as Record<string, unknown> | undefined)
              ?.name === "string"
          ? String((a.addressCountry as Record<string, unknown>).name).trim()
          : undefined;
    const parts = [street, city, region].filter(Boolean);
    return {
      address: parts.length > 0 ? parts.join(", ") : undefined,
      city: city || undefined,
      country,
    };
  }
  return {};
}

function walkHotelJsonNode(
  node: unknown,
  pageUrl: string,
  portal: string,
  countryCode: string | undefined,
  extractedVia: HotelListing["extractedVia"],
  out: HotelListing[],
  depth = 0
): void {
  if (depth > 12 || out.length >= 45 || !node || typeof node !== "object") {
    return;
  }
  if (Array.isArray(node)) {
    for (const item of node) {
      walkHotelJsonNode(
        item,
        pageUrl,
        portal,
        countryCode,
        extractedVia,
        out,
        depth + 1
      );
    }
    return;
  }

  const obj = node as Record<string, unknown>;
  const rawType = String(obj["@type"] || obj.type || "").toLowerCase();
  const name =
    typeof obj.name === "string"
      ? obj.name.trim()
      : typeof obj.hotelName === "string"
        ? obj.hotelName.trim()
        : typeof obj.propertyName === "string"
          ? obj.propertyName.trim()
          : "";

  const offersObj = obj.offers as Record<string, unknown> | undefined;
  const rawPriceVal =
    obj.pricePerNight ??
    obj.nightlyPrice ??
    obj.minPrice ??
    obj.lowPrice ??
    obj.price ??
    offersObj?.price ??
    offersObj?.lowPrice ??
    obj.priceRange;
  const rawCurrency =
    (typeof obj.priceCurrency === "string" ? obj.priceCurrency : undefined) ||
    (typeof obj.currency === "string" ? obj.currency : undefined) ||
    (typeof offersObj?.priceCurrency === "string"
      ? offersObj.priceCurrency
      : undefined);

  const starRatingObj = obj.starRating as Record<string, unknown> | undefined;
  const aggRatingObj = obj.aggregateRating as
    | Record<string, unknown>
    | undefined;

  const starRatingRaw =
    starRatingObj?.ratingValue ?? obj.starRating ?? obj.stars ?? obj.hotelClass;
  const starRatingNum =
    typeof starRatingRaw === "number" || typeof starRatingRaw === "string"
      ? Number.parseFloat(String(starRatingRaw))
      : undefined;

  const guestRatingRaw =
    aggRatingObj?.ratingValue ??
    obj.guestRating ??
    obj.reviewScore ??
    obj.rating;
  const guestRatingNum =
    typeof guestRatingRaw === "number" || typeof guestRatingRaw === "string"
      ? Number.parseFloat(String(guestRatingRaw))
      : undefined;

  const reviewCountRaw =
    aggRatingObj?.reviewCount ??
    aggRatingObj?.ratingCount ??
    obj.reviewCount ??
    obj.numberOfReviews;
  const reviewCountNum =
    typeof reviewCountRaw === "number" || typeof reviewCountRaw === "string"
      ? Number.parseInt(String(reviewCountRaw).replace(/,/g, ""), 10)
      : undefined;

  const isSiteOrArticleNode =
    /^(website|webpage|organization|corporation|article|newsarticle|blogposting|breadcrumblist|faqpage|searchaction)$/i.test(
      rawType
    );

  const isHotel =
    !isSiteOrArticleNode &&
    (HOTEL_TYPES.has(rawType) ||
      (name.length >= 4 &&
        name.length <= 120 &&
        !/^(luxury\s+hotels?|best\s+hotels?|hotels?\s+in\b|cheap\s+hotels?)/i.test(
          name
        ) &&
        (/\b(hotel|resort|suites?|inn|lodge|motel|hostel|palace|hyatt|marriott|hilton|sheraton|intercontinental|novotel|sofitel|ibis|pullman|westin|radisson|ritz|four\s+seasons|holiday\s+inn|crowne\s+plaza|mercure|shangri-la|capella|langham)\b/i.test(
          name
        ) ||
          Boolean(
            obj.starRating !== undefined ||
            obj.pricePerNight !== undefined ||
            obj.nightlyPrice !== undefined ||
            obj.hotelId !== undefined
          )) &&
        (rawPriceVal !== undefined ||
          guestRatingNum !== undefined ||
          starRatingNum !== undefined ||
          obj.address !== undefined)));

  if (isHotel && name) {
    const parsedPrice = parseHotelPrice(
      rawPriceVal as string | number | undefined,
      countryCode,
      rawCurrency
    );
    const addrInfo = extractAddressFields(obj.address || obj.location);
    const geoObj = obj.geo as Record<string, unknown> | undefined;
    const lat =
      typeof geoObj?.latitude === "number"
        ? geoObj.latitude
        : typeof obj.latitude === "number"
          ? obj.latitude
          : undefined;
    const lng =
      typeof geoObj?.longitude === "number"
        ? geoObj.longitude
        : typeof obj.longitude === "number"
          ? obj.longitude
          : undefined;

    let amenities: string[] | undefined;
    if (Array.isArray(obj.amenityFeature)) {
      amenities = (obj.amenityFeature as Array<Record<string, unknown>>)
        .map((a) => (typeof a?.name === "string" ? a.name.trim() : ""))
        .filter(Boolean)
        .slice(0, 8);
    } else if (Array.isArray(obj.amenities)) {
      amenities = (obj.amenities as unknown[])
        .map((a) => (typeof a === "string" ? a.trim() : ""))
        .filter(Boolean)
        .slice(0, 8);
    }

    const itemUrl =
      typeof obj.url === "string"
        ? resolveAbsoluteUrl(obj.url, pageUrl)
        : pageUrl;
    // string | string[] | ImageObject | ImageObject[] (hotel sites use all four)
    const rawImage = ldImage(obj.image ?? obj.photo);
    const image = rawImage ? resolveAbsoluteUrl(rawImage, pageUrl) : undefined;

    out.push({
      name,
      address: addrInfo.address,
      city: addrInfo.city,
      country: addrInfo.country || countryCode,
      pricePerNight: parsedPrice.pricePerNight,
      priceText: parsedPrice.priceText,
      currency: parsedPrice.currency,
      starRating:
        starRatingNum && starRatingNum >= 1 && starRatingNum <= 5
          ? starRatingNum
          : undefined,
      guestRating:
        guestRatingNum && guestRatingNum > 0 && guestRatingNum <= 10
          ? Number(guestRatingNum.toFixed(1))
          : undefined,
      reviewCount:
        reviewCountNum && Number.isFinite(reviewCountNum) && reviewCountNum > 0
          ? reviewCountNum
          : undefined,
      amenities: amenities?.length ? amenities : undefined,
      image,
      latitude: lat,
      longitude: lng,
      url: /undefined|null/i.test(safeHost(itemUrl)) ? pageUrl : itemUrl,
      provider: /undefined|null/i.test(safeHost(itemUrl))
        ? portal
        : extractDomainHost(itemUrl) || portal,
      extractedVia,
    });
  }

  for (const val of Object.values(obj)) {
    if (val && typeof val === "object") {
      walkHotelJsonNode(
        val,
        pageUrl,
        portal,
        countryCode,
        extractedVia,
        out,
        depth + 1
      );
    }
  }
}

export function extractHotelListingsFromHtml(
  html: string,
  pageUrl: string,
  countryCode?: string
): HotelListing[] {
  const out: HotelListing[] = [];
  const portal = extractDomainHost(pageUrl) || "unknown";

  // Tier 1: Schema.org JSON-LD
  const jsonLdRegex =
    /<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let match: RegExpExecArray | null;
  while ((match = jsonLdRegex.exec(html)) !== null) {
    try {
      const parsed = JSON.parse(match[1].trim());
      walkHotelJsonNode(parsed, pageUrl, portal, countryCode, "json-ld", out);
    } catch {
      // Ignore malformed JSON-LD
    }
  }

  // Tier 2: Embedded JSON state (__NEXT_DATA__, application/json)
  if (out.length < 3) {
    const stateRegex =
      /<script[^>]+(?:id=["']__NEXT_DATA__["']|type=["']application\/json["'])[^>]*>([\s\S]*?)<\/script>/gi;
    while ((match = stateRegex.exec(html)) !== null) {
      try {
        const raw = match[1].trim();
        if (raw.length > 20 && raw.length < 2_000_000) {
          const parsed = JSON.parse(raw);
          walkHotelJsonNode(
            parsed,
            pageUrl,
            portal,
            countryCode,
            "json-state",
            out
          );
        }
      } catch {
        // Ignore
      }
    }
  }

  // Tier 2.2: OTA result cards (Booking.com district / search pages ship no JSON-LD)
  if (out.length < 3 && html.includes('data-testid="title"')) {
    out.push(...extractBookingCards(html, pageUrl, portal, countryCode));
  }

  // Tier 2.5: Extract structured hotel cards / headings from HTML when JSON-LD & JSON state have < 3 hotels
  if (out.length < 3) {
    const headingRegex =
      /<h[23][^>]*>([\s\S]{3,160}?)<\/h[23]>([\s\S]{0,600}?)(?=<h[23]|\bfooter\b|$)/gi;
    let hMatch: RegExpExecArray | null;
    while ((hMatch = headingRegex.exec(html)) !== null && out.length < 25) {
      const rawHeading = hMatch[1]
        .replace(/<[^>]+>/g, " ")
        .replace(/&amp;/g, "&")
        .replace(/&#x27;|&#39;/g, "'")
        .replace(/&quot;/g, '"')
        .replace(/^\s*(?:#?\d+\s*[.)\-:]?\s+)/, "")
        .replace(/\s+/g, " ")
        .trim();
      if (
        !rawHeading ||
        rawHeading.length < 4 ||
        rawHeading.length > 90 ||
        /\b(best\s+hotels?|where\s+to\s+stay|frequently\s+asked|faq|about\s+sydney|things\s+to\s+do|how\s+we\s+choose|more\s+hotels?|related|search|filter|map|subscribe|newsletter|luxury\s+hotels?\s+in|widget|advertisement|sponsored)\b/i.test(
          rawHeading
        )
      ) {
        continue;
      }
      const isNamedHotel =
        /\b(hotel|resort|suites?|inn|lodge|palace|hyatt|marriott|hilton|sheraton|intercontinental|novotel|sofitel|ibis|pullman|westin|radisson|ritz|four\s+seasons|crowne\s+plaza|mercure|shangri-la|langham|capella|crown\s+towers|kimpton|oxfords?|pier\s+one|qt\s+\w+|w\s+\w+|ovolos?|ace\s+hotel|paramount\s+house|taronga)\b/i.test(
          rawHeading
        );
      if (!isNamedHotel) {
        continue;
      }
      const snippet = hMatch[2]
        .replace(/<[^>]+>/g, " ")
        .replace(/\s+/g, " ")
        .trim();
      const explicitPrice = snippet.match(
        /(?:A\$|AU\$|US\$|CA\$|NZ\$|S\$|HK\$|\$|£|€|¥|₹|\b(?:USD|AUD|GBP|EUR|CAD|NZD|SGD)\b)\s*(\d[\d,]*(?:\.\d{1,2})?)/i
      );
      const parsedPrice = parseHotelPrice(
        explicitPrice ? explicitPrice[0] : undefined,
        countryCode
      );
      const starMatch = `${rawHeading} ${snippet}`.match(
        /\b([1-5])(?:\.\d)?[- ]star\b/i
      );
      const ratingMatch = snippet.match(/\b([1-9]\.\d)\s*\/\s*(?:5|10)\b/);
      out.push({
        name: rawHeading,
        country: countryCode,
        pricePerNight: parsedPrice.pricePerNight,
        priceText: parsedPrice.priceText,
        currency: parsedPrice.currency,
        starRating: starMatch ? Number.parseInt(starMatch[1], 10) : undefined,
        guestRating: ratingMatch
          ? Number.parseFloat(ratingMatch[1])
          : undefined,
        url: pageUrl,
        provider: portal,
        extractedVia: "json-state",
      });
    }
  }

  return dedupeHotelListings(out);
}

function safeHost(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

const decodeEntities = (s: string) =>
  s
    .replace(/&amp;/g, "&")
    .replace(/&#x27;|&#39;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&nbsp;|&#160;/g, " ");
const stripTags = (s: string) =>
  decodeEntities(s.replace(/<[^>]+>/g, " ")).replace(/\s+/g, " ").trim();

/** Drop affiliate / session params so the same hotel keeps one stable URL. */
function cleanOtaUrl(href: string, pageUrl: string): string {
  const abs = resolveAbsoluteUrl(decodeEntities(href), pageUrl);
  try {
    const u = new URL(abs);
    return `${u.origin}${u.pathname}`;
  } catch {
    return abs;
  }
}

/**
 * Booking.com property cards. District pages use `data-testid="card"`, search
 * results use `data-testid="property-card"`; both carry `data-testid="title"`,
 * a `titleLink`, an `image`, a star aria-label and a "guest rating" line.
 */
export function extractBookingCards(
  html: string,
  pageUrl: string,
  portal: string,
  countryCode?: string
): HotelListing[] {
  const out: HotelListing[] = [];
  const parts = html.split(/<div[^>]+data-testid="(?:property-)?card"/i).slice(1);
  for (const card of parts.slice(0, 30)) {
    const titleBlock = card.match(/data-testid="title"[^>]*>([\s\S]{0,1200}?)<\/(?:h3|div)>/i);
    if (!titleBlock) {
      continue;
    }
    // Name is the first text node inside the title block (stars follow as an empty div).
    const firstText = titleBlock[1].match(/>\s*([^<>]{2,120}?)\s*</);
    const name = stripTags(firstText ? firstText[1] : titleBlock[1]);
    if (!name || name.length < 2 || name.length > 120) {
      continue;
    }

    const href =
      card.match(/data-testid="titleLink"[^>]*href="([^"]+)"/i)?.[1] ??
      card.match(/href="([^"]+)"[^>]*data-testid="titleLink"/i)?.[1] ??
      card.match(/href="(https?:\/\/[^"]*\/hotel\/[^"]+)"/i)?.[1];
    const imgSrc =
      card.match(/data-testid="image"[^>]*src="([^"]+)"/i)?.[1] ??
      card.match(/<img[^>]+src="([^"]+)"[^>]*data-testid="image"/i)?.[1];
    const stars = card.match(/aria-label="([1-5]) out of 5 (?:stars|quality rating)"/i);
    const scored = card.match(/guest rating\s*([0-9]+(?:\.[0-9])?)/i)
      ?? card.match(/data-testid="review-score"[\s\S]{0,300}?>\s*([0-9]{1,2}(?:\.[0-9])?)\s*</i);
    const reviews = card.match(/([\d,.]+)\s+reviews?\b/i);
    const location =
      card.match(/data-testid="address"[^>]*>([^<]{3,100})</i)?.[1] ??
      card.match(/<\/svg><\/span>([^<]{3,100})<\/div>/i)?.[1];

    const priceRaw =
      card.match(/data-testid="price-and-discounted-price"[^>]*>([^<]{2,40})</i)?.[1] ??
      card.match(/Price from[\s\S]{0,400}?<span[^>]*>([^<]{2,40})<\/span>/i)?.[1];
    const parsedPrice = parseHotelPrice(
      priceRaw ? decodeEntities(priceRaw).trim() : undefined,
      countryCode
    );
    const guestRating = scored ? Number.parseFloat(scored[1]) : undefined;

    out.push({
      name: decodeEntities(name),
      address: location ? stripTags(location) : undefined,
      country: countryCode,
      pricePerNight: parsedPrice.pricePerNight,
      priceText: parsedPrice.priceText,
      currency: parsedPrice.currency,
      starRating: stars ? Number.parseInt(stars[1], 10) : undefined,
      guestRating:
        guestRating !== undefined && guestRating > 0 && guestRating <= 10
          ? guestRating
          : undefined,
      reviewCount: reviews
        ? Number.parseInt(reviews[1].replace(/[,.]/g, ""), 10) || undefined
        : undefined,
      image: imgSrc ? resolveAbsoluteUrl(decodeEntities(imgSrc), pageUrl) : undefined,
      url: href ? cleanOtaUrl(href, pageUrl) : pageUrl,
      provider: portal,
      extractedVia: "html-cards",
    });
  }
  return out;
}

export function extractHotelListingFromSerpResult(
  title: string,
  description: string,
  url: string,
  countryCode?: string
): HotelListing | null {
  const cleanTitle = title.replace(/\s*[|\-–\u2014•]\s*.*$/, "").trim();
  if (!cleanTitle || cleanTitle.length < 3) {
    return null;
  }
  // Skip generic roundup / listicle / search hub titles so ScaleDown extracts the actual hotels inside the page
  if (
    /\b(\d+\s+best|best\s+\d+|top\s+\d+|the\s+best\b|hotels?\s+in\b|luxury\s+hotels?\s+in\b|accommodation\s+in\b|where\s+to\s+stay|guide\s+to|compare\s+hotels?)/i.test(
      cleanTitle
    )
  ) {
    return null;
  }

  const combined = `${title} ${description}`;
  const explicitPriceMatch = combined.match(
    /(?:A\$|AU\$|US\$|CA\$|NZ\$|S\$|SG\$|HK\$|Rs\.?|\$|£|€|¥|₹|₫|฿|₱|₩|\b(?:USD|AUD|GBP|EUR|CAD|NZD|SGD|INR|VND|THB|MYR|IDR|CHF|AED)\b)\s*(\d[\d.,]*)|(\d[\d.,]*)\s*(?:€|£|₫|₹|\b(?:EUR|GBP|INR|SGD|VND|CHF)\b)/i
  );
  const priceParsed = explicitPriceMatch
    ? parsePriceString(explicitPriceMatch[0], countryCode, undefined, 15_000)
    : null;
  const starMatch = combined.match(/\b([1-5])(?:\.\d)?[- ]star\b/i);
  const ratingMatch =
    combined.match(/\b([1-9]\.\d)\s*\/\s*(?:5|10)\b/) ||
    combined.match(/\brating[:\s]+([1-9]\.\d)\b/i);
  const reviewMatch = combined.match(/\b(\d[\d,]{1,6})\s+reviews?\b/i);

  const looksLikeSpecificHotel =
    /\b(hotel|resort|suites?|inn|lodge|motel|hostel|palace|hyatt|marriott|hilton|sheraton|intercontinental|novotel|sofitel|ibis|pullman|westin|radisson|ritz|four\s+seasons|crowne\s+plaza|mercure|shangri-la|langham|capella|w\s+sydney|crown\s+towers)\b/i.test(
      cleanTitle
    );
  if (!looksLikeSpecificHotel) {
    return null;
  }

  const parsedPrice = parseHotelPrice(
    priceParsed?.price,
    countryCode,
    priceParsed?.currency
  );
  const amenities: string[] = [];
  if (/\bfree\s+wi-?fi\b/i.test(combined)) {
    amenities.push("Free WiFi");
  }
  if (/\bpool\b/i.test(combined)) {
    amenities.push("Pool");
  }
  if (/\bbreakfast\b/i.test(combined)) {
    amenities.push("Breakfast");
  }
  if (/\bspa\b/i.test(combined)) {
    amenities.push("Spa");
  }
  if (/\bfree\s+cancellation\b/i.test(combined)) {
    amenities.push("Free Cancellation");
  }

  return {
    name: cleanTitle,
    country: countryCode,
    pricePerNight: parsedPrice.pricePerNight,
    priceText: parsedPrice.priceText,
    currency: parsedPrice.currency,
    starRating: starMatch ? Number.parseInt(starMatch[1], 10) : undefined,
    guestRating: ratingMatch ? Number.parseFloat(ratingMatch[1]) : undefined,
    reviewCount: reviewMatch
      ? Number.parseInt(reviewMatch[1].replace(/,/g, ""), 10)
      : undefined,
    amenities: amenities.length > 0 ? amenities : undefined,
    freeCancellation: /\bfree\s+cancellation\b/i.test(combined) || undefined,
    url,
    provider: extractDomainHost(url) || "unknown",
    extractedVia: "serp-snippet",
  };
}

export function dedupeHotelListings(
  hotels: HotelListing[],
  maxItems = 30
): HotelListing[] {
  const seen = new Set<string>();
  const unique: HotelListing[] = [];
  for (const h of hotels) {
    const normName = normalizeIdentity(h.name);
    // Same provider + different URL = different listing; only exact repeats are dropped.
    const key = resultDedupeKey(h.url, normName);
    if (!normName || normName.length < 3 || seen.has(key)) {
      continue;
    }
    seen.add(key);
    unique.push(h);
  }
  if (unique.length <= maxItems) {
    return unique;
  }
  // Over the cap: take providers in turn so the first page to answer does not
  // crowd out every other source.
  const byProvider = new Map<string, HotelListing[]>();
  for (const h of unique) {
    const list = byProvider.get(h.provider) ?? [];
    list.push(h);
    byProvider.set(h.provider, list);
  }
  const queues = [...byProvider.values()];
  const out: HotelListing[] = [];
  for (let i = 0; out.length < maxItems; i++) {
    let took = false;
    for (const q of queues) {
      if (i < q.length && out.length < maxItems) {
        out.push(q[i]);
        took = true;
      }
    }
    if (!took) {
      break;
    }
  }
  return out;
}
