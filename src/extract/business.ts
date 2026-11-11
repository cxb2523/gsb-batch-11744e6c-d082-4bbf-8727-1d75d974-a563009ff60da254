import { extractDomainHost } from "./currency.js";
import { normalizeIdentity, resultDedupeKey } from "./dedupe-key.js";
import { resolveAbsoluteUrl } from "./real-estate.js";

export interface BusinessListing {
  name: string;
  category?: string;
  description?: string;
  address?: string;
  city?: string;
  state?: string;
  postcode?: string;
  country?: string;
  phone?: string;
  email?: string;
  website?: string;
  rating?: number;
  reviewCount?: number;
  priceRange?: string;
  openingHours?: string | string[];
  foundedYear?: number;
  employeeCount?: string;
  headquarters?: string;
  latitude?: number;
  longitude?: number;
  url: string;
  sourceDomain: string;
  extractedVia:
    | "json-state"
    | "rsc-payload"
    | "json-ld"
    | "scaledown-extract-1"
    | "serp-snippet";
}

const BUSINESS_SCHEMA_TYPES = new Set([
  "localbusiness",
  "organization",
  "corporation",
  "restaurant",
  "foodestablishment",
  "cafeorcoffeeshop",
  "bakery",
  "barorpub",
  "store",
  "autodealer",
  "autorepair",
  "medicalbusiness",
  "dentist",
  "physician",
  "pharmacy",
  "hospital",
  "healthandbeautybusiness",
  "dayspa",
  "hairsalon",
  "legalservice",
  "attorney",
  "accountingservice",
  "financialservice",
  "insuranceagency",
  "realestateagent",
  "homeandconstructionbusiness",
  "plumber",
  "electrician",
  "hvacbusiness",
  "generalcontractor",
  "locksmith",
  "movingcompany",
  "professionalservice",
  "employmentagency",
  "travelagency",
  "sportsactivitylocation",
  "exerciseGym",
]);

function isBusinessSchemaType(rawType: string): boolean {
  const clean = rawType.toLowerCase().trim();
  if (BUSINESS_SCHEMA_TYPES.has(clean)) {
    return true;
  }
  return (
    clean.endsWith("business") ||
    clean.endsWith("store") ||
    clean.endsWith("service") ||
    clean.endsWith("shop") ||
    clean.endsWith("clinic") ||
    clean.endsWith("agency") ||
    clean.endsWith("contractor")
  );
}

function parseAddressObject(addr: unknown): {
  address?: string;
  city?: string;
  state?: string;
  postcode?: string;
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
      typeof a.streetAddress === "string"
        ? a.streetAddress.trim()
        : typeof a.address1 === "string"
          ? a.address1.trim()
          : "";
    const city =
      typeof a.addressLocality === "string"
        ? a.addressLocality.trim()
        : typeof a.city === "string"
          ? a.city.trim()
          : "";
    const state =
      typeof a.addressRegion === "string"
        ? a.addressRegion.trim()
        : typeof a.state === "string"
          ? a.state.trim()
          : "";
    const postcode =
      typeof a.postalCode === "string" || typeof a.postalCode === "number"
        ? String(a.postalCode).trim()
        : typeof a.zipCode === "string"
          ? a.zipCode.trim()
          : "";
    const country =
      typeof a.addressCountry === "string"
        ? a.addressCountry.trim()
        : typeof (a.addressCountry as Record<string, unknown> | undefined)
              ?.name === "string"
          ? String((a.addressCountry as Record<string, unknown>).name).trim()
          : undefined;
    const full = [street, city, state, postcode].filter(Boolean).join(", ");
    return {
      address:
        full ||
        (typeof a.formattedAddress === "string"
          ? a.formattedAddress
          : undefined),
      city: city || undefined,
      state: state || undefined,
      postcode: postcode || undefined,
      country,
    };
  }
  return {};
}

function walkBusinessJsonNode(
  node: unknown,
  pageUrl: string,
  portal: string,
  countryCode: string | undefined,
  extractedVia: BusinessListing["extractedVia"],
  out: BusinessListing[],
  depth = 0
): void {
  if (depth > 12 || out.length >= 45 || !node || typeof node !== "object") {
    return;
  }
  if (Array.isArray(node)) {
    for (const item of node) {
      walkBusinessJsonNode(
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
  const rawTypeVal = Array.isArray(obj["@type"])
    ? String(obj["@type"][0] || "")
    : String(obj["@type"] || obj.type || "");
  const name =
    typeof obj.name === "string"
      ? obj.name.trim()
      : typeof obj.businessName === "string"
        ? obj.businessName.trim()
        : typeof obj.companyName === "string"
          ? obj.companyName.trim()
          : "";

  const phone =
    typeof obj.telephone === "string"
      ? obj.telephone.trim()
      : typeof obj.phone === "string"
        ? obj.phone.trim()
        : typeof obj.displayPhone === "string"
          ? obj.displayPhone.trim()
          : undefined;
  const email =
    typeof obj.email === "string"
      ? obj.email.replace(/^mailto:/i, "").trim()
      : undefined;
  const addrInfo = parseAddressObject(obj.address || obj.location);

  const aggRating = obj.aggregateRating as Record<string, unknown> | undefined;
  const ratingRaw = aggRating?.ratingValue ?? obj.rating ?? obj.averageRating;
  const ratingNum =
    typeof ratingRaw === "number" || typeof ratingRaw === "string"
      ? Number.parseFloat(String(ratingRaw))
      : undefined;
  const reviewCountRaw =
    aggRating?.reviewCount ??
    aggRating?.ratingCount ??
    obj.reviewCount ??
    obj.numberOfReviews;
  const reviewCountNum =
    typeof reviewCountRaw === "number" || typeof reviewCountRaw === "string"
      ? Number.parseInt(String(reviewCountRaw).replace(/,/g, ""), 10)
      : undefined;

  const isGenericOrgOnly =
    /^(organization|corporation|brand|newsmediaorganization)$/i.test(
      rawTypeVal
    );
  const hasBusinessSignals =
    (isBusinessSchemaType(rawTypeVal) &&
      (!isGenericOrgOnly ||
        Boolean(addrInfo.address || phone || ratingNum !== undefined))) ||
    Boolean(
      name.length >= 2 &&
      name.length <= 120 &&
      (phone ||
        (addrInfo.address && (ratingNum !== undefined || obj.priceRange)) ||
        (obj.businessId !== undefined && addrInfo.address))
    );

  // Skip generic site-level WebSite / SearchAction / BreadcrumbList nodes
  if (
    hasBusinessSignals &&
    name &&
    !/^(website|webpage|breadcrumblist|searchaction|itemlist|faqpage)$/i.test(
      rawTypeVal
    )
  ) {
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

    let category =
      typeof obj.category === "string"
        ? obj.category
        : Array.isArray(obj.categories) && typeof obj.categories[0] === "string"
          ? obj.categories[0]
          : typeof obj.servesCuisine === "string"
            ? obj.servesCuisine
            : rawTypeVal && !/^(organization|localbusiness)$/i.test(rawTypeVal)
              ? rawTypeVal
              : undefined;
    if (
      Array.isArray(obj.categories) &&
      obj.categories[0] &&
      typeof obj.categories[0] === "object"
    ) {
      const firstCat = obj.categories[0] as Record<string, unknown>;
      if (typeof firstCat.title === "string") {
        category = firstCat.title;
      } else if (typeof firstCat.name === "string") {
        category = firstCat.name;
      }
    }

    let openingHours: string | string[] | undefined;
    if (typeof obj.openingHours === "string") {
      openingHours = obj.openingHours;
    } else if (Array.isArray(obj.openingHours)) {
      openingHours = (obj.openingHours as unknown[])
        .filter((h): h is string => typeof h === "string")
        .slice(0, 7);
    }

    const foundingDate =
      typeof obj.foundingDate === "string" ||
      typeof obj.foundingDate === "number"
        ? String(obj.foundingDate)
        : undefined;
    const foundedMatch = foundingDate?.match(/\b(18\d{2}|19\d{2}|20\d{2})\b/);
    const itemUrl =
      typeof obj.url === "string"
        ? resolveAbsoluteUrl(obj.url, pageUrl)
        : pageUrl;

    if (
      addrInfo.address ||
      phone ||
      email ||
      ratingNum !== undefined ||
      typeof obj.description === "string"
    ) {
      out.push({
        name,
        category,
        description:
          typeof obj.description === "string"
            ? obj.description.trim().slice(0, 280)
            : undefined,
        address: addrInfo.address,
        city: addrInfo.city,
        state: addrInfo.state,
        postcode: addrInfo.postcode,
        country: addrInfo.country || countryCode,
        phone,
        email,
        website: itemUrl,
        rating:
          ratingNum && ratingNum > 0 && ratingNum <= 10
            ? Number(ratingNum.toFixed(1))
            : undefined,
        reviewCount:
          reviewCountNum &&
          Number.isFinite(reviewCountNum) &&
          reviewCountNum > 0
            ? reviewCountNum
            : undefined,
        priceRange:
          typeof obj.priceRange === "string"
            ? obj.priceRange.trim()
            : undefined,
        openingHours,
        foundedYear: foundedMatch
          ? Number.parseInt(foundedMatch[1], 10)
          : undefined,
        latitude: lat,
        longitude: lng,
        url: itemUrl,
        sourceDomain: extractDomainHost(itemUrl) || portal,
        extractedVia,
      });
    }
  }

  for (const val of Object.values(obj)) {
    if (val && typeof val === "object") {
      walkBusinessJsonNode(
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

export function extractBusinessListingsFromHtml(
  html: string,
  pageUrl: string,
  countryCode?: string
): BusinessListing[] {
  const out: BusinessListing[] = [];
  const portal = extractDomainHost(pageUrl) || "unknown";

  // Tier 1: Schema.org JSON-LD
  const jsonLdRegex =
    /<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let match: RegExpExecArray | null;
  while ((match = jsonLdRegex.exec(html)) !== null) {
    try {
      const parsed = JSON.parse(match[1].trim());
      walkBusinessJsonNode(
        parsed,
        pageUrl,
        portal,
        countryCode,
        "json-ld",
        out
      );
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
          walkBusinessJsonNode(
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

  return dedupeBusinessListings(out);
}

export function extractBusinessListingFromSerpResult(
  title: string,
  description: string,
  url: string,
  countryCode?: string
): BusinessListing | null {
  const combined = `${title} ${description}`;
  const cleanName = title.replace(/\s*[|\-–\u2014•:]\s*.*$/, "").trim();
  if (
    !cleanName ||
    cleanName.length < 2 ||
    /\b(the\s+\d+\s+best|best\s+\d+|top\s+\d+|best\s+.*\s+in\b|places?\s+to\b|where\s+to\b|guide\s+to\b|directory\b|yellow\s+pages|yelp|tripadvisor|timeout|broadsheet|urban\s+list)\b/i.test(
      cleanName
    )
  ) {
    return null;
  }

  const phoneMatch = combined.match(
    /(?:\+?\d{1,3}[\s.-]?)?\(?\d{2,4}\)?[\s.-]\d{3,4}[\s.-]\d{3,4}\b/
  );
  const ratingMatch =
    combined.match(/\b([1-5]\.\d)\s*(?:\/\s*5|stars?|★)/i) ||
    combined.match(/\brating[:\s]+([1-5]\.\d)\b/i);
  const reviewMatch = combined.match(/\b(\d[\d,]{0,6})\s+reviews?\b/i);
  const priceRangeMatch = combined.match(/(?:^|\s)(\${1,4})(?:\s|[·•,]|$)/);
  const addrMatch = description.match(
    /\b(\d{1,5}\s+[A-Z][a-zA-Z0-9\s.]{2,30}\s+(?:St|Street|Rd|Road|Ave|Avenue|Blvd|Boulevard|Dr|Drive|Ln|Lane|Way|Pl|Place|Pde|Parade|Hwy|Highway)(?:,\s*[A-Za-z\s]+)?)/
  );

  // Require at least one concrete business attribute (address, phone, or rating) in the SERP snippet
  if (!addrMatch && !phoneMatch && !ratingMatch) {
    return null;
  }

  const sourceDomain = extractDomainHost(url) || "unknown";

  return {
    name: cleanName,
    description: description.trim().slice(0, 240) || undefined,
    address: addrMatch ? addrMatch[1].trim() : undefined,
    country: countryCode,
    phone: phoneMatch ? phoneMatch[0].trim() : undefined,
    website: url,
    rating: ratingMatch ? Number.parseFloat(ratingMatch[1]) : undefined,
    reviewCount: reviewMatch
      ? Number.parseInt(reviewMatch[1].replace(/,/g, ""), 10)
      : undefined,
    priceRange: priceRangeMatch ? priceRangeMatch[1] : undefined,
    url,
    sourceDomain,
    extractedVia: "serp-snippet",
  };
}

export function dedupeBusinessListings(
  businesses: BusinessListing[],
  maxItems = 30
): BusinessListing[] {
  const seen = new Set<string>();
  const out: BusinessListing[] = [];
  for (const b of businesses) {
    const normName = normalizeIdentity(b.name);
    // Same name on different directory pages / URLs is kept; only exact repeats dropped.
    const key = resultDedupeKey(b.url || b.website, normName);
    if (!normName || normName.length < 2 || seen.has(key)) {
      continue;
    }
    seen.add(key);
    out.push(b);
    if (out.length >= maxItems) {
      break;
    }
  }
  return out;
}
