import {
  extractDomainHost,
  parsePriceString,
  resolveCurrencyCode,
} from "./currency.js";
import { resultDedupeKey } from "./dedupe-key.js";

export interface PropertyListing {
  title: string;
  address: string;
  suburb?: string;
  state?: string;
  postcode?: string;
  country?: string;
  price?: number;
  priceText: string;
  currency?: string;
  pricePeriod?: "total" | "week" | "month" | "year";
  listingType: "sale" | "rent" | "sold" | "unknown";
  propertyType?: string;
  bedrooms?: number;
  bathrooms?: number;
  parking?: number;
  landSize?: string;
  buildingSize?: string;
  url: string;
  portal: string;
  agency?: string;
  agent?: string;
  image?: string;
  latitude?: number;
  longitude?: number;
  extractedVia:
    | "json-state"
    | "rsc-payload"
    | "json-ld"
    | "scaledown-extract-1"
    | "serp-snippet";
}

export function inferListingType(
  rawUrl: string,
  rawStatus?: string,
  rawPriceText?: string
): "sale" | "rent" | "sold" | "unknown" {
  const combined =
    `${rawUrl} ${rawStatus || ""} ${rawPriceText || ""}`.toLowerCase();
  if (
    /\b(sold|recently[\s_-]sold)\b/.test(combined) ||
    /\/(sold|recently_sold)\//.test(rawUrl.toLowerCase())
  ) {
    return "sold";
  }
  if (
    /\b(for[\s_-]rent|to[\s_-]rent|rental|lease|per\s*week|\/wk|\bpw\b|\bpcm\b|\/mo)\b/.test(
      combined
    ) ||
    /\/(rent|for-rent|for_rent|to-rent)\//.test(rawUrl.toLowerCase())
  ) {
    return "rent";
  }
  if (
    /\b(for[\s_-]sale|sale|buy|auction|offers|guide)\b/.test(combined) ||
    /\/(sale|for-sale|for_sale|buy|property-for-sale)\//.test(
      rawUrl.toLowerCase()
    )
  ) {
    return "sale";
  }
  return "unknown";
}

export function inferPricePeriod(
  rawPriceText: string,
  listingType: "sale" | "rent" | "sold" | "unknown"
): "total" | "week" | "month" | "year" {
  const lower = rawPriceText.toLowerCase();
  if (/\b(pw|p\/w|per\s*week|\/wk|\/week|weekly)\b/.test(lower)) {
    return "week";
  }
  if (/\b(pcm|p\/m|per\s*month|\/mo|\/month|monthly)\b/.test(lower)) {
    return "month";
  }
  if (/\b(pa|p\.a\.|per\s*annum|\/yr|\/year|yearly)\b/.test(lower)) {
    return "year";
  }
  return listingType === "rent" ? "week" : "total";
}

export function parsePropertyPrice(
  rawPriceText: string | number | undefined | null,
  countryCode?: string,
  explicitCurrency?: string
): { price?: number; priceText: string; currency: string } {
  const defaultCurrency = resolveCurrencyCode(explicitCurrency, countryCode);
  if (
    typeof rawPriceText === "number" &&
    Number.isFinite(rawPriceText) &&
    rawPriceText > 0
  ) {
    return {
      price: Math.round(rawPriceText),
      priceText: `${defaultCurrency} ${Math.round(rawPriceText).toLocaleString("en-US")}`,
      currency: defaultCurrency,
    };
  }
  const cleaned = String(rawPriceText || "")
    .replace(/\$\$/g, "$")
    .replace(/\s+/g, " ")
    .trim();
  if (!cleaned) {
    return { priceText: "Contact Agent", currency: defaultCurrency };
  }
  // Handle shorthand like "$880k" or "$1.45m"
  const shortMatch = cleaned.match(
    /(?:A\$|AU\$|US\$|\$|£|€)\s*(\d+(?:\.\d+)?)\s*([km])\b/i
  );
  if (shortMatch) {
    const mult = shortMatch[2].toLowerCase() === "m" ? 1_000_000 : 1_000;
    const val = Math.round(Number.parseFloat(shortMatch[1]) * mult);
    const symMatch = cleaned.match(/A\$|AU\$|US\$|\$|£|€/);
    const currency = resolveCurrencyCode(
      explicitCurrency || (symMatch ? symMatch[0] : undefined),
      countryCode
    );
    return {
      price: val,
      priceText: cleaned,
      currency,
    };
  }
  const fullMatch = parsePriceString(
    cleaned,
    countryCode,
    explicitCurrency,
    250_000_000
  );
  if (fullMatch && fullMatch.price > 10) {
    return {
      price: fullMatch.price,
      priceText: cleaned,
      currency: fullMatch.currency,
    };
  }
  return {
    priceText: cleaned,
    currency: defaultCurrency,
  };
}

export function resolveAbsoluteUrl(
  href: string | undefined,
  baseUrl: string
): string {
  if (!href) {
    return baseUrl;
  }
  try {
    return new URL(href, baseUrl).toString();
  } catch {
    return baseUrl;
  }
}

/**
 * Generic recursive JSON-tree walker that discovers property listing objects inside any
 * SSR hydration state (`__NEXT_DATA__`, `<script type="application/json">`, Apollo/Relay state)
 * without hardcoding any portal domain or site-specific JSON path.
 */
function extractPropertyListingsFromJsonTree(
  root: unknown,
  pageUrl: string,
  portal: string,
  countryCode?: string
): PropertyListing[] {
  const results: PropertyListing[] = [];
  const visited = new Set<object>();

  const pickString = (
    obj: Record<string, unknown>,
    keys: string[]
  ): string | undefined => {
    for (const k of keys) {
      const val = obj[k];
      if (typeof val === "string" && val.trim().length > 0) {
        return val.trim();
      }
      if (typeof val === "number" && Number.isFinite(val)) {
        return String(val);
      }
      if (val && typeof val === "object" && !Array.isArray(val)) {
        const nested =
          (val as Record<string, unknown>).value ??
          (val as Record<string, unknown>).formattedValue;
        if (typeof nested === "string" && nested.trim().length > 0) {
          return nested.trim();
        }
      }
    }
    return undefined;
  };

  const pickNumber = (
    obj: Record<string, unknown>,
    keys: string[]
  ): number | undefined => {
    for (const k of keys) {
      const val = obj[k];
      if (typeof val === "number" && Number.isFinite(val) && val >= 0) {
        return val;
      }
      if (typeof val === "string" && /^\d+(?:\.\d+)?$/.test(val.trim())) {
        return Number.parseFloat(val.trim());
      }
      if (val && typeof val === "object" && !Array.isArray(val)) {
        const nestedVal = (val as Record<string, unknown>).value;
        if (
          typeof nestedVal === "number" &&
          Number.isFinite(nestedVal) &&
          nestedVal >= 0
        ) {
          return nestedVal;
        }
        const fmt = (val as Record<string, unknown>).formattedValue;
        if (typeof fmt === "string") {
          const m = fmt.match(/(\d+)/);
          if (m) {
            return Number.parseInt(m[1], 10);
          }
        }
      }
    }
    return undefined;
  };

  const tryConvertCandidateObject = (
    node: Record<string, unknown>
  ): PropertyListing | null => {
    const locObj =
      typeof node.location === "object" && node.location !== null
        ? (node.location as Record<string, unknown>)
        : typeof node.address === "object" && node.address !== null
          ? (node.address as Record<string, unknown>)
          : undefined;
    const priceObj =
      typeof node.price === "object" && node.price !== null
        ? (node.price as Record<string, unknown>)
        : undefined;
    const featuresObj =
      typeof node.features === "object" && node.features !== null
        ? (node.features as Record<string, unknown>)
        : undefined;

    const beds =
      pickNumber(node, [
        "bedrooms",
        "beds",
        "bedroomCount",
        "numberOfBedrooms",
        "bed",
      ]) ??
      (featuresObj
        ? pickNumber(featuresObj, ["bedrooms", "beds", "bed"])
        : undefined);
    const baths =
      pickNumber(node, [
        "bathrooms",
        "baths",
        "bathroomCount",
        "numberOfBathroomsTotal",
        "bath",
      ]) ??
      (featuresObj
        ? pickNumber(featuresObj, ["bathrooms", "baths", "bath"])
        : undefined);
    const parking =
      pickNumber(node, [
        "carparks",
        "parking",
        "carSpaces",
        "garages",
        "cars",
        "parkingSpaces",
      ]) ??
      (featuresObj
        ? pickNumber(featuresObj, ["carparks", "parking", "cars", "garages"])
        : undefined);

    const hasPriceSignal =
      node.price !== undefined ||
      node.priceText !== undefined ||
      node.priceFrom !== undefined ||
      node.rentPerWeek !== undefined ||
      node.listPrice !== undefined ||
      node.markerPrice !== undefined ||
      node.displayPrice !== undefined;

    if (beds === undefined && baths === undefined && !hasPriceSignal) {
      return null;
    }

    const directAddress =
      pickString(node, [
        "displayAddress",
        "propertyAddress",
        "fullAddress",
        "formattedAddress",
        "streetAddress",
        "addressText",
      ]) ||
      (typeof node.address === "string" ? node.address.trim() : undefined) ||
      (locObj
        ? pickString(locObj, [
            "displayAddress",
            "fullLocation",
            "formattedLocation",
            "formattedAddress",
            "streetAddress",
            "address",
          ])
        : undefined);

    const unitNum = pickString(node, ["unitNumber", "aptNumber", "flatNumber"]);
    const streetNum = pickString(node, ["streetNumber", "houseNumber"]);
    const streetName =
      pickString(node, ["streetName", "street", "thoroughfare"]) ||
      (locObj ? pickString(locObj, ["streetName", "street"]) : undefined);
    const composedStreet = [
      unitNum ? `${unitNum}/${streetNum || ""}`.replace(/\/$/, "") : streetNum,
      streetName,
    ]
      .filter(Boolean)
      .join(" ")
      .trim();

    const suburb =
      pickString(node, [
        "suburbName",
        "suburb",
        "city",
        "locality",
        "addressLocality",
        "town",
      ]) ||
      (locObj
        ? pickString(locObj, [
            "suburbName",
            "suburb",
            "city",
            "locality",
            "addressLocality",
            "neighborhood",
          ])
        : undefined);
    const state =
      pickString(node, [
        "state",
        "stateCode",
        "region",
        "addressRegion",
        "province",
      ]) ||
      (locObj
        ? pickString(locObj, ["state", "stateCode", "region", "addressRegion"])
        : undefined);
    const postcode =
      pickString(node, ["postcode", "postalCode", "zipCode", "zip"]) ||
      (locObj
        ? pickString(locObj, ["postcode", "postalCode", "zipCode", "zip"])
        : undefined);

    const addressParts = [
      directAddress || composedStreet,
      suburb &&
      (!directAddress ||
        !directAddress.toLowerCase().includes(suburb.toLowerCase()))
        ? suburb
        : undefined,
      [
        state &&
        (!directAddress ||
          !directAddress.toLowerCase().includes(state.toLowerCase()))
          ? state
          : undefined,
        postcode && (!directAddress || !directAddress.includes(postcode))
          ? postcode
          : undefined,
      ]
        .filter(Boolean)
        .join(" "),
    ].filter(Boolean);

    const address = addressParts.join(", ").replace(/\s+/g, " ").trim();
    if (!address || address.length < 5 || /^https?:\/\//i.test(address)) {
      return null;
    }
    if (beds === undefined && baths === undefined && !/\d/.test(address)) {
      return null;
    }

    const displayPrices = Array.isArray(priceObj?.displayPrices)
      ? (priceObj.displayPrices as Array<Record<string, unknown>>)
      : [];
    const rawPriceText =
      pickString(node, [
        "priceText",
        "displayPrice",
        "formattedPrice",
        "priceLabel",
      ]) ||
      (priceObj
        ? pickString(priceObj, [
            "formattedPrice",
            "displayPrice",
            "text",
            "label",
          ])
        : undefined) ||
      (displayPrices[0]
        ? pickString(displayPrices[0], ["displayPrice"])
        : undefined) ||
      (typeof node.price === "string" ? node.price.trim() : undefined);

    const rawPriceNum =
      pickNumber(node, [
        "price",
        "priceFrom",
        "markerPrice",
        "listPrice",
        "rentPerWeek",
        "amount",
      ]) ??
      (priceObj
        ? pickNumber(priceObj, ["amount", "price", "value", "minPrice"])
        : undefined);

    const explicitCurrency =
      pickString(node, ["currency", "currencyCode", "priceCurrency"]) ||
      (priceObj
        ? pickString(priceObj, ["currencyCode", "currency"])
        : undefined);

    const parsedPrice = parsePropertyPrice(
      rawPriceText ?? rawPriceNum,
      countryCode,
      explicitCurrency
    );

    const rawHref =
      pickString(node, [
        "url",
        "propertyUrl",
        "listingDetailLink",
        "propertyDetailsRoutePath",
        "detailUrl",
        "canonicalUrl",
        "permalink",
        "slug",
      ]) || (locObj ? pickString(locObj, ["url", "propertyUrl"]) : undefined);
    const detailUrl = resolveAbsoluteUrl(
      rawHref && !rawHref.startsWith("http") && !rawHref.startsWith("/")
        ? `/${rawHref}`
        : rawHref,
      pageUrl
    );

    const statusHint = pickString(node, [
      "saleMethod",
      "status",
      "standardStatus",
      "displayStatus",
      "currentStatus",
      "transactionType",
      "listingType",
      "channel",
    ]);
    const listingType = inferListingType(
      `${detailUrl} ${pageUrl}`,
      statusHint,
      parsedPrice.priceText
    );

    const propTypesArr = Array.isArray(node.propertyTypes)
      ? (node.propertyTypes as unknown[]).map((x) => String(x))
      : [];
    const rawPropType =
      propTypesArr[0] ||
      pickString(node, [
        "propertyType",
        "propertySubType",
        "primaryPropertyType",
        "propertyTypeValue",
        "homeType",
        "buildingType",
      ]);
    const propertyType = rawPropType
      ? rawPropType.replace(/_/g, " ")
      : undefined;

    const agencyObj =
      typeof node.agency === "object" && node.agency !== null
        ? (node.agency as Record<string, unknown>)
        : typeof node.customer === "object" && node.customer !== null
          ? (node.customer as Record<string, unknown>)
          : typeof node.broker === "object" && node.broker !== null
            ? (node.broker as Record<string, unknown>)
            : undefined;
    const agency =
      pickString(node, ["agencyName", "brokerName", "officeName"]) ||
      (agencyObj
        ? pickString(agencyObj, ["name", "brandTradingName", "companyName"])
        : undefined);

    const mediaObj =
      typeof node.media === "object" && node.media !== null
        ? (node.media as Record<string, unknown>)
        : typeof node.propertyImages === "object" &&
            node.propertyImages !== null
          ? (node.propertyImages as Record<string, unknown>)
          : undefined;
    const photosArr = Array.isArray(node.photos)
      ? (node.photos as Array<Record<string, unknown>>)
      : [];
    const image =
      pickString(node, [
        "heroImageUrl",
        "imageUrl",
        "mainImageSrc",
        "thumbnailUrl",
        "photoUrl",
      ]) ||
      (typeof node.image === "string" ? node.image : undefined) ||
      (mediaObj
        ? pickString(mediaObj, [
            "mainImageSrc",
            "heroImageUrl",
            "medium",
            "small",
            "url",
          ])
        : undefined) ||
      (photosArr[0]
        ? pickString(photosArr[0], ["mediaUrl", "url", "src"])
        : undefined);

    const coordsObj =
      typeof locObj?.coordinates === "object" && locObj.coordinates !== null
        ? (locObj.coordinates as Record<string, unknown>)
        : typeof node.gis === "object" && node.gis !== null
          ? (node.gis as Record<string, unknown>)
          : undefined;
    const latitude =
      pickNumber(node, ["latitude", "lat"]) ??
      (locObj ? pickNumber(locObj, ["latitude", "lat"]) : undefined) ??
      (coordsObj ? pickNumber(coordsObj, ["latitude", "lat"]) : undefined);
    const longitude =
      pickNumber(node, ["longitude", "lon", "lng"]) ??
      (locObj ? pickNumber(locObj, ["longitude", "lon", "lng"]) : undefined) ??
      (coordsObj
        ? pickNumber(coordsObj, ["longitude", "lon", "lng"])
        : undefined);

    const landSqm = pickNumber(node, ["landSizeInSqm", "landArea", "lotSize"]);
    const landSize =
      pickString(node, ["landSize", "formattedLandSize"]) ||
      (landSqm && landSqm > 0 ? `${landSqm} sqm` : undefined);
    const sqft = pickNumber(node, ["squareFeet", "floorArea", "buildingArea"]);
    const floorObj =
      typeof node.floorSpace === "object" && node.floorSpace !== null
        ? (node.floorSpace as Record<string, unknown>)
        : undefined;
    const buildingSize =
      (floorObj ? pickString(floorObj, ["formattedDimension"]) : undefined) ||
      (sqft && sqft > 0 ? `${sqft} sqft` : undefined);

    return {
      title:
        pickString(node, ["title", "headline"]) ||
        `${beds ? `${beds} bed ` : ""}${propertyType ? `${propertyType} ` : ""}at ${address}`
          .replace(/\s+/g, " ")
          .trim(),
      address,
      suburb,
      state,
      postcode,
      country: countryCode,
      price: parsedPrice.price ?? rawPriceNum,
      priceText: parsedPrice.priceText,
      currency: parsedPrice.currency,
      pricePeriod:
        typeof node.rentPerWeek === "number" && node.rentPerWeek > 0
          ? "week"
          : priceObj?.frequency === "monthly"
            ? "month"
            : priceObj?.frequency === "weekly"
              ? "week"
              : inferPricePeriod(parsedPrice.priceText, listingType),
      listingType,
      propertyType,
      bedrooms: beds,
      bathrooms: baths,
      parking,
      landSize,
      buildingSize,
      url: detailUrl,
      portal,
      agency,
      image,
      latitude,
      longitude,
      extractedVia: "json-state",
    };
  };

  const walk = (node: unknown, depth: number): void => {
    if (
      depth > 9 ||
      results.length >= 40 ||
      !node ||
      typeof node !== "object"
    ) {
      return;
    }
    if (visited.has(node as object)) {
      return;
    }
    visited.add(node as object);

    if (Array.isArray(node)) {
      for (const el of node) {
        walk(el, depth + 1);
      }
      return;
    }

    const record = node as Record<string, unknown>;
    const candidate = tryConvertCandidateObject(record);
    if (candidate) {
      results.push(candidate);
      return;
    }

    for (const val of Object.values(record)) {
      if (val && typeof val === "object") {
        walk(val, depth + 1);
      }
    }
  };

  walk(root, 0);
  return results;
}

/**
 * Extract structured real-estate property listings from any HTML page via:
 * 1. Generic recursive JSON-tree discovery over `<script id="__NEXT_DATA__">` and `<script type="application/json">`
 * 2. Next.js App Router Flight RSC payload (`self.__next_f.push`)
 * 3. Schema.org JSON-LD (`RealEstateListing`, `Residence`, `SingleFamilyResidence`, `Apartment`, `House`)
 */
export function extractPropertyListingsFromHtml(
  html: string,
  pageUrl: string,
  countryCode?: string
): PropertyListing[] {
  const listings: PropertyListing[] = [];
  const portal = extractDomainHost(pageUrl) || "unknown";

  // 1. Generic SSR JSON state extraction (`__NEXT_DATA__` or any `<script type="application/json">`)
  const jsonScriptRegex =
    /<script[^>]+(?:id=["']__NEXT_DATA__["']|type=["']application\/json["'])[^>]*>([\s\S]*?)<\/script>/gi;
  let scriptMatch: RegExpExecArray | null;
  while ((scriptMatch = jsonScriptRegex.exec(html)) !== null) {
    const rawJson = scriptMatch[1]?.trim();
    if (!rawJson || rawJson.length < 50) {
      continue;
    }
    try {
      const parsedJson = JSON.parse(rawJson);
      const discovered = extractPropertyListingsFromJsonTree(
        parsedJson,
        pageUrl,
        portal,
        countryCode
      );
      if (discovered.length > 0) {
        listings.push(...discovered);
      }
    } catch {
      // Ignore non-JSON script blocks
    }
  }

  // 2. Next.js App Router RSC payload (`self.__next_f.push`), e.g. Homely.com.au
  if (listings.length === 0 && html.includes('\\"canonicalUri\\":\\"/homes/')) {
    try {
      const rscUnescaped = html.replace(/\\"/g, '"').replace(/\\\\/g, "\\");
      const cardRegex =
        /\{"id":\d+,"statusType":"[^"]+","listingType":"([^"]+)"[\s\S]*?"canonicalUri":"(\/homes\/[^"]+)"[\s\S]*?"priceDetails":\{"longDescription":"([^"]*)"[\s\S]*?"address":\{"streetAddress":"([^"]*)","longAddress":"([^"]*)"[\s\S]*?"features":\{"bathrooms":(\d+|null),"bedrooms":(\d+|null),"cars":(\d+|null)/g;
      for (const m of rscUnescaped.matchAll(cardRegex)) {
        const [
          ,
          rawListingType,
          canonicalUri,
          rawLongPrice,
          ,
          longAddress,
          bathsStr,
          bedsStr,
          carsStr,
        ] = m;
        if (!longAddress) {
          continue;
        }
        const cleanedPriceText = rawLongPrice.replace(/\$\$/g, "$").trim();
        const parsedPrice = parsePropertyPrice(
          cleanedPriceText,
          countryCode || "AU",
          "AUD"
        );
        const detailUrl = resolveAbsoluteUrl(canonicalUri, pageUrl);
        // Photos sit after `features` in the same card object: media.photos[].webDefaultURI.
        // Stop at the next card so one listing never borrows another's photo.
        const tailStart = (m.index ?? 0) + m[0].length;
        const nextCard = rscUnescaped
          .slice(tailStart, tailStart + 4000)
          .search(/\{"id":\d+,"statusType":/);
        const tail = rscUnescaped.slice(
          tailStart,
          tailStart + (nextCard >= 0 ? nextCard : 4000)
        );
        const photo = /"webDefaultURI":"(https:[^"]+)"/.exec(tail)?.[1]
          ?.replace(/\\u0026/g, "&");
        const listingType = inferListingType(
          detailUrl,
          rawListingType,
          cleanedPriceText
        );
        listings.push({
          title: longAddress,
          address: longAddress,
          country: countryCode || "AU",
          price: parsedPrice.price,
          priceText: parsedPrice.priceText,
          currency: parsedPrice.currency,
          pricePeriod: inferPricePeriod(cleanedPriceText, listingType),
          listingType,
          bedrooms:
            bedsStr !== "null" ? Number.parseInt(bedsStr, 10) : undefined,
          bathrooms:
            bathsStr !== "null" ? Number.parseInt(bathsStr, 10) : undefined,
          parking:
            carsStr !== "null" ? Number.parseInt(carsStr, 10) : undefined,
          url: detailUrl,
          image: photo,
          portal,
          extractedVia: "rsc-payload",
        });
      }
    } catch {
      // Ignore RSC regex errors
    }
  }

  // 3. Schema.org JSON-LD (`Residence`, `RealEstateListing`, `SingleFamilyResidence`, `Apartment`, `House`, `Place`)
  if (listings.length === 0) {
    const jsonLdScriptRegex =
      /<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
    const ldBlocks: unknown[] = [];
    let ldMatch: RegExpExecArray | null;
    while ((ldMatch = jsonLdScriptRegex.exec(html)) !== null) {
      try {
        ldBlocks.push(JSON.parse(ldMatch[1].trim()));
      } catch {
        // ignore invalid JSON-LD
      }
    }
    const flattenLd = (item: unknown): Array<Record<string, unknown>> => {
      if (!item || typeof item !== "object") {
        return [];
      }
      if (Array.isArray(item)) {
        // When a JSON-LD block is a small tuple array pairing a Residence/RealEstateListing
        // with a sibling Product/Offer object (e.g. `[{ "@type": "SingleFamilyResidence", ... }, { "@type": "Product", "offers": { "price": ... } }]`),
        // propagate the sibling's `offers` / `price` onto the residence object.
        const objs = item.filter((x): x is Record<string, unknown> =>
          Boolean(x && typeof x === "object" && !Array.isArray(x))
        );
        const offerHolder = objs.find(
          (x) => x.offers !== undefined || x.price !== undefined
        );
        if (offerHolder && objs.length <= 4) {
          return objs.flatMap((x) =>
            flattenLd({
              ...x,
              offers: x.offers ?? offerHolder.offers,
              price: x.price ?? offerHolder.price,
            })
          );
        }
        return item.flatMap(flattenLd);
      }
      const obj = item as Record<string, unknown>;
      const out: Array<Record<string, unknown>> = [obj];
      if (Array.isArray(obj["@graph"])) {
        out.push(...obj["@graph"].flatMap(flattenLd));
      }
      if (Array.isArray(obj.itemListElement)) {
        for (const el of obj.itemListElement) {
          if (el && typeof el === "object") {
            const inner = (el as Record<string, unknown>).item ?? el;
            out.push(...flattenLd(inner));
          }
        }
      }
      if (
        obj.mainEntity &&
        typeof obj.mainEntity === "object" &&
        !Array.isArray(obj.mainEntity)
      ) {
        const mergedChild: Record<string, unknown> = {
          ...(obj.mainEntity as Record<string, unknown>),
        };
        if (mergedChild.offers === undefined && obj.offers !== undefined) {
          mergedChild.offers = obj.offers;
        }
        if (mergedChild.price === undefined && obj.price !== undefined) {
          mergedChild.price = obj.price;
        }
        if (mergedChild.url === undefined && obj.url !== undefined) {
          mergedChild.url = obj.url;
        }
        if (mergedChild.image === undefined && obj.image !== undefined) {
          mergedChild.image = obj.image;
        }
        out.push(...flattenLd(mergedChild));
      } else if (obj.mainEntity && typeof obj.mainEntity === "object") {
        out.push(...flattenLd(obj.mainEntity));
      }
      return out;
    };
    // Some portals (rent.com.au) only attach the photo to a sibling node, e.g. an
    // "Inspection Time" Event whose `url` / `location.url` points at the listing.
    const imageByUrl = new Map<string, string>();
    for (const root of ldBlocks) {
      for (const node of flattenLd(root)) {
        const img = ldImage(node.image);
        if (!img) {
          continue;
        }
        const loc =
          typeof node.location === "object" && node.location !== null
            ? (node.location as Record<string, unknown>)
            : undefined;
        for (const u of [node.url, loc?.url]) {
          if (typeof u === "string") {
            const abs = resolveAbsoluteUrl(u, pageUrl);
            if (!imageByUrl.has(abs)) {
              imageByUrl.set(abs, img);
            }
          }
        }
      }
    }
    for (const root of ldBlocks) {
      const nodes = flattenLd(root);
      for (const node of nodes) {
        const rawType = node["@type"];
        const types = Array.isArray(rawType)
          ? rawType.map((t) => String(t))
          : rawType
            ? [String(rawType)]
            : [];
        const isPropertyType = types.some((t) =>
          /^(RealEstateListing|Residence|SingleFamilyResidence|Apartment|House|Accommodation|GatedResidenceCommunity)$/i.test(
            t
          )
        );
        if (!isPropertyType) {
          continue;
        }
        const name = typeof node.name === "string" ? node.name.trim() : "";
        const addrObj =
          typeof node.address === "object" && node.address !== null
            ? (node.address as Record<string, unknown>)
            : undefined;
        const street =
          typeof addrObj?.streetAddress === "string" &&
          addrObj.streetAddress !== "property"
            ? addrObj.streetAddress
            : "";
        const locality =
          typeof addrObj?.addressLocality === "string"
            ? addrObj.addressLocality
            : undefined;
        const region =
          typeof addrObj?.addressRegion === "string"
            ? addrObj.addressRegion
            : undefined;
        const postalCode =
          typeof addrObj?.postalCode === "string"
            ? addrObj.postalCode
            : undefined;
        const address =
          [street, locality, [region, postalCode].filter(Boolean).join(" ")]
            .filter(Boolean)
            .join(", ") || name;
        if (!address || address.length < 5) {
          continue;
        }
        const itemUrl =
          typeof node.url === "string"
            ? resolveAbsoluteUrl(node.url, pageUrl)
            : pageUrl;
        const rawOffers = node.offers;
        const offersNode = Array.isArray(rawOffers)
          ? (rawOffers[0] as Record<string, unknown> | undefined)
          : typeof rawOffers === "object" && rawOffers !== null
            ? (rawOffers as Record<string, unknown>)
            : undefined;
        const parsedPrice = parsePropertyPrice(
          (offersNode?.price as string | number | undefined) ||
            (node.price as string | number | undefined),
          countryCode,
          typeof offersNode?.priceCurrency === "string"
            ? offersNode.priceCurrency
            : undefined
        );
        const geo =
          typeof node.geo === "object" && node.geo !== null
            ? (node.geo as Record<string, unknown>)
            : undefined;
        const listingType = inferListingType(
          `${itemUrl} ${pageUrl}`,
          typeof node.description === "string" ? node.description : undefined,
          parsedPrice.priceText
        );

        listings.push({
          title: name || address,
          address,
          suburb: locality,
          state: region,
          postcode: postalCode,
          country:
            typeof addrObj?.addressCountry === "string"
              ? addrObj.addressCountry
              : countryCode,
          price: parsedPrice.price,
          priceText: parsedPrice.priceText,
          currency: parsedPrice.currency,
          pricePeriod: inferPricePeriod(parsedPrice.priceText, listingType),
          listingType,
          propertyType: types[0],
          bedrooms:
            typeof node.numberOfBedrooms === "number"
              ? node.numberOfBedrooms
              : typeof node.numberOfRooms === "number"
                ? node.numberOfRooms
                : undefined,
          bathrooms:
            typeof node.numberOfBathroomsTotal === "number"
              ? node.numberOfBathroomsTotal
              : undefined,
          url: itemUrl,
          portal,
          image: (() => {
            const img = ldImage(node.image) ?? imageByUrl.get(itemUrl);
            return img ? resolveAbsoluteUrl(img, pageUrl) : undefined;
          })(),
          latitude:
            typeof geo?.latitude === "number" ? geo.latitude : undefined,
          longitude:
            typeof geo?.longitude === "number" ? geo.longitude : undefined,
          extractedVia: "json-ld",
        });
      }
    }
  }

  return listings;
}

/**
 * Schema.org `image` may be a URL string, an ImageObject (`url` / `contentUrl`),
 * or an array of either. Returns the first usable URL.
 */
export function ldImage(v: unknown): string | undefined {
  if (typeof v === "string") {
    // Some sites leak CSS into the value: "https://…jpg?w=1600), url(/fallback.svg)…"
    const u = (v.trim().split(/\s/)[0] ?? "").replace(/\)?[,;]?$/, "");
    return u || undefined;
  }
  if (Array.isArray(v)) {
    for (const x of v) {
      const u = ldImage(x);
      if (u) {
        return u;
      }
    }
    return undefined;
  }
  if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    return ldImage(o.url) ?? ldImage(o.contentUrl) ?? ldImage(o.thumbnailUrl);
  }
  return undefined;
}

/**
 * Fallback extractor for SERP result snippets when a real-estate result describes a property
 * or suburb listing summary in its title/description.
 */
export function extractPropertyListingFromSerpResult(
  title: string,
  description: string,
  url: string,
  countryCode?: string
): PropertyListing | null {
  const combined = `${title} ${description}`;
  const bedsMatch = combined.match(/(\d+)\s*(?:bed(?:room)?s?|bd|br)\b/i);
  const bathsMatch = combined.match(/(\d+)\s*(?:bath(?:room)?s?|ba)\b/i);
  const carsMatch = combined.match(
    /(\d+)\s*(?:car(?:\s*spaces?)?|parking|garage)\b/i
  );
  const priceMatch = combined.match(
    /((?:A\$|AU\$|US\$|\$|£|€)\s?\d[\d,]*(?:\.\d+)?(?:\s*(?:k|m|pw|per\s*week|\/wk|pcm|\/mo))?)/i
  );

  // Require either a price or bed+bath mention to qualify as a property listing
  if (!priceMatch && !(bedsMatch && bathsMatch)) {
    return null;
  }

  const portal = extractDomainHost(url);
  if (!portal) {
    return null;
  }
  const parsedPrice = parsePropertyPrice(priceMatch?.[1], countryCode);
  const listingType = inferListingType(url, title, parsedPrice.priceText);
  const propTypeMatch = combined.match(
    /\b(house|apartment|unit|flat|townhouse|villa|terrace|penthouse|studio|duplex|land|acreage)\b/i
  );

  return {
    title: title.trim(),
    address: title.replace(/\s*[|-]\s*[^|-]+$/, "").trim(),
    country: countryCode,
    price: parsedPrice.price,
    priceText: parsedPrice.priceText,
    currency: parsedPrice.currency,
    pricePeriod: inferPricePeriod(parsedPrice.priceText, listingType),
    listingType,
    propertyType: propTypeMatch ? propTypeMatch[1] : undefined,
    bedrooms: bedsMatch ? Number.parseInt(bedsMatch[1], 10) : undefined,
    bathrooms: bathsMatch ? Number.parseInt(bathsMatch[1], 10) : undefined,
    parking: carsMatch ? Number.parseInt(carsMatch[1], 10) : undefined,
    url,
    portal,
    extractedVia: "serp-snippet",
  };
}

export function dedupePropertyListings(
  listings: PropertyListing[],
  maxListings = 30
): PropertyListing[] {
  const sourceOrder: Record<PropertyListing["extractedVia"], number> = {
    "json-state": 0,
    "rsc-payload": 1,
    "json-ld": 2,
    "scaledown-extract-1": 3,
    "serp-snippet": 4,
  };
  const sorted = [...listings].sort(
    (a, b) => sourceOrder[a.extractedVia] - sourceOrder[b.extractedVia]
  );
  const seen = new Set<string>();
  const out: PropertyListing[] = [];
  for (const item of sorted) {
    // Same listing seen by two extractors shares URL + address; a different URL on the
    // same portal is a different listing and is kept.
    const key = resultDedupeKey(item.url, item.address);
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    out.push(item);
    if (out.length >= maxListings) {
      break;
    }
  }
  return out;
}
