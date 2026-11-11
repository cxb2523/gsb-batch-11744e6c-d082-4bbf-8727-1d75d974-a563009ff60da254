import {
  extractDomainHost,
  parsePriceString,
  resolveCurrencyCode,
} from "./currency.js";
import { canonicalResultUrl } from "./dedupe-key.js";
import { resolveAbsoluteUrl } from "./real-estate.js";

export interface FlightOffer {
  title: string;
  airline?: string;
  flightNumber?: string;
  origin?: string;
  destination?: string;
  departureTime?: string;
  arrivalTime?: string;
  duration?: string;
  stops?: number | string;
  cabinClass?: "economy" | "premium_economy" | "business" | "first";
  tripType?: "one_way" | "round_trip";
  price?: number;
  priceText: string;
  currency?: string;
  url: string;
  provider: string;
  extractedVia:
    | "json-state"
    | "rsc-payload"
    | "json-ld"
    | "scaledown-extract-1"
    | "serp-snippet";
}

const KNOWN_AIRLINES = [
  "Qantas",
  "Virgin Australia",
  "Jetstar",
  "Rex",
  "Air New Zealand",
  "United Airlines",
  "United",
  "Delta Air Lines",
  "Delta",
  "American Airlines",
  "Southwest Airlines",
  "Southwest",
  "Alaska Airlines",
  "JetBlue",
  "Spirit Airlines",
  "Frontier Airlines",
  "British Airways",
  "EasyJet",
  "Ryanair",
  "Lufthansa",
  "Air France",
  "KLM",
  "Emirates",
  "Qatar Airways",
  "Singapore Airlines",
  "Cathay Pacific",
  "ANA",
  "Japan Airlines",
  "Air Canada",
  "Turkish Airlines",
  "Etihad Airways",
  "Swiss",
  "Iberia",
  "Finnair",
  "Scoot",
  "Fiji Airways",
  "Hawaiian Airlines",
  "Malaysia Airlines",
  "Thai Airways",
  "Korean Air",
];

const AIRLINE_REGEX = new RegExp(
  `\\b(${KNOWN_AIRLINES.map((a) => a.replace(/\s+/g, "\\s+")).join("|")})\\b`,
  "i"
);

export function inferRouteFromText(text: string): {
  origin?: string;
  destination?: string;
} {
  // Check parenthesized IATA codes like "Sydney (SYD) to Los Angeles (LAX)"
  const parenIata = text.match(
    /\(([A-Z]{3})\)[^()]{1,40}?\b(?:to|->|→|–|-|\u2014)\b[^()]{1,40}?\(([A-Z]{3})\)/i
  );
  if (parenIata && parenIata[1].toUpperCase() !== parenIata[2].toUpperCase()) {
    return {
      origin: parenIata[1].toUpperCase(),
      destination: parenIata[2].toUpperCase(),
    };
  }

  // Check IATA pair like "SYD to LAX", "SYD - MEL", "SYD → LHR", "(JFK) to (SFO)"
  const iataMatch = text.match(
    /\(?([A-Z]{3})\)?\s*(?:to|->|→|–|-|\u2014)\s*\(?([A-Z]{3})\)?/
  );
  if (
    iataMatch &&
    iataMatch[1] !== iataMatch[2] &&
    !/^(USD|AUD|GBP|EUR|CAD|NZD|SGD|JPY|INR|THE|AND|FOR|NON|ALL|TOP|LOW|FLY)$/.test(
      iataMatch[1]
    ) &&
    !/^(USD|AUD|GBP|EUR|CAD|NZD|SGD|JPY|INR|THE|AND|FOR|NON|ALL|TOP|LOW|FLY)$/.test(
      iataMatch[2]
    )
  ) {
    return { origin: iataMatch[1], destination: iataMatch[2] };
  }

  // Check "from <Origin> to <Destination>"
  const fromToMatch = text.match(
    /\b(?:flights?\s+from|from)\s+([A-Z][a-zA-Z\s]{2,22}?)\s+to\s+([A-Z][a-zA-Z\s]{2,22}?)(?=\s+(?:from|under|for|starting|on|in|with|\$|£|€|A\$|at|\||-|$))/i
  );
  if (fromToMatch) {
    return {
      origin: fromToMatch[1].trim(),
      destination: fromToMatch[2].trim(),
    };
  }

  // Check "<Origin> to <Destination> Flights"
  const cityToCity = text.match(
    /\b([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)?)\s+to\s+([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)?)\s+flights?\b/i
  );
  if (cityToCity) {
    const o = cityToCity[1].trim();
    const d = cityToCity[2].trim();
    if (!/^(cheap|direct|nonstop|best|book|compare|find)$/i.test(o)) {
      return { origin: o, destination: d };
    }
  }

  return {};
}

export function inferCabinClass(
  text: string
): "economy" | "premium_economy" | "business" | "first" | undefined {
  const lower = text.toLowerCase();
  if (/\bfirst\s+class\b/.test(lower)) {
    return "first";
  }
  if (/\bbusiness\s+class\b/.test(lower)) {
    return "business";
  }
  if (/\bpremium\s+economy\b/.test(lower)) {
    return "premium_economy";
  }
  if (/\beconomy\b/.test(lower)) {
    return "economy";
  }
  return undefined;
}

export function inferTripType(
  text: string
): "one_way" | "round_trip" | undefined {
  const lower = text.toLowerCase();
  if (/\b(one[- ]way)\b/.test(lower)) {
    return "one_way";
  }
  if (/\b(round[- ]trip|return)\b/.test(lower)) {
    return "round_trip";
  }
  return undefined;
}

export function inferDurationAndStops(text: string): {
  duration?: string;
  stops?: number | string;
} {
  const durMatch = text.match(
    /\b(\d{1,2}\s*h(?:rs?|ours?)?(?:\s*\d{1,2}\s*m(?:ins?)?)?)\b/i
  );
  let stops: number | string | undefined;
  if (/\b(non[- ]?stop|direct\s+flights?)\b/i.test(text)) {
    stops = 0;
  } else {
    const stopsMatch = text.match(/\b(\d)\s+stops?\b/i);
    if (stopsMatch) {
      stops = Number.parseInt(stopsMatch[1], 10);
    }
  }
  return {
    duration: durMatch ? durMatch[1].replace(/\s+/g, " ").trim() : undefined,
    stops,
  };
}

export function parseFlightPrice(
  rawPrice: string | number | undefined | null,
  countryCode?: string,
  explicitCurrency?: string
): { price?: number; priceText: string; currency: string } {
  const defaultCurrency = resolveCurrencyCode(explicitCurrency, countryCode);
  if (
    typeof rawPrice === "number" &&
    Number.isFinite(rawPrice) &&
    rawPrice > 10 &&
    rawPrice < 50_000
  ) {
    const rounded = Math.round(rawPrice);
    return {
      price: rounded,
      priceText: `${defaultCurrency} $${rounded.toLocaleString("en-US")}`,
      currency: defaultCurrency,
    };
  }
  const text = String(rawPrice || "").trim();
  if (!text) {
    return { priceText: "Check Fare", currency: defaultCurrency };
  }
  const parsed = parsePriceString(text, countryCode, explicitCurrency, 50_000);
  if (parsed && parsed.price >= 15) {
    return {
      price: Math.round(parsed.price),
      priceText: text,
      currency: parsed.currency,
    };
  }
  return { priceText: text, currency: defaultCurrency };
}

function walkFlightJsonNode(
  node: unknown,
  pageUrl: string,
  portal: string,
  countryCode: string | undefined,
  queryRoute: { origin?: string; destination?: string },
  extractedVia: FlightOffer["extractedVia"],
  out: FlightOffer[],
  depth = 0
): void {
  if (depth > 12 || out.length >= 40 || !node || typeof node !== "object") {
    return;
  }
  if (Array.isArray(node)) {
    for (const item of node) {
      walkFlightJsonNode(
        item,
        pageUrl,
        portal,
        countryCode,
        queryRoute,
        extractedVia,
        out,
        depth + 1
      );
    }
    return;
  }

  const obj = node as Record<string, unknown>;
  const rawType = String(obj["@type"] || obj.type || "").toLowerCase();

  // Check Schema.org Flight / Offer / Product or state flight object
  const airlineObj =
    (obj.airline as Record<string, unknown> | undefined) ||
    (obj.carrier as Record<string, unknown> | undefined) ||
    (obj.provider as Record<string, unknown> | undefined);
  const airlineName =
    typeof obj.airline === "string"
      ? obj.airline
      : typeof obj.carrier === "string"
        ? obj.carrier
        : typeof obj.airlineName === "string"
          ? obj.airlineName
          : typeof airlineObj?.name === "string"
            ? airlineObj.name
            : undefined;

  const depAirport = obj.departureAirport as
    | Record<string, unknown>
    | undefined;
  const arrAirport = obj.arrivalAirport as Record<string, unknown> | undefined;
  const origin =
    typeof obj.origin === "string"
      ? obj.origin
      : typeof obj.departureAirport === "string"
        ? obj.departureAirport
        : typeof depAirport?.iataCode === "string"
          ? depAirport.iataCode
          : typeof depAirport?.name === "string"
            ? depAirport.name
            : queryRoute.origin;
  const destination =
    typeof obj.destination === "string"
      ? obj.destination
      : typeof obj.arrivalAirport === "string"
        ? obj.arrivalAirport
        : typeof arrAirport?.iataCode === "string"
          ? arrAirport.iataCode
          : typeof arrAirport?.name === "string"
            ? arrAirport.name
            : queryRoute.destination;

  const offersObj = obj.offers as Record<string, unknown> | undefined;
  const rawPriceVal =
    obj.price ??
    obj.minPrice ??
    obj.lowPrice ??
    obj.totalPrice ??
    offersObj?.price ??
    offersObj?.lowPrice;
  const rawCurrency =
    (typeof obj.priceCurrency === "string" ? obj.priceCurrency : undefined) ||
    (typeof obj.currency === "string" ? obj.currency : undefined) ||
    (typeof offersObj?.priceCurrency === "string"
      ? offersObj.priceCurrency
      : undefined);

  const isFlightNode =
    rawType.includes("flight") ||
    Boolean(
      airlineName && (origin || destination || rawPriceVal !== undefined)
    ) ||
    Boolean(origin && destination && rawPriceVal !== undefined);

  if (isFlightNode) {
    const parsedPrice = parseFlightPrice(
      rawPriceVal as string | number | undefined,
      countryCode,
      rawCurrency
    );
    const flightNumber =
      typeof obj.flightNumber === "string" ||
      typeof obj.flightNumber === "number"
        ? String(obj.flightNumber)
        : undefined;
    const departureTime =
      typeof obj.departureTime === "string" ? obj.departureTime : undefined;
    const arrivalTime =
      typeof obj.arrivalTime === "string" ? obj.arrivalTime : undefined;
    const duration =
      typeof obj.duration === "string"
        ? obj.duration
        : typeof obj.flightDuration === "string"
          ? obj.flightDuration
          : undefined;
    const stops =
      typeof obj.stops === "number" || typeof obj.stops === "string"
        ? obj.stops
        : typeof obj.numberOfStops === "number"
          ? obj.numberOfStops
          : undefined;
    const itemUrl =
      typeof obj.url === "string"
        ? resolveAbsoluteUrl(obj.url, pageUrl)
        : pageUrl;

    const routeLabel =
      origin && destination
        ? `${origin} → ${destination}`
        : origin || destination || "Flight";
    const title =
      typeof obj.name === "string" && obj.name.trim().length > 4
        ? obj.name.trim()
        : `${airlineName ? `${airlineName} · ` : ""}${routeLabel}`;

    if (parsedPrice.price || airlineName || (origin && destination)) {
      out.push({
        title,
        airline: airlineName,
        flightNumber,
        origin,
        destination,
        departureTime,
        arrivalTime,
        duration,
        stops,
        price: parsedPrice.price,
        priceText: parsedPrice.priceText,
        currency: parsedPrice.currency,
        url: itemUrl,
        provider: extractDomainHost(itemUrl) || portal,
        extractedVia,
      });
    }
  }

  for (const val of Object.values(obj)) {
    if (val && typeof val === "object") {
      walkFlightJsonNode(
        val,
        pageUrl,
        portal,
        countryCode,
        queryRoute,
        extractedVia,
        out,
        depth + 1
      );
    }
  }
}

export function extractFlightOffersFromHtml(
  html: string,
  pageUrl: string,
  countryCode?: string,
  queryHint?: string
): FlightOffer[] {
  const out: FlightOffer[] = [];
  const portal = extractDomainHost(pageUrl) || "unknown";
  const queryRoute = inferRouteFromText(`${queryHint || ""} ${pageUrl}`);

  // Tier 1: Schema.org JSON-LD blocks
  const jsonLdRegex =
    /<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let match: RegExpExecArray | null;
  while ((match = jsonLdRegex.exec(html)) !== null) {
    try {
      const parsed = JSON.parse(match[1].trim());
      walkFlightJsonNode(
        parsed,
        pageUrl,
        portal,
        countryCode,
        queryRoute,
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
          walkFlightJsonNode(
            parsed,
            pageUrl,
            portal,
            countryCode,
            queryRoute,
            "json-state",
            out
          );
        }
      } catch {
        // Ignore
      }
    }
  }

  return dedupeFlightOffers(out);
}

export function extractFlightOfferFromSerpResult(
  title: string,
  description: string,
  url: string,
  countryCode?: string,
  queryHint?: string
): FlightOffer | null {
  const combined = `${title} ${description} ${queryHint || ""}`;
  const route = inferRouteFromText(combined);
  const airlineMatch = `${title} ${description}`.match(AIRLINE_REGEX);
  const explicitPriceMatch = `${title} ${description}`.match(
    /(?:A\$|AU\$|US\$|CA\$|NZ\$|S\$|SG\$|HK\$|Rs\.?|\$|£|€|¥|₹|₫|฿|₱|₩|\b(?:USD|AUD|GBP|EUR|CAD|NZD|SGD|INR|VND|THB|MYR|IDR|CHF|AED)\b)\s*(\d[\d.,]*)|(\d[\d.,]*)\s*(?:€|£|₫|₹|\b(?:EUR|GBP|INR|SGD|VND|CHF)\b)/i
  );
  const priceParsed = explicitPriceMatch
    ? parsePriceString(explicitPriceMatch[0], countryCode, undefined, 25_000)
    : null;
  const { duration, stops } = inferDurationAndStops(`${title} ${description}`);
  const cabinClass = inferCabinClass(combined);
  const tripType = inferTripType(combined);

  // Require an actual fare price or specific airline in the snippet
  if ((!priceParsed || priceParsed.price < 25) && !airlineMatch) {
    return null;
  }

  const defaultCurrency = resolveCurrencyCode(undefined, countryCode);
  const price =
    priceParsed && priceParsed.price >= 25
      ? Math.round(priceParsed.price)
      : undefined;
  const currency = priceParsed?.currency || defaultCurrency;
  const priceText = price
    ? `${currency} $${price.toLocaleString("en-US")}`
    : "Check Live Fare";

  const flightNoMatch = `${title} ${description}`.match(
    /\b([A-Z]{2}\s?\d{2,4})\b/
  );
  const provider = extractDomainHost(url) || "unknown";

  return {
    title:
      title.replace(/\s*[|\-–\u2014•]\s*.*$/, "").trim() ||
      `${route.origin || "Flight"} → ${route.destination || ""}`.trim(),
    airline: airlineMatch ? airlineMatch[1] : undefined,
    flightNumber:
      flightNoMatch &&
      !/^(US|AU|UK|EU|IN|CA|up|to|in|on)\s?\d+$/i.test(flightNoMatch[1])
        ? flightNoMatch[1].replace(/\s+/g, "")
        : undefined,
    origin: route.origin,
    destination: route.destination,
    duration,
    stops,
    cabinClass,
    tripType,
    price,
    priceText,
    currency,
    url,
    provider,
    extractedVia: "serp-snippet",
  };
}

export function dedupeFlightOffers(
  offers: FlightOffer[],
  maxItems = 30
): FlightOffer[] {
  const seen = new Set<string>();
  const out: FlightOffer[] = [];
  for (const offer of offers) {
    const key = `${(offer.airline || "").toLowerCase()}|${(offer.origin || "").toLowerCase()}|${(offer.destination || "").toLowerCase()}|${offer.price || offer.priceText}|${offer.provider}|${canonicalResultUrl(offer.url)}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    out.push(offer);
    if (out.length >= maxItems) {
      break;
    }
  }
  return out.sort((a, b) => {
    if (a.price !== undefined && b.price !== undefined) {
      return a.price - b.price;
    }
    if (a.price !== undefined) {
      return -1;
    }
    if (b.price !== undefined) {
      return 1;
    }
    return 0;
  });
}
