import type { BusinessListing } from "./business.js";
import { extractDomainHost } from "./currency.js";
import { parseFlightPrice, type FlightOffer } from "./flights.js";
import { parseHotelPrice, type HotelListing } from "./hotels.js";
import {
  inferListingType,
  inferPricePeriod,
  parsePropertyPrice,
  resolveAbsoluteUrl,
  type PropertyListing,
} from "./real-estate.js";

/**
 * Tier-2 ultra-cheap RLCD-class structured extraction using `scaledown/scaledown-extract-1`
 * via Vercel AI Gateway ($0.05 / 1M input tokens, $0.00 / 1M output tokens).
 * Extracts structured `PropertyListing[]` from clean page markdown or SERP snippets when
 * deterministic JSON-state / JSON-LD extraction yields insufficient results.
 */
export async function extractPropertyListingsWithScaleDown(
  text: string,
  pageUrl: string,
  countryCode?: string,
  timeoutMs = 3000
): Promise<PropertyListing[]> {
  const apiKey =
    process.env.AI_GATEWAY_API_KEY || process.env.VERCEL_OIDC_TOKEN || "";
  const trimmed = text.trim().slice(0, 6_000);
  if (!apiKey || trimmed.length < 40) {
    return [];
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const portal = extractDomainHost(pageUrl) || "unknown";

  try {
    const res = await fetch(
      "https://ai-gateway.vercel.sh/v1/chat/completions",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          model: "scaledown/scaledown-extract-1",
          messages: [
            {
              role: "system",
              content:
                "Extract distinct residential or commercial property listings with street or suburb addresses, prices, bedrooms, bathrooms, parking, and property types.",
            },
            {
              role: "user",
              content: trimmed,
            },
          ],
          response_format: {
            type: "json_schema",
            json_schema: {
              name: "property_listings",
              schema: {
                type: "object",
                properties: {
                  listings: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        address: {
                          type: "string",
                          description:
                            "street address, suburb, city, state, and postcode of the property",
                        },
                        price: {
                          type: "string",
                          description:
                            "property price, price guide, or weekly/monthly rent amount",
                        },
                        bedrooms: {
                          type: "string",
                          description: "number of bedrooms",
                        },
                        bathrooms: {
                          type: "string",
                          description: "number of bathrooms",
                        },
                        parking: {
                          type: "string",
                          description: "number of car spaces or garages",
                        },
                        property_type: {
                          type: "string",
                          description:
                            "property type such as House, Apartment, Townhouse, Unit, Villa, or Land",
                        },
                        listing_url: {
                          type: "string",
                          description:
                            "URL or path to the property listing if present",
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        }),
        signal: controller.signal,
      }
    );

    if (!res.ok) {
      return [];
    }

    const payload = (await res.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
    };
    const rawContent = payload.choices?.[0]?.message?.content;
    if (!rawContent) {
      return [];
    }

    const parsed = JSON.parse(rawContent) as {
      structured_result?: {
        listings?: Array<Record<string, unknown>>;
      };
      listings?: Array<Record<string, unknown>>;
    };
    const items =
      parsed.structured_result?.listings ??
      (Array.isArray(parsed.listings) ? parsed.listings : []);
    if (!Array.isArray(items) || items.length === 0) {
      return [];
    }

    const out: PropertyListing[] = [];
    for (const item of items) {
      const address =
        typeof item.address === "string" ? item.address.trim() : "";
      if (!address || address.length < 5) {
        continue;
      }
      const rawPrice =
        typeof item.price === "string" ? item.price.trim() : undefined;
      const parsedPrice = parsePropertyPrice(rawPrice, countryCode);
      const rawUrl =
        typeof item.listing_url === "string" && item.listing_url.trim()
          ? resolveAbsoluteUrl(item.listing_url.trim(), pageUrl)
          : pageUrl;
      const listingType = inferListingType(
        rawUrl,
        undefined,
        parsedPrice.priceText
      );
      const bedsMatch =
        typeof item.bedrooms === "string" || typeof item.bedrooms === "number"
          ? String(item.bedrooms).match(/(\d+)/)
          : null;
      const bathsMatch =
        typeof item.bathrooms === "string" || typeof item.bathrooms === "number"
          ? String(item.bathrooms).match(/(\d+)/)
          : null;
      const carsMatch =
        typeof item.parking === "string" || typeof item.parking === "number"
          ? String(item.parking).match(/(\d+)/)
          : null;
      const propType =
        typeof item.property_type === "string" && item.property_type.trim()
          ? item.property_type.trim()
          : undefined;

      out.push({
        title:
          `${bedsMatch ? `${bedsMatch[1]} bed ` : ""}${propType ? `${propType} ` : ""}at ${address}`
            .replace(/\s+/g, " ")
            .trim(),
        address,
        country: countryCode,
        price: parsedPrice.price,
        priceText: parsedPrice.priceText,
        currency: parsedPrice.currency,
        pricePeriod: inferPricePeriod(parsedPrice.priceText, listingType),
        listingType,
        propertyType: propType,
        bedrooms: bedsMatch ? Number.parseInt(bedsMatch[1], 10) : undefined,
        bathrooms: bathsMatch ? Number.parseInt(bathsMatch[1], 10) : undefined,
        parking: carsMatch ? Number.parseInt(carsMatch[1], 10) : undefined,
        url: rawUrl,
        portal: extractDomainHost(rawUrl) || portal,
        extractedVia: "scaledown-extract-1",
      });
    }
    return out;
  } catch {
    return [];
  } finally {
    clearTimeout(timer);
  }
}

export async function extractFlightOffersWithScaleDown(
  text: string,
  pageUrl: string,
  countryCode?: string,
  timeoutMs = 3000
): Promise<FlightOffer[]> {
  const apiKey =
    process.env.AI_GATEWAY_API_KEY || process.env.VERCEL_OIDC_TOKEN || "";
  const trimmed = text.trim().slice(0, 6_000);
  if (!apiKey || trimmed.length < 40) {
    return [];
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const provider = extractDomainHost(pageUrl) || "unknown";

  try {
    const res = await fetch(
      "https://ai-gateway.vercel.sh/v1/chat/completions",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          model: "scaledown/scaledown-extract-1",
          messages: [
            {
              role: "system",
              content:
                "Extract distinct flight offers with airline, origin, destination, duration, stops, cabin class, and fare price.",
            },
            { role: "user", content: trimmed },
          ],
          response_format: {
            type: "json_schema",
            json_schema: {
              name: "flight_offers",
              schema: {
                type: "object",
                properties: {
                  flights: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        airline: { type: "string" },
                        flight_number: { type: "string" },
                        origin: { type: "string" },
                        destination: { type: "string" },
                        duration: { type: "string" },
                        stops: { type: "string" },
                        price: { type: "string" },
                        url: { type: "string" },
                      },
                    },
                  },
                },
              },
            },
          },
        }),
        signal: controller.signal,
      }
    );
    if (!res.ok) {
      return [];
    }
    const payload = (await res.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
    };
    const rawContent = payload.choices?.[0]?.message?.content;
    if (!rawContent) {
      return [];
    }
    const parsed = JSON.parse(rawContent) as {
      structured_result?: { flights?: Array<Record<string, unknown>> };
      flights?: Array<Record<string, unknown>>;
    };
    const items =
      parsed.structured_result?.flights ??
      (Array.isArray(parsed.flights) ? parsed.flights : []);
    const out: FlightOffer[] = [];
    for (const item of items) {
      const airline =
        typeof item.airline === "string" ? item.airline.trim() : undefined;
      const origin =
        typeof item.origin === "string" ? item.origin.trim() : undefined;
      const destination =
        typeof item.destination === "string"
          ? item.destination.trim()
          : undefined;
      const rawPrice =
        typeof item.price === "string" ? item.price.trim() : undefined;
      if (!airline && !origin && !rawPrice) {
        continue;
      }
      const parsedPrice = parseFlightPrice(rawPrice, countryCode);
      const rawUrl =
        typeof item.url === "string" && item.url.trim()
          ? resolveAbsoluteUrl(item.url.trim(), pageUrl)
          : pageUrl;
      out.push({
        title:
          `${airline ? `${airline} · ` : ""}${origin || "Flight"} → ${destination || ""}`.trim(),
        airline,
        flightNumber:
          typeof item.flight_number === "string"
            ? item.flight_number.trim()
            : undefined,
        origin,
        destination,
        duration:
          typeof item.duration === "string" ? item.duration.trim() : undefined,
        stops: typeof item.stops === "string" ? item.stops.trim() : undefined,
        price: parsedPrice.price,
        priceText: parsedPrice.priceText,
        currency: parsedPrice.currency,
        url: rawUrl,
        provider: extractDomainHost(rawUrl) || provider,
        extractedVia: "scaledown-extract-1",
      });
    }
    return out;
  } catch {
    return [];
  } finally {
    clearTimeout(timer);
  }
}

export async function extractHotelListingsWithScaleDown(
  text: string,
  pageUrl: string,
  countryCode?: string,
  timeoutMs = 3000
): Promise<HotelListing[]> {
  const apiKey =
    process.env.AI_GATEWAY_API_KEY || process.env.VERCEL_OIDC_TOKEN || "";
  const trimmed = text.trim().slice(0, 6_000);
  if (!apiKey || trimmed.length < 40) {
    return [];
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const provider = extractDomainHost(pageUrl) || "unknown";

  try {
    const res = await fetch(
      "https://ai-gateway.vercel.sh/v1/chat/completions",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          model: "scaledown/scaledown-extract-1",
          messages: [
            {
              role: "system",
              content:
                "Extract distinct hotel or resort listings with hotel name, address/city, nightly price, star rating, guest rating, and amenities.",
            },
            { role: "user", content: trimmed },
          ],
          response_format: {
            type: "json_schema",
            json_schema: {
              name: "hotel_listings",
              schema: {
                type: "object",
                properties: {
                  hotels: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        name: {
                          type: "string",
                          description: "specific hotel or resort name",
                        },
                        address: {
                          type: "string",
                          description: "street address, neighborhood, or city",
                        },
                        price_per_night: {
                          type: "string",
                          description: "nightly room rate or starting price",
                        },
                        star_rating: {
                          type: "string",
                          description: "hotel star classification from 1 to 5",
                        },
                        guest_rating: {
                          type: "string",
                          description: "guest review score such as 9.2 or 4.7",
                        },
                        url: {
                          type: "string",
                          description: "link to the hotel page",
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        }),
        signal: controller.signal,
      }
    );
    if (!res.ok) {
      return [];
    }
    const payload = (await res.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
    };
    const rawContent = payload.choices?.[0]?.message?.content;
    if (!rawContent) {
      return [];
    }
    const parsed = JSON.parse(rawContent) as {
      structured_result?: { hotels?: Array<Record<string, unknown>> };
      hotels?: Array<Record<string, unknown>>;
    };
    const items =
      parsed.structured_result?.hotels ??
      (Array.isArray(parsed.hotels) ? parsed.hotels : []);
    const out: HotelListing[] = [];
    for (const item of items) {
      const name = typeof item.name === "string" ? item.name.trim() : "";
      if (!name || name.length < 3) {
        continue;
      }
      const parsedPrice = parseHotelPrice(
        typeof item.price_per_night === "string"
          ? item.price_per_night
          : undefined,
        countryCode
      );
      const rawUrl =
        typeof item.url === "string" && item.url.trim()
          ? resolveAbsoluteUrl(item.url.trim(), pageUrl)
          : pageUrl;
      const starNum =
        typeof item.star_rating === "string"
          ? Number.parseFloat(item.star_rating)
          : undefined;
      const guestNum =
        typeof item.guest_rating === "string"
          ? Number.parseFloat(item.guest_rating)
          : undefined;
      out.push({
        name,
        address:
          typeof item.address === "string" ? item.address.trim() : undefined,
        country: countryCode,
        pricePerNight: parsedPrice.pricePerNight,
        priceText: parsedPrice.priceText,
        currency: parsedPrice.currency,
        starRating:
          starNum && starNum >= 1 && starNum <= 5 ? starNum : undefined,
        guestRating:
          guestNum && guestNum > 0 && guestNum <= 10 ? guestNum : undefined,
        url: rawUrl,
        provider: extractDomainHost(rawUrl) || provider,
        extractedVia: "scaledown-extract-1",
      });
    }
    return out;
  } catch {
    return [];
  } finally {
    clearTimeout(timer);
  }
}

export async function extractBusinessListingsWithScaleDown(
  text: string,
  pageUrl: string,
  countryCode?: string,
  timeoutMs = 3000
): Promise<BusinessListing[]> {
  const apiKey =
    process.env.AI_GATEWAY_API_KEY || process.env.VERCEL_OIDC_TOKEN || "";
  const trimmed = text.trim().slice(0, 6_000);
  if (!apiKey || trimmed.length < 40) {
    return [];
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const sourceDomain = extractDomainHost(pageUrl) || "unknown";

  try {
    const res = await fetch(
      "https://ai-gateway.vercel.sh/v1/chat/completions",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          model: "scaledown/scaledown-extract-1",
          messages: [
            {
              role: "system",
              content:
                "Extract distinct businesses or companies with business name, category, address, phone, rating, and website URL.",
            },
            { role: "user", content: trimmed },
          ],
          response_format: {
            type: "json_schema",
            json_schema: {
              name: "business_listings",
              schema: {
                type: "object",
                properties: {
                  businesses: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        name: { type: "string" },
                        category: { type: "string" },
                        address: { type: "string" },
                        phone: { type: "string" },
                        rating: { type: "string" },
                        url: { type: "string" },
                      },
                    },
                  },
                },
              },
            },
          },
        }),
        signal: controller.signal,
      }
    );
    if (!res.ok) {
      return [];
    }
    const payload = (await res.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
    };
    const rawContent = payload.choices?.[0]?.message?.content;
    if (!rawContent) {
      return [];
    }
    const parsed = JSON.parse(rawContent) as {
      structured_result?: { businesses?: Array<Record<string, unknown>> };
      businesses?: Array<Record<string, unknown>>;
    };
    const items =
      parsed.structured_result?.businesses ??
      (Array.isArray(parsed.businesses) ? parsed.businesses : []);
    const out: BusinessListing[] = [];
    for (const item of items) {
      const name = typeof item.name === "string" ? item.name.trim() : "";
      if (!name || name.length < 2) {
        continue;
      }
      const rawUrl =
        typeof item.url === "string" && item.url.trim()
          ? resolveAbsoluteUrl(item.url.trim(), pageUrl)
          : pageUrl;
      const ratingNum =
        typeof item.rating === "string"
          ? Number.parseFloat(item.rating)
          : undefined;
      out.push({
        name,
        category:
          typeof item.category === "string" ? item.category.trim() : undefined,
        address:
          typeof item.address === "string" ? item.address.trim() : undefined,
        country: countryCode,
        phone: typeof item.phone === "string" ? item.phone.trim() : undefined,
        website: rawUrl,
        rating:
          ratingNum && ratingNum > 0 && ratingNum <= 10 ? ratingNum : undefined,
        url: rawUrl,
        sourceDomain: extractDomainHost(rawUrl) || sourceDomain,
        extractedVia: "scaledown-extract-1",
      });
    }
    return out;
  } catch {
    return [];
  } finally {
    clearTimeout(timer);
  }
}
