export {
  extractDomainHost,
  parsePriceString,
  resolveCurrencyCode,
} from "./currency.js";

export {
  extractOfferFromSerpSnippet,
  extractOffersFromHtml,
  groupOffersIntoProducts,
  parseBingShoppingHtml,
  type AggregatedProduct,
  type ProductOffer,
} from "./shopping.js";

export {
  dedupePropertyListings,
  extractPropertyListingFromSerpResult,
  extractPropertyListingsFromHtml,
  inferListingType,
  inferPricePeriod,
  parsePropertyPrice,
  resolveAbsoluteUrl,
  type PropertyListing,
} from "./real-estate.js";

export {
  dedupeFlightOffers,
  extractFlightOfferFromSerpResult,
  extractFlightOffersFromHtml,
  inferCabinClass,
  inferDurationAndStops,
  inferRouteFromText,
  inferTripType,
  parseFlightPrice,
  type FlightOffer,
} from "./flights.js";

export {
  dedupeHotelListings,
  extractHotelListingFromSerpResult,
  extractHotelListingsFromHtml,
  parseHotelPrice,
  type HotelListing,
} from "./hotels.js";

export {
  dedupeBusinessListings,
  extractBusinessListingFromSerpResult,
  extractBusinessListingsFromHtml,
  type BusinessListing,
} from "./business.js";

export {
  cvss3BaseScore,
  cveSeverityLabel,
  extractCveIdsFromText,
  extractGhsaIdsFromText,
  looksLikeVulnId,
  mergeCveRecords,
  normalizeCveId,
  nvdUrl,
  parseNvdCve,
  parseNvdResponse,
  parseOsvVuln,
  severityFromScore,
  sortCveRecords,
  type CveAffected,
  type CveRecord,
  type CveSeverity,
} from "./cve.js";

export {
  extractBusinessListingsWithScaleDown,
  extractFlightOffersWithScaleDown,
  extractHotelListingsWithScaleDown,
  extractPropertyListingsWithScaleDown,
} from "./scaledown.js";

export {
  coerceExtractSchema,
  extractByPromptAndSchema,
  extractQuoteAuthorPairs,
  hasCustomExtractRequest,
  isEmptyExtractResult,
  isJsTemplateJunk,
  nestedQuoteAuthorFields,
  normalizeExtractSchema,
  shapeQuoteAuthors,
  stripNonContentHtml,
  wantsQuoteAuthorExtract,
  type QuoteAuthor,
} from "./structured.js";
