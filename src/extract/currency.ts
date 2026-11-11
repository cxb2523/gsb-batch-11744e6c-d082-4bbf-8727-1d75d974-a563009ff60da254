const VALID_ISO_CURRENCIES = new Set([
  "USD",
  "AUD",
  "GBP",
  "EUR",
  "CAD",
  "NZD",
  "SGD",
  "HKD",
  "JPY",
  "CNY",
  "INR",
  "CHF",
  "SEK",
  "NOK",
  "DKK",
  "ZAR",
  "BRL",
  "MXN",
  "AED",
  "SAR",
  "THB",
  "MYR",
  "IDR",
  "PHP",
  "VND",
  "KRW",
  "PLN",
  "TRY",
  "TWD",
]);

/**
 * Derive ISO 4217 currency code from a raw price string and/or 2-letter ISO country code.
 * Uses standard currency symbols and ISO country conventions without hardcoded retailer lists.
 */
export function resolveCurrencyCode(
  rawPriceOrCurrency?: string,
  countryCode?: string
): string {
  const s = (rawPriceOrCurrency || "").trim();
  const isoMatches = s.match(/\b([A-Z]{3})\b/g);
  if (isoMatches) {
    for (const code of isoMatches) {
      if (VALID_ISO_CURRENCIES.has(code)) {
        return code;
      }
    }
  }
  if (/A\$|AU\$/i.test(s)) {
    return "AUD";
  }
  if (/NZ\$/i.test(s)) {
    return "NZD";
  }
  if (/CA\$|C\$/i.test(s)) {
    return "CAD";
  }
  if (/S\$|SG\$/i.test(s)) {
    return "SGD";
  }
  if (/HK\$/i.test(s)) {
    return "HKD";
  }
  if (/NT\$/i.test(s)) {
    return "TWD";
  }
  if (s.includes("£")) {
    return "GBP";
  }
  if (s.includes("€")) {
    return "EUR";
  }
  if (s.includes("¥")) {
    return (countryCode || "").toUpperCase() === "CN" ? "CNY" : "JPY";
  }
  if (
    s.includes("₹") ||
    /\bRs\.?(?:\s|\d)/i.test(s) ||
    /\b(?:crores?|cr|lakhs?|lacs?)\b/i.test(s)
  ) {
    return "INR";
  }
  if (s.includes("₫") || /\b(?:đồng|vnd|triệu|tỷ)\b/i.test(s)) {
    return "VND";
  }
  if (s.includes("฿")) {
    return "THB";
  }
  if (s.includes("₱")) {
    return "PHP";
  }
  if (s.includes("₩")) {
    return "KRW";
  }
  if (/\bzł\b/i.test(s)) {
    return "PLN";
  }
  if (/\bRM\s*\d/i.test(s)) {
    return "MYR";
  }
  if (/\bRp\.?\s*\d/i.test(s)) {
    return "IDR";
  }

  const cc = (countryCode || "").trim().toUpperCase();
  // Bare "$" in non-dollar countries (e.g. EU, GB, IN, VN, JP) indicates USD pricing
  if (
    s.includes("$") &&
    !["US", "AU", "CA", "NZ", "SG", "HK", "TW", "MX", ""].includes(cc)
  ) {
    return "USD";
  }
  const COUNTRY_TO_CURRENCY: Record<string, string> = {
    AU: "AUD",
    GB: "GBP",
    UK: "GBP",
    CA: "CAD",
    NZ: "NZD",
    SG: "SGD",
    IN: "INR",
    VN: "VND",
    JP: "JPY",
    CN: "CNY",
    HK: "HKD",
    TW: "TWD",
    KR: "KRW",
    TH: "THB",
    MY: "MYR",
    ID: "IDR",
    PH: "PHP",
    CH: "CHF",
    SE: "SEK",
    NO: "NOK",
    DK: "DKK",
    PL: "PLN",
    CZ: "CZK",
    HU: "HUF",
    RO: "RON",
    TR: "TRY",
    AE: "AED",
    SA: "SAR",
    ZA: "ZAR",
    BR: "BRL",
    MX: "MXN",
  };
  if (COUNTRY_TO_CURRENCY[cc]) {
    return COUNTRY_TO_CURRENCY[cc];
  }
  if (
    [
      "DE",
      "FR",
      "IT",
      "ES",
      "NL",
      "IE",
      "AT",
      "BE",
      "PT",
      "FI",
      "GR",
      "LU",
      "SK",
      "SI",
      "EE",
      "LV",
      "LT",
      "HR",
      "CY",
      "MT",
      "EU",
    ].includes(cc)
  ) {
    return "EUR";
  }
  return "USD";
}

/**
 * Parse a numeric price and currency from a human price string such as
 * "$360.41", "A$399.00", "£173.49", "1.299,00 €", "₹1,19,900", "₹1.45 Crores", "S$429", "7.490.000 ₫".
 */
export function parsePriceString(
  raw: string | number | undefined,
  countryCode?: string,
  explicitCurrency?: string,
  maxAllowedPrice = 1_000_000
): { price: number; rawPrice: string; currency: string } | null {
  if (typeof raw === "number") {
    if (!Number.isFinite(raw) || raw <= 0) {
      return null;
    }
    const numCurrency = resolveCurrencyCode(explicitCurrency, countryCode);
    return {
      price: Number(raw.toFixed(2)),
      rawPrice: `${numCurrency} ${raw.toFixed(2)}`,
      currency: numCurrency,
    };
  }
  if (!raw || typeof raw !== "string") {
    return null;
  }
  const cleaned = raw.replace(/\s+/g, " ").trim();
  if (!cleaned) {
    return null;
  }

  const currency = resolveCurrencyCode(
    explicitCurrency || cleaned,
    countryCode
  );

  // High-denomination currencies (VND, IDR, KRW, JPY, INR) allow much higher nominal numeric caps
  const highDenomMultiplier =
    currency === "VND" || currency === "IDR"
      ? 25_000
      : currency === "KRW" || currency === "JPY" || currency === "INR"
        ? 500
        : 1;
  const effectiveMaxPrice = maxAllowedPrice * highDenomMultiplier;

  // Handle Indian Crore / Lakh and Vietnamese tỷ / triệu multipliers
  const unitMatch = cleaned.match(
    /(\d[\d,.]*)\s*(crores?|cr|lakhs?|lacs?|tỷ|triệu)\b/i
  );
  if (unitMatch) {
    const baseNum = Number.parseFloat(unitMatch[1].replace(/,/g, ""));
    const unit = unitMatch[2].toLowerCase();
    const mult = unit.startsWith("cr")
      ? 10_000_000
      : unit.startsWith("la")
        ? 100_000
        : unit === "tỷ"
          ? 1_000_000_000
          : 1_000_000;
    const total = Math.round(baseNum * mult);
    if (Number.isFinite(total) && total > 0 && total <= effectiveMaxPrice) {
      return {
        price: total,
        rawPrice: cleaned,
        currency,
      };
    }
  }

  const numMatch = cleaned.match(/(\d[\d,.]*)/);
  if (!numMatch) {
    return null;
  }
  let numStr = numMatch[1].replace(/[.,]$/, "");

  // Handle multi-dot thousands (e.g. "7.490.000" in VND/EUR/IDR) and European decimal comma ("194,99" or "1.299,00")
  if (/^\d{1,3}(?:\.\d{3}){2,}$/.test(numStr)) {
    numStr = numStr.replace(/\./g, "");
  } else if (
    /^\d{1,3}\.\d{3}$/.test(numStr) &&
    (currency === "VND" || currency === "IDR" || currency === "EUR")
  ) {
    numStr = numStr.replace(/\./g, "");
  } else if (/\.\d{3},\d{1,2}$/.test(numStr)) {
    numStr = numStr.replace(/\./g, "").replace(",", ".");
  } else if (/^\d+,\d{1,2}$/.test(numStr)) {
    numStr = numStr.replace(",", ".");
  } else {
    numStr = numStr.replace(/,/g, "");
  }

  const value = Number.parseFloat(numStr);
  if (!Number.isFinite(value) || value <= 0 || value > effectiveMaxPrice) {
    return null;
  }

  return {
    price: Number(value.toFixed(2)),
    rawPrice: cleaned,
    currency,
  };
}

export function extractDomainHost(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./i, "").toLowerCase();
  } catch {
    return "";
  }
}
