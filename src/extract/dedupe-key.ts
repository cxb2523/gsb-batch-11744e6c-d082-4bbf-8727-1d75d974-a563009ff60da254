const TRACKING_PARAM = /^(utm_|fbclid$|gclid$|msclkid$|mc_cid$|mc_eid$|_ga$|_gl$|ref$|ref_src$)/i;

/**
 * Canonical form of a result URL for duplicate detection: lower-case host without
 * `www.`, no hash, no tracking params, no trailing slash. Distinct paths/queries stay
 * distinct, so two listings on the same provider are never merged.
 */
export function canonicalResultUrl(rawUrl: string | undefined): string {
  if (!rawUrl) {
    return "";
  }
  try {
    const u = new URL(rawUrl.trim());
    u.hash = "";
    u.hostname = u.hostname.toLowerCase().replace(/^www\./, "");
    for (const key of Array.from(u.searchParams.keys())) {
      if (TRACKING_PARAM.test(key)) {
        u.searchParams.delete(key);
      }
    }
    u.searchParams.sort();
    return `${u.hostname}${u.pathname.replace(/\/+$/, "")}${u.search}`;
  } catch {
    return rawUrl.trim().toLowerCase();
  }
}

export function normalizeIdentity(text: string | undefined): string {
  return (text ?? "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
}

/**
 * Duplicate key = same URL AND same identity (address / name). Different URLs from the
 * same provider are kept, and so is one search-results URL that yields several items.
 */
export function resultDedupeKey(
  url: string | undefined,
  identity: string | undefined
): string {
  return `${canonicalResultUrl(url)}::${normalizeIdentity(identity)}`;
}
