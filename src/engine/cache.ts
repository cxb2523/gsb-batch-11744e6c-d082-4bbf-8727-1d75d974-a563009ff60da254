import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

interface ExternalCacheDb {
  getCrawledPage(urlHash: string): Promise<{
    title: string;
    markdown: string;
    links: string[];
    structuredData?: Record<string, unknown> | null;
    statusCode: number;
    contentHash: string;
    etag?: string;
    lastModified?: string;
    crawledAt: string | Date;
    expiresAt: string | Date;
  } | null | undefined>;
  upsertCrawledPage(entry: Record<string, unknown>): Promise<unknown>;
  getCrawledSite(cacheKeyHash: string): Promise<{
    links: string[];
    source: string;
    pagesCrawled: number;
    crawledAt: string | Date;
    expiresAt: string | Date;
  } | null | undefined>;
  upsertCrawledSite(entry: Record<string, unknown>): Promise<unknown>;
}

let cachedDbPromise: Promise<ExternalCacheDb | null> | null = null;

/**
 * Registers an external L3 cache database store (e.g., Supabase Postgres in webcrawl.app cloud)
 * when the engine is consumed as an installed npm package (`webcrawl/engine/cache`).
 */
export function registerExternalCacheDb(db: ExternalCacheDb | null): void {
  cachedDbPromise = Promise.resolve(db);
}

function getOptionalDb(): Promise<ExternalCacheDb | null> {
  if (!cachedDbPromise) {
    const dbModulePath = "../db/index.js";
    cachedDbPromise = import(/* @vite-ignore */ dbModulePath)
      .then((mod) => (mod?.db as ExternalCacheDb) ?? null)
      .catch(() => null);
  }
  return cachedDbPromise;
}

export interface CacheEntry {
  title: string;
  markdown: string;
  links: string[];
  structuredData?: Record<string, unknown> | null;
  statusCode: number;
  contentHash: string;
  etag?: string;
  lastModified?: string;
  cacheLayer?: "memory" | "disk" | "postgres";
  cachedAt: number;
  expiresAt: number;
}

export interface MapCacheEntry {
  links: string[];
  source: string;
  pagesCrawled: number;
  cacheLayer?: "memory" | "disk" | "postgres";
  cachedAt: number;
  expiresAt: number;
}

// 24-hour cache (L1 in-memory + L2 /tmp disk + L3 Postgres shared URL/website store)
export const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const MAX_CACHE_ENTRIES = 2500;
const TMP_CACHE_DIR = "/tmp/webcrawl-cache-v1";

const pageCache = new Map<string, CacheEntry>();
const mapCache = new Map<string, MapCacheEntry>();

try {
  fs.mkdirSync(TMP_CACHE_DIR, { recursive: true });
} catch {
  // ignore if read-only filesystem
}

export function sha256(content: string): string {
  return crypto.createHash("sha256").update(content).digest("hex");
}

export function normalizeCacheUrl(rawUrl: string): {
  normalizedUrl: string;
  domain: string;
} {
  try {
    const u = new URL(rawUrl.trim());
    u.hash = "";
    for (const key of Array.from(u.searchParams.keys())) {
      if (/^(utm_|fbclid|gclid|msclkid|_ga|_gl|ref$)/i.test(key)) {
        u.searchParams.delete(key);
      }
    }
    const normalizedUrl = u.toString().replace(/\/$/, "") || u.origin;
    const domain = u.hostname.toLowerCase().replace(/^www\./, "");
    return { normalizedUrl, domain };
  } catch {
    return {
      normalizedUrl: rawUrl.trim(),
      domain: "unknown",
    };
  }
}

export function clearLocalCacheForTests(): void {
  pageCache.clear();
  mapCache.clear();
  try {
    if (fs.existsSync(TMP_CACHE_DIR)) {
      for (const f of fs.readdirSync(TMP_CACHE_DIR)) {
        try {
          fs.unlinkSync(path.join(TMP_CACHE_DIR, f));
        } catch {
          // ignore
        }
      }
    }
  } catch {
    // ignore
  }
}

export function getCachedPage(
  url: string,
  retainImages: string
): CacheEntry | undefined {
  const { normalizedUrl } = normalizeCacheUrl(url);
  const key = `${normalizedUrl}::${retainImages}`;
  const entry = pageCache.get(key);
  if (entry) {
    if (Date.now() > entry.expiresAt) {
      pageCache.delete(key);
    } else {
      return { ...entry, cacheLayer: "memory" };
    }
  }
  // Check L2 /tmp disk cache for 24-hour persistence across warm/cold workers
  try {
    const diskPath = path.join(TMP_CACHE_DIR, `page_${sha256(key)}.json`);
    if (fs.existsSync(diskPath)) {
      const parsed = JSON.parse(
        fs.readFileSync(diskPath, "utf8")
      ) as CacheEntry;
      if (Date.now() <= parsed.expiresAt) {
        pageCache.set(key, parsed);
        return { ...parsed, cacheLayer: "disk" };
      }
      fs.unlinkSync(diskPath);
    }
  } catch {
    // ignore disk read errors
  }
  return undefined;
}

/**
 * 3-tier read-through lookup: L1 Memory -> L2 /tmp Disk -> L3 Postgres `crawled_pages`.
 * Promotes L3 Postgres hits back into L1 and L2 so repeat requests never re-crawl the target website.
 */
export async function getCachedPageAsync(
  url: string,
  retainImages: string
): Promise<CacheEntry | undefined> {
  const localHit = getCachedPage(url, retainImages);
  if (localHit) {
    return localHit;
  }

  const { normalizedUrl } = normalizeCacheUrl(url);
  const key = `${normalizedUrl}::${retainImages}`;
  const urlHash = sha256(key);

  try {
    const db = await getOptionalDb();
    const pgHit = await db?.getCrawledPage(urlHash);
    if (pgHit) {
      const cachedAt = new Date(pgHit.crawledAt).getTime();
      const expiresAt = new Date(pgHit.expiresAt).getTime();
      if (expiresAt > Date.now()) {
        const promoted: CacheEntry = {
          title: pgHit.title,
          markdown: pgHit.markdown,
          links: pgHit.links,
          structuredData: pgHit.structuredData ?? null,
          statusCode: pgHit.statusCode,
          contentHash: pgHit.contentHash,
          etag: pgHit.etag,
          lastModified: pgHit.lastModified,
          cacheLayer: "postgres",
          cachedAt,
          expiresAt,
        };
        pageCache.set(key, promoted);
        try {
          const diskPath = path.join(TMP_CACHE_DIR, `page_${urlHash}.json`);
          fs.writeFileSync(diskPath, JSON.stringify(promoted));
        } catch {
          // ignore
        }
        return promoted;
      }
    }
  } catch {
    // ignore DB lookup errors
  }
  return undefined;
}

export function setCachedPage(
  url: string,
  retainImages: string,
  entry: Omit<CacheEntry, "expiresAt" | "cachedAt">,
  ttlMs = CACHE_TTL_MS
): void {
  const { normalizedUrl, domain } = normalizeCacheUrl(url);
  const key = `${normalizedUrl}::${retainImages}`;
  const urlHash = sha256(key);

  if (pageCache.size >= MAX_CACHE_ENTRIES) {
    const oldestKey = pageCache.keys().next().value;
    if (oldestKey) {
      pageCache.delete(oldestKey);
    }
  }
  const now = Date.now();
  const fullEntry: CacheEntry = {
    ...entry,
    cacheLayer: "memory",
    cachedAt: now,
    expiresAt: now + ttlMs,
  };
  pageCache.set(key, fullEntry);
  try {
    const diskPath = path.join(TMP_CACHE_DIR, `page_${urlHash}.json`);
    fs.writeFileSync(diskPath, JSON.stringify(fullEntry));
  } catch {
    // ignore disk write errors
  }

  // Write-through to L3 Postgres `crawled_pages` store (when available)
  void getOptionalDb()
    .then((db) =>
      db?.upsertCrawledPage({
        urlHash,
        normalizedUrl,
        domain,
        title: entry.title,
        markdown: entry.markdown,
        links: entry.links || [],
        structuredData: entry.structuredData ?? null,
        statusCode: entry.statusCode,
        contentHash: entry.contentHash,
        etag: entry.etag,
        lastModified: entry.lastModified,
        retainImages,
        fetchCount: 1,
        crawledAt: new Date(now).toISOString(),
        expiresAt: new Date(now + ttlMs).toISOString(),
      })
    )
    .catch(() => {});
}

export function getCachedMap(cacheKey: string): MapCacheEntry | undefined {
  const entry = mapCache.get(cacheKey);
  if (entry) {
    if (Date.now() > entry.expiresAt) {
      mapCache.delete(cacheKey);
    } else {
      return { ...entry, cacheLayer: "memory" };
    }
  }
  try {
    const diskPath = path.join(TMP_CACHE_DIR, `map_${sha256(cacheKey)}.json`);
    if (fs.existsSync(diskPath)) {
      const parsed = JSON.parse(
        fs.readFileSync(diskPath, "utf8")
      ) as MapCacheEntry;
      if (Date.now() <= parsed.expiresAt) {
        mapCache.set(cacheKey, parsed);
        return { ...parsed, cacheLayer: "disk" };
      }
      fs.unlinkSync(diskPath);
    }
  } catch {
    // ignore
  }
  return undefined;
}

/**
 * 3-tier read-through lookup for website maps/crawls: L1 Memory -> L2 Disk -> L3 Postgres `crawled_sites`.
 */
export async function getCachedMapAsync(
  cacheKey: string
): Promise<MapCacheEntry | undefined> {
  const localHit = getCachedMap(cacheKey);
  if (localHit) {
    return localHit;
  }
  const cacheKeyHash = sha256(cacheKey);
  try {
    const db = await getOptionalDb();
    const pgHit = await db?.getCrawledSite(cacheKeyHash);
    if (pgHit) {
      const cachedAt = new Date(pgHit.crawledAt).getTime();
      const expiresAt = new Date(pgHit.expiresAt).getTime();
      if (expiresAt > Date.now()) {
        const promoted: MapCacheEntry = {
          links: pgHit.links,
          source: pgHit.source,
          pagesCrawled: pgHit.pagesCrawled,
          cacheLayer: "postgres",
          cachedAt,
          expiresAt,
        };
        mapCache.set(cacheKey, promoted);
        try {
          const diskPath = path.join(TMP_CACHE_DIR, `map_${cacheKeyHash}.json`);
          fs.writeFileSync(diskPath, JSON.stringify(promoted));
        } catch {
          // ignore
        }
        return promoted;
      }
    }
  } catch {
    // ignore
  }
  return undefined;
}

export function setCachedMap(
  cacheKey: string,
  entry: Omit<MapCacheEntry, "cachedAt" | "expiresAt">,
  ttlMs = CACHE_TTL_MS,
  rootUrl?: string
): void {
  const now = Date.now();
  const cacheKeyHash = sha256(cacheKey);
  const fullEntry: MapCacheEntry = {
    ...entry,
    cacheLayer: "memory",
    cachedAt: now,
    expiresAt: now + ttlMs,
  };
  mapCache.set(cacheKey, fullEntry);
  try {
    const diskPath = path.join(TMP_CACHE_DIR, `map_${cacheKeyHash}.json`);
    fs.writeFileSync(diskPath, JSON.stringify(fullEntry));
  } catch {
    // ignore
  }

  const rawRoot = rootUrl || cacheKey.split("::")[0] || "";
  const { normalizedUrl, domain } = normalizeCacheUrl(rawRoot);
  void getOptionalDb()
    .then((db) =>
      db?.upsertCrawledSite({
        cacheKeyHash,
        rootUrl: normalizedUrl,
        domain,
        links: entry.links || [],
        source: entry.source,
        pagesCrawled: entry.pagesCrawled,
        crawledAt: new Date(now).toISOString(),
        expiresAt: new Date(now + ttlMs).toISOString(),
      })
    )
    .catch(() => {});
}
