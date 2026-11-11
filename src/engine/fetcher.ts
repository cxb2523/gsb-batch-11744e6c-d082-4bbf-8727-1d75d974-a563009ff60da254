import { followSafely, UnsafeUrlError } from "./safe-url.js";
import {
  isDomainProxyNeeded,
  markDomainProxyNeeded,
} from "./session.js";

export interface ScrapeOptions {
  url: string;
  formats?: Array<"markdown" | "html" | "links">;
  retainImages?: "all" | "none";
  removeSelectors?: string[];
  render?: boolean;
  timeout?: number;
  bypassCache?: boolean;
  cache?: boolean;
}

export interface ScrapeResult {
  success: boolean;
  url: string;
  title: string;
  markdown: string;
  html?: string;
  links?: string[];
  statusCode: number;
  contentHash: string;
  tier: "cache" | "static" | "sandbox" | "cloudflare" | "browser" | "impersonate" | "proxy-impersonate";
  latencyMs: number;
  error?: string;
}

const domainCookies = new Map<string, string>();
const domainUserAgents = new Map<string, string>();

const BROWSER_USER_AGENTS = [
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
];

export function getBrowserHeaders(
  targetUrl: string,
  extraHeaders?: Record<string, string>
): Record<string, string> {
  const parsed = new URL(targetUrl);
  const ua = domainUserAgents.get(parsed.hostname) ?? BROWSER_USER_AGENTS[
    Math.abs(hashCode(targetUrl)) % BROWSER_USER_AGENTS.length
  ];
  let hostCookie: string | undefined;
  try {
    hostCookie = domainCookies.get(parsed.hostname);
  } catch {
    // ignore invalid URL
  }

  return {
    "User-Agent": ua,
    Accept:
      "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Cache-Control": "no-cache",
    Pragma: "no-cache",
    "Sec-Ch-Ua":
      '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"macOS"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
    ...(hostCookie ? { Cookie: hostCookie } : {}),
    ...extraHeaders,
  };
}

export function setDomainCookie(hostname: string, cookieHeader: string): void {
  if (hostname && cookieHeader) {
    domainCookies.set(hostname, cookieHeader);
  }
}

/**
 * User-Agent paired with a domain's replayed session cookies. Cloudflare's
 * `cf_clearance` (and similar bound tokens) only validate when the exact UA
 * that solved the challenge is reused, so replay sets both together.
 */
export function setDomainUserAgent(hostname: string, userAgent: string): void {
  if (hostname && userAgent) {
    domainUserAgents.set(hostname, userAgent);
  }
}

function hashCode(str: string): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = (hash << 5) - hash + str.charCodeAt(i);
    hash |= 0;
  }
  return hash;
}

/** Markers that only appear on an AWS WAF challenge interstitial. */
const AWS_WAF_CHALLENGE_MARKERS = [
  "awswafcookiedomainlist",
  "awswafintegration",
  "aws-waf-token",
  'id="challenge-container"',
  "/__challenge_",
];

/**
 * True when an HTML response (with optional status) is an AWS WAF challenge
 * interstitial: a marker match proves it regardless of status; otherwise a
 * documented HTTP 202 whose payload is a `<script>`-only HTML shell with zero
 * visible text (APIs legitimately return 202 too, so status alone is not proof).
 */
export function isAwsWafChallenge(html: string, status?: number): boolean {
  const lower = String(html ?? "").slice(0, 8000).toLowerCase();
  if (AWS_WAF_CHALLENGE_MARKERS.some((m) => lower.includes(m))) return true;
  if (status === 202) {
    if (!lower.includes("<html")) return false;
    const visibleText = lower
      .slice(0, 8000)
      .replace(/<script[\s\S]*?<\/script>/g, "")
      .replace(/<noscript[\s\S]*?<\/noscript>/g, "")
      .replace(/<style[\s\S]*?<\/style>/g, "")
      .replace(/<[^>]+>/g, " ")
      .trim();
    return visibleText.length === 0;
  }
  return false;
}

export function isAntiBotChallenge(html: string, status: number): boolean {
  if (status === 403 || status === 429 || status === 503) {
    return true;
  }
  const raw = String(html ?? "");
  // Reddit (and similar) hide this copy after tens of KB of CSS + a data-URI PNG.
  if (/blocked by network security/i.test(raw)) {
    return true;
  }
  // Head slice catches title/meta markers on ordinary challenge interstitials.
  const lower = raw.slice(0, 8000).toLowerCase();
  if (
    lower.includes("cf-browser-verification") ||
    lower.includes("challenge-platform") ||
    lower.includes("just a moment...") ||
    lower.includes("vercel security checkpoint") ||
    lower.includes("_vercel/security") ||
    lower.includes("enable javascript and cookies to continue") ||
    lower.includes("_cf_chl_opt")
  ) {
    return true;
  }
  // IP-reputation interstitials (stubhub, expedia) that pass the TLS gate
  // but gate datacenter IPs behind a "enable JS / are you human" shell.
  // These can arrive cached or served with status 200, so text markers are
  // required on top of the 403/429 status check above.
  if (
    lower.includes("enable javascript and disable any ad blocker") ||
    lower.includes("show us your human side") ||
    lower.includes("we can't tell if you're a human or a bot") ||
    lower.includes("we can’t tell if you’re a human or a bot")
  ) {
    return true;
  }
  // AWS WAF serves its invisible JS challenge as HTTP 202 with none of the
  // Cloudflare/Vercel markers, so those pages used to pass as real content.
  return isAwsWafChallenge(html, status);
}

let sharedImpit: any = null;

interface RawHop {
  status: number;
  headers: Record<string, string>;
  body: ArrayBuffer;
}

/** Tier that won the most recent rawGet ladder ("impit-tls" → "impersonate" → "proxy-impersonate" → "fetch"). */
let lastTier: "impit-tls" | "impersonate" | "proxy-impersonate" | "fetch" = "impit-tls";
/** Bytes pulled through the residential proxy on the most recent ladder run. */
let lastProxyBytes = 0;

/** Transport tier that won the last fetch ladder run (for result evidence). */
export function lastFetchTier(): "impit-tls" | "impersonate" | "proxy-impersonate" | "fetch" {
  return lastTier;
}

/** Bytes transferred through the residential proxy on the last ladder run (bandwidth accounting). */
export function lastProxyBytesCount(): number {
  return lastProxyBytes;
}

/**
 * Residential proxy URL from env, or null when the tier is disabled.
 * Generic: a full `WEBCRAWL_PROXY_URL` (`http://user:pass@host:port`) or the
 * split `WEBCRAWL_PROXY_USER` + `WEBCRAWL_PROXY_PWD` pair, with the gateway
 * host/port overridable via `WEBCRAWL_PROXY_HOST` / `WEBCRAWL_PROXY_PORT`.
 * `DECODO_*` equivalents are honored as a legacy fallback so existing
 * deployments keep working (their default gateway is `gate.decodo.com:7000`).
 */
export function residentialProxyUrl(): string | null {
  const direct = process.env.WEBCRAWL_PROXY_URL?.trim() || process.env.DECODO_URL?.trim();
  if (direct) return direct;
  const user = process.env.WEBCRAWL_PROXY_USER?.trim() || process.env.DECODO_USER?.trim();
  const pwd = process.env.WEBCRAWL_PROXY_PWD?.trim() || process.env.DECODO_PWD?.trim();
  if (user && pwd) {
    const host = process.env.WEBCRAWL_PROXY_HOST?.trim() || "gate.decodo.com";
    const port = process.env.WEBCRAWL_PROXY_PORT?.trim() || "7000";
    return `http://${encodeURIComponent(user)}:${encodeURIComponent(pwd)}@${host}:${port}`;
  }
  return null;
}

/** One request, redirects NOT followed (callers validate each hop via followSafely). */
async function rawGet(
  url: string,
  reqHeaders: Record<string, string>,
  timeoutMs: number,
  maxBytes?: number
): Promise<RawHop> {
  const read = async (
    status: number,
    headers: Record<string, string>,
    getBuf: () => Promise<ArrayBuffer>
  ): Promise<RawHop> => {
    const isRedirect = status >= 300 && status < 400 && !!headers["location"];
    if (!isRedirect && maxBytes !== undefined) checkDeclaredLength(headers, maxBytes);
    return { status, headers, body: isRedirect ? new ArrayBuffer(0) : await getBuf() };
  };
  lastProxyBytes = 0;
  // Tier P1 fast path: domains memoized as IP-blocked (DataDome) skip the
  // datacenter attempts entirely and go straight to the residential proxy —
  // saves latency and never burns proxy bytes on a doomed direct hop first.
  const proxyUrl = residentialProxyUrl();
  let host = "";
  try {
    host = new URL(url).hostname;
  } catch {
    /* let the direct hops surface the URL error */
  }
  if (proxyUrl && host && (await isDomainProxyNeeded(host).catch(() => false))) {
    const proxyHop = await rawGetImpersonateProxy(url, reqHeaders, timeoutMs, maxBytes, proxyUrl);
    if (proxyHop) {
      lastTier = "proxy-impersonate";
      return proxyHop;
    }
  }
  try {
    if (!sharedImpit) {
      const impitMod = await import("impit");
      sharedImpit = new impitMod.Impit({
        browser: "chrome",
        ignoreTlsErrors: true,
        timeout: timeoutMs,
      });
    }
    const res = await sharedImpit.fetch(url, {
      method: "GET",
      headers: reqHeaders,
      timeout: timeoutMs,
      redirect: "manual",
    });
    const hop = await read(res.status, headersToObject(res.headers), () => res.arrayBuffer());
    // AWS-WAF-style blocks (403/429/challenge shells) on the impit tier
    // (Chrome 136) retry once on the curl-impersonate tier (Chrome 150),
    // which passes WAFs that block the older fingerprint.
    if (isAntiBotChallenge(new TextDecoder().decode(hop.body).slice(0, 8000), hop.status)) {
      const impersonateHop = await rawGetImpersonate(url, reqHeaders, timeoutMs, maxBytes);
      if (impersonateHop) {
        if (isAntiBotChallenge(new TextDecoder().decode(impersonateHop.body).slice(0, 8000), impersonateHop.status)) {
          // Direct datacenter egress is IP-blocked (DataDome): last cheap try
          // is the residential proxy hop before browser escalation. Costs
          // ~100-300KB of proxy bandwidth instead of a 5-15MB page load.
          if (proxyUrl) {
            const proxyHop = await rawGetImpersonateProxy(url, reqHeaders, timeoutMs, maxBytes, proxyUrl);
            if (proxyHop) {
              lastTier = "proxy-impersonate";
              return proxyHop;
            }
          }
        }
        lastTier = "impersonate";
        return impersonateHop;
      }
    }
    lastTier = "impit-tls";
    return hop;
  } catch (err) {
    if (err instanceof ResourceTooLargeError || err instanceof UnsafeUrlError) throw err;
    // impit unavailable/failed: curl-impersonate tier, then plain fetch.
    const impersonateHop = await rawGetImpersonate(url, reqHeaders, timeoutMs, maxBytes);
    if (impersonateHop) {
      lastTier = "impersonate";
      return impersonateHop;
    }
    const res = await fetch(url, {
      headers: reqHeaders,
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
    });
    lastTier = "fetch";
    return await read(res.status, headersToObject(res.headers), () => res.arrayBuffer());
  }
}

/**
 * One GET hop with the curl-impersonate tier (Chrome 150 TLS/HTTP2 fingerprint).
 * Used by `rawGet` when the impit hop is blocked (403/429/challenge) — newer
 * fingerprints pass AWS WAF domains (stubhub, expedia) that block Chrome 136.
 * Falls back to plain `fetch` when the binary is unavailable.
 */
async function rawGetImpersonate(
  url: string,
  reqHeaders: Record<string, string>,
  timeoutMs: number,
  maxBytes?: number
): Promise<RawHop | null> {
  let impersonate: typeof import("@webcrawl/curl-impersonate");
  try {
    impersonate = await import("@webcrawl/curl-impersonate");
  } catch {
    return null;
  }
  // The chrome150 profile's own identity headers MUST survive (profileHeaders
  // merges extras last, so a stale UA would override the profile UA and the
  // UA/TLS mismatch is exactly what DataDome/AWS WAF block). Keep cookies and
  // referer, drop UA + sec-ch/client-hint identity headers.
  const extra: Record<string, string> = {};
  for (const [key, value] of Object.entries(reqHeaders)) {
    const lower = key.toLowerCase();
    if (
      lower === "user-agent" ||
      lower.startsWith("sec-ch-ua") ||
      lower.startsWith("sec-fetch-") ||
      lower === "upgrade-insecure-requests" ||
      lower === "priority"
    ) {
      continue;
    }
    extra[key] = value;
  }
  try {
    const res = await impersonate.impersonateFetch(url, {
      headers: extra,
      timeoutMs,
      maxBytes,
    });
    const headers = res.headers;
    const isRedirect = res.status >= 300 && res.status < 400 && !!headers["location"];
    if (!isRedirect && maxBytes !== undefined) checkDeclaredLength(headers, maxBytes);
    return {
      status: res.status,
      headers,
      body: isRedirect ? new ArrayBuffer(0) : (res.body.buffer as ArrayBuffer),
    };
  } catch (err) {
    if (err instanceof UnsafeUrlError) throw err;
    return null; // tier unavailable or fetch failed — caller falls back
  }
}

/**
 * Tier P1 — one GET hop with curl-impersonate through the residential proxy
 * (Decodo or any `http://user:pass@host:port` HTTP proxy). The target sees a
 * clean residential egress IP while the TLS/HTTP2 fingerprint stays a real
 * Chrome's. Only reached for domains whose datacenter egress is proven
 * IP-blocked, so the domain is memoized and later ladder runs skip the
 * doomed direct attempts entirely. Gzipped HTML only (~100-300KB/request);
 * a 2MB byte cap keeps a runaway response from draining proxy bandwidth.
 */
async function rawGetImpersonateProxy(
  url: string,
  reqHeaders: Record<string, string>,
  timeoutMs: number,
  maxBytes: number | undefined,
  proxyUrl: string
): Promise<RawHop | null> {
  let host = "";
  try {
    host = new URL(url).hostname;
  } catch {
    /* URL errors surface via the direct hops */
  }
  if (host) await markDomainProxyNeeded(host).catch(() => {});
  let impersonate: typeof import("@webcrawl/curl-impersonate");
  try {
    impersonate = await import("@webcrawl/curl-impersonate");
  } catch {
    return null;
  }
  // Same identity-header hygiene as the direct impersonate hop: the profile's
  // UA/sec-ch headers must survive or the UA/TLS mismatch is what DataDome
  // blocks even from a clean IP.
  const extra: Record<string, string> = {};
  for (const [key, value] of Object.entries(reqHeaders)) {
    const lower = key.toLowerCase();
    if (
      lower === "user-agent" ||
      lower.startsWith("sec-ch-ua") ||
      lower.startsWith("sec-fetch-") ||
      lower === "upgrade-insecure-requests" ||
      lower === "priority"
    ) {
      continue;
    }
    extra[key] = value;
  }
  try {
    const res = await impersonate.impersonateFetch(url, {
      headers: extra,
      timeoutMs,
      maxBytes: maxBytes ?? 2 * 1024 * 1024,
      proxy: proxyUrl,
    });
    lastProxyBytes += res.bytes;
    const headers = res.headers;
    const isRedirect = res.status >= 300 && res.status < 400 && !!headers["location"];
    if (!isRedirect && maxBytes !== undefined) checkDeclaredLength(headers, maxBytes);
    return {
      status: res.status,
      headers,
      body: isRedirect ? new ArrayBuffer(0) : (res.body.buffer as ArrayBuffer),
    };
  } catch (err) {
    if (err instanceof UnsafeUrlError) throw err;
    return null; // proxy tier unavailable or fetch failed — caller escalates
  }
}

/**
 * Fetches a URL using `impit` (BoringSSL Chrome 136 TLS JA3/JA4 + HTTP/2 fingerprint impersonation)sonation)
 * so Cloudflare Bot Management and Vercel Security Checkpoint treat requests as real Chrome.
 * Falls back to standard `fetch` if `impit` is unavailable on the current platform.
 * Every redirect hop is checked against the SSRF guard.
 */
export async function fetchWithTlsImpersonation(
  url: string,
  timeoutMs = 12_000
): Promise<{ status: number; html: string; headers: Record<string, string> }> {
  // Session hydration: when a warm stealth session exists for this domain, its
  // solved cookies (and the UA they were solved under — bound cookies require
  // the pair) ride the request so the lightweight tier can skip the challenge.
  let hostname = "";
  try {
    hostname = new URL(url).hostname;
  } catch {
    /* invalid URL handled below */
  }
  if (hostname) {
    try {
      const { getWarmSession } = await import("./session.js");
      const warm = await getWarmSession(hostname);
      if (warm) {
        if (warm.cookieHeader) setDomainCookie(hostname, warm.cookieHeader);
        if (warm.userAgent) setDomainUserAgent(hostname, warm.userAgent);
      }
    } catch {
      /* session module unavailable — plain fetch */
    }
  }
  const { res, finalUrl } = await followSafely(url, (hop) =>
    rawGet(hop, getBrowserHeaders(hop), timeoutMs)
  );
  if (res.headers["set-cookie"]) {
    try {
      setDomainCookie(new URL(finalUrl).hostname, res.headers["set-cookie"].split(";")[0]);
    } catch {
      // ignore
    }
  }
  return {
    status: res.status,
    html: new TextDecoder().decode(res.body),
    headers: res.headers,
  };
}

export interface FetchedResource {
  status: number;
  headers: Record<string, string>;
  /** Declared content type without parameters, lower-cased ("" when missing). */
  contentType: string;
  body: Uint8Array;
  /** Final URL after redirects when the transport reports it. */
  url: string;
}

export class ResourceTooLargeError extends Error {
  constructor(public readonly bytes: number, public readonly maxBytes: number) {
    super(`File is ${(bytes / 1e6).toFixed(1)} MB; the limit is ${(maxBytes / 1e6).toFixed(0)} MB`);
    this.name = "ResourceTooLargeError";
  }
}

/** Largest download accepted for any file (the per-type caps in src/parse/limits.ts are tighter). */
export const MAX_RESOURCE_BYTES = 100 * 1024 * 1024;

function headersToObject(headers: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  const h = headers as { forEach?: (cb: (v: string, k: string) => void) => void };
  if (h && typeof h.forEach === "function") {
    h.forEach((v, k) => {
      out[String(k).toLowerCase()] = String(v);
    });
  }
  return out;
}

function checkDeclaredLength(headers: Record<string, string>, maxBytes: number): void {
  const declared = Number(headers["content-length"]);
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new ResourceTooLargeError(declared, maxBytes);
  }
}

/**
 * Binary-safe GET. Same TLS impersonation as `fetchWithTlsImpersonation`, but keeps
 * the body as bytes so PDFs, Office files, images and media survive intact.
 */
export async function fetchResource(
  url: string,
  options: { timeoutMs?: number; maxBytes?: number } = {}
): Promise<FetchedResource> {
  const timeoutMs = options.timeoutMs ?? 30_000;
  const maxBytes = options.maxBytes ?? MAX_RESOURCE_BYTES;
  const { res, finalUrl } = await followSafely(url, (hop) =>
    rawGet(hop, { ...getBrowserHeaders(hop), Accept: "*/*" }, timeoutMs, maxBytes)
  );
  if (res.body.byteLength > maxBytes) throw new ResourceTooLargeError(res.body.byteLength, maxBytes);
  return {
    status: res.status,
    headers: res.headers,
    contentType: (res.headers["content-type"] || "").split(";")[0].trim().toLowerCase(),
    body: new Uint8Array(res.body),
    url: finalUrl,
  };
}

/**
 * Detects whether an HTML response is an empty SPA shell or a Cloudflare/WAF challenge page
 * that requires headless browser / Vercel Sandbox escalation.
 */
export function needsBrowserEscalation(
  status: number,
  html: string,
  markdown: string
): boolean {
  if (isAntiBotChallenge(html, status)) {
    return true;
  }
  const text = markdown.trim();
  const lower = html.slice(0, 8000).toLowerCase();
  // Empty or near-empty body: nothing to return until a renderer hydrates it.
  if (text.length === 0) {
    return true;
  }
  // Empty SPA shell check (<div id="root"></div> or <div id="app"></div> with almost no text)
  if (
    text.length < 200 &&
    (lower.includes('id="root"') ||
      lower.includes('id="app"') ||
      lower.includes('id="__next"') ||
      lower.includes('id="__nuxt"'))
  ) {
    return true;
  }
  // Header-only JS pages (quotes.toscrape.com/js): real content lives in a
  // <script> as JSON + document.write / innerHTML, so markdown is just the chrome.
  if (
    text.length < 200 &&
    /<script[\s>]/i.test(html) &&
    /document\.write|innerHTML\s*=/i.test(html)
  ) {
    return true;
  }
  // Big-HTML/no-content SPA shell: a very large page (JS bundles / inline
  // state, e.g. StubHub category pages ~3MB) that yields almost no
  // extractable text is serving its real content client-side.
  if (html.length > 250_000 && text.length < 500) {
    return true;
  }
  return false;
}
