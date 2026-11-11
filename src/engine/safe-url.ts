import { isIP } from "node:net";
import { lookup } from "node:dns/promises";

export class UnsafeUrlError extends Error {
  constructor(message = "That address isn't publicly reachable") {
    super(message);
    this.name = "UnsafeUrlError";
  }
}

export function isPrivateAddress(ip: string): boolean {
  const v = isIP(ip);
  if (v === 4) {
    const [a, b] = ip.split(".").map(Number);
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 198 && (b === 18 || b === 19)) ||
      a >= 224
    );
  }
  if (v === 6) {
    const s = ip.toLowerCase();
    if (s.startsWith("::ffff:")) return isPrivateAddress(s.slice(7));
    return (
      s === "::" ||
      s === "::1" ||
      s.startsWith("fc") ||
      s.startsWith("fd") ||
      s.startsWith("fe8") ||
      s.startsWith("fe9") ||
      s.startsWith("fea") ||
      s.startsWith("feb")
    );
  }
  return true;
}

/**
 * True for 198.18.0.0/15, the benchmarking range that fake-IP proxies
 * (Clash, Surge, sing-box, some VPN clients) hand out for every hostname.
 */
export function isFakeIpAddress(ip: string): boolean {
  const s = ip.toLowerCase().replace(/^::ffff:/, "");
  if (isIP(s) !== 4) return false;
  const [a, b] = s.split(".").map(Number);
  return a === 198 && (b === 18 || b === 19);
}

export const FAKE_IP_HINT =
  "That address isn't publicly reachable: it resolved to 198.18.x.x, which fake-IP proxies " +
  "(Clash, Surge, sing-box, some VPNs) return for every site. Switch the proxy to redir-host/real-IP " +
  "DNS mode, or set WEBCRAWL_ALLOW_PRIVATE_URLS=true for local runs you trust.";

export type HostResolver = (host: string) => Promise<string[]>;

const defaultResolve: HostResolver = async (h) =>
  (await lookup(h, { all: true })).map((r) => r.address);

/** Local development escape hatch (never set in production). */
function allowPrivate(): boolean {
  return process.env.WEBCRAWL_ALLOW_PRIVATE_URLS === "true";
}

/**
 * Throws `UnsafeUrlError` unless `raw` is an http(s) URL whose host resolves
 * only to public addresses. Call it before every request and every redirect hop.
 */
export async function assertSafeUrl(
  raw: string,
  resolve: HostResolver = defaultResolve
): Promise<URL> {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new UnsafeUrlError("Invalid URL");
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new UnsafeUrlError("Only http and https addresses are supported");
  }
  if (allowPrivate()) return u;
  const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal")
  ) {
    throw new UnsafeUrlError();
  }
  const addrs = isIP(host) ? [host] : await resolve(host).catch(() => []);
  if (addrs.length === 0) throw new UnsafeUrlError("We couldn't find that website");
  if (addrs.some(isPrivateAddress)) {
    // Every address in the fake-IP range means a local proxy rewrote DNS,
    // not that the site is internal: say so and name the workaround.
    throw new UnsafeUrlError(addrs.every(isFakeIpAddress) ? FAKE_IP_HINT : undefined);
  }
  return u;
}

export const MAX_REDIRECTS = 8;

export interface HopResponse {
  status: number;
  headers: Record<string, string>;
}

/**
 * Runs `send` for `url` and follows redirects manually, validating every hop
 * with `assertSafeUrl`. `send` must NOT follow redirects itself.
 */
export async function followSafely<T extends HopResponse>(
  url: string,
  send: (hopUrl: string) => Promise<T>,
  resolve?: HostResolver
): Promise<{ res: T; finalUrl: string }> {
  let current = url;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    await assertSafeUrl(current, resolve);
    const res = await send(current);
    const loc = res.headers["location"];
    if (res.status >= 300 && res.status < 400 && loc) {
      current = new URL(loc, current).toString();
      continue;
    }
    return { res, finalUrl: current };
  }
  throw new UnsafeUrlError("Too many redirects");
}
