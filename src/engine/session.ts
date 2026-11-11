/**
 * Stealth session reuse: warm-sandbox registry, cookie-replay state and the
 * JS-challenge memo.
 *
 * A solved bot check (AWS WAF, Cloudflare, Vercel checkpoint) leaves behind a
 * valuable session: the sandbox's egress IP, its User-Agent and the cleared
 * cookies. Instead of throwing that away with the sandbox, this module keeps:
 *   - a warm registry (domain -> sandboxId + UA + cookies) so the next query
 *     reconnects to the still-running sandbox (`Sandbox.get`) instead of
 *     cold-booting and re-solving;
 *   - the cookie header for replay on the lightweight TLS-impersonated tier
 *     (works only where the provider does not bind tokens to the solver IP —
 *     Cloudflare's `cf_clearance` does; AWS WAF's 300 s immunity may not);
 *   - a memo of domains known to serve JS challenges, so the useless
 *     curl-sandbox tier is skipped for them.
 *
 * Everything is in-memory by default; `registerExternalSessionStore` plugs in
 * persistence (Postgres in the hosted app) so warm sessions survive across
 * serverless instances. A registered store is always optional: every call
 * degrades gracefully when it is unavailable.
 */

/** A solved stealth session kept for reuse. */
export interface WarmSession {
  domain: string;
  sandboxId: string;
  userAgent: string;
  /** `Cookie:` header value for the solved session (UA-paired: replay both or neither). */
  cookieHeader: string;
  /** Epoch ms after which the entry is stale. */
  expiresAt: number;
}

export interface ExternalSessionStore {
  getWarmSession(domain: string): Promise<WarmSession | null>;
  saveWarmSession(session: WarmSession): Promise<void>;
  deleteWarmSession(domain: string): Promise<void>;
  markDomainChallenged(domain: string): Promise<void>;
  isDomainChallenged(domain: string): Promise<boolean>;
  /** Optional persistence for the residential-proxy memo (Tier P1). */
  markDomainProxyNeeded?(domain: string): Promise<void>;
  isDomainProxyNeeded?(domain: string): Promise<boolean>;
  /** Optional persistence for the render-provider memo (Tier R). */
  markDomainRenderNeeded?(domain: string): Promise<void>;
  isDomainRenderNeeded?(domain: string): Promise<boolean>;
}

/** How long a solved session is offered for warm reconnect / cookie replay. */
export const WARM_TTL_MS = 8 * 60_000;
/** VM `timeout` headroom set at Sandbox.create so a warm sandbox outlives its registry TTL. */
export const WARM_SANDBOX_TIMEOUT_MS = 10 * 60_000;
/** Cap on concurrently warm sandboxes; LRU entries beyond the cap are evicted. */
export const WARM_CAP = 4;
/** How long a domain stays on the JS-challenge memo. */
export const CHALLENGE_MEMO_TTL_MS = 30 * 60_000;
/** How long a domain stays on the residential-proxy memo (Tier P1). */
export const PROXY_MEMO_TTL_MS = 60 * 60_000;
/** How long a domain stays on the render-provider memo (Tier R). */
export const RENDER_MEMO_TTL_MS = 12 * 60 * 60_000;

let external: ExternalSessionStore | null = null;

export function registerExternalSessionStore(store: ExternalSessionStore): void {
  external = store;
}

const warm = new Map<string, WarmSession>();
const challenged = new Map<string, number>();
const proxyNeeded = new Map<string, number>();
const renderNeeded = new Map<string, number>();

function reap(now = Date.now()): void {
  for (const [d, s] of warm) if (s.expiresAt <= now) warm.delete(d);
  for (const [d, t] of challenged) if (t <= now) challenged.delete(d);
  for (const [d, t] of proxyNeeded) if (t <= now) proxyNeeded.delete(d);
  for (const [d, t] of renderNeeded) if (t <= now) renderNeeded.delete(d);
}

export interface CookieLike {
  name: string;
  value: string;
  domain?: string;
  path?: string;
  expires?: number;
}

/** Serializes captured browser cookies into a `Cookie:` header value (drops expired). */
export function cookieHeaderFrom(cookies: CookieLike[]): string {
  const now = Date.now() / 1000;
  return cookies
    .filter((c) => c.name && c.value && (!c.expires || c.expires > now))
    .map((c) => `${c.name}=${c.value}`)
    .join("; ");
}

/** Best-available warm session for a domain (in-memory first, then the external store). */
export async function getWarmSession(domain: string): Promise<WarmSession | null> {
  if (!domain) return null;
  reap();
  const local = warm.get(domain);
  if (local && local.expiresAt > Date.now()) return local;
  if (local) warm.delete(domain);
  if (external) {
    try {
      const stored = await external.getWarmSession(domain);
      if (stored && stored.expiresAt > Date.now()) {
        warm.set(domain, stored);
        return stored;
      }
    } catch {
      /* store unavailable */
    }
  }
  return null;
}

/**
 * Registers a solved session as warm. Returns the sandboxIds evicted by the
 * cap — the caller must stop those sandboxes so idle compute does not linger.
 */
export async function saveWarmSession(session: WarmSession): Promise<string[]> {
  if (!session.domain) return [];
  reap();
  warm.delete(session.domain);
  warm.set(session.domain, { ...session });
  const evicted: string[] = [];
  while (warm.size > WARM_CAP) {
    const [d, s] = warm.entries().next().value as [string, WarmSession];
    warm.delete(d);
    if (s.sandboxId && s.sandboxId !== session.sandboxId) evicted.push(s.sandboxId);
  }
  if (external) {
    try {
      await external.saveWarmSession(session);
    } catch {
      /* store unavailable */
    }
  }
  return evicted;
}

export async function deleteWarmSession(domain: string): Promise<void> {
  if (!domain) return;
  warm.delete(domain);
  if (external) {
    try {
      await external.deleteWarmSession(domain);
    } catch {
      /* store unavailable */
    }
  }
}

/** Marks a domain as known to serve JS challenges (skips the curl tier next time). */
export async function markDomainChallenged(domain: string): Promise<void> {
  if (!domain) return;
  challenged.set(domain, Date.now() + CHALLENGE_MEMO_TTL_MS);
  if (external) {
    try {
      await external.markDomainChallenged(domain);
    } catch {
      /* store unavailable */
    }
  }
}

export async function isDomainChallenged(domain: string): Promise<boolean> {
  if (!domain) return false;
  reap();
  const until = challenged.get(domain);
  if (until && until > Date.now()) return true;
  if (until) challenged.delete(domain);
  if (external) {
    try {
      if (await external.isDomainChallenged(domain)) {
        challenged.set(domain, Date.now() + CHALLENGE_MEMO_TTL_MS);
        return true;
      }
    } catch {
      /* store unavailable */
    }
  }
  return false;
}

/**
 * Marks a domain as needing the residential-proxy tier (Tier P1): every
 * datacenter egress attempt is blocked by IP reputation (DataDome et al), so
 * future ladder runs skip straight to the proxy hop.
 */
export async function markDomainProxyNeeded(domain: string): Promise<void> {
  if (!domain) return;
  proxyNeeded.set(domain, Date.now() + PROXY_MEMO_TTL_MS);
  if (external?.markDomainProxyNeeded) {
    try {
      await external.markDomainProxyNeeded(domain);
    } catch {
      /* store unavailable */
    }
  }
}

export async function isDomainProxyNeeded(domain: string): Promise<boolean> {
  if (!domain) return false;
  reap();
  const until = proxyNeeded.get(domain);
  if (until && until > Date.now()) return true;
  if (until) proxyNeeded.delete(domain);
  if (external?.isDomainProxyNeeded) {
    try {
      if (await external.isDomainProxyNeeded(domain)) {
        proxyNeeded.set(domain, Date.now() + PROXY_MEMO_TTL_MS);
        return true;
      }
    } catch {
      /* store unavailable */
    }
  }
  return false;
}

/**
 * Marks a domain as needing the render-provider tier (Tier R): the native
 * fetch ladder passes the bot check but the page's content only appears after
 * JS renders, so future runs skip the ladder and go provider-first.
 */
export async function markDomainRenderNeeded(domain: string): Promise<void> {
  if (!domain) return;
  renderNeeded.set(domain, Date.now() + RENDER_MEMO_TTL_MS);
  if (external?.markDomainRenderNeeded) {
    try {
      await external.markDomainRenderNeeded(domain);
    } catch {
      /* store unavailable */
    }
  }
}

export async function isDomainRenderNeeded(domain: string): Promise<boolean> {
  if (!domain) return false;
  reap();
  const until = renderNeeded.get(domain);
  if (until && until > Date.now()) return true;
  if (until) renderNeeded.delete(domain);
  if (external?.isDomainRenderNeeded) {
    try {
      if (await external.isDomainRenderNeeded(domain)) {
        renderNeeded.set(domain, Date.now() + RENDER_MEMO_TTL_MS);
        return true;
      }
    } catch {
      /* store unavailable */
    }
  }
  return false;
}

/** Test helper: resets all in-memory state (external stores are untouched). */
export function resetSessionStateForTests(): void {
  warm.clear();
  challenged.clear();
  proxyNeeded.clear();
  renderNeeded.clear();
}
