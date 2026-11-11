/**
 * Remote CDP browser providers for stealth fetches.
 *
 * A remote provider hosts the browser and hands back a CDP URL. Our step runner
 * (sandbox or local Node) connects to it over CDP, so STEP_SCRIPT runs unchanged.
 *
 * WEBCRAWL_STEALTH_PROVIDER picks one:
 * - browser-use: BROWSER_USE_API_KEY. Custom Chromium + residential proxy ($5/GB).
 * - cloudflare:  CLOUDFLARE_ACCOUNT_ID + CLOUDFLARE_BROWSER_TOKEN (Browser Rendering - Edit).
 *                Cloudflare Browser Run, $0.09 per browser hour, Cloudflare egress IPs.
 * Only the stealth path (stealthFetch) uses it; /v1/interact keeps the sandbox.
 */

export type RemoteProvider = "browser-use" | "cloudflare";

export interface RemoteSession {
  provider: RemoteProvider;
  sessionId: string;
  cdpUrl: string;
  /** Headers the CDP websocket needs (Cloudflare wants the bearer token on connect). */
  cdpHeaders?: Record<string, string>;
  startedAt: number;
}

export interface RemoteSessionCost {
  /** Provider charge for the session in USD (browser time + proxy traffic). */
  costUsd: number;
  proxyMb: number;
}

/** Cloudflare Browser Run: $0.09 per browser hour past the included hours. */
export const CLOUDFLARE_BROWSER_HOUR_USD = 0.09;

const BROWSER_USE_API = () => (process.env.BROWSER_USE_API_URL || "https://api.browser-use.com/api/v4").replace(/\/+$/, "");

function cloudflareCreds(): { accountId: string; token: string } | null {
  const accountId = (process.env.CLOUDFLARE_ACCOUNT_ID || "").trim();
  const token = (process.env.CLOUDFLARE_BROWSER_TOKEN || process.env.CLOUDFLARE_API_TOKEN || "").trim();
  return accountId && token ? { accountId, token } : null;
}

const CF_API = (accountId: string) =>
  `${(process.env.CLOUDFLARE_API_URL || "https://api.cloudflare.com/client/v4").replace(/\/+$/, "")}/accounts/${encodeURIComponent(accountId)}/browser-run`;

/** The configured remote provider, or null when stealth runs on our own browser. */
export function remoteStealthProvider(): RemoteProvider | null {
  const name = (process.env.WEBCRAWL_STEALTH_PROVIDER || "").trim().toLowerCase();
  if (name === "browser-use" && process.env.BROWSER_USE_API_KEY) return "browser-use";
  if (name === "cloudflare" && cloudflareCreds()) return "cloudflare";
  return null;
}

function browserUseHeaders(): Record<string, string> {
  return { "X-Browser-Use-API-Key": process.env.BROWSER_USE_API_KEY || "", "Content-Type": "application/json" };
}

function num(v: unknown): number {
  const n = typeof v === "number" ? v : Number.parseFloat(String(v ?? "0"));
  return Number.isFinite(n) ? n : 0;
}

function errorDetail(body: unknown): string {
  const b = (body ?? {}) as { detail?: unknown; errors?: { message?: string }[] };
  if (typeof b.detail === "string") return b.detail;
  if (Array.isArray(b.errors) && b.errors[0]?.message) return String(b.errors[0].message);
  return b.detail ? JSON.stringify(b.detail).slice(0, 200) : "";
}

/** Starts a remote browser. `timeoutMs` caps how long the provider keeps it (and bills it) if we never stop it. */
export async function startRemoteSession(
  opts: { provider?: RemoteProvider; timeoutMs: number; fetchImpl?: typeof fetch } = { timeoutMs: 5 * 60_000 }
): Promise<RemoteSession> {
  const provider = opts.provider ?? "browser-use";
  return provider === "cloudflare" ? startCloudflareSession(opts) : startBrowserUseSession(opts);
}

async function startBrowserUseSession(opts: { timeoutMs: number; fetchImpl?: typeof fetch }): Promise<RemoteSession> {
  const f = opts.fetchImpl ?? fetch;
  const country = (process.env.BROWSER_USE_PROXY_COUNTRY || "us").trim().toLowerCase();
  const res = await f(`${BROWSER_USE_API()}/browsers`, {
    method: "POST",
    headers: browserUseHeaders(),
    body: JSON.stringify({
      timeout: Math.max(1, Math.min(240, Math.ceil(opts.timeoutMs / 60_000))),
      // "none" turns the residential proxy off (cheaper, weaker against IP reputation checks).
      proxyCountryCode: country === "none" ? null : country,
      solveCaptchas: process.env.BROWSER_USE_SOLVE_CAPTCHAS !== "false",
      metadata: { app: "webcrawl" },
    }),
    signal: AbortSignal.timeout(30_000),
  });
  const body = (await res.json().catch(() => ({}))) as { id?: string; cdpUrl?: string | null };
  if (!res.ok || !body.id || !body.cdpUrl) {
    const detail = errorDetail(body);
    throw new Error(`Browser Use session failed (HTTP ${res.status})${detail ? `: ${detail}` : ""}`);
  }
  return { provider: "browser-use", sessionId: body.id, cdpUrl: body.cdpUrl, startedAt: Date.now() };
}

async function startCloudflareSession(opts: { timeoutMs: number; fetchImpl?: typeof fetch }): Promise<RemoteSession> {
  const creds = cloudflareCreds();
  if (!creds) throw new Error("Cloudflare Browser Run is not configured");
  const f = opts.fetchImpl ?? fetch;
  // keep_alive is how long the session idles before Cloudflare closes it: 10s..20min.
  const keepAlive = Math.max(10_000, Math.min(1_200_000, opts.timeoutMs));
  const res = await f(`${CF_API(creds.accountId)}/devtools/browser?keep_alive=${keepAlive}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${creds.token}` },
    signal: AbortSignal.timeout(30_000),
  });
  const raw = (await res.json().catch(() => ({}))) as {
    sessionId?: string;
    webSocketDebuggerUrl?: string;
    result?: { sessionId?: string; webSocketDebuggerUrl?: string };
  };
  const body = raw.result ?? raw;
  if (!res.ok || !body.sessionId) {
    const detail = errorDetail(raw);
    throw new Error(`Cloudflare Browser Run session failed (HTTP ${res.status})${detail ? `: ${detail}` : ""}`);
  }
  return {
    provider: "cloudflare",
    sessionId: body.sessionId,
    cdpUrl:
      body.webSocketDebuggerUrl ||
      `${CF_API(creds.accountId).replace(/^http/, "ws")}/devtools/browser/${encodeURIComponent(body.sessionId)}`,
    cdpHeaders: { Authorization: `Bearer ${creds.token}` },
    startedAt: Date.now(),
  };
}

/** Stops the session (unused time is refunded) and returns what it cost. Never throws. */
export async function stopRemoteSession(
  session: Pick<RemoteSession, "sessionId"> & Partial<Pick<RemoteSession, "provider" | "startedAt">>,
  opts: { fetchImpl?: typeof fetch; now?: number } = {}
): Promise<RemoteSessionCost | null> {
  const f = opts.fetchImpl ?? fetch;
  if (session.provider === "cloudflare") {
    const creds = cloudflareCreds();
    if (creds) {
      await f(`${CF_API(creds.accountId)}/devtools/browser/${encodeURIComponent(session.sessionId)}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${creds.token}` },
        signal: AbortSignal.timeout(20_000),
      }).catch(() => null);
    }
    // Cloudflare does not report per-session cost; bill browser time (rounded up to a minute).
    if (!session.startedAt) return null;
    const minutes = Math.max(1, Math.ceil(((opts.now ?? Date.now()) - session.startedAt) / 60_000));
    return { costUsd: (minutes / 60) * CLOUDFLARE_BROWSER_HOUR_USD, proxyMb: 0 };
  }
  try {
    const res = await f(`${BROWSER_USE_API()}/browsers/${encodeURIComponent(session.sessionId)}`, {
      method: "PATCH",
      headers: browserUseHeaders(),
      body: JSON.stringify({ action: "stop" }),
      signal: AbortSignal.timeout(20_000),
    });
    if (!res.ok) return null;
    const body = (await res.json().catch(() => ({}))) as { proxyCost?: unknown; browserCost?: unknown; proxyUsedMb?: unknown };
    return { costUsd: num(body.proxyCost) + num(body.browserCost), proxyMb: num(body.proxyUsedMb) };
  } catch {
    return null;
  }
}
