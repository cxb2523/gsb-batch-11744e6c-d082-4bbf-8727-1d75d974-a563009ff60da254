/**
 * Fetch-chain audit: a pure, offline reconstruction of what the fetcher ladder
 * (`fetcher.ts`), SSRF guard (`safe-url.ts`) and politeness layer
 * (`crawl-policy.ts`) would do for one URL, given an injected data snapshot.
 *
 * The audit performs no network I/O and no disk I/O: DNS answers come from the
 * injected `dns` map, tier attempts from the injected `tierAttempts` array,
 * redirects from `redirects`, robots from `robotsText`. Where exact behavior
 * matters, the real `assertSafeUrl` / `followSafely` / `parseRobots` /
 * `withRetries` functions are driven with injected adapters (never network
 * access) so the audit's verdicts match source behavior by construction.
 */
import { isIP } from "node:net";
import {
  assertSafeUrl,
  FAKE_IP_HINT,
  followSafely,
  isFakeIpAddress,
  isPrivateAddress,
  MAX_REDIRECTS,
  UnsafeUrlError,
} from "./safe-url.js";
import {
  isRetryableStatus,
  parseRobots,
  withRetries,
} from "./crawl-policy.js";

/** Tier names in the exact ladder order implemented by `rawGet` in fetcher.ts. */
export const TIER_ORDER = [
  "impit-tls",
  "impersonate",
  "proxy-impersonate",
  "fetch",
] as const;

export type AuditTierName = (typeof TIER_ORDER)[number];

/** Rejection category, mirroring the branches inside `assertSafeUrl`. */
export type UrlRejectReason =
  | "invalid-url"
  | "non-http-scheme"
  | "local-hostname"
  | "resolution-failed"
  | "private-address"
  | "fake-ip"
  | "unknown";

/** One recorded attempt at one tier of the fetch ladder. */
export interface TierAttemptRecord {
  tier: AuditTierName | string;
  /** HTTP status when a response was received. */
  status?: number | null;
  /** Whether `isAntiBotChallenge` flagged the response as a block. */
  blocked?: boolean;
  /** Whether the attempt threw instead of returning a response. */
  errored?: boolean;
  /** `error.name` of the thrown error (e.g. "UnsafeUrlError"). */
  errorName?: string | null;
  /** Bytes transferred through the residential proxy on this attempt. */
  proxyBytes?: number | null;
}

/** One observed redirect response in the redirect chain. */
export interface RedirectHopRecord {
  status: number;
  location?: string | null;
}

/** One observed invocation inside a `withRetries` run. */
export interface RetryAttemptRecord {
  status?: number | null;
  errored?: boolean;
  errorName?: string | null;
}

export interface FetchAuditSnapshot {
  url: string;
  /** Hostname -> resolved address list (the injected, offline DNS view). */
  dns?: Record<string, string[]>;
  /** Tier attempts in the order the ladder actually tried them. */
  tierAttempts?: TierAttemptRecord[];
  /** Whether a residential proxy was configured (proxy tier enabled). */
  proxyConfigured?: boolean;
  robotsText?: string | null;
  retry?: {
    attempts: RetryAttemptRecord[];
    /** `withRetries` `retries` option (default 2, matching the source). */
    retries?: number;
  } | null;
  redirects?: RedirectHopRecord[] | null;
}

export interface AuditCheck {
  name: string;
  passed: boolean;
  reason: string | null;
}

export interface UrlSafetyAudit {
  allowed: boolean;
  rejectReason: UrlRejectReason | null;
  /** Readable explanation; for fake-IP this is the exact source hint text. */
  message: string | null;
  resolvedAddresses: string[];
  /** Set when the mirror classification disagrees with `assertSafeUrl`. */
  degraded: boolean;
  degradedFields: string[];
}

export interface TierLadderAudit {
  /** Tier that the ladder would return, or null when no tier produced a hop. */
  winner: AuditTierName | string | null;
  /** Every tier available in this configuration was tried. */
  exhaustedAllTiers: boolean;
  /** Canonical order this configuration allows. */
  configuredOrder: string[];
  attemptedTiers: string[];
  proxyBytesTotal: number;
  degraded: boolean;
  degradedFields: string[];
}

export interface RedirectAudit {
  /** Number of followed redirect responses (3xx with a location header). */
  hopCount: number;
  overLimit: boolean;
  /** Index (into the redirects array) of the first hop that failed SSRF validation, if any. */
  rejectedHopIndex: number | null;
  rejectedUrl: string | null;
  rejectedReason: string | null;
  /** False when the conclusion does not match the real `followSafely`. */
  consistentWithFollowSafely: boolean;
  invalidLocationIndex: number | null;
  degraded: boolean;
  degradedFields: string[];
}

export interface RobotsAudit {
  allowed: boolean;
  crawlDelayMs: number;
  robotsPresent: boolean;
  degraded: boolean;
  degradedFields: string[];
}

export interface RetryAudit {
  observedAttempts: number;
  expectedAttempts: number;
  retried: boolean;
  consistentWithWithRetries: boolean;
  degraded: boolean;
  degradedFields: string[];
}

export interface FetchAuditReport {
  url: string;
  urlSafety: UrlSafetyAudit;
  tierLadder: TierLadderAudit;
  redirects: RedirectAudit;
  robots: RobotsAudit;
  retry: RetryAudit | null;
  checks: AuditCheck[];
  /** True when any section had to fall back to a degraded result. */
  degraded: boolean;
  degradedFields: string[];
}

/** Builds the offline resolver backed by the injected DNS snapshot. */
function snapshotResolver(dns: Record<string, string[]> | undefined): (host: string) => Promise<string[]> {
  return async (host: string) => {
    const addrs = dns?.[host];
    return Array.isArray(addrs) ? [...addrs] : [];
  };
}

/**
 * Mirror of the `assertSafeUrl` branch order, used to label the rejection
 * category. `assertSafeUrl` itself is still run (with the injected resolver)
 * and its throw/no-throw outcome is the authoritative allow/deny verdict.
 */
function classifyRejection(
  raw: string,
  addresses: string[]
): { reason: UrlRejectReason; message: string } {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return { reason: "invalid-url", message: "Invalid URL" };
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return { reason: "non-http-scheme", message: "Only http and https addresses are supported" };
  }
  const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal")
  ) {
    return {
      reason: "local-hostname",
      message: new UnsafeUrlError().message,
    };
  }
  if (addresses.length === 0) {
    return { reason: "resolution-failed", message: "We couldn't find that website" };
  }
  // Every address in the fake-IP range means a local proxy rewrote DNS, not
  // that the site is internal: the message must say so (same as safe-url.ts).
  if (addresses.every(isFakeIpAddress)) {
    return { reason: "fake-ip", message: FAKE_IP_HINT };
  }
  return {
    reason: "private-address",
    message: new UnsafeUrlError().message,
  };
}

async function auditUrlSafety(
  raw: string,
  dns: Record<string, string[]> | undefined
): Promise<UrlSafetyAudit> {
  const degradedFields: string[] = [];
  const resolve = snapshotResolver(dns);

  // Addresses the injected resolver would hand out for this host (IP literals
  // are validated directly by assertSafeUrl and never invoke the resolver).
  let resolvedAddresses: string[] = [];
  let parseable = false;
  let parsedHost = "";
  try {
    const u = new URL(raw);
    parseable = true;
    parsedHost = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  } catch {
    /* invalid-url branch below */
  }
  if (parseable) {
    // Replicate the source's IP-literal shortcut vs. resolver lookup.
    resolvedAddresses = isIP(parsedHost) ? [parsedHost] : (dns?.[parsedHost] ?? []);
  }

  // Authoritative verdict: drive the real guard with the offline resolver.
  let allowed = false;
  let thrownMessage: string | null = null;
  try {
    await assertSafeUrl(raw, resolve);
    allowed = true;
  } catch (err) {
    thrownMessage = err instanceof Error ? err.message : String(err);
  }

  if (allowed) {
    return {
      allowed: true,
      rejectReason: null,
      message: null,
      resolvedAddresses,
      degraded: false,
      degradedFields,
    };
  }

  const classified = classifyRejection(raw, resolvedAddresses);
  // The real thrown message is the authoritative wording; the mirror only
  // supplies the category label. For fake-IP they must be identical anyway.
  const message = thrownMessage ?? classified.message;
  if (
    classified.reason === "fake-ip" &&
    thrownMessage !== null &&
    !thrownMessage.includes("fake-IP")
  ) {
    degradedFields.push("urlSafety.message");
  }
  return {
    allowed: false,
    rejectReason: classified.reason,
    message,
    resolvedAddresses,
    degraded: degradedFields.length > 0,
    degradedFields,
  };
}

function auditTierLadder(
  attemptsInput: TierAttemptRecord[] | undefined,
  proxyConfigured: boolean,
  urlAllowed: boolean
): TierLadderAudit {
  const degradedFields: string[] = [];
  const configuredOrder: string[] = proxyConfigured
    ? [...TIER_ORDER]
    : TIER_ORDER.filter((t) => t !== "proxy-impersonate");
  const attempts = Array.isArray(attemptsInput) ? attemptsInput : [];
  const attemptedTiers = attempts.map((a) => String(a?.tier));

  if (!Array.isArray(attemptsInput)) {
    degradedFields.push("tierAttempts");
  }

  let winner: string | null = null;
  attempts.forEach((a) => {
    if (!a?.errored) {
      winner = String(a.tier);
    }
  });

  // A proxy winner must never appear when the proxy tier is not configured.
  if (winner === "proxy-impersonate" && !proxyConfigured) {
    degradedFields.push("tierLadder.winner");
    winner = null;
  }
  if (attemptedTiers.includes("proxy-impersonate") && !proxyConfigured) {
    degradedFields.push("tierLadder.attemptedTiers");
  }

  // Order check: observed tiers must follow the canonical ladder order.
  const orderOk = attemptedTiers.every((t, i) => {
    const idx = configuredOrder.indexOf(t);
    if (idx < 0) return false;
    if (i === 0) return true;
    return idx > configuredOrder.indexOf(attemptedTiers[i - 1]);
  });
  if (!orderOk) degradedFields.push("tierLadder.attemptedTiers");

  // Escalation check: a non-blocked, non-error response ends the ladder, so no
  // later attempt may exist after it.
  attempts.forEach((a, i) => {
    if (!a?.errored && !a.blocked && i < attempts.length - 1) {
      degradedFields.push("tierLadder.attemptedTiers");
    }
  });

  // When the URL is rejected, the guard runs before any tier: no attempts and
  // no winner are legitimate.
  if (!urlAllowed && attempts.length > 0) {
    degradedFields.push("tierLadder.attemptedTiers");
  }

  const exhaustedAllTiers =
    attempts.length > 0 &&
    configuredOrder.every((t) => attemptedTiers.includes(t));

  let proxyBytesTotal = 0;
  for (const a of attempts) {
    const n = Number(a?.proxyBytes);
    if (Number.isFinite(n) && n > 0) proxyBytesTotal += n;
  }

  return {
    winner: attempts.length === 0 ? null : winner,
    exhaustedAllTiers,
    configuredOrder,
    attemptedTiers,
    proxyBytesTotal,
    degraded: degradedFields.length > 0,
    degradedFields,
  };
}

async function auditRedirects(
  raw: string,
  redirectsInput: RedirectHopRecord[] | null | undefined,
  dns: Record<string, string[]> | undefined,
  urlAllowed: boolean
): Promise<RedirectAudit> {
  const degradedFields: string[] = [];
  const resolve = snapshotResolver(dns);
  const empty: RedirectAudit = {
    hopCount: 0,
    overLimit: false,
    rejectedHopIndex: null,
    rejectedUrl: null,
    rejectedReason: null,
    consistentWithFollowSafely: true,
    invalidLocationIndex: null,
    degraded: false,
    degradedFields: [],
  };

  if (redirectsInput === null || redirectsInput === undefined) {
    // No redirect data supplied: not an error, nothing to audit.
    return empty;
  }
  if (!Array.isArray(redirectsInput)) {
    return { ...empty, degraded: true, degradedFields: ["redirects"] };
  }

  // Walk the chain exactly like followSafely: resolve each location against
  // the current URL, re-validate every candidate hop with the real guard.
  let current = raw;
  let hopCount = 0;
  let rejectedHopIndex: number | null = null;
  let rejectedUrl: string | null = null;
  let rejectedReason: string | null = null;
  let invalidLocationIndex: number | null = null;

  for (let i = 0; i < redirectsInput.length; i++) {
    const hop = redirectsInput[i];
    const isRedirect =
      !!hop &&
      hop.status >= 300 &&
      hop.status < 400 &&
      hop.location !== undefined &&
      hop.location !== null &&
      hop.location !== "";
    if (!isRedirect) break; // terminal response, chain ends

    let next: URL;
    try {
      next = new URL(String(hop.location), current);
    } catch {
      invalidLocationIndex = i;
      degradedFields.push(`redirects[${i}].location`);
      break;
    }
    const nextStr = next.toString();

    // Every hop is re-validated before another request is sent.
    let hopAllowed = false;
    let hopMessage: string | null = null;
    try {
      await assertSafeUrl(nextStr, resolve);
      hopAllowed = true;
    } catch (err) {
      hopMessage = err instanceof Error ? err.message : String(err);
    }
    if (!hopAllowed) {
      rejectedHopIndex = i;
      rejectedUrl = nextStr;
      rejectedReason = hopMessage;
      break;
    }

    hopCount++;
    current = nextStr;
  }

  // Authoritative cross-check: drive the real followSafely over the same
  // chain. When the initial URL is unsafe the guard throws before any send,
  // so there is nothing to compare against — skip the cross-check.
  let sourceOverLimit = false;
  let sourceRejected = false;
  let followSends = 0;
  if (urlAllowed && invalidLocationIndex === null) {
    let followThrew: Error | null = null;
    try {
      await followSafely(
        raw,
        async (): Promise<{ status: number; headers: Record<string, string> }> => {
          followSends++;
          const idx = followSends - 1;
          const hop = redirectsInput[idx];
          if (!hop || idx >= redirectsInput.length) {
            return { status: 200, headers: {} };
          }
          return {
            status: hop.status,
            headers:
              hop.location === undefined || hop.location === null
                ? {}
                : { location: String(hop.location) },
          };
        },
        resolve
      );
    } catch (err) {
      followThrew = err instanceof Error ? err : new Error(String(err));
    }
    sourceOverLimit =
      followThrew instanceof UnsafeUrlError &&
      followThrew.message === "Too many redirects";
    sourceRejected =
      followThrew instanceof UnsafeUrlError && !sourceOverLimit;
  }

  const overLimit = sourceOverLimit || hopCount > MAX_REDIRECTS;

  // The mirror must agree with the source on hop count and the limit verdict.
  let consistentWithFollowSafely = true;
  if (urlAllowed && invalidLocationIndex === null && rejectedHopIndex === null) {
    if (sourceOverLimit !== overLimit) consistentWithFollowSafely = false;
    if (!sourceOverLimit && followSends - 1 !== hopCount) {
      consistentWithFollowSafely = false;
    }
  } else if (rejectedHopIndex !== null) {
    if (!sourceRejected) consistentWithFollowSafely = false;
  }
  if (!consistentWithFollowSafely) degradedFields.push("redirects.verdict");

  // A rejected initial URL means the chain could never start.
  if (!urlAllowed && redirectsInput.length > 0) {
    degradedFields.push("redirects");
  }

  return {
    hopCount,
    overLimit,
    rejectedHopIndex,
    rejectedUrl,
    rejectedReason,
    consistentWithFollowSafely,
    invalidLocationIndex,
    degraded: degradedFields.length > 0,
    degradedFields,
  };
}

function auditRobots(
  robotsInput: string | null | undefined,
  url: string
): RobotsAudit {
  const degradedFields: string[] = [];
  let text: string | null | undefined = robotsInput;
  if (
    text !== null &&
    text !== undefined &&
    typeof text !== "string"
  ) {
    degradedFields.push("robotsText");
    text = null;
  }
  const robotsPresent = typeof text === "string" && text.length > 0;
  // parseRobots itself accepts null/undefined/"" as allow-all — never throws.
  const rules = parseRobots(text ?? null);
  return {
    allowed: rules.allows(url),
    crawlDelayMs: rules.crawlDelayMs,
    robotsPresent,
    degraded: degradedFields.length > 0,
    degradedFields,
  };
}

async function auditRetry(
  retryInput: FetchAuditSnapshot["retry"]
): Promise<RetryAudit | null> {
  if (retryInput === null || retryInput === undefined) return null;
  const degradedFields: string[] = [];
  if (
    typeof retryInput !== "object" ||
    !Array.isArray((retryInput as { attempts?: unknown }).attempts)
  ) {
    return {
      observedAttempts: 0,
      expectedAttempts: 0,
      retried: false,
      consistentWithWithRetries: false,
      degraded: true,
      degradedFields: ["retry"],
    };
  }

  const observed = retryInput.attempts as RetryAttemptRecord[];
  const retries = typeof retryInput.retries === "number" ? retryInput.retries : 2;
  const observedAttempts = observed.length;

  // Replay the same observations through the real withRetries loop.
  let playhead = 0;
  let replayAttempts = 0;
  const noWait = async () => {};

  const run = async (): Promise<{ status: number }> => {
    replayAttempts++;
    const rec = observed[playhead++];
    if (!rec) {
      // Snapshot ends before the loop would: treat as a terminal 200 so the
      // real loop's own decision logic stays in control.
      return { status: 200 };
    }
    if (rec.errored) {
      const e = new Error(rec.errorName ?? "Error");
      e.name = rec.errorName ?? "Error";
      throw e;
    }
    return { status: Number(rec.status ?? 0) };
  };

  // Drive the real withRetries (with a no-op sleep) as an authoritative
  // cross-check; its outcome count is compared against the contract below.
  try {
    await withRetries(run, { retries, sleepFn: noWait });
  } catch {
    // Throwing after exhausting retries (or on UnsafeUrlError) is a valid path.
  }

  // Independent expectation computed straight from the retry contract.
  let expectedAttempts = 0;
  for (let i = 0; i < observed.length && i <= retries; i++) {
    expectedAttempts++;
    const rec = observed[i];
    const isUnsafe = rec.errored && rec.errorName === "UnsafeUrlError";
    if (isUnsafe) break; // never retried
    if (!rec.errored && !isRetryableStatus(Number(rec.status ?? 0))) break;
    if (i === retries) break; // budget exhausted
  }

  const retried = observedAttempts > 1;
  let consistent = replayAttempts === expectedAttempts;
  if (observedAttempts !== expectedAttempts) consistent = false;
  // An UnsafeUrlError anywhere after the first attempt would mean it was retried.
  if (
    observed.some(
      (r, i) => i > 0 && r.errored && r.errorName === "UnsafeUrlError"
    )
  ) {
    consistent = false;
    degradedFields.push("retry.attempts");
  }
  // A non-retryable status (e.g. 404) must be terminal: nothing may follow it.
  observed.forEach((r, i) => {
    if (
      !r.errored &&
      !isRetryableStatus(Number(r.status ?? 0)) &&
      i < observed.length - 1
    ) {
      consistent = false;
      degradedFields.push("retry.attempts");
    }
  });
  if (!consistent && !degradedFields.includes("retry.attempts")) {
    degradedFields.push("retry.attempts");
  }

  return {
    observedAttempts,
    expectedAttempts,
    retried,
    consistentWithWithRetries: consistent,
    degraded: degradedFields.length > 0,
    degradedFields,
  };
}

function buildChecks(
  urlSafety: UrlSafetyAudit,
  ladder: TierLadderAudit | null,
  redirects: RedirectAudit | null,
  robots: RobotsAudit,
  retry: RetryAudit | null
): AuditCheck[] {
  const checks: AuditCheck[] = [];

  checks.push({
    name: "url-safety",
    passed: urlSafety.allowed,
    reason: urlSafety.allowed
      ? null
      : urlSafety.message ?? `URL rejected (${urlSafety.rejectReason})`,
  });

  checks.push({
    name: "no-tier-attempts-on-unsafe-url",
    passed:
      urlSafety.allowed ||
      (ladder !== null && ladder.attemptedTiers.length === 0),
    reason:
      urlSafety.allowed || (ladder !== null && ladder.attemptedTiers.length === 0)
        ? null
        : "Tier attempts were recorded even though the URL failed the SSRF guard",
  });

  if (urlSafety.allowed && ladder) {
    checks.push({
      name: "tier-order",
      passed: !ladder.degradedFields.includes("tierLadder.attemptedTiers"),
      reason: ladder.degradedFields.includes("tierLadder.attemptedTiers")
        ? `Observed tier order ${JSON.stringify(ladder.attemptedTiers)} does not match the source ladder ${JSON.stringify(ladder.configuredOrder)}`
        : null,
    });

    checks.push({
      name: "blocked-escalation",
      passed: ladder.attemptedTiers.length <= 1 || ladder.winner !== null,
      reason:
        ladder.attemptedTiers.length <= 1 || ladder.winner !== null
          ? null
          : "Every tier was tried and none returned a response",
    });

    checks.push({
      name: "proxy-tier-configuration",
      passed:
        !ladder.degradedFields.includes("tierLadder.winner") &&
        !ladder.degradedFields.includes("tierLadder.attemptedTiers"),
      reason:
        !ladder.degradedFields.includes("tierLadder.winner") &&
        !ladder.degradedFields.includes("tierLadder.attemptedTiers")
          ? null
          : "The residential-proxy tier appeared although no proxy was configured",
    });
  }

  if (redirects) {
    checks.push({
      name: "redirect-hop-revalidation",
      passed:
        redirects.rejectedHopIndex === null &&
        redirects.invalidLocationIndex === null &&
        redirects.consistentWithFollowSafely,
      reason:
        redirects.invalidLocationIndex !== null
          ? `Redirect #${redirects.invalidLocationIndex + 1} has an illegal Location header`
          : redirects.rejectedHopIndex !== null
            ? `Redirect #${redirects.rejectedHopIndex + 1} to ${redirects.rejectedUrl} was rejected before another request was sent: ${redirects.rejectedReason}`
            : !redirects.consistentWithFollowSafely
              ? "Redirect verdict disagrees with followSafely"
              : null,
    });

    checks.push({
      name: "redirect-limit",
      passed: !redirects.overLimit,
      reason: redirects.overLimit
        ? `Too many redirects: ${redirects.hopCount} hop(s) exceeds the limit of ${MAX_REDIRECTS}`
        : null,
    });
  }

  if (retry) {
    const unsafeRetried = retry.degradedFields.includes("retry.attempts");
    checks.push({
      name: "unsafe-url-not-retried",
      passed: !unsafeRetried,
      reason: unsafeRetried
        ? "An UnsafeUrlError was retried; the source never retries it"
        : null,
    });

    checks.push({
      name: "retryable-status-policy",
      passed: retry.consistentWithWithRetries,
      reason: retry.consistentWithWithRetries
        ? null
        : `Observed ${retry.observedAttempts} attempt(s) but withRetries policy allows ${retry.expectedAttempts} (only 408/425/429/5xx and network errors retry)`,
    });
  }

  // fake-IP wording must identify proxy DNS rewriting, not an internal site.
  if (!urlSafety.allowed && urlSafety.rejectReason === "fake-ip") {
    const wordingOk =
      urlSafety.message !== null &&
      urlSafety.message.includes("fake-IP") &&
      !/internal site/i.test(urlSafety.message);
    checks.push({
      name: "fake-ip-reason-wording",
      passed: wordingOk,
      reason: wordingOk
        ? null
        : "fake-IP rejection must be labeled as proxy DNS rewriting, not an internal site",
    });
  }

  checks.push({
    name: "robots-allowed",
    passed: robots.allowed,
    reason: robots.allowed ? null : "robots.txt disallows this URL",
  });

  return checks;
}

/**
 * Audit one fetch chain from a pure data snapshot. Never performs network or
 * disk I/O, never mutates its inputs, and never throws: malformed snapshots
 * produce a degraded report naming the affected fields.
 */
export async function auditFetchChain(
  snapshot: FetchAuditSnapshot
): Promise<FetchAuditReport> {
  try {
    const safeSnapshot =
      snapshot && typeof snapshot === "object" ? snapshot : ({} as FetchAuditSnapshot);
    const url = String(safeSnapshot.url ?? "");
    const dns =
      safeSnapshot.dns && typeof safeSnapshot.dns === "object"
        ? safeSnapshot.dns
        : undefined;
    const proxyConfigured = safeSnapshot.proxyConfigured === true;

    const urlSafety = await auditUrlSafety(url, dns);
    const ladder = auditTierLadder(
      Array.isArray(safeSnapshot.tierAttempts)
        ? [...safeSnapshot.tierAttempts]
        : safeSnapshot.tierAttempts,
      proxyConfigured,
      urlSafety.allowed
    );
    const redirects = await auditRedirects(
      url,
      safeSnapshot.redirects ?? null,
      dns,
      urlSafety.allowed
    );
    const robots = auditRobots(safeSnapshot.robotsText, url);
    const retry = await auditRetry(safeSnapshot.retry ?? null);
    const checks = buildChecks(urlSafety, ladder, redirects, robots, retry);

    const degradedFields = [
      ...urlSafety.degradedFields.map((f) => `urlSafety.${f}`),
      ...ladder.degradedFields.map((f) => f),
      ...redirects.degradedFields.map((f) => `redirects.${f}`),
      ...robots.degradedFields.map((f) => `robots.${f}`),
      ...(retry?.degradedFields ?? []).map((f) => `retry.${f}`),
    ];

    return {
      url,
      urlSafety,
      tierLadder: ladder,
      redirects,
      robots,
      retry,
      checks,
      degraded: degradedFields.length > 0,
      degradedFields,
    };
  } catch (err) {
    // Last-resort guard: the audit contract forbids uncaught exceptions.
    const message = err instanceof Error ? err.message : String(err);
    return {
      url:
        snapshot && typeof snapshot === "object"
          ? String((snapshot as { url?: unknown }).url ?? "")
          : "",
      urlSafety: {
        allowed: false,
        rejectReason: "unknown",
        message: `Audit failed while evaluating URL safety: ${message}`,
        resolvedAddresses: [],
        degraded: true,
        degradedFields: ["urlSafety"],
      },
      tierLadder: {
        winner: null,
        exhaustedAllTiers: false,
        configuredOrder: [...TIER_ORDER],
        attemptedTiers: [],
        proxyBytesTotal: 0,
        degraded: true,
        degradedFields: ["tierLadder"],
      },
      redirects: {
        hopCount: 0,
        overLimit: false,
        rejectedHopIndex: null,
        rejectedUrl: null,
        rejectedReason: null,
        consistentWithFollowSafely: false,
        invalidLocationIndex: null,
        degraded: true,
        degradedFields: ["redirects"],
      },
      robots: {
        allowed: true,
        crawlDelayMs: 0,
        robotsPresent: false,
        degraded: true,
        degradedFields: ["robots"],
      },
      retry: null,
      checks: [
        {
          name: "audit-runtime",
          passed: false,
          reason: `The audit could not complete: ${message}`,
        },
      ],
      degraded: true,
      degradedFields: ["audit"],
    };
  }
}

// Re-exported for callers that want the same address classification locally.
export { isPrivateAddress, isFakeIpAddress, MAX_REDIRECTS };
