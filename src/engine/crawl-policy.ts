/**
 * Crawl politeness helpers: robots.txt rules, adaptive concurrency (AIMD) and retries.
 * Pure and dependency-free so they are easy to test.
 */

const ROBOT_TOKEN = "webcrawl";

export interface RobotsRules {
  allows(url: string): boolean;
  /** Crawl-delay in ms for our agent (or `*`), 0 when unset. */
  crawlDelayMs: number;
}

interface Rule {
  allow: boolean;
  pattern: RegExp;
  length: number;
}

function patternToRegExp(path: string): RegExp {
  const anchored = path.endsWith("$");
  const body = (anchored ? path.slice(0, -1) : path)
    .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*");
  return new RegExp(`^${body}${anchored ? "$" : ""}`);
}

/** Parses robots.txt. Our own group wins over `*`; longest matching rule wins; Allow beats Disallow on ties. */
export function parseRobots(text: string | null | undefined): RobotsRules {
  const groups: Array<{ agents: string[]; rules: Rule[]; delay: number }> = [];
  let current: { agents: string[]; rules: Rule[]; delay: number } | null = null;
  let lastWasAgent = false;
  for (const rawLine of (text ?? "").split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, "").trim();
    if (!line) continue;
    const idx = line.indexOf(":");
    if (idx < 0) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    if (key === "user-agent") {
      if (!current || !lastWasAgent) {
        current = { agents: [], rules: [], delay: 0 };
        groups.push(current);
      }
      current.agents.push(value.toLowerCase());
      lastWasAgent = true;
      continue;
    }
    lastWasAgent = false;
    if (!current) continue;
    if (key === "disallow" || key === "allow") {
      if (!value && key === "disallow") continue; // empty Disallow = allow all
      current.rules.push({
        allow: key === "allow",
        pattern: patternToRegExp(value),
        length: value.length,
      });
    } else if (key === "crawl-delay") {
      const n = Number(value);
      if (Number.isFinite(n) && n > 0) current.delay = Math.min(n, 10) * 1000;
    }
  }
  const mine =
    groups.filter((g) => g.agents.some((a) => a !== "*" && ROBOT_TOKEN.includes(a))) ;
  const chosen = mine.length ? mine : groups.filter((g) => g.agents.includes("*"));
  const rules = chosen.flatMap((g) => g.rules);
  const crawlDelayMs = Math.max(0, ...chosen.map((g) => g.delay));
  return {
    crawlDelayMs,
    allows(url: string) {
      let path: string;
      try {
        const u = new URL(url);
        path = u.pathname + u.search;
      } catch {
        return true;
      }
      let best: Rule | null = null;
      for (const r of rules) {
        if (!r.pattern.test(path)) continue;
        if (!best || r.length > best.length || (r.length === best.length && r.allow)) best = r;
      }
      return best ? best.allow : true;
    },
  };
}

/** Additive-increase / multiplicative-decrease concurrency controller. */
export class AdaptiveConcurrency {
  private target: number;
  constructor(
    private readonly min = 1,
    private readonly max = 16,
    initial = 4
  ) {
    this.target = Math.min(Math.max(initial, min), max);
  }
  get current(): number {
    return this.target;
  }
  /** Feed the outcome of a finished wave. */
  record(outcome: { ok: number; failed: number; throttled: boolean }): number {
    const total = outcome.ok + outcome.failed;
    if (outcome.throttled || (total > 0 && outcome.failed / total > 0.3)) {
      this.target = Math.max(this.min, Math.floor(this.target / 2));
    } else if (outcome.ok > 0) {
      this.target = Math.min(this.max, this.target + 1);
    }
    return this.target;
  }
}

export const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export function backoffDelayMs(attempt: number, baseMs = 250, capMs = 4000, rand = Math.random): number {
  const exp = Math.min(capMs, baseMs * 2 ** attempt);
  return Math.round(exp / 2 + rand() * (exp / 2));
}

export function isRetryableStatus(status: number): boolean {
  return status === 408 || status === 425 || status === 429 || status >= 500;
}

/** Retries transient failures (network errors, 408/425/429/5xx) with jittered exponential backoff. */
export async function withRetries<T extends { status: number }>(
  run: () => Promise<T>,
  opts: { retries?: number; baseMs?: number; sleepFn?: (ms: number) => Promise<void> } = {}
): Promise<T> {
  const retries = opts.retries ?? 2;
  const wait = opts.sleepFn ?? sleep;
  let lastErr: unknown;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await run();
      if (!isRetryableStatus(res.status) || attempt === retries) return res;
    } catch (err) {
      if ((err as Error)?.name === "UnsafeUrlError") throw err;
      lastErr = err;
      if (attempt === retries) throw err;
    }
    await wait(backoffDelayMs(attempt, opts.baseMs));
  }
  throw lastErr;
}
