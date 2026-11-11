import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { auditFetchChain, TIER_ORDER } from "../engine/fetch-audit.js";
import {
  assertSafeUrl,
  followSafely,
  MAX_REDIRECTS,
  UnsafeUrlError,
} from "../engine/safe-url.js";
import { parseRobots, withRetries } from "../engine/crawl-policy.js";

const PUBLIC_DNS = {
  "example.com": ["93.184.216.34"],
  "a.example": ["93.184.216.35"],
  "cdn.example.net": ["93.184.216.36"],
};

const check = (report: Awaited<ReturnType<typeof auditFetchChain>>, name: string) => {
  const found = report.checks.find((c) => c.name === name);
  assert.ok(found, `missing check: ${name}`);
  return found;
};

describe("auditFetchChain — happy path", () => {
  it("public host, impit blocked then impersonate wins, robots allows; all checks pass", async () => {
    const robotsText = [
      "User-agent: *",
      "Disallow: /private",
      "Crawl-delay: 1",
    ].join("\n");
    const report = await auditFetchChain({
      url: "https://example.com/start",
      dns: PUBLIC_DNS,
      proxyConfigured: false,
      tierAttempts: [
        { tier: "impit-tls", status: 403, blocked: true },
        { tier: "impersonate", status: 200, blocked: false },
      ],
      robotsText,
      retry: { attempts: [{ status: 200 }] },
      redirects: [{ status: 200 }],
    });

    // URL safety
    assert.equal(report.urlSafety.allowed, true);
    assert.equal(report.urlSafety.rejectReason, null);
    assert.deepEqual(report.urlSafety.resolvedAddresses, ["93.184.216.34"]);

    // Ladder: impersonate wins; proxy never appears while unconfigured
    assert.equal(report.tierLadder?.winner, "impersonate");
    assert.equal(report.tierLadder!.exhaustedAllTiers, false);
    assert.ok(!report.tierLadder!.configuredOrder.includes("proxy-impersonate"));
    assert.deepEqual(report.tierLadder!.attemptedTiers, ["impit-tls", "impersonate"]);
    assert.equal(report.tierLadder!.proxyBytesTotal, 0);

    // Robots: allow + crawl-delay exactly as parseRobots computes
    const sourceRules = parseRobots(robotsText);
    assert.equal(report.robots.allowed, sourceRules.allows("https://example.com/start"));
    assert.equal(report.robots.allowed, true);
    assert.equal(report.robots.crawlDelayMs, sourceRules.crawlDelayMs);
    assert.equal(report.robots.crawlDelayMs, 1000);

    // No degraded sections and every check passes
    assert.equal(report.degraded, false, JSON.stringify(report.degradedFields));
    for (const c of report.checks) {
      assert.equal(c.passed, true, `${c.name}: ${c.reason}`);
    }
  });

  it("plain impit success leaves the winner as impit-tls with one attempt", async () => {
    const report = await auditFetchChain({
      url: "https://example.com/",
      dns: PUBLIC_DNS,
      tierAttempts: [{ tier: "impit-tls", status: 200, blocked: false }],
      robotsText: null,
    });
    assert.equal(report.tierLadder?.winner, "impit-tls");
    assert.equal(report.tierLadder!.exhaustedAllTiers, false);
    assert.equal(report.robots.allowed, true);
    assert.equal(report.robots.crawlDelayMs, 0);
  });
});

describe("auditFetchChain — negative URL safety", () => {
  it("private address 10.0.0.5 is rejected as private-address with no winner", async () => {
    const report = await auditFetchChain({
      url: "https://evil.example/",
      dns: { "evil.example": ["10.0.0.5"] },
      tierAttempts: [],
      robotsText: null,
    });
    assert.equal(report.urlSafety.allowed, false);
    assert.equal(report.urlSafety.rejectReason, "private-address");
    assert.match(report.urlSafety.message ?? "", /publicly reachable/);
    assert.doesNotMatch(report.urlSafety.message ?? "", /fake-IP/);

    assert.equal(report.tierLadder?.winner, null);
    assert.equal(report.tierLadder!.exhaustedAllTiers, false);
    assert.deepEqual(report.tierLadder!.attemptedTiers, []);

    // Must match the real assertSafeUrl verdict for the same inputs.
    await assert.rejects(
      assertSafeUrl("https://evil.example/", async () => ["10.0.0.5"]),
      UnsafeUrlError
    );
    assert.equal(check(report, "url-safety").passed, false);
    assert.equal(check(report, "no-tier-attempts-on-unsafe-url").passed, true);
  });

  it("fake-IP 198.18.0.42 is labeled as proxy DNS rewriting, not an internal site", async () => {
    const report = await auditFetchChain({
      url: "https://example.com/",
      dns: { "example.com": ["198.18.0.42"] },
      tierAttempts: [],
      robotsText: null,
    });
    assert.equal(report.urlSafety.allowed, false);
    assert.equal(report.urlSafety.rejectReason, "fake-ip");
    // The wording must be the exact source hint.
    assert.match(report.urlSafety.message ?? "", /fake-IP/);
    assert.match(report.urlSafety.message ?? "", /WEBCRAWL_ALLOW_PRIVATE_URLS=true/);
    assert.equal(report.tierLadder?.winner, null);
    assert.equal(check(report, "fake-ip-reason-wording").passed, true);
    assert.equal(check(report, "no-tier-attempts-on-unsafe-url").passed, true);

    // Cross-check against the real guard.
    await assert.rejects(
      assertSafeUrl("https://example.com/", async () => ["198.18.0.42"]),
      (e: Error) => {
        assert.ok(e instanceof UnsafeUrlError);
        assert.equal(e.message, report.urlSafety.message);
        return true;
      }
    );
  });

  it("empty DNS snapshot yields resolution-failed and no tier winner", async () => {
    const report = await auditFetchChain({
      url: "https://missing.example/",
      dns: {},
      tierAttempts: [],
    });
    assert.equal(report.urlSafety.allowed, false);
    assert.equal(report.urlSafety.rejectReason, "resolution-failed");
    assert.equal(report.tierLadder?.winner, null);
  });

  it("covers the other rejection categories consistently with assertSafeUrl", async () => {
    const cases: Array<{ url: string; reason: string; dns?: Record<string, string[]> }> = [
      { url: "file:///etc/passwd", reason: "non-http-scheme" },
      { url: "not a url at all", reason: "invalid-url" },
      { url: "http://localhost:8080/", reason: "local-hostname" },
      { url: "http://foo.internal/", reason: "local-hostname" },
      { url: "http://169.254.169.254/latest/meta-data", reason: "private-address" },
    ];
    for (const c of cases) {
      const report = await auditFetchChain({
        url: c.url,
        dns: c.dns ?? PUBLIC_DNS,
        tierAttempts: [],
      });
      assert.equal(report.urlSafety.allowed, false, c.url);
      assert.equal(report.urlSafety.rejectReason, c.reason, c.url);
      await assert.rejects(
        assertSafeUrl(c.url, async (h) => c.dns?.[h] ?? []),
        UnsafeUrlError,
        c.url
      );
    }
  });

  it("tier attempts recorded for an unsafe URL fail the guardrail check", async () => {
    const report = await auditFetchChain({
      url: "https://evil.example/",
      dns: { "evil.example": ["10.0.0.5"] },
      tierAttempts: [{ tier: "impit-tls", status: 200 }],
    });
    assert.equal(check(report, "no-tier-attempts-on-unsafe-url").passed, false);
    assert.equal(report.degraded, true);
  });
});

describe("auditFetchChain — tier ladder", () => {
  it("full ladder with proxy configured ends at fetch and sums proxy bytes", async () => {
    const report = await auditFetchChain({
      url: "https://example.com/",
      dns: PUBLIC_DNS,
      proxyConfigured: true,
      tierAttempts: [
        { tier: "impit-tls", status: 503, blocked: true },
        { tier: "impersonate", status: 403, blocked: true, proxyBytes: 1200 },
        { tier: "proxy-impersonate", status: 429, blocked: true, proxyBytes: 3400 },
        { tier: "fetch", status: 200 },
      ],
      robotsText: null,
    });
    assert.deepEqual(report.tierLadder?.configuredOrder, [...TIER_ORDER]);
    assert.equal(report.tierLadder!.winner, "fetch");
    assert.equal(report.tierLadder!.exhaustedAllTiers, true);
    assert.equal(report.tierLadder!.proxyBytesTotal, 4600);
  });

  it("proxy tier can never win or be attempted when unconfigured", async () => {
    const report = await auditFetchChain({
      url: "https://example.com/",
      dns: PUBLIC_DNS,
      proxyConfigured: false,
      tierAttempts: [
        { tier: "impit-tls", status: 503, blocked: true },
        { tier: "proxy-impersonate", status: 200, proxyBytes: 10 },
      ],
    });
    assert.equal(report.tierLadder!.winner, null);
    assert.ok(report.tierLadder!.degradedFields.some((f) => f.includes("winner")));
    assert.equal(check(report, "proxy-tier-configuration").passed, false);
  });

  it("an out-of-order tier sequence is flagged", async () => {
    const report = await auditFetchChain({
      url: "https://example.com/",
      dns: PUBLIC_DNS,
      tierAttempts: [
        { tier: "fetch", status: 200 },
        { tier: "impit-tls", status: 200 },
      ],
    });
    assert.equal(check(report, "tier-order").passed, false);
  });

  it("empty attempt list produces no winner and does not exhaust tiers", async () => {
    const report = await auditFetchChain({
      url: "https://example.com/",
      dns: PUBLIC_DNS,
      tierAttempts: [],
    });
    assert.equal(report.tierLadder?.winner, null);
    assert.equal(report.tierLadder!.exhaustedAllTiers, false);
  });
});

describe("auditFetchChain — redirect boundaries", () => {
  const chain = (n: number, terminalStatus = 200): Array<{ status: number; location?: string }> =>
    (Array.from({ length: n }, (_, i) => ({
      status: 302,
      location: `/r${i + 1}`,
    })) as Array<{ status: number; location?: string }>).concat([
      { status: terminalStatus },
    ]);

  it("exactly 8 redirects is allowed and matches followSafely", async () => {
    const redirects = chain(MAX_REDIRECTS);
    const report = await auditFetchChain({
      url: "https://a.example/start",
      dns: PUBLIC_DNS,
      tierAttempts: [{ tier: "impit-tls", status: 200 }],
      redirects,
    });
    assert.equal(report.redirects?.hopCount, MAX_REDIRECTS);
    assert.equal(report.redirects.overLimit, false);
    assert.equal(report.redirects.consistentWithFollowSafely, true);
    assert.equal(check(report, "redirect-limit").passed, true);

    // Authoritative source behavior for the same chain.
    let sends = 0;
    const { finalUrl } = await followSafely(
      "https://a.example/start",
      async (): Promise<{ status: number; headers: Record<string, string> }> => {
        const hop = redirects[sends++];
        return {
          status: hop.status,
          headers: hop.location ? { location: hop.location } : {},
        };
      },
      async () => ["93.184.216.35"]
    );
    assert.equal(finalUrl, "https://a.example/r8");
  });

  it("9 redirects exceeds the limit and matches followSafely", async () => {
    const redirects = chain(MAX_REDIRECTS + 1);
    const report = await auditFetchChain({
      url: "https://a.example/start",
      dns: PUBLIC_DNS,
      tierAttempts: [{ tier: "impit-tls", status: 200 }],
      redirects,
    });
    assert.equal(report.redirects?.hopCount, MAX_REDIRECTS + 1);
    assert.equal(report.redirects.overLimit, true);
    assert.equal(report.redirects.consistentWithFollowSafely, true);
    assert.equal(check(report, "redirect-limit").passed, false);
    assert.match(check(report, "redirect-limit").reason ?? "", /Too many redirects/);

    await assert.rejects(
      followSafely(
        "https://a.example/start",
        async (u) => {
          const idx = Number((u.split("/r").pop() ?? "0").replace("start", "0"));
          return { status: 302, headers: { location: `/r${idx + 1}` } };
        },
        async () => ["93.184.216.35"]
      ),
      /Too many redirects/
    );
  });

  it("a redirect hop to a private/metadata address is rejected and not followed", async () => {
    const report = await auditFetchChain({
      url: "https://a.example/start",
      dns: {
        ...PUBLIC_DNS,
        "169.254.169.254": ["169.254.169.254"],
      },
      tierAttempts: [{ tier: "impit-tls", status: 302 }],
      redirects: [
        { status: 302, location: "http://169.254.169.254/latest/meta-data" },
        { status: 200 },
      ],
    });
    assert.equal(report.redirects?.rejectedHopIndex, 0);
    assert.match(report.redirects.rejectedUrl ?? "", /169\.254\.169\.254/);
    assert.equal(report.redirects.hopCount, 0);
    assert.equal(check(report, "redirect-hop-revalidation").passed, false);

    // Source behavior for the same chain: one send, then UnsafeUrlError.
    const sends: string[] = [];
    await assert.rejects(
      followSafely(
        "https://a.example/start",
        async (u) => {
          sends.push(u);
          return {
            status: 302,
            headers: { location: "http://169.254.169.254/latest/meta-data" },
          };
        },
        async (h) => PUBLIC_DNS[h as keyof typeof PUBLIC_DNS] ?? [h]
      ),
      UnsafeUrlError
    );
    assert.deepEqual(sends, ["https://a.example/start"]);
  });

  it("an illegal Location header degrades gracefully without throwing", async () => {
    const report = await auditFetchChain({
      url: "https://a.example/start",
      dns: PUBLIC_DNS,
      redirects: [{ status: 302, location: "http://[bad:host:/" }],
    });
    assert.equal(report.redirects?.invalidLocationIndex, 0);
    assert.equal(report.degraded, true);
    assert.ok(report.degradedFields.some((f) => f.includes("location")));
    assert.equal(check(report, "redirect-hop-revalidation").passed, false);
  });
});

describe("auditFetchChain — retry policy", () => {
  it("404 is tried exactly once and agrees with withRetries", async () => {
    const report = await auditFetchChain({
      url: "https://example.com/missing",
      dns: PUBLIC_DNS,
      tierAttempts: [{ tier: "impit-tls", status: 404, blocked: false }],
      retry: { attempts: [{ status: 404 }] },
      robotsText: null,
    });
    assert.equal(report.retry?.observedAttempts, 1);
    assert.equal(report.retry.expectedAttempts, 1);
    assert.equal(report.retry.retried, false);
    assert.equal(report.retry.consistentWithWithRetries, true);

    let calls = 0;
    await withRetries(
      async () => ({ status: (calls++, 404) }),
      { sleepFn: async () => {} }
    );
    assert.equal(calls, 1);
  });

  it("503 retries until success and agrees with withRetries", async () => {
    const report = await auditFetchChain({
      url: "https://example.com/flaky",
      dns: PUBLIC_DNS,
      tierAttempts: [{ tier: "impit-tls", status: 200 }],
      retry: { attempts: [{ status: 503 }, { status: 503 }, { status: 200 }] },
    });
    assert.equal(report.retry?.observedAttempts, 3);
    assert.equal(report.retry.expectedAttempts, 3);
    assert.equal(report.retry.retried, true);
    assert.equal(report.retry.consistentWithWithRetries, true);
    assert.equal(check(report, "retryable-status-policy").passed, true);

    let i = 0;
    const res = await withRetries(
      async () => ({ status: [503, 503, 200][i++] }),
      { sleepFn: async () => {} }
    );
    assert.equal(res.status, 200);
    assert.equal(i, 3);
  });

  it("UnsafeUrlError is never retried and fails the audit check if it were", async () => {
    const clean = await auditFetchChain({
      url: "https://example.com/",
      dns: PUBLIC_DNS,
      retry: { attempts: [{ errored: true, errorName: "UnsafeUrlError" }] },
    });
    assert.equal(clean.retry?.observedAttempts, 1);
    assert.equal(clean.retry.expectedAttempts, 1);
    assert.equal(clean.retry.consistentWithWithRetries, true);

    const bad = await auditFetchChain({
      url: "https://example.com/",
      dns: PUBLIC_DNS,
      retry: {
        attempts: [
          { errored: true, errorName: "UnsafeUrlError" },
          { status: 200 },
        ],
      },
    });
    assert.equal(bad.retry?.consistentWithWithRetries, false);
    assert.equal(check(bad, "unsafe-url-not-retried").passed, false);
  });

  it("a network error retries within the budget", async () => {
    const report = await auditFetchChain({
      url: "https://example.com/",
      dns: PUBLIC_DNS,
      retry: {
        attempts: [
          { errored: true, errorName: "TypeError" },
          { status: 200 },
        ],
      },
    });
    assert.equal(report.retry?.expectedAttempts, 2);
    assert.equal(report.retry.consistentWithWithRetries, true);
  });
});

describe("auditFetchChain — degradation and serialization", () => {
  it("null robots means allow-all, matching parseRobots(null)", async () => {
    const report = await auditFetchChain({
      url: "https://example.com/a",
      dns: PUBLIC_DNS,
      robotsText: null,
    });
    assert.equal(report.robots.allowed, parseRobots(null).allows("https://example.com/a"));
    assert.equal(report.robots.allowed, true);
    assert.equal(report.robots.robotsPresent, false);
    assert.equal(report.robots.crawlDelayMs, 0);
  });

  it("missing optional sections never throw and are reported as empty or null", async () => {
    const report = await auditFetchChain({
      url: "https://example.com/",
      dns: PUBLIC_DNS,
    });
    assert.equal(report.redirects?.hopCount, 0);
    assert.equal(report.redirects.overLimit, false);
    assert.equal(report.retry, null);
    assert.equal(report.tierLadder?.winner, null);
    assert.doesNotThrow(() => JSON.stringify(report));
  });

  it("never throws on malformed snapshots and marks affected fields", async () => {
    const weird = [
      undefined,
      null,
      {},
      { url: "" },
      { url: "https://example.com/", dns: null as never, tierAttempts: "nope" as never },
      { url: "https://example.com/", retry: { attempts: null as never } },
      { url: "https://example.com/", redirects: { bad: true } as never },
    ];
    for (const snapshot of weird) {
      const report = await auditFetchChain(snapshot as never);
      assert.ok(report && typeof report === "object");
      // Must remain JSON-serializable with no Error/function payloads.
      const round = JSON.parse(JSON.stringify(report));
      assert.equal(typeof round.url, "string");
      assert.ok(Array.isArray(round.checks));
    }
  });

  it("the whole report survives JSON.stringify with no functions or error objects", async () => {
    const report = await auditFetchChain({
      url: "https://example.com/start",
      dns: PUBLIC_DNS,
      proxyConfigured: true,
      tierAttempts: [
        { tier: "impit-tls", status: 403, blocked: true },
        { tier: "impersonate", status: 200, proxyBytes: 2048 },
      ],
      robotsText: "User-agent: *\nCrawl-delay: 3",
      retry: { attempts: [{ status: 503 }, { status: 200 }] },
      redirects: [
        { status: 301, location: "/next" },
        { status: 200 },
      ],
    });
    const text = JSON.stringify(report);
    assert.equal(typeof text, "string");
    const parsed = JSON.parse(text);
    assert.equal(parsed.tierLadder.winner, "impersonate");
    assert.equal(parsed.tierLadder.proxyBytesTotal, 2048);
    assert.equal(parsed.robots.crawlDelayMs, 3000);
    assert.equal(parsed.redirects.hopCount, 1);
    assert.equal(parsed.retry.observedAttempts, 2);
    // No prototype leakage of Error/function anywhere in the payload.
    assert.doesNotMatch(text, /"name":"Error"/);
    for (const value of Object.values(parsed)) {
      assert.notEqual(typeof value, "function");
    }
  });

  it("does not mutate the input arrays", async () => {
    const attempts = [{ tier: "impit-tls", status: 200 }];
    const redirects = [{ status: 200 }];
    const dns = { ...PUBLIC_DNS };
    const snapshot = {
      url: "https://example.com/",
      dns,
      tierAttempts: attempts,
      redirects,
      retry: { attempts: [{ status: 200 }] },
    };
    await auditFetchChain(snapshot);
    assert.deepEqual(attempts, [{ tier: "impit-tls", status: 200 }]);
    assert.deepEqual(redirects, [{ status: 200 }]);
    assert.deepEqual(Object.keys(dns).sort(), Object.keys(PUBLIC_DNS).sort());
  });
});
