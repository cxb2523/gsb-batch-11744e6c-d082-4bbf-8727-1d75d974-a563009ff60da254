import assert from "node:assert/strict";
import { mkdtempSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { WebcrawlClient, WebcrawlError, describeError, resolveConfig, writeConfigFile, readConfigFile } from "../src/index.js";

function fakeFetch(status: number, body: unknown, headers: Record<string, string> = {}) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const f = (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return new Response(JSON.stringify(body), { status, headers });
  }) as unknown as typeof fetch;
  return { f, calls };
}

describe("WebcrawlClient", () => {
  it("sends bearer auth, timezone and JSON body to /v1/search", async () => {
    const { f, calls } = fakeFetch(200, { success: true, results: [] });
    const c = new WebcrawlClient({ apiKey: "wc_live_x", baseUrl: "https://x.test/", fetch: f, timezone: "Australia/Sydney" });
    await c.search({ query: "hotels", category: "hotels", sites: ["booking.com"], city: "Sydney" });
    assert.equal(calls[0].url, "https://x.test/v1/search");
    const h = calls[0].init.headers as Record<string, string>;
    assert.equal(h.authorization, "Bearer wc_live_x");
    assert.equal(h["x-user-timezone"], "Australia/Sydney");
    const body = JSON.parse(String(calls[0].init.body));
    assert.deepEqual(body, { query: "hotels", category: "hotels", city: "Sydney", filters: { sites: ["booking.com"] } });
  });

  it("omits authorization when there is no key", async () => {
    const { f, calls } = fakeFetch(200, {});
    await new WebcrawlClient({ fetch: f }).categories();
    assert.equal((calls[0].init.headers as Record<string, string>).authorization, undefined);
    assert.equal(calls[0].init.method, "GET");
  });

  it("parse sends bytes as base64 with options and maps noCache", async () => {
    const { f, calls } = fakeFetch(200, { markdown: "x" });
    await new WebcrawlClient({ fetch: f }).parse({
      bytes: new Uint8Array([37, 80, 68, 70]),
      fileName: "a.pdf",
      ocr: "off",
      pages: [1],
      noCache: true,
    });
    assert.equal(calls[0].url.endsWith("/v1/parse"), true);
    assert.deepEqual(JSON.parse(String(calls[0].init.body)), {
      fileName: "a.pdf",
      ocr: "off",
      pages: [1],
      base64: "JVBERg==",
      noCache: true,
    });
  });

  it("parse rejects calls with no input", () => {
    const { f } = fakeFetch(200, {});
    assert.throws(() => new WebcrawlClient({ fetch: f }).parse({}), (e: unknown) => e instanceof WebcrawlError && e.kind === "bad_request");
  });

  it("caps crawl maxPages at 25", async () => {
    const { f, calls } = fakeFetch(200, {});
    await new WebcrawlClient({ fetch: f }).crawl({ url: "https://a.com", maxPages: 500 });
    assert.equal(JSON.parse(String(calls[0].init.body)).maxPages, 25);
  });

  for (const [status, kind] of [[401, "auth"], [402, "credits"], [429, "rate_limit"], [404, "not_found"], [500, "server"], [400, "bad_request"]] as const) {
    it(`maps HTTP ${status} to ${kind}`, async () => {
      const { f } = fakeFetch(status, { success: false, error: "nope" }, status === 429 ? { "retry-after": "7" } : {});
      await assert.rejects(new WebcrawlClient({ fetch: f }).scrape({ url: "https://a.com" }), (e: unknown) => {
        assert.ok(e instanceof WebcrawlError);
        assert.equal(e.kind, kind);
        assert.equal(e.status, status);
        if (status === 429) {assert.equal(e.retryAfter, 7);}
        return true;
      });
    });
  }

  it("wraps network failures", async () => {
    const f = (async () => {
      throw new TypeError("fetch failed");
    }) as unknown as typeof fetch;
    await assert.rejects(new WebcrawlClient({ fetch: f }).categories(), (e: unknown) => e instanceof WebcrawlError && e.kind === "network");
  });

  it("describeError gives actionable text", () => {
    assert.match(describeError(new WebcrawlError("credits", "x", { status: 402 })), /out of credits/i);
    assert.match(describeError(new WebcrawlError("auth", "x", { status: 401 })), /webcrawl login/);
    assert.match(describeError(new WebcrawlError("rate_limit", "x", { retryAfter: 3 })), /3s/);
  });

  it("supports monitor lifecycle methods (create, list, get, check, update, delete)", async () => {
    const { f, calls } = fakeFetch(200, {
      success: true,
      monitor: { id: "mon_1", url: "https://example.com/pricing", status: "active", intervalMinutes: 60 },
    });
    const c = new WebcrawlClient({ apiKey: "wc_live_x", baseUrl: "https://x.test", fetch: f });

    await c.createMonitor({
      url: "https://example.com/pricing",
      mode: "page",
      watchFor: "Plan prices",
      condition: "price < 50",
      notifyEmail: true,
    });
    assert.equal(calls[0].url, "https://x.test/v1/monitors");
    assert.equal(calls[0].init.method, "POST");
    assert.deepEqual(JSON.parse(String(calls[0].init.body)), {
      url: "https://example.com/pricing",
      mode: "page",
      watchFor: "Plan prices",
      condition: "price < 50",
      notifyEmail: true,
    });

    await c.monitors();
    assert.equal(calls[1].url, "https://x.test/v1/monitors");
    assert.equal(calls[1].init.method, "GET");

    await c.getMonitor("mon_1");
    assert.equal(calls[2].url, "https://x.test/v1/monitors/mon_1");
    assert.equal(calls[2].init.method, "GET");

    await c.checkMonitor("mon_1");
    assert.equal(calls[3].url, "https://x.test/v1/monitors/mon_1/check");
    assert.equal(calls[3].init.method, "POST");

    await c.updateMonitor({ id: "mon_1", status: "paused", condition: "price < 40" });
    assert.equal(calls[4].url, "https://x.test/v1/monitors/mon_1");
    assert.equal(calls[4].init.method, "PATCH");
    assert.deepEqual(JSON.parse(String(calls[4].init.body)), { status: "paused", condition: "price < 40" });

    await c.deleteMonitor("mon_1");
    assert.equal(calls[5].url, "https://x.test/v1/monitors/mon_1");
    assert.equal(calls[5].init.method, "DELETE");
  });
});

describe("resolveConfig", () => {
  it("prefers flags over env over file over defaults", () => {
    const file = { apiKey: "file", baseUrl: "https://file.test" };
    const env = { WEBCRAWL_API_KEY: "env", WEBCRAWL_URL: "https://env.test" } as NodeJS.ProcessEnv;
    assert.equal(resolveConfig({ apiKey: "flag" }, env, file).apiKey, "flag");
    assert.equal(resolveConfig({}, env, file).apiKey, "env");
    assert.equal(resolveConfig({}, {}, file).apiKey, "file");
    const none = resolveConfig({}, {}, {});
    assert.equal(none.apiKey, undefined);
    assert.equal(none.baseUrl, "https://webcrawl.app");
    assert.equal(resolveConfig({ baseUrl: "https://a.test///" }, {}, {}).baseUrl, "https://a.test");
    assert.equal(resolveConfig({}, env, file).source.baseUrl, "env");
  });

  it("writes the config file with 0600 and reads it back", () => {
    const p = join(mkdtempSync(join(tmpdir(), "wc-")), "sub", "config.json");
    writeConfigFile({ apiKey: "wc_live_abc" }, p);
    assert.equal(statSync(p).mode & 0o777, 0o600);
    assert.equal(readConfigFile(p).apiKey, "wc_live_abc");
    assert.deepEqual(readConfigFile(join(tmpdir(), "does-not-exist.json")), {});
  });
});
