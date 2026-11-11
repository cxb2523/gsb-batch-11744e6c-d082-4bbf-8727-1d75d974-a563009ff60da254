import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { AdaptiveConcurrency, backoffDelayMs, parseRobots, withRetries } from "../engine/crawl-policy.js";

describe("parseRobots", () => {
  const robots = parseRobots(`
User-agent: *
Disallow: /private
Disallow: /*.pdf$
Allow: /private/public
Crawl-delay: 2

User-agent: badbot
Disallow: /
`);
  it("blocks disallowed paths and honors longer Allow", () => {
    assert.equal(robots.allows("https://x.test/private/a"), false);
    assert.equal(robots.allows("https://x.test/private/public/a"), true);
    assert.equal(robots.allows("https://x.test/docs"), true);
  });
  it("supports wildcards and end anchors", () => {
    assert.equal(robots.allows("https://x.test/a/file.pdf"), false);
    assert.equal(robots.allows("https://x.test/a/file.pdf?x=1"), true);
  });
  it("reads crawl-delay and ignores other agents' groups", () => {
    assert.equal(robots.crawlDelayMs, 2000);
    assert.equal(robots.allows("https://x.test/"), true);
  });
  it("treats empty / missing robots as allow-all", () => {
    assert.equal(parseRobots("").allows("https://x.test/a"), true);
    assert.equal(parseRobots("User-agent: *\nDisallow:").allows("https://x.test/a"), true);
    assert.equal(parseRobots(null).allows("https://x.test/a"), true);
  });
  it("prefers our own group over *", () => {
    const r = parseRobots("User-agent: *\nDisallow: /\n\nUser-agent: webcrawl\nAllow: /");
    assert.equal(r.allows("https://x.test/a"), true);
  });
});

describe("AdaptiveConcurrency", () => {
  it("grows on success and halves on throttling", () => {
    const c = new AdaptiveConcurrency(1, 8, 4);
    assert.equal(c.record({ ok: 4, failed: 0, throttled: false }), 5);
    assert.equal(c.record({ ok: 2, failed: 3, throttled: false }), 2);
    assert.equal(c.record({ ok: 0, failed: 1, throttled: true }), 1);
    for (let i = 0; i < 20; i++) c.record({ ok: 1, failed: 0, throttled: false });
    assert.equal(c.current, 8);
  });
});

describe("withRetries", () => {
  const noWait = async () => {};
  it("retries 429/5xx then succeeds", async () => {
    const statuses = [503, 429, 200];
    let i = 0;
    const res = await withRetries(async () => ({ status: statuses[i++] }), { sleepFn: noWait });
    assert.equal(res.status, 200);
    assert.equal(i, 3);
  });
  it("returns the last retryable response when retries run out", async () => {
    let i = 0;
    const res = await withRetries(async () => ({ status: (i++, 503) }), { retries: 1, sleepFn: noWait });
    assert.equal(res.status, 503);
    assert.equal(i, 2);
  });
  it("does not retry 404 and never retries unsafe URLs", async () => {
    let i = 0;
    await withRetries(async () => ({ status: (i++, 404) }), { sleepFn: noWait });
    assert.equal(i, 1);
    let j = 0;
    await assert.rejects(
      withRetries(async () => {
        j++;
        const e = new Error("no");
        e.name = "UnsafeUrlError";
        throw e;
      }, { sleepFn: noWait })
    );
    assert.equal(j, 1);
  });
  it("backoff grows and is capped", () => {
    assert.ok(backoffDelayMs(0, 250, 4000, () => 0) <= 125 + 1);
    assert.ok(backoffDelayMs(10, 250, 4000, () => 1) <= 4000);
  });
});
