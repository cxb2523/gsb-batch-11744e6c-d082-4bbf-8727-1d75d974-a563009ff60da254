import { test } from "node:test";
import assert from "node:assert/strict";
import {
  collectSitemapPages,
  isBlockedResponse,
  parseSitemapLocs,
  sitemapsFromRobots,
  stealthAvailable,
  stealthDiscover,
  stealthFetch,
} from "../engine/stealth.js";
import { escalateToSandboxOrBrowser, isChallengeResult } from "../sandbox.js";

const VERCEL_CHECKPOINT = `<!doctype html><html><head><title>Vercel Security Checkpoint</title></head>
<body><p>We're verifying your browser</p><script src="/.well-known/vercel/security/static/challenge.v2.min.js"></script></body></html>`;

/** Runs `fn` with env overrides, restoring the previous values afterwards. */
async function withEnv<T>(vars: Record<string, string | undefined>, fn: () => Promise<T>): Promise<T> {
  const prev: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(vars)) {
    prev[k] = process.env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    return await fn();
  } finally {
    for (const [k, v] of Object.entries(prev)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

const NO_BROWSER = {
  WEBCRAWL_STEALTH: "false",
  CF_ACCOUNT_ID: undefined,
  CF_API_TOKEN: undefined,
  VERCEL: undefined,
  VERCEL_OIDC_TOKEN: undefined,
  VERCEL_SANDBOX_ENABLED: undefined,
};

test("parseSitemapLocs splits page URLs from child sitemaps and decodes entities", () => {
  const xml = `<?xml version="1.0"?><urlset>
    <url><loc>https://example.com/</loc></url>
    <url><loc> https://example.com/pricing?a=1&amp;b=2 </loc></url>
    <url><loc><![CDATA[https://example.com/blog/hello]]></loc></url>
    <url><loc>https://example.com/sitemap-posts.xml</loc></url>
  </urlset>`;
  const { pages, sitemaps } = parseSitemapLocs(xml);
  assert.deepEqual(pages, [
    "https://example.com/",
    "https://example.com/pricing?a=1&b=2",
    "https://example.com/blog/hello",
  ]);
  assert.deepEqual(sitemaps, ["https://example.com/sitemap-posts.xml"]);
});

test("parseSitemapLocs treats every <loc> in a sitemap index as a sitemap", () => {
  const xml = `<sitemapindex><sitemap><loc>https://example.com/pages</loc></sitemap>
    <sitemap><loc>https://example.com/posts.xml.gz</loc></sitemap></sitemapindex>`;
  const { pages, sitemaps } = parseSitemapLocs(xml);
  assert.deepEqual(pages, []);
  assert.deepEqual(sitemaps, ["https://example.com/pages", "https://example.com/posts.xml.gz"]);
});

test("sitemapsFromRobots reads every Sitemap: line, case-insensitive", () => {
  const robots = "User-agent: *\nDisallow: /admin\nSitemap: https://example.com/sitemap.xml\n  sitemap:   https://example.com/news.xml  \n";
  assert.deepEqual(sitemapsFromRobots(robots), [
    "https://example.com/sitemap.xml",
    "https://example.com/news.xml",
  ]);
});

test("collectSitemapPages skips robots.txt, blocked, failed and non-sitemap docs", () => {
  const sitemap = "<urlset><url><loc>https://example.com/a</loc></url><url><loc>https://example.com/b</loc></url></urlset>";
  const { pages, sitemapsRead } = collectSitemapPages([
    { url: "https://example.com/robots.txt", ok: true, status: 200, body: "Sitemap: https://example.com/sitemap.xml <loc>x</loc>" },
    { url: "https://example.com/sitemap.xml", ok: true, status: 200, body: sitemap },
    { url: "https://example.com/sitemap_index.xml", ok: true, status: 404, body: "<loc>https://example.com/404</loc>" },
    { url: "https://example.com/sitemap-index.xml", ok: true, status: 200, blocked: true, body: VERCEL_CHECKPOINT },
    { url: "https://example.com/other.xml", ok: false, error: "timeout" },
    { url: "https://example.com/sitemap-dupe.xml", ok: true, status: 200, body: sitemap },
  ]);
  assert.deepEqual(pages, ["https://example.com/a", "https://example.com/b"]);
  assert.deepEqual(sitemapsRead, ["https://example.com/sitemap.xml", "https://example.com/sitemap-dupe.xml"]);
});

test("isBlockedResponse flags challenge pages and WAF status codes, not real pages", () => {
  assert.equal(isBlockedResponse(200, VERCEL_CHECKPOINT), true);
  assert.equal(isBlockedResponse(429, "<html>slow down</html>"), true);
  assert.equal(isBlockedResponse(200, "<html><title>Just a moment...</title></html>"), true);
  assert.equal(isBlockedResponse(200, "<html><h1>Pricing</h1><p>Plans for every team</p></html>"), false);
  assert.equal(isBlockedResponse(null, ""), false);
});

test("isChallengeResult rejects challenge HTML and short challenge markdown only", () => {
  assert.equal(isChallengeResult(VERCEL_CHECKPOINT, ""), true);
  assert.equal(isChallengeResult("", "# Vercel Security Checkpoint\n\nWe're verifying your browser"), true);
  assert.equal(isChallengeResult("", "# Just a moment...\n\nChecking your browser"), true);
  assert.equal(isChallengeResult("", "# Pricing\n\nPlans for every team"), false);
  // A long real article that happens to say "just a moment" is content.
  const article = `# Release notes\n\nJust a moment of your time: ${"real content ".repeat(200)}`;
  assert.equal(isChallengeResult("", article), false);
});

test("stealth is off when WEBCRAWL_STEALTH=false, and fetch/discover fail honestly", async () => {
  await withEnv(NO_BROWSER, async () => {
    assert.equal(await stealthAvailable(), false);
    const res = await stealthFetch("https://example.com", [{ url: "https://example.com/sitemap.xml", raw: true }]);
    assert.equal(res.solved, false);
    assert.deepEqual(res.docs, []);
    assert.equal(res.error, "Stealth browser not configured");

    const found = await stealthDiscover("https://example.com/docs");
    assert.equal(found.solved, false);
    assert.deepEqual(found.sitemapPages, []);
    assert.equal(found.entry, null);
    assert.ok(found.error);
  });
});

test("escalateToSandboxOrBrowser returns null (not a challenge page) when no tier can run", async () => {
  await withEnv(NO_BROWSER, async () => {
    const res = await escalateToSandboxOrBrowser("https://example.com", { browser: true, timeoutMs: 1000 });
    assert.equal(res, null);
  });
});
