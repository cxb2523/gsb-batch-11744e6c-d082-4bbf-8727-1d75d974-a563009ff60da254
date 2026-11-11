import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  EMPTY_SEARCH_ERROR,
  canonicalSearchUrl,
  fetchKeylessSearchFallbacks,
  isSerpChallengeHtml,
  mergeSearchCandidates,
  parseBingWebRss,
  withRetry,
} from "../search/providers.js";
import { SEARCH_CATEGORY_CATALOG } from "../search/catalog.js";

describe("keyless search fallbacks", () => {
  it("flags DDG and Brave challenge pages so they are not parsed as results", () => {
    assert.equal(
      isSerpChallengeHtml(
        "<html>Unfortunately, bots use DuckDuckGo too. Please complete the following challenge</html>",
        202
      ),
      true
    );
    assert.equal(isSerpChallengeHtml("<html>anomaly-modal</html>", 200), true);
    assert.equal(isSerpChallengeHtml("flagged as being suspicious; schedule a captcha", 200), true);
    assert.equal(isSerpChallengeHtml("<html>results</html>", 429), true);
    assert.equal(
      isSerpChallengeHtml(
        "<html><a class='result-link' href='https://example.com'>Real result</a></html>",
        200
      ),
      false
    );
  });

  it("parses Bing RSS item title/link/description", () => {
    const xml = `<?xml version="1.0"?><rss><channel>
      <item><title>Next.js App Router</title><link>https://nextjs.org/docs/app</link><description>The App Router</description></item>
      <item><title>Pages vs App</title><link>https://example.com/pages-vs-app</link><description>Comparison</description></item>
    </channel></rss>`;
    const items = parseBingWebRss(xml, 5);
    assert.equal(items.length, 2);
    assert.equal(items[0].url, "https://nextjs.org/docs/app");
    assert.equal(items[0].title, "Next.js App Router");
    assert.equal(items[0].engine, "bing-rss");
  });

  it("fetchKeylessSearchFallbacks returns Wikipedia/HN/Bing hits from mocked fetch", async () => {
    const realFetch = globalThis.fetch;
    try {
      globalThis.fetch = (async (input: string | URL) => {
        const url = String(input);
        if (url.includes("en.wikipedia.org")) {
          return new Response(
            JSON.stringify({
              query: {
                search: [{ title: "Next.js", snippet: "React framework", timestamp: "2024-01-01" }],
              },
            }),
            { status: 200 }
          );
        }
        if (url.includes("hn.algolia.com")) {
          return new Response(
            JSON.stringify({
              hits: [
                {
                  title: "Next.js App Router Update",
                  url: "https://news.ycombinator.com/item?id=1",
                  objectID: "1",
                  points: 10,
                  num_comments: 2,
                  created_at: "2024-01-01",
                },
              ],
            }),
            { status: 200 }
          );
        }
        if (url.includes("bing.com/search")) {
          return new Response(
            `<?xml version="1.0"?><rss><channel><item><title>App Router docs</title><link>https://nextjs.org/docs</link><description>docs</description></item></channel></rss>`,
            { status: 200 }
          );
        }
        return new Response("nope", { status: 404 });
      }) as typeof fetch;
      const docs = await fetchKeylessSearchFallbacks("next.js app router", 5);
      assert.ok(docs.length >= 2, JSON.stringify(docs));
      assert.ok(docs.some((d) => d.engine === "hn-algolia"));
      assert.ok(docs.some((d) => d.engine === "wikipedia"));
      assert.ok(docs.some((d) => /nextjs\.org/i.test(d.url)));
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  it("documents the honest empty-search error", () => {
    assert.match(EMPTY_SEARCH_ERROR, /BRAVE_SEARCH_API_KEY/);
    assert.match(EMPTY_SEARCH_ERROR, /no results/);
  });

  it("round-robin merges and dedupes so Wikipedia cannot fill n alone", () => {
    assert.equal(
      canonicalSearchUrl("https://EN.Wikipedia.org/wiki/Foo/?utm_source=x"),
      canonicalSearchUrl("https://en.wikipedia.org/wiki/Foo")
    );
    const merged = mergeSearchCandidates(
      [
        [
          { title: "W1", url: "https://en.wikipedia.org/wiki/A", description: "w", engine: "wikipedia", engineRank: 1 },
          { title: "W2", url: "https://en.wikipedia.org/wiki/B", description: "w", engine: "wikipedia", engineRank: 2 },
          { title: "W3", url: "https://en.wikipedia.org/wiki/C", description: "w", engine: "wikipedia", engineRank: 3 },
        ],
        [
          { title: "HN1", url: "https://news.ycombinator.com/item?id=1", description: "hn", engine: "hn-algolia", engineRank: 1 },
          { title: "HN2", url: "https://news.ycombinator.com/item?id=2", description: "hn", engine: "hn-algolia", engineRank: 2 },
        ],
        [
          { title: "B1", url: "https://example.com/web-crawler", description: "b", engine: "bing-rss", engineRank: 1 },
        ],
      ],
      5
    );
    assert.equal(merged.length, 5);
    const engines = new Set(merged.map((m) => m.engine));
    assert.ok(engines.has("wikipedia"));
    assert.ok(engines.has("hn-algolia"));
    assert.ok(engines.has("bing-rss"));
  });

  it("withRetry retries empty results then returns the filled value", async () => {
    let n = 0;
    const out = await withRetry(
      async () => {
        n++;
        return n === 1 ? [] : [1];
      },
      { retries: 2, delayMs: 10, isEmpty: (v) => v.length === 0 }
    );
    assert.deepEqual(out, [1]);
    assert.equal(n, 2);
  });

  it("general search plan includes keyless HN and Bing RSS fillers", () => {
    const engines = SEARCH_CATEGORY_CATALOG.general.engines;
    assert.ok(engines.includes("hn-algolia"));
    assert.ok(engines.includes("bing-rss"));
    assert.ok(engines.includes("wikipedia"));
  });

  it("fetchKeylessSearchFallbacks fills n from multiple sources including DDG IA", async () => {
    const realFetch = globalThis.fetch;
    try {
      globalThis.fetch = (async (input: string | URL) => {
        const url = String(input);
        if (url.includes("en.wikipedia.org")) {
          return new Response(
            JSON.stringify({
              query: {
                search: [
                  { title: "Web crawler", snippet: "bot", timestamp: "2024-01-01" },
                  { title: "Web scraping", snippet: "extract", timestamp: "2024-01-01" },
                ],
              },
            }),
            { status: 200 }
          );
        }
        if (url.includes("hn.algolia.com")) {
          return new Response(
            JSON.stringify({
              hits: [
                { title: "Show HN: crawler", url: "https://github.com/example/crawler", objectID: "1", points: 10, num_comments: 2 },
                { title: "Open source web crawler", url: "https://news.ycombinator.com/item?id=2", objectID: "2", points: 8, num_comments: 1 },
              ],
            }),
            { status: 200 }
          );
        }
        if (url.includes("bing.com/search")) {
          return new Response(
            `<?xml version="1.0"?><rss><channel>
              <item><title>Open source crawler</title><link>https://example.org/oss-crawler</link><description>cli</description></item>
              <item><title>Another crawler</title><link>https://example.org/crawler-2</link><description>lib</description></item>
            </channel></rss>`,
            { status: 200 }
          );
        }
        if (url.includes("api.duckduckgo.com")) {
          return new Response(
            JSON.stringify({
              Heading: "Web crawler",
              AbstractURL: "https://en.wikipedia.org/wiki/Web_crawler",
              AbstractText: "A web crawler is a bot.",
              RelatedTopics: [
                { FirstURL: "https://www.scrapy.org/", Text: "Scrapy - Python crawler" },
              ],
            }),
            { status: 200 }
          );
        }
        return new Response("nope", { status: 404 });
      }) as typeof fetch;
      const docs = await fetchKeylessSearchFallbacks("open source web crawler", 5);
      assert.ok(docs.length >= 5, JSON.stringify(docs));
      const engines = new Set(docs.map((d) => d.engine));
      assert.ok(engines.size >= 2, JSON.stringify([...engines]));
    } finally {
      globalThis.fetch = realFetch;
    }
  });
});
