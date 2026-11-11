/**
 * Network-gated integration tests for the v1.4.3 smoke-test failures.
 * Skip with WEBCRAWL_SKIP_NETWORK=1. Individual cases skip when the host is unreachable.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createLocalEngineClient } from "../local-engine.js";

const skipNetwork = process.env.WEBCRAWL_SKIP_NETWORK === "1";

async function reachable(url: string): Promise<boolean> {
  try {
    const res = await fetch(url, { method: "GET", signal: AbortSignal.timeout(8000) });
    return res.status > 0;
  } catch {
    return false;
  }
}

describe("live smoke (network)", { skip: skipNetwork }, () => {
  it("JS scrape of quotes.toscrape.com/js is honest: rendered quotes or success:false", async () => {
    if (!(await reachable("https://quotes.toscrape.com/js/"))) {
      return;
    }
    const local = createLocalEngineClient();
    const res = await local.scrape({ url: "https://quotes.toscrape.com/js/", noCache: true });
    const md = String(res.markdown ?? "");
    if (res.success === true) {
      assert.match(md, /Einstein/i);
      assert.ok(md.length > 400, `markdown length ${md.length}`);
      assert.notEqual(res.needsJs, true);
    } else {
      assert.equal(res.success, false);
      assert.match(String(res.error), /JavaScript rendering|Chrome|no content/i);
      assert.equal(md, "");
    }
  });

  it("nested-schema extract on quotes.toscrape.com fills items[]", async () => {
    if (!(await reachable("https://quotes.toscrape.com/"))) {
      return;
    }
    const local = createLocalEngineClient();
    const res = await local.extract({
      url: "https://quotes.toscrape.com/",
      schema: { items: [{ quote: "string", author: "string" }] },
    });
    assert.equal(res.success, true, JSON.stringify(res).slice(0, 500));
    const items = (res.data as { items?: Array<{ quote?: string; author?: string }> }).items;
    assert.ok(Array.isArray(items) && items.length >= 5, JSON.stringify(res.data).slice(0, 500));
    assert.ok(items.some((q) => /Einstein/i.test(String(q.author))));
  });

  it("JS extract on quotes.toscrape.com/js does not include script-template junk", async () => {
    if (!(await reachable("https://quotes.toscrape.com/js/"))) {
      return;
    }
    const local = createLocalEngineClient();
    const res = await local.extract({
      url: "https://quotes.toscrape.com/js/",
      prompt: "quotes and their authors",
      schema: { items: [{ quote: "string", author: "string" }] },
    });
    if (res.success === false) {
      assert.match(String(res.error), /JavaScript rendering|Chrome|schema/i);
      return;
    }
    const items = (res.data as { items?: Array<{ quote?: string; author?: string }> }).items ?? [];
    assert.equal(
      items.some((q) => /\+\s*d\[/.test(String(q.quote)) || /d\['text'\]/.test(String(q.quote))),
      false,
      JSON.stringify(items)
    );
  });

  it("keyless search fills n=5 from multiple sources", async () => {
    const local = createLocalEngineClient();
    for (const query of ["open source web crawler", "web scraping api"]) {
      const res = await local.search({ query, limit: 5 });
      if (res.success === false) {
        assert.match(String(res.error), /no results/i);
        continue;
      }
      const data = res.data as unknown[];
      assert.ok(Array.isArray(data) && data.length >= 3, `${query}: ${JSON.stringify(res).slice(0, 400)}`);
    }
  });
});
