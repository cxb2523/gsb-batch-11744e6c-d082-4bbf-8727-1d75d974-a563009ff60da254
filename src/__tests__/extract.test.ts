import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { extractWebsiteData } from "../engine/crawler.js";
import {
  extractByPromptAndSchema,
  extractQuoteAuthorPairs,
  hasCustomExtractRequest,
  isEmptyExtractResult,
  isJsTemplateJunk,
  normalizeExtractSchema,
  stripNonContentHtml,
  wantsQuoteAuthorExtract,
} from "../extract/structured.js";
import { extractOutputData, withOptionalHtml } from "../local-engine.js";

const QUOTES_JS_HTML = `<!DOCTYPE html><html><head><title>Quotes to Scrape</title></head><body>
<h1>Quotes to Scrape</h1>
<script>
    var data = [
    {"tags":["change"],"author":{"name":"Albert Einstein"},"text":"The world as we have created it is a process of our thinking."},
    {"tags":["choices"],"author":{"name":"J.K. Rowling"},"text":"It is our choices, Harry, that show what we truly are."}
];
    for (var i in data) {
        document.write("<div class='quote'><span class='text'>" + data[i]['text'] + "</span><span>by <small class='author'>" + data[i]['author']['name'] + "</small></span></div>");
    }
</script>
</body></html>`;

const QUOTES_STATIC_HTML = `<html><body>
<div class="quote" itemscope itemtype="http://schema.org/CreativeWork">
  <span class="text" itemprop="text">"The world as we have created it is a process of our thinking."</span>
  <span>by <small class="author" itemprop="author">Albert Einstein</small></span>
</div>
<div class="quote">
  <span class="text">"It is our choices, Harry, that show what we truly are."</span>
  <span>by <small class="author">J.K. Rowling</small></span>
</div>
</body></html>`;

const QUOTES_SCHEMA = {
  type: "object",
  properties: {
    quotes: {
      type: "array",
      items: {
        type: "object",
        properties: {
          quote: { type: "string" },
          author: { type: "string" },
        },
      },
    },
  },
};

describe("prompt/schema extract", () => {
  it("detects a custom extract request from prompt or schema", () => {
    assert.equal(hasCustomExtractRequest(undefined, undefined), false);
    assert.equal(hasCustomExtractRequest("quotes and authors", undefined), true);
    assert.equal(hasCustomExtractRequest(undefined, QUOTES_SCHEMA), true);
    assert.equal(wantsQuoteAuthorExtract("extract the quotes and authors", undefined), true);
    assert.equal(wantsQuoteAuthorExtract(undefined, QUOTES_SCHEMA), true);
  });

  it("parses quote/author pairs from JS-embedded JSON and from static cards", () => {
    const fromJs = extractQuoteAuthorPairs(QUOTES_JS_HTML, "");
    assert.ok(fromJs.length >= 2);
    assert.equal(fromJs[0].author, "Albert Einstein");
    assert.match(fromJs[0].text, /world as we have created it/);
    assert.equal(fromJs[1].author, "J.K. Rowling");

    const fromCards = extractQuoteAuthorPairs(QUOTES_STATIC_HTML, "");
    assert.ok(fromCards.some((p) => p.author === "Albert Einstein"));
    assert.ok(fromCards.some((p) => p.author === "J.K. Rowling"));
  });

  it("shapes pairs to the caller's schema field names", () => {
    const shaped = extractByPromptAndSchema(
      QUOTES_STATIC_HTML,
      "",
      "quotes and authors",
      QUOTES_SCHEMA
    );
    assert.ok(shaped);
    const quotes = shaped.quotes as Array<{ quote: string; author: string }>;
    assert.ok(Array.isArray(quotes) && quotes.length >= 2);
    assert.equal(quotes[0].author, "Albert Einstein");
    assert.match(quotes[0].quote, /world as we have created it/);
    assert.equal("app_name" in shaped, false);
  });

  it("extractWebsiteData follows prompt/schema instead of app_name/product_features", async () => {
    const out = await extractWebsiteData("https://quotes.toscrape.com/", {
      prompt: "quotes and their authors",
      schema: QUOTES_SCHEMA,
      html: QUOTES_STATIC_HTML,
      markdown: "# Quotes to Scrape",
      bypassCache: true,
    });
    const quotes = out.quotes as Array<{ quote: string; author: string }>;
    assert.ok(Array.isArray(quotes) && quotes.length >= 2, JSON.stringify(out));
    assert.ok(quotes.some((q) => q.author === "Albert Einstein"));
    assert.equal(out.app_name, undefined);
    assert.equal(out.product_features, undefined);
  });

  it("extractWebsiteData fills nested {items:[{quote,author}]} and ignores script junk", async () => {
    const nested = { items: [{ quote: "string", author: "string" }] };
    const out = await extractWebsiteData("https://quotes.toscrape.com/js/", {
      schema: nested,
      html: QUOTES_JS_HTML,
      markdown: "# Quotes to Scrape\n\nLogin",
      bypassCache: true,
    });
    const items = out.items as Array<{ quote: string; author: string }>;
    assert.ok(Array.isArray(items) && items.length >= 2, JSON.stringify(out));
    assert.ok(items.some((q) => q.author === "Albert Einstein"));
    assert.equal(
      items.some((q) => /\+\s*d\[/.test(q.quote) || /\+\s*d\[/.test(q.author)),
      false,
      JSON.stringify(items)
    );
  });

  it("keeps the default app_name shape when no prompt or schema is given", async () => {
    const out = await extractWebsiteData("https://example.com/docs", {
      markdown: "# Docs\n\n## Fast crawl\n\n## Local search\n",
      bypassCache: true,
    });
    assert.equal(typeof out.app_name, "string");
    assert.ok(Array.isArray(out.product_features));
  });

  it("omits the target sidecar when the caller passed a prompt or schema", () => {
    const extracted = { quotes: [{ quote: "q", author: "a" }] };
    const custom = extractOutputData(extracted, {
      prompt: "quotes and authors",
      schema: QUOTES_SCHEMA,
      target: { kind: "generic-web" },
    });
    assert.deepEqual(custom, extracted);
    assert.equal("target" in custom, false);

    const generic = extractOutputData(
      { app_name: "X", product_features: ["a"] },
      { target: { kind: "generic-web" } }
    );
    assert.equal((generic.target as { kind: string }).kind, "generic-web");
  });

  it("normalizes shorthand nested schemas like {items:[{quote,author}]}", () => {
    const nested = { items: [{ quote: "string", author: "string" }] };
    const normalized = normalizeExtractSchema(nested);
    assert.equal(normalized?.type, "object");
    const items = (normalized?.properties as { items: { type: string } }).items;
    assert.equal(items.type, "array");
    assert.equal(wantsQuoteAuthorExtract(undefined, nested), true);
    const shaped = extractByPromptAndSchema(QUOTES_STATIC_HTML, "", undefined, nested);
    assert.ok(shaped);
    const rows = shaped.items as Array<{ quote: string; author: string }>;
    assert.ok(Array.isArray(rows) && rows.length >= 2);
    assert.equal(rows[0].author, "Albert Einstein");
    assert.match(rows[0].quote, /world as we have created it/);
  });

  it("does not treat empty nested extract as a filled result", () => {
    assert.equal(isEmptyExtractResult({}), true);
    assert.equal(isEmptyExtractResult({ cached: false, cacheLayer: "miss" }), true);
    assert.equal(isEmptyExtractResult({ items: [] }), true);
    assert.equal(isEmptyExtractResult({ items: [{ quote: "q", author: "a" }] }), false);
    const empty = extractByPromptAndSchema(
      "<html><body><p>No quotes here.</p></body></html>",
      "No quotes here.",
      undefined,
      { items: [{ quote: "string", author: "string" }] }
    );
    assert.equal(empty, null);
  });

  it("strips script/style and ignores document.write template junk", () => {
    assert.equal(isJsTemplateJunk("+ d['text'] +"), true);
    assert.equal(isJsTemplateJunk("The world as we have created it is a process of our thinking."), false);
    const stripped = stripNonContentHtml(QUOTES_JS_HTML);
    assert.doesNotMatch(stripped, /document\.write/);
    assert.doesNotMatch(stripped, /d\['text'\]/);
    const pairs = extractQuoteAuthorPairs(QUOTES_JS_HTML, "");
    assert.ok(pairs.length >= 2);
    assert.equal(
      pairs.some((p) => isJsTemplateJunk(p.text) || isJsTemplateJunk(p.author)),
      false
    );
    assert.ok(pairs.every((p) => !/\+\s*d\[/.test(p.text)));
  });

  it("attaches rendered HTML on scrape results when formats includes html", () => {
    const rendered = "<html><body><div class='quote'>Einstein</div></body></html>";
    const withHtml = withOptionalHtml(
      { success: true, markdown: "Einstein", data: { markdown: "Einstein" } },
      rendered,
      ["markdown", "html"]
    );
    assert.equal(withHtml.html, rendered);
    assert.equal((withHtml.data as { html: string }).html, rendered);
    const without = withOptionalHtml(
      { success: true, markdown: "Einstein", data: { markdown: "Einstein" } },
      rendered,
      ["markdown"]
    );
    assert.equal("html" in without, false);
  });
});
