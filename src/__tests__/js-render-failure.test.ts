import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { jsRenderFailedResult } from "../local-engine.js";
import { needsBrowserEscalation } from "../engine/fetcher.js";

describe("honest JS-render failure", () => {
  it("jsRenderFailedResult is success:false with an actionable error, not a nav shell", () => {
    const res = jsRenderFailedResult(
      "https://quotes.toscrape.com/js/",
      200,
      "impit-tls",
      2400,
      "JavaScript rendering failed (cdp/new timed out). Install Chrome or chrome-headless-shell."
    );
    assert.equal(res.success, false);
    assert.equal(res.blocked, false);
    assert.equal(res.needsJs, true);
    assert.equal(res.markdown, "");
    assert.equal((res.data as { markdown: string }).markdown, "");
    assert.match(String(res.error), /JavaScript rendering failed/);
    assert.match(String(res.error), /chrome-headless-shell/);
  });

  it("quotes.toscrape.com/js shell still escalates to the browser tier", () => {
    const html = `<html><body><h1>Quotes to Scrape</h1>
<script>
var data = [{"author":{"name":"Albert Einstein"},"text":"The world as we have created it."}];
for (var i in data) { document.write("<div class='quote'>"+data[i].text+"</div>"); }
</script></body></html>`;
    const markdown = "# Quotes to Scrape\n\nLogin\n\nNext";
    assert.equal(needsBrowserEscalation(200, html, markdown), true);
    assert.ok(markdown.length < 120);
  });
});
