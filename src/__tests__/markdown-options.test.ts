import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { fastHtmlToMarkdown, keepElements, removeElements } from "../engine/markdown.js";

const filler = "Lorem ipsum dolor sit amet. ".repeat(20);
const page = `<html><head><title>T</title></head><body>
<header>SITE HEADER</header>
<nav>NAV LINKS</nav>
<main><h1>Main</h1><p>${filler}</p>
<div class="cookie-banner"><div>inner</div>COOKIE TEXT</div>
<div id="related"><p>RELATED POSTS</p></div>
</main>
<footer>SITE FOOTER</footer>
</body></html>`;

describe("fastHtmlToMarkdown content options", () => {
  it("defaults to main content only", () => {
    const { markdown } = fastHtmlToMarkdown(page, "https://x.test/");
    assert.match(markdown, /Main/);
    assert.doesNotMatch(markdown, /SITE HEADER|SITE FOOTER|NAV LINKS/);
  });
  it("onlyMainContent:false keeps the whole body", () => {
    const html = page.replace(/<main>[\s\S]*<\/main>/, `<p>${filler}</p>`) ;
    const { markdown } = fastHtmlToMarkdown(html, "https://x.test/", { onlyMainContent: false });
    assert.match(markdown, /SITE HEADER/);
    assert.match(markdown, /SITE FOOTER/);
  });
  it("excludeTags removes nested elements by class and id", () => {
    const { markdown } = fastHtmlToMarkdown(page, "https://x.test/", {
      excludeTags: [".cookie-banner", "#related"],
    });
    assert.doesNotMatch(markdown, /COOKIE TEXT|inner|RELATED POSTS/);
    assert.match(markdown, /Main/);
  });
  it("includeTags keeps only matching elements", () => {
    const { markdown } = fastHtmlToMarkdown(page, "https://x.test/", { includeTags: ["#related"] });
    assert.match(markdown, /RELATED POSTS/);
    assert.doesNotMatch(markdown, /Main|SITE FOOTER/);
  });
});

describe("element helpers", () => {
  it("removeElements balances nested same-tag elements", () => {
    const out = removeElements('<div class="a"><div>x</div>y</div><div>keep</div>', [".a"]);
    assert.equal(out, "<div>keep</div>");
  });
  it("ignores invalid selectors", () => {
    assert.equal(removeElements("<p>a</p>", ["div > p", "[x]"]), "<p>a</p>");
    assert.equal(keepElements("<p>a</p>", ["???"]), "<p>a</p>");
  });
});
