import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { blockedScrapeResult } from "../local-engine.js";
import { isAntiBotChallenge } from "../engine/fetcher.js";
import { isChallengeMarkdown } from "../engine/crawler.js";

describe("blocked local scrape", () => {
  it("returns success:false with no content and an actionable error", () => {
    const res = blockedScrapeResult("https://www.g2.com/products/x/reviews", 403, "impit-tls", 120);
    assert.equal(res.success, false);
    assert.equal(res.blocked, true);
    assert.equal(res.statusCode, 403);
    assert.equal(res.markdown, "");
    assert.deepEqual((res.data as Record<string, unknown>).markdown, "");
    assert.match(String(res.error), /HTTP 403/);
    assert.match(String(res.error), /--mode cloud/);
  });

  it("treats 403 / 429 / 503 and challenge markers as blocked, a normal 200 page as not", () => {
    assert.equal(isAntiBotChallenge("<html>Forbidden</html>", 403), true);
    assert.equal(isAntiBotChallenge("", 429), true);
    assert.equal(isAntiBotChallenge("<title>Just a moment...</title>", 200), true);
    assert.equal(isAntiBotChallenge("<html><h1>Quotes</h1><p>Real text</p></html>", 200), false);
  });

  it("treats Reddit network-security walls as blocked", () => {
    assert.equal(
      isAntiBotChallenge(
        "<html><body>You've been blocked by network security. To continue, log in to your Reddit account</body></html>",
        200
      ),
      true
    );
    assert.equal(
      isAntiBotChallenge("<html><body>Blocked by network security.</body></html>", 403),
      true
    );
    // Copy sits after a huge CSS block and a data-URI image (live Reddit 403 page).
    const cssHeavy = `<html><head><style>${":root{--x:1;}".repeat(4000)}</style></head><body><img src="data:image/png;base64,${"A".repeat(8000)}">You've been blocked by network security.</body></html>`;
    assert.ok(cssHeavy.indexOf("blocked by network") > 20000);
    assert.equal(isAntiBotChallenge(cssHeavy, 200), true);
    const paddedMarkdown = `${"x".repeat(80000)}\nYou've been blocked by network security.`;
    assert.equal(isChallengeMarkdown("reddit.com", paddedMarkdown), true);
  });

  it("empty 200 responses use blocked:true with an explicit no-content error", () => {
    const res = blockedScrapeResult(
      "https://www.reddit.com/r/test/comments/x",
      200,
      "impit-tls",
      80,
      "Page returned no readable content (HTTP 200). The site may be blocking automated clients."
    );
    assert.equal(res.success, false);
    assert.equal(res.blocked, true);
    assert.equal(res.statusCode, 200);
    assert.equal(res.markdown, "");
    assert.match(String(res.error), /no readable content/i);
  });
});
