import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { buildPathScope } from "../engine/path-scope.js";

describe("buildPathScope", () => {
  it("auto-scopes to the start URL's subpath at a segment boundary", () => {
    const s = buildPathScope("https://x.test/docs");
    assert.equal(s.allows("https://x.test/docs"), true);
    assert.equal(s.allows("https://x.test/docs/intro"), true);
    assert.equal(s.allows("https://x.test/docs?page=2"), true);
    assert.equal(s.allows("https://x.test/docs-old/a"), false);
    assert.equal(s.allows("https://x.test/blog/a"), false);
  });
  it("allows everything for a root start URL", () => {
    const s = buildPathScope("https://x.test/");
    assert.equal(s.allows("https://x.test/anything"), true);
  });
  it("restrictToSubpath:false disables the automatic prefix", () => {
    const s = buildPathScope("https://x.test/docs", { restrictToSubpath: false });
    assert.equal(s.allows("https://x.test/blog/a"), true);
  });
  it("includePaths override the automatic prefix and support wildcards", () => {
    const s = buildPathScope("https://x.test/docs", { includePaths: ["/blog/*", "guides"] });
    assert.equal(s.allows("https://x.test/blog/post"), true);
    assert.equal(s.allows("https://x.test/guides/a"), true);
    assert.equal(s.allows("https://x.test/docs/a"), false);
    // start URL always allowed
    assert.equal(s.allows("https://x.test/docs"), true);
  });
  it("excludePaths win over includes", () => {
    const s = buildPathScope("https://x.test/", { excludePaths: ["/admin", "/*/draft$"] });
    assert.equal(s.allows("https://x.test/admin/users"), false);
    assert.equal(s.allows("https://x.test/blog/draft"), false);
    assert.equal(s.allows("https://x.test/blog/draft/x"), true);
    assert.equal(s.allows("https://x.test/blog"), true);
  });
  it("accepts full URLs as patterns and ignores empty ones", () => {
    const s = buildPathScope("https://x.test/", { includePaths: ["https://x.test/help", "", "  "] });
    assert.equal(s.allows("https://x.test/help/a"), true);
    assert.equal(s.allows("https://x.test/other"), false);
  });
  it("signature differs by scope", () => {
    assert.notEqual(
      buildPathScope("https://x.test/a").signature,
      buildPathScope("https://x.test/b").signature
    );
  });
});
