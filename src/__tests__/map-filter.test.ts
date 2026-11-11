import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { filterMappedLinks } from "../local-engine.js";

describe("filterMappedLinks (map --filter)", () => {
  const links = [
    "https://docs.stripe.com/payments",
    "https://docs.stripe.com/webhooks",
    "https://docs.stripe.com/webhooks/signatures",
    "https://docs.stripe.com/billing",
    "https://docs.stripe.com/api/webhook_endpoints",
  ];

  it("keeps matching URLs when the needle is past the caller's -n window", () => {
    // Without post-discovery filter+slice, discovering only the first 2 URLs
    // would miss every /webhooks/ path.
    const out = filterMappedLinks(links, "webhooks", 2);
    assert.deepEqual(out, [
      "https://docs.stripe.com/webhooks",
      "https://docs.stripe.com/webhooks/signatures",
    ]);
  });

  it("matches case-insensitively as a substring", () => {
    const out = filterMappedLinks(links, "WEBHOOKS", 10);
    assert.deepEqual(out, [
      "https://docs.stripe.com/webhooks",
      "https://docs.stripe.com/webhooks/signatures",
    ]);
  });

  it("returns the first `limit` URLs when search is empty", () => {
    assert.deepEqual(filterMappedLinks(links, undefined, 2), links.slice(0, 2));
    assert.deepEqual(filterMappedLinks(links, "   ", 2), links.slice(0, 2));
  });
});
