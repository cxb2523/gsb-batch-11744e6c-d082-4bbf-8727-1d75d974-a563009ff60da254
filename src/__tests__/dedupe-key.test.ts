import { test } from "node:test";
import assert from "node:assert/strict";
import {
  canonicalResultUrl,
  resultDedupeKey,
} from "../extract/dedupe-key.js";
import { dedupePropertyListings } from "../extract/real-estate.js";
import { dedupeHotelListings } from "../extract/hotels.js";

test("canonicalResultUrl strips tracking, www, hash and trailing slash only", () => {
  assert.equal(
    canonicalResultUrl("https://WWW.Rentola.com/listing/1/?utm_source=x#top"),
    "rentola.com/listing/1"
  );
  assert.notEqual(
    canonicalResultUrl("https://rentola.com/listing/1"),
    canonicalResultUrl("https://rentola.com/listing/2")
  );
});

test("same provider + different URL is kept; exact repeat dropped", () => {
  const base = {
    title: "2 bed apartment",
    address: "Sydney NSW",
    portal: "rentola.com",
    country: "AU",
    extractedVia: "json-ld" as const,
  };
  const out = dedupePropertyListings([
    { ...base, url: "https://rentola.com/listing/1" },
    { ...base, url: "https://rentola.com/listing/2" },
    { ...base, url: "https://www.rentola.com/listing/1?utm_medium=x" },
  ] as never);
  assert.equal(out.length, 2);
});

test("hotels with the same name on different URLs are both kept", () => {
  const h = { name: "Hilton Sydney", country: "AU", provider: "booking.com", extractedVia: "json-ld" };
  const out = dedupeHotelListings([
    { ...h, url: "https://booking.com/a" },
    { ...h, url: "https://expedia.com/b", provider: "expedia.com" },
    { ...h, url: "https://booking.com/a" },
  ] as never);
  assert.equal(out.length, 2);
  assert.equal(resultDedupeKey("https://a.com/x", "N"), resultDedupeKey("https://www.a.com/x/", "n"));
});
