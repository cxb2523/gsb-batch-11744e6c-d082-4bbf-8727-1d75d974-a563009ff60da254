import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  dedupeHotelListings,
  extractHotelListingsFromHtml,
} from "../extract/hotels.js";

const fixture = readFileSync(
  new URL("./fixtures/booking-district.html", import.meta.url),
  "utf8"
);
const PAGE = "https://www.booking.com/district/jp/tokyo/shibuya.html";

test("Booking.com district cards yield named hotels with photo, stars and rating", () => {
  const hotels = extractHotelListingsFromHtml(fixture, PAGE, "AU");
  assert.equal(hotels.length, 3);

  const stream = hotels.find((h) => h.name === "Shibuya STREAM HOTEL");
  assert.ok(stream, "expected Shibuya STREAM HOTEL");
  assert.equal(stream.extractedVia, "html-cards");
  assert.equal(stream.provider, "booking.com");
  assert.equal(stream.starRating, 4);
  assert.match(stream.image ?? "", /^https:\/\/cf\.bstatic\.com\/xdata\/images\/hotel\//);
  assert.equal(
    stream.url,
    "https://www.booking.com/hotel/jp/shibuya-stream-excel-tokyu.html"
  );

  for (const h of hotels) {
    assert.ok(h.image, `${h.name} has a photo`);
    assert.ok(!/</.test(h.name), `${h.name} has no markup`);
    assert.ok(!h.url.includes("aid="), "affiliate params stripped");
  }
});

test("dedupeHotelListings mixes providers when over the cap", () => {
  const mk = (provider: string, i: number) => ({
    name: `${provider} Hotel ${i}`,
    priceText: "",
    url: `https://${provider}/h/${i}`,
    provider,
    extractedVia: "json-ld" as const,
  });
  const many = [
    ...Array.from({ length: 20 }, (_, i) => mk("kayak.com", i)),
    ...Array.from({ length: 5 }, (_, i) => mk("booking.com", i)),
  ];
  const out = dedupeHotelListings(many, 10);
  assert.equal(out.length, 10);
  assert.equal(out.filter((h) => h.provider === "booking.com").length, 5);
});

test("Booking.com 'Price from' text is read as nightly price", () => {
  const hotels = extractHotelListingsFromHtml(fixture, PAGE, "AU");
  const priced = hotels.filter((h) => h.pricePerNight);
  assert.ok(priced.length >= 1);
  assert.equal(priced[0].currency, "AUD");
  assert.ok(hotels.some((h) => h.guestRating && h.guestRating > 7 && h.guestRating <= 10));
});
