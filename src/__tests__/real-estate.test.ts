import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  extractPropertyListingsFromHtml,
  ldImage,
} from "../extract/real-estate.js";

const ld = (o: unknown) =>
  `<script type="application/ld+json">${JSON.stringify(o)}</script>`;

describe("ldImage", () => {
  it("reads strings, ImageObjects and arrays", () => {
    assert.equal(ldImage("https://a.test/1.jpg"), "https://a.test/1.jpg");
    assert.equal(ldImage({ "@type": "ImageObject", url: "https://a.test/2.jpg" }), "https://a.test/2.jpg");
    assert.equal(ldImage({ contentUrl: "https://a.test/3.jpg" }), "https://a.test/3.jpg");
    assert.equal(ldImage([null, { url: "https://a.test/4.jpg" }]), "https://a.test/4.jpg");
    assert.equal(ldImage(42), undefined);
  });

  it("strips CSS that leaked into the value", () => {
    assert.equal(
      ldImage("https://cdn.test/p.jpg?width=1600), url(/fallback.svg);background-size:contain"),
      "https://cdn.test/p.jpg?width=1600"
    );
  });
});

describe("JSON-LD listing photos", () => {
  const page = "https://www.rent.com.au/properties/surry-hills-nsw-2010";

  it("takes the photo from a sibling Event that points at the listing url", () => {
    const html =
      ld({
        "@type": "Residence",
        url: "https://www.rent.com.au/property/159-reservoir-st-6520948",
        name: "159 Reservoir Street, surry hills NSW 2010",
        address: [{ "@type": "PostalAddress", streetAddress: "159 Reservoir Street", addressLocality: "surry hills" }],
      }) +
      ld({
        "@type": "Event",
        url: "https://www.rent.com.au/property/159-reservoir-st-6520948",
        name: "Inspection Time",
        image: "https://cdn.rent.com.au/photos/159-primary.jpg",
      });
    const [l] = extractPropertyListingsFromHtml(html, page, "AU");
    assert.equal(l?.image, "https://cdn.rent.com.au/photos/159-primary.jpg");
  });

  it("reads an ImageObject image on the listing itself", () => {
    const html = ld({
      "@type": "Apartment",
      url: "/property/1",
      name: "1 Crown Street, Surry Hills",
      image: { "@type": "ImageObject", url: "/photos/1.jpg" },
    });
    const [l] = extractPropertyListingsFromHtml(html, page, "AU");
    assert.equal(l?.image, "https://www.rent.com.au/photos/1.jpg");
  });
});
