/**
 * Live smoke test for @webcrawl/curl-impersonate.
 *
 * Hits example.com (no WAF), stubhub + expedia (AWS WAF: 403/429 at
 * Chrome-136-era fingerprints like impit's, full content at chrome150),
 * and booking.com (JS challenge — this tier is expected to see the
 * challenge/fall to the browser tier).
 *
 * Redirects are followed manually hop-by-hop (max 5), the same way the
 * engine's followSafely guard drives rawGet.
 *
 * Usage: npx tsx scripts/impersonate-live.ts
 */

import { impersonateFetch, ensureImpersonate } from "../packages/curl-impersonate/src/index.js";

const TARGETS: Array<{ label: string; url: string; expect: string }> = [
  { label: "example.com", url: "https://example.com/", expect: "200, real (small) page" },
  {
    label: "stubhub (AWS WAF)",
    url: "https://www.stubhub.com/concert-tickets/",
    expect: "200 + real listings after redirect hops",
  },
  {
    label: "expedia (AWS WAF)",
    url: "https://www.expedia.com/Hotel-Search?destination=Chicago",
    expect: "200 + real results",
  },
  {
    label: "booking.com (JS challenge)",
    url: "https://www.booking.com/Share-wODRfr",
    expect: "redirect/challenge — falls to browser tier",
  },
];

function isChallengeOrShell(text: string, status: number): boolean {
  const lower = text.slice(0, 8000).toLowerCase();
  if (status === 403 || status === 429 || status === 503) return true;
  return (
    lower.includes("challenge-container") ||
    lower.includes("awswafintegration") ||
    lower.includes("awswafcookiedomainlist") ||
    lower.includes("bot or not") ||
    lower.includes("just a moment") ||
    lower.includes("cf-browser-verification")
  );
}

async function follow(url: string, maxHops = 5) {
  let current = url;
  for (let hop = 0; hop <= maxHops; hop++) {
    const res = await impersonateFetch(current, { timeoutMs: 20_000 });
    const location = res.headers["location"];
    if (res.status >= 300 && res.status < 400 && location) {
      current = new URL(location, current).href;
      continue;
    }
    return { res, finalUrl: current, hops: hop };
  }
  throw new Error("too many redirects");
}

async function main() {
  const bin = await ensureImpersonate();
  console.log(`binary: ${bin ?? "UNAVAILABLE"}`);
  if (!bin) process.exit(1);

  let pass = 0;
  const results: string[] = [];
  for (const t of TARGETS) {
    const t0 = performance.now();
    try {
      const { res, finalUrl, hops } = await follow(t.url);
      const ms = Math.round(performance.now() - t0);
      const text = Buffer.from(res.body).toString("utf8");
      const title = text.match(/<title[^>]*>([^<]*)/i)?.[1] ?? "";
      const challenge = isChallengeOrShell(text, res.status);
      const real = res.status === 200 && !challenge && text.length > 100;

      let ok: boolean;
      let verdict: string;
      if (t.label.startsWith("booking.com")) {
        // JS-challenge domain: a redirect or challenge at this tier is the
        // expected outcome; the browser tier owns solving it.
        ok = challenge || res.status >= 300 || res.status === 202;
        verdict = challenge || res.status >= 300 ? "redirect/challenge (expected)" : `${res.status}`;
      } else {
        ok = real;
        verdict = challenge ? "CHALLENGE SHELL" : real ? "REAL CONTENT" : `${res.status} ${text.length}B`;
      }
      console.log(
        `${ok ? "PASS" : "FAIL"} ${t.label}: ${res.status} ${ms}ms ${res.body.byteLength}B ${hops}hops verdict=${verdict} title="${title.slice(0, 50)}"`
      );
      if (!ok) {
        console.log(`     final: ${finalUrl}`);
        console.log(`     expect: ${t.expect}`);
      }
      if (ok) pass++;
    } catch (e) {
      console.log(`FAIL ${t.label}: ${(e as Error).message}`);
    }
  }
  results.push(`${pass}/${TARGETS.length} targets behaved as expected`);
  console.log(`\n${results[0]}`);
  process.exit(pass === TARGETS.length ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
