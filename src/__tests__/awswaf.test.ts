import { test } from "node:test";
import assert from "node:assert/strict";
import { isAwsWafChallenge, isBlockedLike } from "../engine/awswaf.js";

/** Captured from https://www.booking.com/Share-wODRfr (AWS WAF challenge interstitial, HTTP 202). */
const BOOKING_AWS_WAF_CHALLENGE = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title></title>
    <script type="text/javascript" nonce="nSe2IkHppYyMZSL">
        window.awsWafCookieDomainList = ['booking.com'];
    </script>
    <script type="text/javascript" src="https://www.booking.com/__challenge_h78IRKX3kpQxScCExxShBNwRUlb/d8c14d4960ca/a18a4859af9c/challenge.js" nonce="nSe2IkHppYyMZSL"></script>
</head>
<body>
    <div id="challenge-container"></div>
    <script type="text/javascript" nonce="nSe2IkHppYyMZSL">
        AwsWafIntegration.saveReferrer();
        AwsWafIntegration.checkForceRefresh().then((forceRefresh) => {
            if (forceRefresh) {
                AwsWafIntegration.forceRefreshToken().then(() => {
                    window.location.href = newHref;
                });
            } else {
                AwsWafIntegration.getToken().then(() => {
                    window.location.href = newHref;
                });
            }
        });
    </script>
    <noscript>
        <h1>JavaScript is disabled</h1>
        In order to continue, we need to verify that you're not a robot.
    </noscript>
</body>
</html>`;

const VERCEL_CHECKPOINT = `<!doctype html><html><head><title>Vercel Security Checkpoint</title></head>
<body><p>We're verifying your browser</p><script src="/.well-known/vercel/security/static/challenge.v2.min.js"></script></body></html>`;

const REAL_BOOKING_PAGE = `<!doctype html><html><head><title>Shibuya STREAM HOTEL - Booking.com</title></head>
<body><main><h1>Shibuya STREAM HOTEL</h1><p>Hotel in Shibuya Ward, Tokyo. Scored 9.2 from 2105 reviews.</p></main></body></html>`;

test("isAwsWafChallenge detects the captured booking.com AWS WAF interstitial (HTTP 202)", () => {
  assert.equal(isAwsWafChallenge(BOOKING_AWS_WAF_CHALLENGE, 202), true);
  // Marker alone flags it regardless of status.
  assert.equal(isAwsWafChallenge(BOOKING_AWS_WAF_CHALLENGE, 200), true);
  assert.equal(isAwsWafChallenge(BOOKING_AWS_WAF_CHALLENGE), true);
});

test("isAwsWafChallenge does not flag real pages, other bot checks or empty inputs", () => {
  assert.equal(isAwsWafChallenge(REAL_BOOKING_PAGE, 200), false);
  assert.equal(isAwsWafChallenge(VERCEL_CHECKPOINT, 200), false);
  assert.equal(isAwsWafChallenge("", undefined), false);
  // A real HTML page with content is not a challenge even on 202.
  assert.equal(isAwsWafChallenge("<html><body><p>ok</p></body></html>", 202), false);
});

test("isAwsWafChallenge treats a 202 HTML shell with no visible text as a challenge (status-only case)", () => {
  // Indistinguishable from the interstitial without markers, and routing an
  // empty 202 page to the browser is safe, so the heuristic errs on challenge.
  assert.equal(isAwsWafChallenge("<html><body></body></html>", 202), true);
  assert.equal(isAwsWafChallenge("<html><head><title></title></head><body><noscript>x</noscript></body></html>", 202), true);
});

test("isBlockedLike covers upstream Cloudflare/Vercel checks plus AWS WAF", () => {
  assert.equal(isBlockedLike(BOOKING_AWS_WAF_CHALLENGE, 202), true);
  assert.equal(isBlockedLike(VERCEL_CHECKPOINT, 200), true);
  assert.equal(isBlockedLike("<html><title>Just a moment...</title></html>", 403), true);
  assert.equal(isBlockedLike(REAL_BOOKING_PAGE, 200), false);
});

test("isAntiBotChallenge (shared detector) folds in AWS WAF detection", async () => {
  const { isAntiBotChallenge } = await import("../engine/fetcher.js");
  // The captured AWS WAF interstitial used to pass as real content.
  assert.equal(isAntiBotChallenge(BOOKING_AWS_WAF_CHALLENGE, 202), true);
  assert.equal(isAntiBotChallenge(BOOKING_AWS_WAF_CHALLENGE, 200), true);
  // Status-only empty shell.
  assert.equal(isAntiBotChallenge("<html><body></body></html>", 202), true);
  // False-positive guards: real 202 with content, real page, other bot checks.
  assert.equal(isAntiBotChallenge("<html><body><p>ok</p></body></html>", 202), false);
  assert.equal(isAntiBotChallenge(REAL_BOOKING_PAGE, 200), false);
  assert.equal(isAntiBotChallenge("<html><title>Just a step</title></html>", 200), false);
  assert.equal(isAntiBotChallenge("<html><title>Just a moment...</title></html>", 200), true);
  assert.equal(isAntiBotChallenge(VERCEL_CHECKPOINT, 200), true);
  // A 202 JSON API body is not an HTML challenge shell.
  assert.equal(isAntiBotChallenge('{"accepted": true}', 202), false);
});

test("isAntiBotChallenge detects IP-reputation interstitials (stubhub, expedia) even at status 200", async () => {
  const { isAntiBotChallenge } = await import("../engine/fetcher.js");
  // stubhub-style shell served after the TLS gate passes (datacenter IP).
  // Can arrive cached with status 200, so text markers must catch it alone.
  const STUBHUB_INTERSTITIAL = `<!DOCTYPE html><html><head><title>stubhub.com</title></head>
<body><noscript><p>Please enable JavaScript and disable any ad blocker to continue.</p></noscript>
<div>Please enable JS and disable any ad blocker</div></body></html>`;
  assert.equal(isAntiBotChallenge(STUBHUB_INTERSTITIAL, 403), true);
  assert.equal(isAntiBotChallenge(STUBHUB_INTERSTITIAL, 200), true);
  // expedia-style "Bot or Not?" shell.
  const EXPEDIA_INTERSTITIAL = `<!DOCTYPE html><html><head><title>Bot or Not?</title></head>
<body><h1>Show us your human side...</h1><p>We can't tell if you're a human or a bot.</p></body></html>`;
  assert.equal(isAntiBotChallenge(EXPEDIA_INTERSTITIAL, 429), true);
  assert.equal(isAntiBotChallenge(EXPEDIA_INTERSTITIAL, 200), true);
  // Curly-apostrophe variant of the expedia copy.
  assert.equal(
    isAntiBotChallenge("<html><body><p>We can’t tell if you’re a human or a bot.</p></body></html>", 200),
    true
  );
  // False-positive guards: real pages mentioning ads/JS/bots in passing.
  assert.equal(isAntiBotChallenge("<html><body><p>Our site requires JavaScript for maps. Ad blocker detected? Click here.</p></body></html>", 200), false);
  assert.equal(isAntiBotChallenge("<html><body><p>This bot can't tell if it's human or not — a real article about bots.</p></body></html>", 200), false);
});

test("sandbox challenge guard treats an AWS WAF interstitial as non-content", async () => {
  const { isChallengeResult } = await import("../sandbox.js");
  // The curl tier's guard mirrors isAntiBotChallenge, so the AWS WAF
  // interstitial must be flagged and force a fall-through to the browser tier.
  assert.equal(isChallengeResult(BOOKING_AWS_WAF_CHALLENGE, "", 200), true);
  assert.equal(isChallengeResult(BOOKING_AWS_WAF_CHALLENGE, BOOKING_AWS_WAF_CHALLENGE, 200), true);
  // Real content is not a challenge.
  assert.equal(isChallengeResult(REAL_BOOKING_PAGE, "Shibuya STREAM HOTEL", 200), false);
});
