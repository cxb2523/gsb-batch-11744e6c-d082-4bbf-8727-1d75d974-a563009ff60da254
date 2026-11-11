/**
 * Live AWS WAF challenge check against a real site through the local browser.
 *
 *   npx tsx scripts/awswaf-live.ts https://www.booking.com/Share-wODRfr
 *
 * Gates on INTERACT_LOCAL_PLAYWRIGHT=true (the same local-browser opt-in the
 * interact driver uses) so it never runs as part of a plain test suite.
 * Prints detection verdict, stealth outcome, title and markdown length.
 */
import { crawlPageWithAwsWaf } from "../src/engine/awswaf.js";

const url = process.argv[2] || "https://www.booking.com/Share-wODRfr";

if (process.env.INTERACT_LOCAL_PLAYWRIGHT !== "true") {
  console.error("Set INTERACT_LOCAL_PLAYWRIGHT=true to run the live AWS WAF check.");
  process.exit(2);
}

const started = Date.now();
try {
  const page = await crawlPageWithAwsWaf(url, { stealthTimeoutMs: 45_000 });
  console.log(
    JSON.stringify(
      {
        url,
        detectedAwsWaf: Boolean(page.awsWaf),
        solved: page.markdown.length > 0,
        blocked: page.blocked ?? false,
        title: page.title,
        statusCode: page.statusCode ?? null,
        markdownLen: page.markdown.length,
        linksCount: page.linksCount,
        markdownPreview: page.markdown.slice(0, 400),
        error: page.error ?? null,
        durationMs: Date.now() - started,
      },
      null,
      2
    )
  );
  process.exit(page.markdown.length > 0 ? 0 : 1);
} catch (err) {
  console.error(err instanceof Error ? err.stack || err.message : String(err));
  process.exit(1);
}
