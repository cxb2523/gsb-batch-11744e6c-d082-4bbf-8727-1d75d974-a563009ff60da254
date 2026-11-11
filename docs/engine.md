# How the engine works

Webcrawl's local engine is in `src/`. The CLI and MCP server call the same code.

## JavaScript pages

Static HTML is fetched without a browser. Pages that only fill in after scripts run are opened in local Chrome over the Chrome DevTools Protocol. After load, the driver polls main-content text length and DOM size (including open shadow roots and same-origin iframes) until the page looks stable. Visible loading placeholders and empty content mounts stay "not ready"; after the first content growth the quiet window is about **1.5s** so staggered chunk fetches are included, otherwise about **500ms**. The post-load wait is capped (about **10 seconds**) so never-settling pages cannot hang. Tiny finished pages (404, OK, image-only) are allowed to finish early. The non-JS fetch path is unchanged. Lazy-below-the-fold content is not scrolled into view.

Each attempt has a hard timeout. Chrome launch and CDP connect default to **4 seconds** (`WEBCRAWL_CHROME_CONNECT_TIMEOUT_MS`, or `connectTimeoutMs` on the renderer). Page navigation and DOM wait default to **18 seconds** (`WEBCRAWL_CHROME_TIMEOUT_MS` / `timeoutMs`). Those budgets are separate: a hung binary that never answers over CDP fails fast instead of waiting out the page timeout, while a slow but working JS page (often around 7 seconds) still has time to render after Chrome connects.

If Chrome hangs, the engine retries with the other headless flag. dump-dom is skipped when the Chrome process is still running but CDP never became ready (dump-dom would hang too). If a page needs JavaScript and rendering still fails, the result is `success: false` with `needsJs: true` and an actionable error, not an unrendered navigation shell.

## Extract

Structured extract walks nested objects and arrays in the caller schema. Script, style, and template tags are stripped before card matching so inline script text is not treated as page content. An empty extract for a custom prompt or schema is reported as failure.

## Search

Keyless search fans out across public sources (DuckDuckGo, Brave HTML, Wikipedia, Hacker News, Bing RSS), merges and dedupes URLs, retries thin results, and fills up to `n`. Optional keyed providers run only when their environment variables are set.
