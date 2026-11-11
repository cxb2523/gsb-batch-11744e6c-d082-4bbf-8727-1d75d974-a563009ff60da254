# Troubleshooting webcrawl scrapes

## Empty or boilerplate output

- **Challenge shell** (tiny output, "Checking your browser", status 403/429/202): the site challenged the client — escalate via the protected-sites tier ladder (see the `webcrawl-protected-sites` skill). Do NOT conclude "no content exists".
- **JS-rendered SPA** (skeleton with no data): the page renders client-side. Local mode escalates to installed Chrome (`webcrawl doctor` reports the binary; override with `WEBCRAWL_CHROME_PATH`) and hydrates the DOM. Empty or bot-blocked pages return `success: false`, `blocked: true` instead of an empty success.
- **Wrong URL** (404): check the URL actually resolves in a browser before debugging webcrawl.

## Command failures

| Symptom | Fix |
|---|---|
| `impit` binary missing | `npx webcrawl doctor` — reinstall or use cloud mode |
| Timeout on large pages | retry once; if persistent, the site may rate-limit — slow down or add proxy |
| `extract` returns generic `{app_name, product_features}` | Pass `--prompt` and/or `--schema`; extract follows those instead of the default product-feature shape. |
| `extract` returns nothing | The prompt may target content not in the Markdown (JS-rendered). Scrape first, inspect the Markdown, adjust the prompt. |
| Local `search` is empty or errors | Keyless HTML SERPs (DuckDuckGo/Brave) are often challenged. The engine falls back to Wikipedia, Hacker News, and Bing RSS; if those are empty too it returns `success: false` with a hint to set `BRAVE_SEARCH_API_KEY` or `SERPER_API_KEY`. |
| `map` finds few URLs | Site may block sitemap.xml; try `--filter` with broader terms or crawl from the index page |

## Rate limiting & politeness

- Space requests to the same domain at least a few seconds apart for one-off work; for crawling, rely on the engine's built-in concurrency limits.
- The engine caches by content hash — repeated scrapes of the same URL in one session are free.
- If you see repeated 429s, stop and back off; don't retry-storm.

## When to escalate to cloud

Local engine covers everything zero-key except: managed residential proxy fleets (bring your own via `WEBCRAWL_PROXY_*`), and sub-50ms global cache. If a site defeats all local tiers including stealth browser, `npx webcrawl login` switches to the cloud stealth fleet (`--mode cloud`).

## Diagnostics fields

- `tier`: which fetch tier served the request (`impit-tls`, `impersonate`, `proxy-impersonate`, browser).
- `proxyBytes`: bytes through the residential proxy (0 = direct).
- `sha256`: content hash for dedupe/caching.
- Run `npx webcrawl doctor` for engine readiness before deep debugging.
