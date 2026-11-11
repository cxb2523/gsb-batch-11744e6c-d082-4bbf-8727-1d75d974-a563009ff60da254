# Corpus-building recipes

## llms.txt as canonical page list

Many modern docs sites publish `/llms.txt` — a Markdown manifest of their crawlable pages. When present it beats sitemap guessing:

```bash
npx webcrawl scrape https://example.com/llms.txt
```

Parse the returned Markdown's link list; crawl those URLs directly.

## Sitemap pagination and large sites

- `map` merges sitemap.xml + robots.txt + link-graph discovery; prefer `--filter` to keep the list on-topic.
- For sites with sitemap indexes (sitemap-of-sitemaps), map the root and filter to section URLs, then map each section separately.
- Budget: `crawl -n <max>` pages per invocation. For a 500-page docs site, loop section-by-section with short pauses between batches rather than one giant run.

## Batching pattern (pseudo)

```
sections = map(site, filter=<topic>)
for section in sections:
    crawl(section, n=25)
    sleep(polite-interval)
```

## Chunking for RAG

webcrawl Markdown preserves semantic heading structure. Recommended:

- Split on `\n## ` (H2) boundaries; keep the H1 + intro with the first chunk.
- Chunk target: 300-800 tokens; break long sections at paragraph boundaries.
- Metadata per chunk: `{url, crawledAt, sha256, h2}` — enables citation-grounded retrieval ("answer + the doc page it came from").

## Hash-dedupe across runs

```js
// state: Map<sha256, {url, firstSeen}>
for (page of newCrawl) {
  if (state.has(page.sha256)) continue;        // unchanged, skip
  write(`${corpus}/${slug(page.url)}.md`, page);
  state.set(page.sha256, { url: page.url, firstSeen: now });
}
// re-embed only files whose hash is new since the last embedding run
```

## Storage layout

```
corpus/
  raw/<domain>/<slug>.md      # full pages with frontmatter (url, crawledAt, sha256)
  chunks/<domain>/<slug>.jsonl  # chunked, embedding-ready
  state.json                  # hash index
```

## Politeness

- Default concurrency is bounded by the engine; don't raise it for protected sites.
- Space batches 5-10s apart on the same domain.
- Re-crawl only sections that change (docs changelogs often list what moved).
