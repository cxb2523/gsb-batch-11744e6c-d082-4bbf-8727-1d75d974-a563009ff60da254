# Launch post (draft, not published)

**Angle:** your coding agent can read the web locally, free, with no API key, and it shows its evidence.

One promise, repeated everywhere. Every number below came from `scripts/benchmark-local.mjs` and anyone can reproduce it.

---

## Title options

- Give your coding agent the web. Free, local, one command.
- webcrawl: the open-source web layer for Claude Code, Cursor and Codex
- I gave my coding agent a browser it can run without an API key

## Post

Coding agents are great until they need something from the web. Then you're pasting docs, copying CVE pages, or paying per request for a scraping API.

**webcrawl** is an open-source CLI and MCP server that lets Claude Code, Cursor, Codex and any MCP client scrape, map, crawl, search and monitor the web. It runs on your machine with no account and no API key.

```bash
npx webcrawl setup
```

That single command wires up the MCP server and agent skills for every agent it finds. Then ask your agent things like:

> Is CVE-2024-3094 in anything I depend on? Give me the CVSS score, KEV status and fixed versions, then check my lockfile.

> Map https://docs.stripe.com/webhooks, crawl it, and write me a cheat sheet with a source link under each section.

> Watch Hacker News every hour and tell me when a story about MCP hits the front page.

### Evidence, not vibes

Every result carries its provenance: source URL, which tier fetched it, a content hash, and what the extractor could not see. Your agent can cite instead of guess.

### Numbers

Run on a laptop (darwin/arm64, Node 22) on 2026-11-03, `--mode local`, no API key, 5 runs per case, cache bypassed for scrapes:

| Task | Example | OK | p50 | p95 |
|---|---|---|---|---|
| Docs page → Markdown | `scrape https://docs.stripe.com/webhooks` | 5/5 | 1.08 s | 1.23 s |
| Docs page → Markdown | `scrape https://react.dev/learn` | 5/5 | 175 ms | 322 ms |
| Docs page → Markdown | `scrape https://developer.mozilla.org/…/JavaScript` | 5/5 | 149 ms | 161 ms |
| GitHub repo summary | `scrape https://github.com/torvalds/linux` | 5/5 | 220 ms | 641 ms |
| arXiv paper | `scrape https://arxiv.org/abs/1706.03762` | 5/5 | 152 ms | 344 ms |
| Hacker News front page | `scrape https://news.ycombinator.com` | 5/5 | 568 ms | 599 ms |
| Site map | `map https://react.dev -n 20` | 5/5 | 84 ms | 257 ms |
| Web search | `search "postgres jsonb index performance"` | 5/5 | 1.06 s | 1.65 s |
| Web search | `search "next.js app router vs pages router differences"` | 2/5 | 885 ms | 988 ms |
| CVE lookup (NVD + OSV) | `search "CVE-2024-3094" -c security --sub cve` | 5/5 | 1.26 s | 1.35 s |

**47/50 runs succeeded. Median p50 was 568 ms.**

The miss is real. Keyless local search relies on public search pages, and some queries come back empty when those engines throttle. If you need reliable search, add a Brave or Serper key, or use the hosted API. Reproduce it with:

```bash
git clone https://github.com/brainfish-ai/webcrawl-anything && cd webcrawl-anything
npm install && npm run build
node scripts/benchmark-local.mjs --runs 5
```

### What it's good at, and what it isn't

- Good at docs, repos, papers, news, CVEs, site maps, crawls into Markdown for RAG, and change monitors with alerts.
- When a site challenges automated clients, it escalates through a Chrome TLS fingerprint and then a real browser session. It respects robots.txt and keeps polite rates.
- It isn't for logging in as you, buying things, or getting around paywalls.
- Not great yet at direct PDF URLs in local mode and YouTube transcripts. Both are open issues if you want to help.

### Open source, MIT

The CLI, the MCP server and the engine that runs the hosted API at webcrawl.app are the same code. Every target plugin you add (it's one file plus a test, see CONTRIBUTING.md) ships to both.

**Repo:** https://github.com/brainfish-ai/webcrawl-anything
**Show what you built:** the Discussions "Show and tell" category. The best builds get featured in the README.

---

## Notes for the poster

- Lead with the demo animation (`docs/assets/demo.svg`) or the clip `docs/assets/clips/1-cve.svg`, not the table.
- Keep the 2/5 row in. HN readers trust a benchmark that shows a miss.
- Don't say "bypasses Cloudflare/DataDome". Say "sites that challenge automated clients".
- Re-run the benchmark on launch day and update the date and numbers.
