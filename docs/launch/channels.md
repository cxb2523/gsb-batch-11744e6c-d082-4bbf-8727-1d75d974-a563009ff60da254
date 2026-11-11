# Staggered launch kit (drafts, nothing posted)

One angle everywhere: **your coding agent can read the web locally, free, with no API key, and it shows its evidence.**
Long-form source: [`launch-post.md`](./launch-post.md). Clips: [`../demos.md`](../demos.md).

## Schedule

The REA pattern was to own one channel per day, then let creators carry it. Don't post everywhere at once.

| Day | Channel | Owner | Goal |
|---|---|---|---|
| D-3 | Merge launch PR, re-run `scripts/benchmark-local.mjs`, update numbers | Eng | Every claim reproducible |
| D-2 | DM creator list (see [`creators.md`](./creators.md)) with early access and prompts | Founder | Third-party demos ready for D+1 |
| D0, Tue/Wed 8–9am PT | **Show HN** | Founder | Front page. Reply to every comment for 6h |
| D0 +2h | **X thread** (links to HN, not the repo) | Founder | Drive HN votes and RTs from agent devs |
| D+1 | **Reddit**: r/ClaudeAI, r/LocalLLaMA, r/mcp (one per 3h, native post, no link-only) | Founder | Comments and installs |
| D+1 → D+7 | Creator videos go live and get quote-tweeted from the project account | Founder | The REA multiplier |
| D+3 | **Product Hunt** (12:01am PT) | Founder | Second spike for a different audience |
| D+3 → D+10 | **Newsletters**: TLDR AI, Ben's Bites, Console.dev, Changelog News, Latent Space, MCP-focused newsletters | Founder | Long tail |
| D+7 | "Week one" follow-up post: stars, best community builds, what we fixed | Founder | Second wave and contributor pull |

**Rules:** never ask for upvotes. Link HN from X, not the other way round. Answer the hard questions (ethics, robots.txt, why local-first) in the first hour.

---

## Show HN

**Title** (80 char max): `Show HN: Webcrawl – free, local web scraping and search for coding agents (MCP)`

**URL:** https://github.com/brainfish-ai/webcrawl-anything

**First comment** (post immediately):

> Hi HN, I built webcrawl because my coding agents kept hitting a wall whenever a task needed the web: pasted docs, copied CVE pages, or a paid scraping API per request.
>
> It's an MIT CLI and MCP server. `npx webcrawl setup` wires it into Claude Code, Cursor, Codex or any MCP client. Everything runs on your machine with no account or key: scrape → Markdown, map, crawl, search, CVE lookup (NVD + OSV), and change monitors with webhook alerts.
>
> Every result carries provenance (source URL, fetch tier, content hash, and what the extractor couldn't see) so the agent can cite instead of guess.
>
> Benchmark, reproducible with `node scripts/benchmark-local.mjs`: 47/50 runs OK across docs, GitHub, arXiv, HN, maps, search and CVEs, median p50 568 ms on a laptop. The misses were keyless web search getting throttled, and that's filed as issue #8.
>
> What it won't do: log in as you, buy things or get past paywalls. It respects robots.txt.
>
> I'd love feedback on the target-plugin API (one file plus a test) and which sites break for you.

**Prepared answers:**
- *Why not a hosted scraping API?* Same job, but local and free by default, with MCP and agent skills built in and provenance on every result. The hosted API is optional and runs the same engine.
- *Is this ethical?* It reads what a normal browser can, respects robots.txt and keeps polite rates. No purchase or auto-apply automation.
- *Why so fast?* Most pages are a single TLS-impersonated fetch plus native parsers. A real browser only starts when a site challenges automated clients.

---

## X thread

**1/** (attach `docs/assets/clips/1-cve.svg` exported as MP4, or a 20s screen recording)
> Gave Claude Code the web. Free, local, no API key.
>
> "Is CVE-2024-3094 in my deps?" CVSS, KEV status, fixed versions and a lockfile verdict, with links.
>
> One command: npx webcrawl setup
>
> Open source 👇

**2/**
> It's a CLI + MCP server for any coding agent:
> • scrape any URL → clean Markdown
> • map + crawl docs sites into RAG corpora
> • search, including CVEs from NVD + OSV
> • monitors: "ping me when MCP hits the HN front page"

**3/** (attach `docs/assets/clips/2-docs-cheatsheet.svg`)
> Every answer ships with evidence: source URL, fetch tier, content hash, and what it couldn't see.
>
> Your agent cites instead of guessing.

**4/**
> Benchmarked on a laptop, no key: 47/50 runs OK, median p50 568ms.
> The 3 misses are keyless search getting throttled, and they're in the table on purpose.
> Reproduce: node scripts/benchmark-local.mjs

**5/**
> MIT. Adding a site is one file + one test.
> Repo: github.com/brainfish-ai/webcrawl-anything
> On HN today: <HN link>

---

## Reddit

Write a native post per sub. Lead with the problem and the clip, put the link at the end, and disclose that you're the author.

**r/ClaudeAI.** *I made Claude Code able to read any docs site / CVE / repo locally, free, no API key (open source MCP)*
> Body: problem (pasting docs) → demo 2 prompt and the result → `npx webcrawl setup` → link → "I'm the author, happy to take feature requests."

**r/LocalLLaMA.** *Open-source local web layer for agents: scrape, crawl to RAG corpus, search, no cloud key*
> Lead with demo 7 (RAG corpus) and the benchmark table. Stress that it's local and needs no account.

**r/mcp.** *webcrawl MCP server: scrape/map/crawl/search/monitor, compact schema profile, runs locally*
> Lead with tool list and schema size (`WEBCRAWL_MCP_SCHEMA_PROFILE=compact`), plus the setup config snippet.

---

## Product Hunt

- **Name:** Webcrawl Anything
- **Tagline** (60 chars): `Give your coding agent the web. Free, local, no API key.`
- **Topics:** Developer Tools, Artificial Intelligence, Open Source
- **Gallery:** social preview, then clips 1, 2, 3 (monitor), then the benchmark table as an image
- **Maker comment:** the first two paragraphs of the HN comment, plus "launch offer: N free hosted credits for PH folks". Confirm credits before posting.

## Newsletter pitch (≤90 words)

> Subject: Open-source web layer for coding agents (free, local)
>
> webcrawl gives Claude Code, Cursor and Codex the web: scrape → Markdown, crawl docs into RAG corpora, search including CVEs, and change monitors. `npx webcrawl setup`, MIT, runs locally with no API key, and every result carries provenance so agents cite instead of guess. Reproducible benchmark: 47/50 OK, median 568 ms on a laptop. Repo: github.com/brainfish-ai/webcrawl-anything. Happy to send a 30s clip.
