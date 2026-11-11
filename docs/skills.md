# Webcrawl Agent Skills

Webcrawl ships as [Agent Skills](https://agentskills.io/specification) so any coding agent (Claude Code, Cursor, Codex, Gemini CLI, Windsurf, and anything else that reads `SKILL.md`) can use it.

## Install

```bash
# All skills from this repo
npx skills add brainfish-ai/webcrawl-anything

# Or the MCP server + skill in one shot
npx webcrawl setup
```

Skills live in [`.agents/skills/`](../.agents/skills/) and follow the open Agent Skills spec: `name` matches the directory, `description` is the routing trigger, and details live in `references/*.md` (progressive disclosure).

## The eight skills

| Skill | One-liner | Hero |
|---|---|---|
| [`webcrawl-ticket-watch`](../.agents/skills/webcrawl-ticket-watch/SKILL.md) | Event ticket price/availability monitor that pings your phone when tickets hit your target | ⭐ launch hero |
| [`webcrawl-jobs-leads`](../.agents/skills/webcrawl-jobs-leads/SKILL.md) | Crawl careers pages & ATS boards into structured job data; daily new-posting diffs | ⭐ launch hero |
| [`webcrawl-deal-watch`](../.agents/skills/webcrawl-deal-watch/SKILL.md) | Black Friday / price-drop watchlist with free mobile push alerts (ntfy.sh) | ⭐ launch hero |
| [`webcrawl-crawl`](../.agents/skills/webcrawl-crawl/SKILL.md) | Any URL → clean Markdown: scrape, crawl, map, extract, categorized search | core |
| [`webcrawl-protected-sites`](../.agents/skills/webcrawl-protected-sites/SKILL.md) | Read sites that challenge automated clients: TLS-impersonate → proxy → real-browser ladder | flagship |
| [`webcrawl-learn-topic`](../.agents/skills/webcrawl-learn-topic/SKILL.md) | Deep-research any topic into a cited digest with a reading list | |
| [`webcrawl-research-corpus`](../.agents/skills/webcrawl-research-corpus/SKILL.md) | Build RAG-ready Markdown corpora from docs sites (llms.txt, sitemaps, hash dedupe) | |
| [`webcrawl-real-estate`](../.agents/skills/webcrawl-real-estate/SKILL.md) | Property listing search & watch with the built-in extractor; new-listing/price-cut alerts | |

## Trigger phrases (routing test matrix)

Each skill's `description` is what routes a user request to it. Use these phrases to test routing (positive: should trigger; negative: should NOT trigger).

### webcrawl-crawl
- ✅ "Scrape https://github.com/torvalds/linux into Markdown" · "crawl the Stripe webhooks docs" · "map this site and find the API pages" · "extract the top stories from HN" · "what does this page say?"
- ❌ "read my local file" · "fix this function" · "summarize this text I pasted" (content already present)

### webcrawl-protected-sites
- ✅ "this page returns Access denied / Checking your browser" · "scrape Expedia" · "getting 403 from this site" · "page comes back empty — is it a bot check?" · "read this StubHub listing"
- ❌ "this URL 404s" · "the site is down for me too" · normal scrape already works

### webcrawl-learn-topic
- ✅ "learn about vector databases" · "deep research on WebGPU adoption" · "build me a cited report on RAG eval" · "reading list for CRDTs" · "what's new in Zig this year?"
- ❌ "scrape this one URL" (webcrawl-crawl) · "summarize this PDF I have" · offline questions

### webcrawl-research-corpus
- ✅ "crawl docs.stripe.com into Markdown files for RAG" · "build a knowledge base from this site" · "prepare these pages for embeddings" · "corpus building for fine-tuning"
- ❌ single-page scrape · protected-site debug · non-web sources

### webcrawl-ticket-watch
- ✅ "watch these Cubs tickets, alert me below $85 all-in" · "is the Taylor Swift show sold out?" · "track SeatGeek prices for this event" · "ping my phone when good seats open"
- ❌ "buy me tickets" · "snipe tickets at on-sale" · "bulk-buy for resale"

### webcrawl-jobs-leads
- ✅ "find all SRE postings at companies using Kubernetes" · "track new jobs on acme's Greenhouse board" · "build a lead list of startups hiring ML engineers" · "normalize these job listings into a table"
- ❌ "apply to jobs for me" · "scrape my logged-in LinkedIn" · "email these recruiters"

### webcrawl-deal-watch
- ✅ "watch this Amazon item, ping my phone below $248" · "track Black Friday deals for my list" · "alert me when the PS5 goes back in stock" · "monitor these prices for Cyber Monday"
- ❌ "auto-buy this when it's cheap" · "cart-hold at checkout" · "mass-scrape the marketplace"

### webcrawl-real-estate
- ✅ "find 3BR houses in Marrickville under $1.4M" · "watch this suburb for new listings" · "track rent prices in Bronte" · "alert me when this property's price drops"
- ❌ "estimate my mortgage" · "contact the agent" · non-property pages

## Skill anatomy (for contributors)

```text
.agents/skills/<skill-name>/
├── SKILL.md          # frontmatter (name, description, license, metadata) + short body
└── references/       # detail docs loaded only when needed (progressive disclosure)
```

Rules (from the [spec](https://agentskills.io/specification)): `name` = directory name, lowercase/hyphens, ≤64 chars; `description` ≤1024 chars, written as "Use when… / Covers… / Trigger for… / Skip for…"; body under ~500 lines with runnable commands and a validation loop.

## Compliance

Every skill embeds the same rules: respect robots.txt and site terms, keep request rates polite, public pages only, never automate purchases or applications, never bypass purchase limits. The anti-bot ladder exists so a legitimate automated client can read what a normal browser could — not to hammer sites.
