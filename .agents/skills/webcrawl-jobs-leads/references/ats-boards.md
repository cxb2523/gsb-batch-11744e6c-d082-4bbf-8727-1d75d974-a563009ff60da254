# ATS board patterns (Greenhouse, Lever, Workable, Ashby)

## Canonical URL patterns

| ATS | Board URL | Notes |
|---|---|---|
| Greenhouse | `https://boards.greenhouse.io/<company>` | Server-rendered HTML; `embed` variant at `boards.greenhouse.io/embed/job_board?for=<company>` |
| Lever | `https://jobs.lever.co/<company>` | Server-rendered; JSON at `jobs.lever.co/<company>/.json` — prefer scraping the JSON |
| Workable | `https://<company>.workable.com` | JS-rendered; jobs list at `/<company>/jobs` |
| Ashby | `https://jobs.ashbyhq.com/<company>` | JS-rendered; posts API at `jobs.ashbyhq.com/<company>` |

## Extraction tips

- **Server-rendered boards** (Greenhouse, Lever): the zero-key tiers read them directly; `extract` with a prompt like "all postings: title, department, location, absolute URL" works first try.
- **JSON endpoints** (Lever): scrape `jobs.lever.co/<company>/.json` — structured data with no extraction prompt needed.
- **JS-rendered boards** (Workable, Ashby): if `extract` returns nothing, the stealth-browser tier renders the board first; check `npx webcrawl doctor`.
- **JSON-LD**: many boards embed schema.org `JobPosting` JSON-LD (fields: `title`, `datePosted`, `validThrough`, `employmentType`, `jobLocation`, `baseSalary`) — webcrawl preserves JSON-LD in the Markdown; prefer it over CSS selectors when present.

## Pagination

- Greenhouse boards paginate at ~100 postings; follow `?page=N` links found in the board HTML.
- Lever's JSON endpoint returns everything at once — no pagination needed.
- For very large boards, consider scoping by department via the board's department filter URLs.

## Diff/state file schema

```json
{
  "acme": {
    "seen": {
      "https://boards.greenhouse.io/acme/jobs/123456": { "title": "Senior SRE", "firstSeen": "2026-11-01", "lastSeen": "2026-11-01" }
    },
    "lastChecked": "2026-11-01T09:00:00Z"
  }
}
```

On each run: postings whose URL is absent from `seen` = **new** (surface these); URLs in `seen` but absent from the board = **filled/withdrawn**; mark `lastSeen` accordingly.

## Politeness

One pass per board per day is plenty — postings change daily at most. ATS boards are generally not bot-protected, but hammering them can get your IP flagged anyway. Never log in, never apply automatically.
