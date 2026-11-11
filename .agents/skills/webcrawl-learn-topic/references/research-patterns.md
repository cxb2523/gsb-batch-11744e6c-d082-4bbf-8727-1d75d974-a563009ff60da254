# Research patterns for topic learning

## Query variation

Run 2-3 searches per topic with different phrasings — coverage gaps are the #1 failure mode:

- Plain natural language: `"how does transformer attention work"`
- Keyword form: `"transformer self-attention architecture explained"`
- Time-bounded: `"transformer attention 2026 state of"` for fast-moving topics

Category filters: `-c arxiv` for papers, `-c github` for repos/implementations, `-c security` for CVE-flavored topics. Default web search for everything else.

## Source-tier ranking

1. **Primary**: official docs, standards, papers, vendor announcements, source code.
2. **Secondary**: reputable engineering blogs, conference talks, well-known newsletters.
3. **Tertiary**: forums, Q&A, tutorials (use for signals, verify against tier 1-2).

Cross-check contested claims across 2+ independent domains. If two good sources disagree, present both with dates.

## Dedupe and near-dupes

The same story gets syndicated widely. Dedupe by content: if two pages make the same points with the same facts, keep the earlier/more-primary one and note the other as corroboration, not a second source.

## Paywalled sources

Don't fabricate content from a paywall page. Options: search for the same fact on open sources, use the abstract (papers), or note the paywall in the digest and move on. Never quote a paywalled article you didn't actually read.

## Handling protected sources

Docs/airline/booking sites that challenge bots: the anti-bot ladder (webcrawl-protected-sites skill) usually clears them. Don't skip primary sources just because they're protected — that biases the research.

## Reading-list format

```markdown
- [Title](url) — why it matters (1 line) · date
```

Rank by signal-to-length, put the single best "start here" link first.

## Digest quality checklist

- TL;DR answers the question directly (no throat-clearing).
- Every claim cited to a crawled URL.
- Controversies/disagreements surfaced, not smoothed over.
- Dates visible for fast-moving claims.
- Open questions are genuinely open (you searched and couldn't answer them).
