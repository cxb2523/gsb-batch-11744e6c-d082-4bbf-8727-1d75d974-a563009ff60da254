# Contributing to Webcrawl Anything

Thank you for helping build **Webcrawl Anything**! Because the open-source CLI (`packages/cli`), MCP server (`packages/mcp`), and the hosted [`webcrawl.app`](https://webcrawl.app) cloud API all run on the **exact same `src/` engine**, every target plugin, parser improvement, or vertical extractor you contribute immediately benefits both local zero-key users and cloud agents.

---

## Quick Development Setup

Requires **Node.js >= 20**.

```bash
git clone https://github.com/brainfish-ai/webcrawl-anything.git
cd webcrawl-anything
npm install

# Run the core engine & target registry test suite
npm test

# Build and test packages/client, packages/cli, and packages/mcp
npm run test:packages
```

---

## Adding a New Crawl Target in 3 Steps

All targets live in `src/targets/` and implement the `CrawlTargetPlugin` interface defined in `src/targets/types.ts`.

### 1. Define your `CrawlTargetPlugin`

Create a plugin in `src/targets/` (for example, `src/targets/hackernews.ts` or inside `src/targets/developer.ts`):

```ts
import type { CrawlTargetPlugin } from "./types.js";

export const myTargetPlugin: CrawlTargetPlugin = {
  id: "my-target",
  name: "My Target Name",
  category: "developer", // "web" | "documents" | "media" | "commerce" | "travel" | "real-estate" | "security" | "developer"
  returns: "What structured fields and Markdown this target returns",
  requirements: "Built-in zero-key HTML/JSON extractor",
  examples: ["npx webcrawl scrape https://example.com/item/123"],
  matches({ url, query, category }) {
    if (url && /example\.com\/item\/\d+/i.test(url)) {
      return { matched: true, confidence: 0.95, reason: "Example item URL" };
    }
    return { matched: false, confidence: 0 };
  },
  async inspect(input) {
    // Parse input.html or input.markdown and return structured data + evidence provenance
    return {
      targetId: "my-target",
      targetName: "My Target Name",
      markdown: input.markdown,
      structured: {
        kind: "my_item",
      },
      evidence: {
        targetId: "my-target",
        tier: "native-parser",
        contentHash: "my-target:123",
        latencyMs: 0,
        sourceUrl: input.url,
        matchedSignals: ["selector:.item-header"],
        limitations: [],
      },
    };
  },
};
```

### 2. Register the Target in `src/targets/registry.ts`

Import your plugin in `src/targets/registry.ts` and add it to `BUILTIN_TARGET_PLUGINS`. It will automatically appear in:
- `npx webcrawl targets`
- `GET /v1/targets`
- Local & cloud `inspectTarget()` / `resolveTarget()` calls

### 3. Add a Deterministic Unit Test

Add a fixture-based test in `src/__tests__/targets.test.ts` verifying:
- `resolveTarget({ url })` matches your target with expected confidence.
- `inspectTarget({ url, html })` extracts structured fields and populates `evidence.matchedSignals` and `evidence.limitations`.

Run `npm test && npm run test:packages` before opening your Pull Request.

---

## Where to start

- [`good first issue`](https://github.com/brainfish-ai/webcrawl-anything/issues?q=is%3Aopen+label%3A%22good+first+issue%22) issues are scoped to one file plus a test.
- [`target-plugin`](https://github.com/brainfish-ai/webcrawl-anything/issues?q=is%3Aopen+label%3Atarget-plugin) issues ask for a new site. Comment "I'll take this" so nobody duplicates the work.
- Found a site that breaks? Open a bug with the exact `npx webcrawl …` command and its output.

## How you get credit

- Your name and PR link go into the release notes for the version that ships your change (generated from merged PRs).
- You appear in the README contributors grid automatically.
- Built something with webcrawl? Post it in [Discussions › Show and tell](https://github.com/brainfish-ai/webcrawl-anything/discussions/categories/show-and-tell). The best builds get the `showcase` label and a spot in the README.
