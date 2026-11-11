# @webcrawl/mcp

Model Context Protocol (MCP) server for **[Webcrawl Anything](https://github.com/brainfish-ai/webcrawl-anything)**.

Gives Claude Code, Cursor, Codex, Windsurf, and Gemini CLI live access to web search, structured verticals (shopping, flights, hotels, real-estate, local business, CVEs), page reading for JavaScript-heavy sites, and PDF/Office parsing. It runs on your machine with no API key and no account.

## One-Command Agent Setup

Register `@webcrawl/mcp` and install the `webcrawl-anything` Agent Skill (`SKILL.md`) automatically:

```bash
npx webcrawl setup
```

## Manual MCP Configuration

Add to `.cursor/mcp.json`, `~/.claude.json`, or your MCP client config:

```json
{
  "mcpServers": {
    "webcrawl": {
      "command": "npx",
      "args": ["-y", "@webcrawl/mcp@latest"],
      "env": {
        "WEBCRAWL_MCP_SCHEMA_PROFILE": "compact"
      }
    }
  }
}
```

### Optional: webcrawl.app cloud

Local mode is the default and needs nothing else. The packaged server loads the local engine from `dist/core`; if that import fails it exits with an error instead of silently calling webcrawl.app. To run the same tools on the hosted service, either:

- add `"WEBCRAWL_API_KEY": "wc_live_..."` to `env` above (get a key at [webcrawl.app](https://webcrawl.app)), or
- connect your client to the hosted endpoint `https://webcrawl.app/mcp` and sign in in the browser. No local install is needed.

`WEBCRAWL_MODE` can be `local`, `cloud` or `auto` (default: local unless a key is set).

### Compact Schema Profile

Set `WEBCRAWL_MCP_SCHEMA_PROFILE=compact` (default when installed via `npx webcrawl setup`) to minimize tool schema token usage in context-constrained agents while keeping full server-side validation. Set `WEBCRAWL_MCP_SCHEMA_PROFILE=full` for verbose parameter descriptions.

## Tools Provided

- `web_search` — Search the web or structured verticals (`shopping`, `flights`, `hotels`, `real-estate`, `business`, `security`, `academic`, `tech`, `news`).
- `web_read` — Fetch a URL and return clean Markdown with target evidence.
- `web_parse` / `web_parse_status` — Parse PDFs (native + OCR), Word/Excel/PowerPoint files, YouTube videos, and audio/video into Markdown.
- `web_map` — Discover all URLs on a domain (`sitemap.xml`, `robots.txt`, and link graph).
- `web_crawl` — Crawl up to 25 pages starting from a URL.
- `web_extract` — Extract structured JSON from a URL using a prompt or JSON Schema.
- `web_rerank` — Rerank candidate documents by relevance to a query.
- `web_monitor` — Watch a page, URL list or site on a schedule with trigger conditions and email/webhook alerts (cloud only).
- `search_categories` — List all supported search categories, subcategories, and filters.

## License

MIT
