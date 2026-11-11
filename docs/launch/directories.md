# Directory and awesome-list submissions (drafts, not submitted)

Submit after the launch PR merges, so the README these lists link to is the new one. Read each list's CONTRIBUTING first, since most want alphabetical order and one line per entry.

Repo status checked 2026-11-03:

| Where | Stars | Status | Section | Entry |
|---|---|---|---|---|
| [punkpeye/awesome-mcp-servers](https://github.com/punkpeye/awesome-mcp-servers) | 97k | active | Search & Data Extraction | A |
| [hesreallyhim/awesome-claude-code](https://github.com/hesreallyhim/awesome-claude-code) | 57k | active | Tooling / MCP | B |
| [e2b-dev/awesome-ai-agents](https://github.com/e2b-dev/awesome-ai-agents) | 31k | active (last push Aug 2026) | Open-source → tools | B |
| [lorien/awesome-web-scraping](https://github.com/lorien/awesome-web-scraping) | 8k | active | JavaScript / Node | C |
| [modelcontextprotocol/registry](https://github.com/modelcontextprotocol/registry) | 7k | active | Official registry as `io.github.brainfish-ai/webcrawl`. **Live since 1.3.9.** The release workflow republishes `server.json` after each npm publish. | — |
| [ChatGPT / Codex plugin directory](https://platform.openai.com/plugins) | — | package ready | Hosted `webcrawl.app/mcp` with OAuth. Build the ZIP with `npm run package:chatgpt` (see `plugins/chatgpt/`), upload, connect, submit. | — |
| appcypher/awesome-mcp-servers | 6k | **archived, skip** | — | — |

Also submit through the web forms on Smithery, Glama, mcp.so and PulseMCP (listing pages read from the npm package and repo).

## Entry A (MCP lists)

```markdown
- [brainfish-ai/webcrawl-anything](https://github.com/brainfish-ai/webcrawl-anything) 📇 🏠 ☁️ - Scrape, map, crawl, search (incl. CVEs via NVD/OSV) and monitor the web. Runs locally with no API key; every result carries source URL, fetch tier and content hash.
```

(📇 = TypeScript, 🏠 = local, ☁️ = optional cloud. Match the list's legend.)

## Entry B (agent and Claude Code lists)

```markdown
- [webcrawl](https://github.com/brainfish-ai/webcrawl-anything) - Gives Claude Code, Cursor and Codex the web: scrape → Markdown, crawl docs into RAG corpora, search, CVE lookup and change monitors. `npx webcrawl setup`, local, no API key, MIT.
```

## Entry C (web-scraping list)

```markdown
- [webcrawl](https://github.com/brainfish-ai/webcrawl-anything) - CLI and MCP server for scraping, crawling and site maps to clean Markdown, with Chrome TLS impersonation and a browser fallback. Local, MIT.
```

## PR body for awesome lists

> Adds webcrawl, an MIT CLI + MCP server for scraping, crawling, search and monitoring that runs locally with no API key. Placed alphabetically in {section}. I'm one of the maintainers.
