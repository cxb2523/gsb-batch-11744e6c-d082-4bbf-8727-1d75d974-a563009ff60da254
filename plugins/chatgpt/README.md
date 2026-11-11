# ChatGPT / Codex plugin

Plugin package for the OpenAI plugin directory (shared by ChatGPT and Codex). It connects to the hosted MCP endpoint `https://webcrawl.app/mcp`. Users sign in with OAuth, and ChatGPT registers itself as a client through dynamic client registration.

The local, no-key MCP server (`npx @webcrawl/mcp`) is not part of this package. OpenAI only accepts local (stdio) MCP plugins from allowlisted partners.

## Build the ZIP

```bash
npm run package:chatgpt
```

This validates `plugin.json`, `mcp.json`, the onboarding skill and every referenced asset, then writes `dist/webcrawl-chatgpt.zip`.

## What lives where

| File | Purpose |
|---|---|
| `plugin.json` | Listing metadata, default prompts, reviewer test cases, publication countries |
| `mcp.json` | The hosted server. No auth block: the Agent Plugins schema rejects extra keys on HTTP servers, and the portal finds OAuth (DCR + PKCE) through `/.well-known/oauth-protected-resource/mcp` |
| `skills/get-started/SKILL.md` | Onboarding skill shown after install |
| `assets/` | Logos and composer icons, light and dark |

## Updating

- **Tool changes** ship through `@webcrawl/mcp` and the hosted deploy. After the first publish, OpenAI rescans the server and picks them up without a new ZIP.
- **Metadata or skill changes** need a new ZIP. Bump `version` in `plugin.json`, rebuild, then upload it in the portal.
