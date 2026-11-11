#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { WebcrawlClient, resolveConfig } from "@webcrawl/client";
import { loadLocalEngineClient } from "./load-local-engine.js";
import { createServer, resolveSchemaProfile, type WebcrawlLikeClient } from "./server.js";

const cfg = resolveConfig();
let client: WebcrawlLikeClient;

if (cfg.effectiveMode === "local") {
  try {
    client = await loadLocalEngineClient();
    process.stderr.write(
      "webcrawl-mcp: running in zero-key LOCAL engine mode. Set WEBCRAWL_API_KEY (or run `webcrawl login`) to upgrade to webcrawl.app cloud.\n"
    );
  } catch (e) {
    process.stderr.write(`${e instanceof Error ? e.message : String(e)}\n`);
    process.exit(1);
  }
} else {
  client = new WebcrawlClient({ apiKey: cfg.apiKey, baseUrl: cfg.baseUrl, userAgent: "webcrawl-mcp/0.1" });
}

await createServer(client, { schemaProfile: resolveSchemaProfile() }).connect(new StdioServerTransport());
