import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { WebcrawlClient } from "@webcrawl/client";
import { LOCAL_ENGINE_LOAD_ERROR, MAX_OUTPUT_CHARS, createServer } from "../src/index.js";

type Handler = (url: string, body: Record<string, unknown> | undefined) => { status?: number; json: unknown };

async function connect(handler: Handler) {
  const calls: Array<{ url: string; body?: Record<string, unknown> }> = [];
  const f = (async (url: string, init: RequestInit) => {
    const body = init.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : undefined;
    calls.push({ url, body });
    const r = handler(url, body);
    return new Response(JSON.stringify(r.json), { status: r.status ?? 200 });
  }) as unknown as typeof fetch;
  const server = createServer(new WebcrawlClient({ apiKey: "k", baseUrl: "https://x.test", fetch: f }));
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(a);
  const client = new Client({ name: "t", version: "0" });
  await client.connect(b);
  return { client, calls };
}

const text = (r: unknown) => ((r as { content: Array<{ text: string }> }).content[0]?.text ?? "");

describe("webcrawl MCP server", () => {
  it("lists all tools with instructions", async () => {
    const { client } = await connect(() => ({ json: {} }));
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map((t) => t.name).sort(), [
      "search_categories",
      "web_crawl",
      "web_extract",
      "web_map",
      "web_monitor",
      "web_parse",
      "web_parse_status",
      "web_read",
      "web_rerank",
      "web_search",
    ]);
    assert.match(client.getInstructions() ?? "", /web_search/);
  });

  // ChatGPT/Codex plugin review requires all three hints as explicit booleans on every tool.
  it("declares explicit readOnly/destructive/openWorld hints on every tool", async () => {
    const { client } = await connect(() => ({ json: {} }));
    const { tools } = await client.listTools();
    for (const t of tools) {
      for (const hint of ["readOnlyHint", "destructiveHint", "openWorldHint"] as const) {
        assert.equal(typeof t.annotations?.[hint], "boolean", `${t.name} is missing ${hint}`);
      }
      if (t.annotations?.readOnlyHint) assert.equal(t.annotations.destructiveHint, false, `${t.name}: read-only tools are not destructive`);
    }
    const byName = Object.fromEntries(tools.map((t) => [t.name, t.annotations]));
    assert.equal(byName.web_parse?.readOnlyHint, false, "web_parse can queue a background job");
    assert.equal(byName.web_monitor?.destructiveHint, true, "web_monitor can delete monitors");
  });

  it("web_search formats structured hotels and passes arguments through", async () => {
    const { client, calls } = await connect(() => ({
      json: { hotels: [{ name: "Hotel A", priceText: "$120/night", provider: "booking.com", url: "https://b.com/a" }], credits: { charged: 2, remaining: 98 } },
    }));
    const r = await client.callTool({ name: "web_search", arguments: { query: "hotels shibuya", category: "hotels", sites: ["booking.com"] } });
    assert.ok(!r.isError);
    assert.match(text(r), /1\. Hotel A \(\$120\/night · booking\.com\)/);
    assert.match(text(r), /98 remaining/);
    assert.equal(calls[0].url, "https://x.test/v1/search");
    assert.deepEqual(calls[0].body?.filters, { sites: ["booking.com"] });
  });

  it("web_search with success:false is a tool error", async () => {
    const { client } = await connect(() => ({
      json: { success: false, error: "Keyless search engines returned no results.", data: [] },
    }));
    const r = await client.callTool({ name: "web_search", arguments: { query: "x" } });
    assert.equal(r.isError, true);
    assert.match(text(r), /Keyless search engines returned no results/);
  });

  it("web_extract with success:false is a tool error", async () => {
    const { client } = await connect(() => ({
      json: { success: false, error: "Extraction produced no data matching the prompt/schema.", data: {} },
    }));
    const r = await client.callTool({
      name: "web_extract",
      arguments: { url: "https://a.com", prompt: "quotes" },
    });
    assert.equal(r.isError, true);
    assert.match(text(r), /Extraction produced no data matching the prompt\/schema/);
  });

  it("web_read returns markdown with title", async () => {
    const { client } = await connect(() => ({ json: { data: { title: "Hi", markdown: "# body" } } }));
    const r = await client.callTool({ name: "web_read", arguments: { url: "https://a.com" } });
    assert.match(text(r), /^# Hi\n\n# body/);
  });

  it("caps oversized output", async () => {
    const { client } = await connect(() => ({ json: { markdown: "x".repeat(MAX_OUTPUT_CHARS * 2) } }));
    const r = await client.callTool({ name: "web_read", arguments: { url: "https://a.com" } });
    assert.ok(text(r).length < MAX_OUTPUT_CHARS + 100);
    assert.match(text(r), /\[truncated \d+ characters\]/);
  });

  it("maps API errors to isError with actionable text", async () => {
    const { client } = await connect(() => ({ status: 402, json: { success: false, error: "credits" } }));
    const r = await client.callTool({ name: "web_map", arguments: { url: "https://a.com" } });
    assert.equal(r.isError, true);
    assert.match(text(r), /out of credits/i);
  });

  it("rejects bad input via schema (max_pages > 25)", async () => {
    const { client } = await connect(() => ({ json: {} }));
    const r = await client.callTool({ name: "web_crawl", arguments: { url: "https://a.com", max_pages: 99 } }).catch((e: unknown) => ({ isError: true, e }));
    assert.equal(r.isError, true);
  });

  it("web_rerank and search_categories work", async () => {
    const { client, calls } = await connect((url) =>
      url.endsWith("/rerank") ? { json: { results: [{ description: "best doc", score: 0.91 }] } } : { json: { categories: ["general"] } }
    );
    const r = await client.callTool({ name: "web_rerank", arguments: { query: "q", documents: ["a", "b"], top_k: 1 } });
    assert.match(text(r), /1\. \[0\.910\] best doc/);
    assert.equal(calls[0].body?.topK, 1);
    const c = await client.callTool({ name: "search_categories", arguments: {} });
    assert.match(text(c), /general/);
  });

  it("web_parse shows OCR and skipped pages honestly", async () => {
    const { client, calls } = await connect(() => ({
      json: {
        title: "Report",
        markdown: "Body",
        metadata: { parse: { kind: "pdf", pages: 3, pagesOcr: [2], pagesSkipped: [{ page: 3, reason: "ocr_failed" }], warnings: [] } },
        credits: { charged: 2, remaining: 10 },
      },
    }));
    const r = await client.callTool({ name: "web_parse", arguments: { url: "https://a.com/r.pdf", ocr: "auto", pages: [1, 2, 3] } });
    assert.match(text(r), /OCR on pages 2/);
    assert.match(text(r), /not read: p3 \(ocr_failed\)/);
    assert.match(text(r), /# Report\n\nBody/);
    assert.deepEqual(calls[0].body, { url: "https://a.com/r.pdf", ocr: "auto", pages: [1, 2, 3] });
  });

  it("web_parse in background returns a run id, web_parse_status returns the result", async () => {
    const { client } = await connect((url) =>
      url.includes("/v1/runs/")
        ? { json: { status: "completed", result: { title: "T", markdown: "Done", metadata: { parse: { kind: "audio", durationSeconds: 61 } } } } }
        : { status: 202, json: { success: true, id: "wrun_1", status: "running" } }
    );
    const r = await client.callTool({ name: "web_parse", arguments: { url: "https://a.com/a.mp3", background: true } });
    assert.match(text(r), /run wrun_1/);
    const s = await client.callTool({ name: "web_parse_status", arguments: { id: "wrun_1" } });
    assert.match(text(s), /61s of audio/);
    assert.match(text(s), /Done/);
  });

  it("supports compact schema profile via schemaProfile option", async () => {
    const server = createServer(
      new WebcrawlClient({ apiKey: "k", baseUrl: "https://x.test", fetch: (async () => new Response("{}")) as unknown as typeof fetch }),
      { schemaProfile: "compact" }
    );
    const [a, b] = InMemoryTransport.createLinkedPair();
    await server.connect(a);
    const client = new Client({ name: "t", version: "0" });
    await client.connect(b);
    const { tools } = await client.listTools();
    const searchTool = tools.find((t) => t.name === "web_search");
    assert.ok(searchTool);
    assert.match(searchTool.description ?? "", /Search the web or structured verticals/);
  });

  it("web_monitor creates, lists, checks, pauses, and deletes watches", async () => {
    const { client, calls } = await connect((url, body) => {
      if (url.endsWith("/v1/monitors") && body) {
        return {
          json: {
            success: true,
            monitor: {
              id: "mon_42",
              name: "Pricing Watch",
              mode: body.mode ?? "page",
              url: body.url,
              intervalMinutes: 60,
              status: "active",
              conditionJev: body.condition,
              lastDiffSummary: "Initial snapshot captured",
            },
            initialCheck: {
              conditionResult: { met: false, summary: "price ($79) < 50 -> false" },
              snapshot: "# Plans\nPro: $79/mo",
            },
            credits: { charged: 1, remaining: 99 },
          },
        };
      }
      if (url.endsWith("/v1/monitors/mon_42/check")) {
        return {
          json: {
            success: true,
            monitor: {
              id: "mon_42",
              name: "Pricing Watch",
              mode: "page",
              url: "https://example.com/pricing",
              intervalMinutes: 60,
              status: "active",
              lastConditionMet: true,
              lastDiffSummary: "Price dropped to $45",
            },
            check: {
              conditionResult: { met: true, summary: "price ($45) < 50 -> true" },
            },
          },
        };
      }
      if (url.endsWith("/v1/monitors/mon_42") && body) {
        return {
          json: {
            success: true,
            monitor: {
              id: "mon_42",
              name: "Pricing Watch",
              url: "https://example.com/pricing",
              intervalMinutes: 60,
              status: body.status ?? "paused",
            },
          },
        };
      }
      if (url.endsWith("/v1/monitors/mon_42")) {
        return { json: { success: true, deleted: true } };
      }
      return {
        json: {
          success: true,
          monitors: [
            {
              id: "mon_42",
              name: "Pricing Watch",
              mode: "page",
              url: "https://example.com/pricing",
              intervalMinutes: 60,
              status: "active",
              conditionJev: "price < 50",
            },
          ],
        },
      };
    });

    const created = await client.callTool({
      name: "web_monitor",
      arguments: {
        url: "https://example.com/pricing",
        name: "Pricing Watch",
        watch_for: "Plan prices",
        condition: "price < 50",
        notify_email: "true",
      },
    });
    assert.ok(!created.isError);
    assert.match(text(created), /Pricing Watch \[mon_42\]/);
    assert.match(text(created), /rule: price < 50/);
    assert.equal(calls[0].body?.notifyEmail, true);

    const listed = await client.callTool({ name: "web_monitor", arguments: { action: "list" } });
    assert.match(text(listed), /monitors \(1\):/);

    const checked = await client.callTool({ name: "web_monitor", arguments: { action: "check", id: "mon_42" } });
    assert.match(text(checked), /Price dropped to \$45/);

    const paused = await client.callTool({ name: "web_monitor", arguments: { action: "pause", id: "mon_42" } });
    assert.match(text(paused), /\(paused/);

    const deleted = await client.callTool({ name: "web_monitor", arguments: { action: "delete", id: "mon_42" } });
    assert.match(text(deleted), /Monitor deleted\./);
  });

  it("stdio binary never silently falls back to webcrawl.app", () => {
    const bin = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "../src/bin.ts"), "utf8");
    assert.doesNotMatch(bin, /falling back to https:\/\/webcrawl\.app/);
    assert.match(bin, /loadLocalEngineClient/);
    assert.match(bin, /process\.exit\(1\)/);
    assert.match(LOCAL_ENGINE_LOAD_ERROR, /Reinstall @webcrawl\/mcp/);
  });
});
