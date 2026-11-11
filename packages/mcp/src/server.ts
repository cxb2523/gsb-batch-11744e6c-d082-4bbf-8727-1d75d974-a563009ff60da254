import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebcrawlClient, WebcrawlError, describeError } from "@webcrawl/client";
import { z } from "zod";
import {
  formatCredits,
  formatCrawl,
  formatMap,
  formatMonitor,
  formatParse,
  formatScrape,
  formatSearch,
  truncate,
} from "./format.js";

export type SchemaProfile = "compact" | "full";

export interface McpServerOptions {
  version?: string;
  schemaProfile?: SchemaProfile;
}

export type WebcrawlLikeClient = Pick<
  WebcrawlClient,
  "baseUrl" | "search" | "scrape" | "parse" | "run" | "map" | "crawl" | "extract" | "rerank" | "categories"
> & {
  targets?: () => Promise<Record<string, unknown>>;
  monitors?: WebcrawlClient["monitors"];
  getMonitor?: WebcrawlClient["getMonitor"];
  createMonitor?: WebcrawlClient["createMonitor"];
  checkMonitor?: WebcrawlClient["checkMonitor"];
  updateMonitor?: WebcrawlClient["updateMonitor"];
  deleteMonitor?: WebcrawlClient["deleteMonitor"];
};

const INSTRUCTIONS = `Webcrawl Anything gives you live web & target inspection access (zero-key local engine or webcrawl.app cloud).
- web_search: find pages or structured results. Set category for flights, hotels, real-estate, shopping, news, local business, security (CVEs), academic or tech. Results are localised to the user.
- web_read: read one URL as clean markdown with target evidence (websites, SPAs, GitHub, ArXiv, llms.txt).
- web_parse: read a PDF, Office file, YouTube video, image, or audio/video at a URL as markdown (OCR and transcripts included). For long files set background and poll web_parse_status.
- web_map: list the URLs on a site before deciding what to scrape.
- web_crawl: read several pages of one site (max 25).
- web_extract: pull structured JSON from one URL with a prompt or schema.
- web_rerank: order your own documents by relevance to a query.
- web_monitor: watch a page, list of URLs, or whole website on a schedule with trigger conditions and email/webhook alerts (create, list, get, check, pause, resume, delete).
- search_categories: list valid categories, subcategories, filters, and supported crawl targets.`;

type ToolResult = { content: Array<{ type: "text"; text: string }>; isError?: boolean };

const ok = (text: string): ToolResult => ({ content: [{ type: "text", text: truncate(text) }] });

export function resolveSchemaProfile(env: NodeJS.ProcessEnv = process.env): SchemaProfile {
  const raw = (
    env.WEBCRAWL_MCP_SCHEMA_PROFILE ||
    env.WEBCRAWL_MCP_INPUT_SCHEMA_PROFILE ||
    "full"
  )
    .trim()
    .toLowerCase();
  return raw === "compact" ? "compact" : "full";
}

/**
 * Builds the webcrawl MCP server around an API or local engine client. Shared by
 * the stdio binary (`npx webcrawl-mcp`) and the hosted Streamable HTTP endpoint (`webcrawl.app/mcp`).
 */
export function createWebcrawlMcpServer(
  client: WebcrawlLikeClient,
  versionOrOpts: string | McpServerOptions = "0.1.0"
): McpServer {
  const opts: McpServerOptions =
    typeof versionOrOpts === "string" ? { version: versionOrOpts } : versionOrOpts;
  const version = opts.version ?? "0.1.0";
  const compact = (opts.schemaProfile ?? resolveSchemaProfile()) === "compact";
  const desc = <T extends z.ZodTypeAny>(schema: T, text: string): T =>
    compact ? schema : schema.describe(text);

  const server = new McpServer({ name: "webcrawl", version }, { instructions: INSTRUCTIONS });

  const run = async (fn: () => Promise<string>): Promise<ToolResult> => {
    try {
      return ok(await fn());
    } catch (e) {
      return { isError: true, content: [{ type: "text", text: describeError(e, client.baseUrl) }] };
    }
  };

  server.registerTool(
    "web_search",
    {
      title: "Web search",
      description: compact
        ? "Search the web or structured verticals (shopping, flights, hotels, real-estate, business, security CVEs, academic, tech)."
        : "Search the web. Use `category` for structured results (flights, hotels, real-estate, shopping with prices, news, local business, security: CVE records with CVSS, affected and fixed versions). Results are localised to the user unless a place is given.",
      inputSchema: {
        query: desc(z.string().min(1), "What to search for"),
        category: desc(
          z.string().optional(),
          "e.g. general, news, shopping, flights, hotels, real-estate, business, security, academic, tech. See search_categories."
        ),
        subcategory: desc(z.string().optional(), "e.g. buy or rent for real-estate, cve for security"),
        limit: desc(z.number().int().min(1).max(20).optional(), "Max results, default 5"),
        country: desc(z.string().optional(), "ISO country code, e.g. AU"),
        city: z.string().optional(),
        sites: desc(z.array(z.string()).optional(), "Only these domains, e.g. [\"booking.com\"]"),
        include_content: desc(
          z.boolean().optional(),
          "Also fetch page markdown for each result (slower, more credits)"
        ),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
    },
    ({ query, category, subcategory, limit, country, city, sites, include_content }) =>
      run(async () => {
        const res = await client.search({
          query,
          category,
          subcategory,
          limit,
          country,
          city,
          sites,
          scrapeContent: include_content,
        });
        if (res.success === false && typeof res.error === "string") {
          throw new Error(formatSearch(res) + formatCredits(res));
        }
        return formatSearch(res) + formatCredits(res);
      })
  );

  server.registerTool(
    "web_read",
    {
      title: "Read a page",
      description: compact
        ? "Fetch one URL as clean markdown."
        : "Fetch one URL and return its main content as markdown.",
      inputSchema: {
        url: z.string().url(),
        no_cache: desc(z.boolean().optional(), "Skip cached copy"),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
    },
    ({ url, no_cache }) =>
      run(async () => {
        const res = await client.scrape({ url, formats: ["markdown"], noCache: no_cache });
        // Blocked pages: surface as a tool error (isError) instead of empty content.
        if (res.success === false && typeof res.error === "string") {
          throw new Error(formatScrape(res) + formatCredits(res));
        }
        return formatScrape(res) + formatCredits(res);
      })
  );

  server.registerTool(
    "web_parse",
    {
      title: "Read a file",
      description: compact
        ? "Read a PDF, Office file, YouTube link, image, or audio/video URL as Markdown."
        : "Read a PDF, Word/Excel/PowerPoint file, image, or audio/video file at a URL and return Markdown. Scanned PDF pages are OCR'd; audio/video is transcribed with timestamps. Pages it could not read are listed, never guessed.",
      inputSchema: {
        url: z.string().url(),
        ocr: desc(z.enum(["auto", "force", "off"]).optional(), "auto (default) OCRs only scanned pages"),
        pages: desc(z.array(z.number().int().min(1)).max(2000).optional(), "1-indexed PDF pages to read"),
        language: desc(z.string().max(8).optional(), "Spoken language hint, e.g. en"),
        background: desc(
          z.boolean().optional(),
          "Run as a background job for long files; returns a run id"
        ),
      },
      // Not read-only: `background` queues a stateful job. Additive, so not destructive.
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
    },
    ({ url, ocr, pages, language, background }) =>
      run(async () => {
        const res = await client.parse({ url, ocr, pages, language, async: background });
        return formatParse(res) + formatCredits(res);
      })
  );

  server.registerTool(
    "web_parse_status",
    {
      title: "Check a file read",
      description: "Check a background web_parse run and return its Markdown when it has finished.",
      inputSchema: { id: z.string().min(1) },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    ({ id }) =>
      run(async () => {
        const res = await client.run(id);
        const result =
          res.result && typeof res.result === "object"
            ? (res.result as Record<string, unknown>)
            : null;
        if (!result) {
          return `Run ${id} is ${String(res.status ?? "running")}.`;
        }
        return formatParse(result) + formatCredits(result);
      })
  );

  server.registerTool(
    "web_map",
    {
      title: "Map a site",
      description: compact
        ? "List URLs on a website."
        : "List the URLs on a website (sitemap, robots and links). Use before scraping to pick the right pages.",
      inputSchema: {
        url: z.string().url(),
        search: desc(z.string().optional(), "Only URLs matching this text"),
        limit: z.number().int().min(1).max(5000).optional(),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
    },
    ({ url, search, limit }) =>
      run(async () => {
        const res = await client.map({ url, search, limit });
        return formatMap(res) + formatCredits(res);
      })
  );

  server.registerTool(
    "web_crawl",
    {
      title: "Crawl a site",
      description: compact
        ? "Crawl up to 25 pages starting from a URL."
        : "Read several pages starting from a URL and return each as markdown. Capped at 25 pages.",
      inputSchema: {
        url: z.string().url(),
        max_pages: desc(z.number().int().min(1).max(25).optional(), "Default 5"),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
    },
    ({ url, max_pages }) =>
      run(async () => {
        const res = await client.crawl({ url, maxPages: max_pages });
        return formatCrawl(res) + formatCredits(res);
      })
  );

  server.registerTool(
    "web_extract",
    {
      title: "Extract structured data",
      description: compact
        ? "Extract structured JSON from a URL."
        : "Pull structured JSON from one URL. Describe what you want with `prompt`, or pass a JSON `schema`.",
      inputSchema: {
        url: z.string().url(),
        prompt: z.string().optional(),
        schema: desc(z.record(z.string(), z.any()).optional(), "JSON Schema for the output"),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
    },
    ({ url, prompt, schema }) =>
      run(async () => {
        const res = await client.extract({ url, prompt, schema });
        if (res.success === false && typeof res.error === "string") {
          throw new Error(res.error + formatCredits(res));
        }
        return JSON.stringify(res.data ?? res, null, 2) + formatCredits(res);
      })
  );

  server.registerTool(
    "web_rerank",
    {
      title: "Rerank documents",
      description: compact
        ? "Order documents by relevance to a query."
        : "Order your own documents by relevance to a query. Returns the best matches first.",
      inputSchema: {
        query: z.string().min(1),
        documents: z.array(z.string()).min(1).max(200),
        top_k: z.number().int().min(1).optional(),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    ({ query, documents, top_k }) =>
      run(async () => {
        const res = await client.rerank({ query, documents, topK: top_k });
        const items = Array.isArray(res.results)
          ? res.results
          : Array.isArray(res.data)
            ? res.data
            : [];
        const lines = items.map((r, i) => {
          const o = (r ?? {}) as Record<string, unknown>;
          const text = String(o.description ?? o.markdown ?? o.title ?? "").slice(0, 200);
          const score = typeof o.score === "number" ? ` [${o.score.toFixed(3)}]` : "";
          return `${i + 1}.${score} ${text}`;
        });
        return (lines.length ? lines.join("\n") : JSON.stringify(res, null, 2)) + formatCredits(res);
      })
  );

  server.registerTool(
    "web_monitor",
    {
      title: "Monitor web pages or sites",
      description: compact
        ? "Create, list, inspect, check, pause, resume, or delete scheduled web monitors with trigger conditions."
        : "Watch a single page, a list of URLs, or a whole website section on a schedule. Supports natural-language `watch_for` focus, explicit `condition` rules (e.g. `price < 50`, `content contains \"In Stock\"`, `added_urls_count > 0`), and email or webhook notifications.",
      inputSchema: {
        action: desc(
          z.enum(["create", "list", "get", "check", "pause", "resume", "delete"]).optional(),
          "Action to perform (defaults to 'create' when url/urls given, else 'list')"
        ),
        id: desc(z.string().optional(), "Monitor ID (required for get, check, pause, resume, delete)"),
        url: desc(z.string().url().optional(), "Page or site URL to watch"),
        urls: desc(z.array(z.string().url()).optional(), "Multiple URLs to watch when mode is 'urls'"),
        mode: desc(z.enum(["page", "urls", "site"]).optional(), "Watch scope: page (default), urls, or site"),
        max_pages: desc(z.number().int().min(1).max(25).optional(), "Max pages to sample when mode is 'site' (default 5)"),
        name: desc(z.string().optional(), "Optional friendly watch name"),
        interval_minutes: desc(z.number().int().min(5).max(10080).optional(), "Check interval in minutes (default 60)"),
        watch_for: desc(z.string().optional(), "What to watch for, e.g. 'Pricing tiers and discounts'"),
        condition: desc(
          z.string().optional(),
          "Optional trigger rule expression, e.g. 'price < 50', 'content contains \"In Stock\"', 'added_urls_count > 0'"
        ),
        notify_email: desc(
          z.string().optional(),
          "Email address to notify when triggered, or 'true' to use the account email"
        ),
        webhook_url: desc(z.string().url().optional(), "HTTPS webhook URL to POST when triggered"),
      },
      // Destructive: the `delete` action removes a monitor and its history.
      annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
    },
    ({
      action,
      id,
      url,
      urls,
      mode,
      max_pages,
      name,
      interval_minutes,
      watch_for,
      condition,
      notify_email,
      webhook_url,
    }) =>
      run(async () => {
        const effectiveAction = action ?? (url || (urls && urls.length) ? "create" : "list");
        const requireId = (op: string): string => {
          if (!id) {
            throw new WebcrawlError("bad_request", `web_monitor action '${op}' requires 'id'`);
          }
          return id;
        };

        switch (effectiveAction) {
          case "list": {
            if (!client.monitors) {
              throw new WebcrawlError("bad_request", "Web monitors require a cloud WebcrawlClient (set WEBCRAWL_API_KEY).");
            }
            const res = await client.monitors();
            return formatMonitor(res) + formatCredits(res);
          }
          case "get": {
            if (!client.getMonitor) {
              throw new WebcrawlError("bad_request", "Web monitors require a cloud WebcrawlClient (set WEBCRAWL_API_KEY).");
            }
            const res = await client.getMonitor(requireId("get"));
            return formatMonitor(res) + formatCredits(res);
          }
          case "check": {
            if (!client.checkMonitor) {
              throw new WebcrawlError("bad_request", "Web monitors require a cloud WebcrawlClient (set WEBCRAWL_API_KEY).");
            }
            const res = await client.checkMonitor(requireId("check"));
            return formatMonitor(res) + formatCredits(res);
          }
          case "pause":
          case "resume": {
            if (!client.updateMonitor) {
              throw new WebcrawlError("bad_request", "Web monitors require a cloud WebcrawlClient (set WEBCRAWL_API_KEY).");
            }
            const res = await client.updateMonitor({
              id: requireId(effectiveAction),
              status: effectiveAction === "pause" ? "paused" : "active",
              ...(name !== undefined ? { name } : {}),
              ...(interval_minutes !== undefined ? { intervalMinutes: interval_minutes } : {}),
              ...(watch_for !== undefined ? { watchFor: watch_for } : {}),
              ...(condition !== undefined ? { condition } : {}),
              ...(notify_email !== undefined
                ? { notifyEmail: notify_email === "true" ? true : notify_email }
                : {}),
              ...(webhook_url !== undefined ? { webhookUrl: webhook_url } : {}),
            });
            return formatMonitor(res) + formatCredits(res);
          }
          case "delete": {
            if (!client.deleteMonitor) {
              throw new WebcrawlError("bad_request", "Web monitors require a cloud WebcrawlClient (set WEBCRAWL_API_KEY).");
            }
            const res = await client.deleteMonitor(requireId("delete"));
            return formatMonitor(res) + formatCredits(res);
          }
          case "create": {
            if (!client.createMonitor) {
              throw new WebcrawlError("bad_request", "Web monitors require a cloud WebcrawlClient (set WEBCRAWL_API_KEY).");
            }
            const res = await client.createMonitor({
              url: url ?? urls?.[0],
              urls,
              mode: mode ?? (urls && urls.length > 1 ? "urls" : "page"),
              maxPages: max_pages,
              name,
              intervalMinutes: interval_minutes,
              watchFor: watch_for,
              condition,
              notifyEmail: notify_email === "true" ? true : notify_email,
              webhookUrl: webhook_url,
            });
            return formatMonitor(res) + formatCredits(res);
          }
        }
      })
  );

  server.registerTool(
    "search_categories",
    {
      title: "Search categories",
      description: "List the search categories, subcategories and filters web_search supports.",
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    () => run(async () => JSON.stringify(await client.categories(), null, 2))
  );

  return server;
}

/** Back-compat alias used by the stdio binary. */
export const createServer = createWebcrawlMcpServer;
