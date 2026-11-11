import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const mcpRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = join(mcpRoot, "..", "..");

function textOf(r: unknown): string {
  return ((r as { content: Array<{ text: string }> }).content[0]?.text ?? "");
}

describe("packed @webcrawl/mcp local engine", { timeout: 180_000 }, () => {
  it("npm pack + install uses the local engine with no API key and never calls webcrawl.app", async () => {
    const tmp = mkdtempSync(join(tmpdir(), "wc-mcp-pack-"));
    const home = join(tmp, "home");
    const configHome = join(tmp, "xdg");
    try {
      // Packed installs run outside the git workspace. Sibling @webcrawl/*
      // versions are not on the registry yet during a version bump, so pack
      // them too and install the local tarballs together (avoids ETARGET).
      const packDir = join(tmp, "tarballs");
      mkdirSync(packDir);
      const workspacePackDirs = [
        join(repoRoot, "packages", "client"),
        join(repoRoot, "packages", "curl-impersonate"),
        mcpRoot,
      ];
      for (const pkgDir of workspacePackDirs) {
        execFileSync("npm", ["pack", "--pack-destination", packDir], {
          cwd: pkgDir,
          stdio: "pipe",
          env: { ...process.env },
        });
      }
      const tarballs = readdirSync(packDir).filter((n) => n.endsWith(".tgz")).map((n) => join(packDir, n));
      const tgz = tarballs.find((n) => /webcrawl-mcp-/.test(n));
      assert.ok(tgz, "npm pack should emit the MCP tgz");
      assert.equal(tarballs.length, workspacePackDirs.length, `expected ${workspacePackDirs.length} workspace tarballs`);

      const listing = execFileSync("tar", ["-tzf", tgz], { encoding: "utf8" });
      assert.match(listing, /package\/dist\/bin\.js/);
      assert.match(listing, /package\/dist\/core\/local-engine\.js/);
      assert.doesNotMatch(listing, /src\/local-engine/);

      const binJs = execFileSync("tar", ["-xOf", tgz, "package/dist/bin.js"], { encoding: "utf8" });
      assert.doesNotMatch(binJs, /falling back to https:\/\/webcrawl\.app/);
      assert.match(binJs, /load-local-engine|core\/local-engine/);

      execFileSync("npm", ["init", "-y"], { cwd: tmp, stdio: "pipe" });
      execFileSync("npm", ["install", ...tarballs], {
        cwd: tmp,
        stdio: "pipe",
        env: { ...process.env },
      });

      const installedCore = join(tmp, "node_modules", "@webcrawl", "mcp", "dist", "core", "local-engine.js");
      const engine = (await import(pathToFileURL(installedCore).href)) as {
        createLocalEngineClient: () => {
          scrape: (p: { url: string; noCache?: boolean }) => Promise<Record<string, unknown>>;
        };
      };
      const local = engine.createLocalEngineClient();
      process.env.WEBCRAWL_ALLOW_PRIVATE_URLS = "true";

      const cloudHits: string[] = [];
      const origFetch = globalThis.fetch;
      globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
        if (/webcrawl\.app/i.test(url)) {
          cloudHits.push(url);
          throw new Error(`unexpected cloud request: ${url}`);
        }
        return origFetch(input, init);
      }) as typeof fetch;
      try {
        const scraped = await local.scrape({ url: "https://example.com/", noCache: true });
        assert.equal(scraped.success, true);
        assert.equal(scraped.mode, "local");
        assert.match(String(scraped.markdown ?? ""), /example/i);
        assert.ok(String(scraped.markdown ?? "").length > 40);
        assert.equal(cloudHits.length, 0, `cloud fetch: ${cloudHits.join(", ")}`);
      } finally {
        globalThis.fetch = origFetch;
      }

      const bin = join(tmp, "node_modules", ".bin", "webcrawl-mcp");
      const stderrChunks: Buffer[] = [];
      const transport = new StdioClientTransport({
        command: bin,
        args: [],
        stderr: "pipe",
        cwd: tmp,
        env: {
          PATH: process.env.PATH ?? "/usr/bin",
          HOME: home,
          XDG_CONFIG_HOME: configHome,
          WEBCRAWL_MODE: "local",
          WEBCRAWL_URL: "http://127.0.0.1:1",
          WEBCRAWL_ALLOW_PRIVATE_URLS: "true",
          npm_config_cache: process.env.npm_config_cache ?? join(repoRoot, ".npm-cache"),
        },
      });
      if (transport.stderr) {
        transport.stderr.on("data", (c: Buffer) => stderrChunks.push(c));
      }
      const client = new Client({ name: "pack-test", version: "0" });
      await client.connect(transport);
      try {
        const read = await client.callTool({
          name: "web_read",
          arguments: { url: "https://example.com/", no_cache: true },
        });
        assert.equal(Boolean(read.isError), false, textOf(read));
        assert.match(textOf(read), /example/i);
        assert.doesNotMatch(textOf(read), /webcrawl\.app/i);
        assert.doesNotMatch(textOf(read), /charged /);

        const mapped = await client.callTool({
          name: "web_map",
          arguments: { url: "https://example.com/" },
        });
        assert.equal(Boolean(mapped.isError), false, textOf(mapped));
        assert.doesNotMatch(textOf(mapped), /webcrawl\.app/i);

        const extracted = await client.callTool({
          name: "web_extract",
          arguments: {
            url: "https://quotes.toscrape.com/",
            prompt: "quotes and their authors",
            schema: {
              type: "object",
              properties: {
                quotes: {
                  type: "array",
                  items: {
                    type: "object",
                    properties: { quote: { type: "string" }, author: { type: "string" } },
                  },
                },
              },
            },
          },
        });
        assert.equal(Boolean(extracted.isError), false, textOf(extracted));
        assert.match(textOf(extracted), /Albert Einstein/);
        assert.doesNotMatch(textOf(extracted), /"target"/);
        assert.doesNotMatch(textOf(extracted), /app_name/);

        const searched = await client.callTool({
          name: "web_search",
          arguments: { query: "example domain IANA", limit: 3 },
        });
        const searchText = textOf(searched);
        assert.doesNotMatch(searchText, /webcrawl\.app/i);
        assert.doesNotMatch(searchText, /charged /);
        // Local search may return hits or an honest empty-engine error — never cloud credits.
        assert.ok(
          Boolean(searched.isError) || /example|iana|http/i.test(searchText),
          searchText.slice(0, 400)
        );

        const stderr = Buffer.concat(stderrChunks).toString("utf8");
        assert.match(stderr, /LOCAL engine mode/i);
        assert.doesNotMatch(stderr, /falling back to https:\/\/webcrawl\.app/);
      } finally {
        await client.close();
      }
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});
