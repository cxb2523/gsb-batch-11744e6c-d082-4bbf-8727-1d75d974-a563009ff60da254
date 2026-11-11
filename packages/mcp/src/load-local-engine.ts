/**
 * Load the zero-key local engine that ships inside this package (`dist/core`).
 * Never falls back to webcrawl.app — callers must fail if this throws.
 */
import type { WebcrawlLikeClient } from "./server.js";

export const LOCAL_ENGINE_LOAD_ERROR =
  "webcrawl-mcp: failed to load the local engine bundled in this package (dist/core/local-engine.js). " +
  "Reinstall @webcrawl/mcp. To use webcrawl.app cloud instead, set WEBCRAWL_API_KEY or run `webcrawl login`.";

async function importEngine(spec: string): Promise<WebcrawlLikeClient> {
  const localMod = (await import(spec)) as {
    createLocalEngineClient?: () => WebcrawlLikeClient;
  };
  if (typeof localMod.createLocalEngineClient !== "function") {
    throw new Error(`no createLocalEngineClient export from ${spec}`);
  }
  return localMod.createLocalEngineClient();
}

export async function loadLocalEngineClient(): Promise<WebcrawlLikeClient> {
  const errors: string[] = [];
  const packaged = new URL("./core/local-engine.js", import.meta.url).href;
  for (const spec of [packaged, "webcrawl/local-engine"]) {
    try {
      return await importEngine(spec);
    } catch (e) {
      errors.push(`${spec}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  throw new Error(`${LOCAL_ENGINE_LOAD_ERROR}\n${errors.join("\n")}`);
}
