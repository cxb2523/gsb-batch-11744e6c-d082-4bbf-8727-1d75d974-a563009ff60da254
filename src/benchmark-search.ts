/**
 * Search benchmark: webcrawl `/v1/search` vs Jina `s.jina.ai`.
 * Compares the search step only (Jina content fetch is disabled) on latency,
 * result count and URL overlap. Prints top results so relevance can be eyeballed.
 *
 * Usage:
 *   WEBCRAWL_API_KEY=... JINA_API_KEY=... npx tsx src/benchmark-search.ts
 */

const WEBCRAWL_URL = (process.env.WEBCRAWL_URL || "https://webcrawl.app").replace(/\/$/, "");
const WEBCRAWL_API_KEY = process.env.WEBCRAWL_API_KEY;
const JINA_API_KEY = process.env.JINA_API_KEY;
const LIMIT = 5;
const RUNS = 2;

const QUERIES: Array<{ q: string; kind: string }> = [
  { q: "how to configure cloudflare workers cron triggers", kind: "technical" },
  { q: "next.js app router vs pages router differences", kind: "technical" },
  { q: "postgres jsonb index performance", kind: "technical" },
  { q: "what is retrieval augmented generation", kind: "concept" },
  { q: "latest openai model release", kind: "fresh" },
  { q: "sydney weather this week", kind: "local" },
  { q: "best espresso machine under 500", kind: "shopping" },
  { q: "vercel sandbox pricing", kind: "product" },
  { q: "youtube-transcript-api cloud ip blocked", kind: "long-tail" },
  { q: "australian gst registration threshold", kind: "factual" },
];

interface Hit {
  url: string;
  title: string;
}
interface Run {
  ms: number;
  hits: Hit[];
  error?: string;
}

function norm(u: string): string {
  try {
    const x = new URL(u);
    return (x.hostname.replace(/^www\./, "") + x.pathname.replace(/\/$/, "")).toLowerCase();
  } catch {
    return u.toLowerCase();
  }
}

async function runWebcrawl(q: string): Promise<Run> {
  const t0 = performance.now();
  try {
    const res = await fetch(`${WEBCRAWL_URL}/v1/search`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${WEBCRAWL_API_KEY}` },
      body: JSON.stringify({ query: q, limit: LIMIT, bypassCache: true }),
      signal: AbortSignal.timeout(30000),
    });
    const json: any = await res.json();
    const ms = performance.now() - t0;
    if (!res.ok || json.success === false) return { ms, hits: [], error: `${res.status} ${json.error ?? ""}` };
    return { ms, hits: (json.data ?? []).map((d: any) => ({ url: d.url, title: d.title ?? "" })) };
  } catch (e: any) {
    return { ms: performance.now() - t0, hits: [], error: String(e?.message ?? e) };
  }
}

async function runJina(q: string): Promise<Run> {
  const t0 = performance.now();
  try {
    const res = await fetch(`https://s.jina.ai/?q=${encodeURIComponent(q)}&num=${LIMIT}`, {
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${JINA_API_KEY}`,
        "X-Respond-With": "no-content",
        "X-No-Cache": "true",
      },
      signal: AbortSignal.timeout(45000),
    });
    const json: any = await res.json();
    const ms = performance.now() - t0;
    if (!res.ok) return { ms, hits: [], error: `${res.status} ${json.message ?? ""}` };
    return { ms, hits: (json.data ?? []).slice(0, LIMIT).map((d: any) => ({ url: d.url, title: d.title ?? "" })) };
  } catch (e: any) {
    return { ms: performance.now() - t0, hits: [], error: String(e?.message ?? e) };
  }
}

function pct(a: number[], p: number): number {
  if (!a.length) return 0;
  const s = [...a].sort((x, y) => x - y);
  return Math.round(s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))]);
}

async function main() {
  if (!WEBCRAWL_API_KEY || !JINA_API_KEY) {
    console.error("Set WEBCRAWL_API_KEY and JINA_API_KEY");
    process.exit(1);
  }
  const wcMs: number[] = [];
  const jMs: number[] = [];
  let wcOk = 0;
  let jOk = 0;
  let wcCount = 0;
  let jCount = 0;
  let overlapSum = 0;
  let overlapN = 0;
  const total = QUERIES.length * RUNS;

  for (const { q, kind } of QUERIES) {
    let lastWc: Run = { ms: 0, hits: [] };
    let lastJ: Run = { ms: 0, hits: [] };
    for (let i = 0; i < RUNS; i++) {
      // Sequential so the two services never compete for our bandwidth.
      lastWc = await runWebcrawl(q);
      lastJ = await runJina(q);
      if (!lastWc.error) {
        wcOk++;
        wcMs.push(lastWc.ms);
        wcCount += lastWc.hits.length;
      }
      if (!lastJ.error) {
        jOk++;
        jMs.push(lastJ.ms);
        jCount += lastJ.hits.length;
      }
    }
    const a = new Set(lastWc.hits.map((h) => norm(h.url)));
    const b = new Set(lastJ.hits.map((h) => norm(h.url)));
    const shared = [...a].filter((x) => b.has(x)).length;
    if (a.size && b.size) {
      overlapSum += shared / Math.min(a.size, b.size);
      overlapN++;
    }
    console.log(`\n## [${kind}] ${q}`);
    console.log(
      `   webcrawl ${Math.round(lastWc.ms)}ms n=${lastWc.hits.length}${lastWc.error ? ` ERR ${lastWc.error}` : ""}   |   jina ${Math.round(lastJ.ms)}ms n=${lastJ.hits.length}${lastJ.error ? ` ERR ${lastJ.error}` : ""}   |   shared URLs ${shared}`
    );
    const rows = Math.max(lastWc.hits.length, lastJ.hits.length, 0);
    for (let i = 0; i < rows; i++) {
      const w = lastWc.hits[i];
      const j = lastJ.hits[i];
      console.log(
        `   ${i + 1}. WC: ${(w ? norm(w.url) : "-").slice(0, 52).padEnd(52)} JINA: ${(j ? norm(j.url) : "-").slice(0, 52)}`
      );
    }
  }

  console.log("\n=== Summary ===");
  console.log(`webcrawl: success ${wcOk}/${total}  p50 ${pct(wcMs, 50)}ms  p95 ${pct(wcMs, 95)}ms  avg results ${(wcCount / Math.max(wcOk, 1)).toFixed(1)}`);
  console.log(`jina:     success ${jOk}/${total}  p50 ${pct(jMs, 50)}ms  p95 ${pct(jMs, 95)}ms  avg results ${(jCount / Math.max(jOk, 1)).toFixed(1)}`);
  console.log(`mean URL overlap (of smaller list): ${overlapN ? Math.round((overlapSum / overlapN) * 100) : 0}%`);
}

main();

export {};
