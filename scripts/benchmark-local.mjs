#!/usr/bin/env node
// Local, zero-key benchmark used in the launch post. Anyone can reproduce it:
//
//   npm run build && node scripts/benchmark-local.mjs [--runs 3] [--json]
//
// Runs the real CLI in `--mode local` (no API key, no account) against a fixed set of
// public pages and searches, and reports success rate, p50/p95 latency and output size.
// A run "succeeds" when the CLI exits 0 and prints at least MIN_CHARS of output.
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);
const BIN = "packages/cli/dist/bin.js";
const MIN_CHARS = 200;
const args = process.argv.slice(2);
const RUNS = Number(args[args.indexOf("--runs") + 1]) || 3;
const AS_JSON = args.includes("--json");

const CASES = [
  { kind: "docs", cmd: ["scrape", "https://docs.stripe.com/webhooks"] },
  { kind: "docs", cmd: ["scrape", "https://react.dev/learn"] },
  { kind: "docs", cmd: ["scrape", "https://developer.mozilla.org/en-US/docs/Web/JavaScript"] },
  { kind: "github", cmd: ["scrape", "https://github.com/torvalds/linux"] },
  { kind: "arxiv", cmd: ["scrape", "https://arxiv.org/abs/1706.03762"] },
  { kind: "news", cmd: ["scrape", "https://news.ycombinator.com"] },
  // map prints one URL per line, so a short-but-correct answer is a few hundred chars.
  { kind: "map", cmd: ["map", "https://react.dev", "-n", "20"], minChars: 60 },
  // `crawl` is left out: it has no --no-cache flag, so repeat runs would measure the cache.
  { kind: "search", cmd: ["search", "postgres jsonb index performance", "-n", "5"] },
  { kind: "search", cmd: ["search", "next.js app router vs pages router differences", "-n", "5"] },
  { kind: "cve", cmd: ["search", "CVE-2024-3094 xz utils", "-c", "security", "--sub", "cve", "-n", "2"] },
];

const pct = (sorted, p) => (sorted.length ? sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))] : 0);

const rows = [];
for (const c of CASES) {
  const times = [];
  let ok = 0;
  let chars = 0;
  for (let i = 0; i < RUNS; i++) {
    // --no-cache on scrape so repeat runs measure the network, not the local LRU.
    const extra = c.cmd[0] === "scrape" ? ["--no-cache"] : [];
    const t0 = performance.now();
    try {
      const { stdout } = await run("node", [BIN, ...c.cmd, ...extra, "--mode", "local"], {
        env: { ...process.env, WEBCRAWL_API_KEY: "" },
        maxBuffer: 64 * 1024 * 1024,
        timeout: 60_000,
      });
      times.push(performance.now() - t0);
      if (stdout.length >= (c.minChars ?? MIN_CHARS)) {
        ok++;
        chars = Math.max(chars, stdout.length);
      }
    } catch {
      times.push(performance.now() - t0);
    }
  }
  times.sort((a, b) => a - b);
  rows.push({
    kind: c.kind,
    command: `webcrawl ${c.cmd.join(" ")}`,
    ok: `${ok}/${RUNS}`,
    p50Ms: Math.round(pct(times, 50)),
    p95Ms: Math.round(pct(times, 95)),
    chars,
  });
}

const all = rows.map((r) => r.p50Ms).sort((a, b) => a - b);
const okTotal = rows.reduce((n, r) => n + Number(r.ok.split("/")[0]), 0);
const summary = {
  date: new Date().toISOString().slice(0, 10),
  node: process.version,
  platform: `${process.platform}/${process.arch}`,
  runsPerCase: RUNS,
  successRate: `${okTotal}/${rows.length * RUNS}`,
  medianOfP50Ms: pct(all, 50),
};

if (AS_JSON) {
  console.log(JSON.stringify({ summary, rows }, null, 2));
} else {
  console.log("| Kind | Command | OK | p50 | p95 | Output chars |");
  console.log("|---|---|---|---|---|---|");
  for (const r of rows) console.log(`| ${r.kind} | \`${r.command}\` | ${r.ok} | ${r.p50Ms} ms | ${r.p95Ms} ms | ${r.chars.toLocaleString("en-US")} |`);
  console.log(`\n${summary.successRate} runs succeeded · median p50 ${summary.medianOfP50Ms} ms · ${summary.runsPerCase} runs per case · ${summary.platform} · node ${summary.node} · ${summary.date}`);
}
