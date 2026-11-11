#!/usr/bin/env node
// Records the README demo as an asciicast (docs/assets/demo.cast) from REAL CLI output,
// then renders it to an animated SVG with svg-term-cli:
//
//   npm run build && node scripts/record-demo.mjs
//   npx svg-term-cli --in docs/assets/demo.cast --out docs/assets/demo.svg --window --no-cursor --width 100 --height 26
//
// Every frame is the actual output of the command shown, run locally with no API key.
import { execFileSync } from "node:child_process";
import { writeFileSync, mkdirSync } from "node:fs";

const BIN = "packages/cli/dist/bin.js";
const WIDTH = 100;
const HEIGHT = 26;
const MAX_LINES = 12;

const STEP = {
  cve: { show: 'npx webcrawl search "CVE-2024-3094 xz utils" -c security --sub cve -n 2', args: ["search", "CVE-2024-3094 xz utils", "-c", "security", "--sub", "cve", "-n", "2"] },
  map: { show: "npx webcrawl map https://docs.stripe.com/webhooks -n 6", args: ["map", "https://docs.stripe.com/webhooks", "-n", "6"] },
  crawl: { show: "npx webcrawl crawl https://docs.stripe.com/webhooks -n 3", args: ["crawl", "https://docs.stripe.com/webhooks", "-n", "3"] },
  github: { show: "npx webcrawl scrape https://github.com/torvalds/linux", args: ["scrape", "https://github.com/torvalds/linux"] },
  arxiv: { show: "npx webcrawl scrape https://arxiv.org/abs/1706.03762", args: ["scrape", "https://arxiv.org/abs/1706.03762"] },
  research: { show: 'npx webcrawl search "model context protocol spec changes 2026" -n 4', args: ["search", "model context protocol spec changes 2026", "-n", "4"] },
  corpus: { show: "npx webcrawl map https://react.dev -n 10", args: ["map", "https://react.dev", "-n", "10"] },
};

// `node scripts/record-demo.mjs` records the README loop (docs/assets/demo.cast).
// `node scripts/record-demo.mjs <clip>` records one clip from docs/demos.md (docs/assets/clips/<clip>.cast).
const CLIPS = {
  readme: ["cve", "map", "github"],
  "1-cve": ["cve"],
  "2-docs-cheatsheet": ["map", "crawl"],
  "4-github": ["github"],
  "5-arxiv": ["arxiv"],
  "6-research": ["research"],
  "7-corpus": ["corpus"],
};
const clipName = process.argv[2] ?? "readme";
if (!CLIPS[clipName]) {
  console.error(`unknown clip "${clipName}". Choose one of: ${Object.keys(CLIPS).join(", ")}`);
  process.exit(1);
}
const DEMOS = CLIPS[clipName].map((k) => STEP[k]);

const clip = (line) => (line.length > WIDTH - 2 ? line.slice(0, WIDTH - 3) + "…" : line);

const events = [];
let t = 0.4;
const emit = (text, dt = 0) => {
  t += dt;
  events.push([Number(t.toFixed(3)), "o", text]);
};

for (const demo of DEMOS) {
  emit("\x1b[1;32m$\x1b[0m ", 0.3);
  for (const ch of demo.show) emit(ch, 0.035);
  emit("\r\n", 0.35);
  const started = Date.now();
  const out = execFileSync("node", [BIN, ...demo.args, "--mode", "local"], {
    encoding: "utf8",
    env: { ...process.env, WEBCRAWL_API_KEY: "", FORCE_COLOR: "0" },
  });
  const secs = (Date.now() - started) / 1000;
  const lines = out.split("\n").filter((l) => l.trim() !== "").slice(0, MAX_LINES).map(clip);
  // Replay at the real wall-clock latency (capped so the loop stays short).
  emit(lines.map((l) => l + "\r\n").join(""), Math.min(secs, 2.5));
  emit(`\x1b[2m# ${secs.toFixed(1)}s, local, no API key\x1b[0m\r\n\r\n`, 0.1);
  t += 2.2;
}
emit("", 1.5);

const outFile = clipName === "readme" ? "docs/assets/demo.cast" : `docs/assets/clips/${clipName}.cast`;
mkdirSync(outFile.slice(0, outFile.lastIndexOf("/")), { recursive: true });
const header = { version: 2, width: WIDTH, height: HEIGHT, env: { SHELL: "/bin/zsh", TERM: "xterm-256color" } };
writeFileSync(outFile, [JSON.stringify(header), ...events.map((e) => JSON.stringify(e))].join("\n") + "\n");
console.log(`wrote ${outFile} (${events.length} events, ${t.toFixed(1)}s)`);
