import { searchWeb } from "./search.js";
const qs = ["next.js app router vs pages router differences","what is retrieval augmented generation","best espresso machine under 500","vercel sandbox pricing"];
for (const q of qs) {
  console.log("\n## " + q);
  const t0 = performance.now();
  const r = await searchWeb({ query: q, limit: 5, bypassCache: true });
  console.log(`total=${Math.round(performance.now() - t0)}ms n=${r.data.length} rank=${JSON.stringify({lex: r.rankingMetrics?.lexicalLatencyMs, dec: r.rankingMetrics?.decisionLatencyMs, tot: r.rankingMetrics?.totalRankingLatencyMs, model: r.rankingMetrics?.decisionModelUsed})}`);
}
export {};
