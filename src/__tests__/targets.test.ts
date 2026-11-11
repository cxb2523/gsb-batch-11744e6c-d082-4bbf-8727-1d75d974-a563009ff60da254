import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  BUILTIN_TARGETS,
  extractArxivFromHtml,
  extractGitHubFromHtml,
  extractLlmsTxt,
  getTargetById,
  inspectTarget,
  listTargets,
  registerTarget,
  resolveTarget,
} from "../targets/index.js";

describe("Target & Extractor Plugin Registry (src/targets/)", () => {
  it("lists all built-in targets with REA-style returns and requirements metadata", () => {
    const targets = listTargets();
    assert.ok(targets.length >= 12);
    for (const t of targets) {
      assert.ok(t.id.length > 0);
      assert.ok(t.name.length > 0);
      assert.ok(t.returns.length > 10);
      assert.ok(t.requirements.length > 10);
      assert.ok(Array.isArray(t.examples) && t.examples.length > 0);
    }
  });

  it("resolves GitHub, ArXiv, llms.txt, YouTube, PDF, and CVE targets with high confidence", () => {
    assert.equal(resolveTarget({ url: "https://github.com/morluto/rea" }).plugin.id, "github");
    assert.equal(resolveTarget({ url: "https://arxiv.org/abs/2307.09288" }).plugin.id, "arxiv");
    assert.equal(resolveTarget({ url: "https://docs.anthropic.com/llms.txt" }).plugin.id, "llms-txt");
    assert.equal(resolveTarget({ url: "https://www.youtube.com/watch?v=dQw4w9WgXcQ" }).plugin.id, "youtube-media");
    assert.equal(resolveTarget({ url: "https://example.com/report.pdf" }).plugin.id, "pdf-office");
    assert.equal(resolveTarget({ query: "CVE-2024-3094 xz backdoor" }).plugin.id, "cve-security");
    assert.equal(resolveTarget({ category: "shopping", query: "headphones" }).plugin.id, "shopping");
    assert.equal(resolveTarget({ url: "https://example.com/about" }).plugin.id, "web-spa");
  });

  it("extracts GitHub repository structured metadata and evidence signals", () => {
    const html = `
      <html>
        <head>
          <title>morluto/rea: Reverse engineer anything with agents</title>
          <meta property="og:description" content="Reverse engineer anything with agents, from app behavior down to native binaries." />
        </head>
        <body>
          <span id="repo-stars-counter-star" title="14,250">14.2k</span>
          <span id="repo-network-counter" title="1,120">1.1k</span>
          <span itemprop="programmingLanguage">TypeScript</span>
          <a class="topic-tag">reverse-engineering</a>
          <a class="topic-tag">mcp</a>
          <article class="markdown-body"><h1>REA</h1><p>Inspect native binaries and Electron apps.</p></article>
        </body>
      </html>
    `;
    const res = extractGitHubFromHtml("https://github.com/morluto/rea", html);
    assert.equal(res.targetId, "github");
    assert.equal(res.structured?.kind, "repository");
    assert.equal(res.structured?.owner, "morluto");
    assert.equal(res.structured?.repo, "rea");
    assert.equal(res.structured?.stars, 14250);
    assert.equal(res.structured?.forks, 1120);
    assert.equal(res.structured?.language, "TypeScript");
    assert.deepEqual(res.structured?.topics, ["reverse-engineering", "mcp"]);
    assert.ok(res.structured?.readmeExcerpt?.includes("Inspect native binaries"));
    assert.ok(res.evidence.matchedSignals.includes("dom:repo-stars-counter"));
    assert.equal(res.evidence.limitations.length, 0);
  });

  it("extracts ArXiv paper metadata, authors, abstract, and PDF URL with evidence", () => {
    const html = `
      <html>
        <head>
          <meta name="citation_title" content="Attention Is All You Need" />
          <meta name="citation_author" content="Vaswani, Ashish" />
          <meta name="citation_author" content="Shazeer, Noam" />
          <meta name="citation_date" content="2017/06/12" />
          <meta name="citation_doi" content="10.48550/arXiv.1706.03762" />
        </head>
        <body>
          <span class="primary-subject">Computation and Language (cs.CL)</span>
          <blockquote class="abstract">Abstract: The dominant sequence transduction models are based on complex recurrent or convolutional neural networks.</blockquote>
        </body>
      </html>
    `;
    const res = extractArxivFromHtml("https://arxiv.org/abs/1706.03762", html);
    assert.equal(res.structured?.arxivId, "1706.03762");
    assert.equal(res.structured?.title, "Attention Is All You Need");
    assert.deepEqual(res.structured?.authors, ["Vaswani, Ashish", "Shazeer, Noam"]);
    assert.equal(res.structured?.pdfUrl, "https://arxiv.org/pdf/1706.03762.pdf");
    assert.equal(res.structured?.primaryCategory, "Computation and Language (cs.CL)");
    assert.ok(res.structured?.abstract.startsWith("The dominant sequence transduction"));
    assert.ok(res.evidence.matchedSignals.includes("meta:citation_title"));
  });

  it("extracts llms.txt sections and documentation links", () => {
    const md = `# Webcrawl Anything
> Open-source search and universal web crawler for AI agents.

## Core Guides
- [Quickstart](https://webcrawl.app/docs/quickstart): Set up in 30 seconds
- [Targets](https://webcrawl.app/docs/targets): Full target matrix
`;
    const res = extractLlmsTxt("https://webcrawl.app/llms.txt", md);
    assert.equal(res.structured?.title, "Webcrawl Anything");
    assert.equal(res.structured?.totalLinks, 2);
    assert.equal(res.structured?.sections[0]?.heading, "Core Guides");
    assert.ok(res.evidence.matchedSignals.includes("md:links(2)"));
  });

  it("supports custom community target registration via registerTarget()", async () => {
    registerTarget({
      id: "custom-sec-edgar",
      name: "SEC EDGAR Filings",
      category: "developer",
      returns: "10-K and 10-Q filing sections",
      requirements: "Built-in HTML parser",
      examples: ["https://www.sec.gov/edgar/searchedgar/companysearch"],
      matches({ url }) {
        return { matched: Boolean(url?.includes("sec.gov/edgar")), confidence: 0.99 };
      },
      extract(input) {
        return {
          targetId: "custom-sec-edgar",
          targetName: "SEC EDGAR Filings",
          category: "developer",
          structured: { cik: "0000320193" },
          evidence: {
            targetId: "custom-sec-edgar",
            tier: "static",
            sourceUrl: input.url,
            matchedSignals: ["sec:cik"],
            limitations: [],
          },
        };
      },
    });
    assert.ok(getTargetById("custom-sec-edgar"));
    const inspected = await inspectTarget({ url: "https://www.sec.gov/edgar/apple" });
    assert.equal(inspected.targetId, "custom-sec-edgar");
    assert.ok(typeof inspected.evidence.latencyMs === "number");
    assert.equal(BUILTIN_TARGETS.length, 12);
  });
});
