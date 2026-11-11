/**
 * Built-in Developer & Research Target Extractors:
 * - GitHub Repositories, Issues, Pull Requests & Releases
 * - ArXiv Papers (abstract, authors, PDF link, categories, submission history)
 * - llms.txt / AI Documentation Manifests & Sitemaps
 * - Hacker News Threads & Discussions
 */
import crypto from "node:crypto";
import type { CrawlTargetPlugin, TargetInspectInput, TargetInspectResult } from "./types.js";

function sha256(text: string): string {
  return crypto.createHash("sha256").update(text).digest("hex");
}

function stripTags(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\s+/g, " ")
    .trim();
}

export interface GitHubTargetData {
  kind: "repository" | "issue" | "pull_request" | "release" | "discussion" | "unknown";
  owner: string;
  repo: string;
  number?: number;
  tag?: string;
  description?: string;
  stars?: number;
  forks?: number;
  language?: string;
  license?: string;
  topics: string[];
  readmeExcerpt?: string;
}

export function extractGitHubFromHtml(url: string, html: string): TargetInspectResult<GitHubTargetData> {
  const matchedSignals: string[] = [];
  const limitations: string[] = [];

  let owner = "";
  let repo = "";
  let kind: GitHubTargetData["kind"] = "unknown";
  let number: number | undefined;
  let tag: string | undefined;

  try {
    const u = new URL(url);
    const parts = u.pathname.split("/").filter(Boolean);
    owner = parts[0] ?? "";
    repo = parts[1] ?? "";
    if (parts[2] === "issues" && parts[3]) {
      kind = "issue";
      number = Number(parts[3]);
      matchedSignals.push("url:github-issue-path");
    } else if (parts[2] === "pull" && parts[3]) {
      kind = "pull_request";
      number = Number(parts[3]);
      matchedSignals.push("url:github-pr-path");
    } else if (parts[2] === "releases" && parts[3] === "tag" && parts[4]) {
      kind = "release";
      tag = parts[4];
      matchedSignals.push("url:github-release-tag");
    } else if (parts[2] === "discussions" && parts[3]) {
      kind = "discussion";
      number = Number(parts[3]);
      matchedSignals.push("url:github-discussion-path");
    } else if (owner && repo) {
      kind = "repository";
      matchedSignals.push("url:github-repo-root");
    }
  } catch {
    limitations.push("Could not parse canonical GitHub URL path");
  }

  const descMatch =
    html.match(/<meta[^>]+property=["']og:description["'][^>]+content=["']([^"']+)["']/i) ??
    html.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']+)["']/i);
  const description = descMatch ? stripTags(descMatch[1]) : undefined;
  if (description) matchedSignals.push("meta:og:description");

  const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const title = titleMatch ? stripTags(titleMatch[1]) : `${owner}/${repo}`;

  // Parse stars / forks from social count or JSON payload
  let stars: number | undefined;
  const starMatch =
    html.match(/id=["']repo-stars-counter-star["'][^>]*title=["']([\d,]+)["']/i) ??
    html.match(/([\d,]+)\s+users?\s+starred\s+this\s+repository/i);
  if (starMatch) {
    stars = Number(starMatch[1].replace(/,/g, ""));
    matchedSignals.push("dom:repo-stars-counter");
  }

  let forks: number | undefined;
  const forkMatch = html.match(/id=["']repo-network-counter["'][^>]*title=["']([\d,]+)["']/i);
  if (forkMatch) {
    forks = Number(forkMatch[1].replace(/,/g, ""));
    matchedSignals.push("dom:repo-network-counter");
  }

  const topics: string[] = [];
  const topicRe = /class=["'][^"']*\btopic-tag\b[^"']*["'][^>]*>([\s\S]*?)<\/a>/gi;
  for (const m of html.matchAll(topicRe)) {
    const t = stripTags(m[1]);
    if (t && !topics.includes(t)) topics.push(t);
  }
  if (topics.length > 0) matchedSignals.push(`dom:topic-tag(${topics.length})`);

  const langMatch = html.match(/itemprop=["']programmingLanguage["'][^>]*>([\s\S]*?)<\//i);
  const language = langMatch ? stripTags(langMatch[1]) : undefined;
  if (language) matchedSignals.push("dom:itemprop=programmingLanguage");

  const articleMatch = html.match(/<article[^>]*class=["'][^"']*\bmarkdown-body\b[^"']*["'][^>]*>([\s\S]*?)<\/article>/i);
  const readmeExcerpt = articleMatch ? stripTags(articleMatch[1]).slice(0, 1200) : undefined;
  if (readmeExcerpt) matchedSignals.push("dom:article.markdown-body");
  else limitations.push("No rendered README <article class='markdown-body'> found in HTML snapshot");

  return {
    targetId: "github",
    targetName: "GitHub Repositories, Issues & Releases",
    category: "developer",
    title,
    structured: {
      kind,
      owner,
      repo,
      number,
      tag,
      description,
      stars,
      forks,
      language,
      topics,
      readmeExcerpt,
    },
    evidence: {
      targetId: "github",
      tier: "static",
      contentHash: sha256(html),
      sourceUrl: url,
      matchedSignals,
      limitations,
    },
  };
}

export interface ArxivPaperData {
  arxivId: string;
  title: string;
  authors: string[];
  abstract: string;
  primaryCategory?: string;
  publishedDate?: string;
  pdfUrl: string;
  doi?: string;
}

export function extractArxivFromHtml(url: string, html: string): TargetInspectResult<ArxivPaperData> {
  const matchedSignals: string[] = [];
  const limitations: string[] = [];

  const idMatch = url.match(/arxiv\.org\/(?:abs|pdf|html)\/([0-9]{4}\.[0-9]{4,5}(?:v\d+)?|[a-z-]+\/[0-9]{7})/i);
  const arxivId = idMatch ? idMatch[1] : "unknown";
  if (idMatch) matchedSignals.push("url:arxiv-id");

  const citationTitle =
    html.match(/<meta[^>]+name=["']citation_title["'][^>]+content=["']([^"']+)["']/i)?.[1] ??
    html.match(/<h1[^>]*class=["'][^"']*\btitle\b[^"']*["'][^>]*>([\s\S]*?)<\/h1>/i)?.[1];
  const title = citationTitle ? stripTags(citationTitle.replace(/^Title:\s*/i, "")) : `arXiv:${arxivId}`;
  if (citationTitle) matchedSignals.push("meta:citation_title");

  const authors: string[] = [];
  for (const m of html.matchAll(/<meta[^>]+name=["']citation_author["'][^>]+content=["']([^"']+)["']/gi)) {
    authors.push(stripTags(m[1]));
  }
  if (authors.length === 0) {
    const authorsBlock = html.match(/<div[^>]*class=["'][^"']*\bauthors\b[^"']*["'][^>]*>([\s\S]*?)<\/div>/i);
    if (authorsBlock) {
      for (const a of authorsBlock[1].matchAll(/<a[^>]*>([\s\S]*?)<\/a>/gi)) {
        authors.push(stripTags(a[1]));
      }
    }
  }
  if (authors.length > 0) matchedSignals.push(`meta:citation_author(${authors.length})`);
  else limitations.push("No citation_author meta tags or .authors block found");

  const abstractMatch =
    html.match(/<blockquote[^>]*class=["'][^"']*\babstract\b[^"']*["'][^>]*>([\s\S]*?)<\/blockquote>/i)?.[1] ??
    html.match(/<meta[^>]+property=["']og:description["'][^>]+content=["']([^"']+)["']/i)?.[1];
  const abstract = abstractMatch ? stripTags(abstractMatch.replace(/^Abstract:\s*/i, "")) : "";
  if (abstract) matchedSignals.push("dom:blockquote.abstract");
  else limitations.push("Abstract text missing from HTML");

  const dateMatch = html.match(/<meta[^>]+name=["']citation_date["'][^>]+content=["']([^"']+)["']/i);
  const publishedDate = dateMatch ? dateMatch[1].trim() : undefined;
  if (publishedDate) matchedSignals.push("meta:citation_date");

  const subjMatch = html.match(/<span[^>]*class=["'][^"']*\bprimary-subject\b[^"']*["'][^>]*>([\s\S]*?)<\/span>/i);
  const primaryCategory = subjMatch ? stripTags(subjMatch[1]) : undefined;
  if (primaryCategory) matchedSignals.push("dom:span.primary-subject");

  const doiMatch = html.match(/<meta[^>]+name=["']citation_doi["'][^>]+content=["']([^"']+)["']/i);
  const doi = doiMatch ? doiMatch[1].trim() : undefined;

  return {
    targetId: "arxiv",
    targetName: "ArXiv Research Papers",
    category: "academic",
    title,
    structured: {
      arxivId,
      title,
      authors,
      abstract,
      primaryCategory,
      publishedDate,
      pdfUrl: `https://arxiv.org/pdf/${arxivId}.pdf`,
      doi,
    },
    evidence: {
      targetId: "arxiv",
      tier: "static",
      contentHash: sha256(html),
      sourceUrl: url,
      matchedSignals,
      limitations,
    },
  };
}

export interface LlmsTxtData {
  title: string;
  summary?: string;
  sections: Array<{
    heading: string;
    links: Array<{ title: string; url: string; description?: string }>;
  }>;
  totalLinks: number;
}

export function extractLlmsTxt(url: string, text: string): TargetInspectResult<LlmsTxtData> {
  const matchedSignals: string[] = [];
  const limitations: string[] = [];

  const lines = text.split(/\r?\n/);
  let title = "llms.txt";
  let summary: string | undefined;
  const sections: LlmsTxtData["sections"] = [];
  let currentSection: LlmsTxtData["sections"][number] = { heading: "Root", links: [] };

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) continue;
    if (line.startsWith("# ") && title === "llms.txt") {
      title = line.slice(2).trim();
      matchedSignals.push("md:h1-title");
      continue;
    }
    if (line.startsWith("> ") && !summary) {
      summary = line.slice(2).trim();
      matchedSignals.push("md:blockquote-summary");
      continue;
    }
    if (line.startsWith("## ")) {
      if (currentSection.links.length > 0 || currentSection.heading !== "Root") {
        sections.push(currentSection);
      }
      currentSection = { heading: line.slice(3).trim(), links: [] };
      continue;
    }
    const linkMatch = line.match(/^[-*]\s+\[([^\]]+)\]\(([^)]+)\)(?:\s*:\s*(.*))?$/);
    if (linkMatch) {
      currentSection.links.push({
        title: linkMatch[1].trim(),
        url: linkMatch[2].trim(),
        description: linkMatch[3]?.trim() || undefined,
      });
    }
  }
  if (currentSection.links.length > 0 || sections.length === 0) {
    sections.push(currentSection);
  }
  const totalLinks = sections.reduce((acc, s) => acc + s.links.length, 0);
  if (totalLinks > 0) matchedSignals.push(`md:links(${totalLinks})`);
  else limitations.push("No standard `- [Title](url): description` entries found in llms.txt");

  return {
    targetId: "llms-txt",
    targetName: "llms.txt & AI Documentation Manifests",
    category: "developer",
    title,
    markdown: text,
    structured: {
      title,
      summary,
      sections,
      totalLinks,
    },
    evidence: {
      targetId: "llms-txt",
      tier: "static",
      contentHash: sha256(text),
      sourceUrl: url,
      matchedSignals,
      limitations,
    },
  };
}

export const githubTargetPlugin: CrawlTargetPlugin<GitHubTargetData> = {
  id: "github",
  name: "GitHub Repositories, Issues & Releases",
  category: "developer",
  returns: "Repository metadata, stars/forks, topics, language, issue/PR threads, release notes, and README markdown",
  requirements: "Built-in zero-key HTML/JSON inspector via impit TLS fetch",
  examples: [
    "https://github.com/morluto/rea",
    "https://github.com/vercel/next.js/releases",
  ],
  matches({ url, query }) {
    if (url && /^https?:\/\/(www\.)?github\.com\/[^/]+\/[^/]+/i.test(url)) {
      return { matched: true, confidence: 0.98, reason: "GitHub repository/issue/release URL" };
    }
    if (query && /\b(github\.com\/|gh\s+repo|github\s+release|github\s+issue)\b/i.test(query)) {
      return { matched: true, confidence: 0.75, reason: "GitHub query intent" };
    }
    return { matched: false, confidence: 0 };
  },
  extract(input: TargetInspectInput) {
    return extractGitHubFromHtml(input.url ?? "https://github.com", input.html ?? "");
  },
};

export const arxivTargetPlugin: CrawlTargetPlugin<ArxivPaperData> = {
  id: "arxiv",
  name: "ArXiv Research Papers",
  category: "academic",
  returns: "Paper title, authors, abstract, primary subject, DOI, submission date, and direct PDF link",
  requirements: "Built-in citation meta & abstract parser; combine with pdf-office target for full paper text",
  examples: [
    "https://arxiv.org/abs/2307.09288",
    "webcrawl search \"test-time compute scaling\" -c academic",
  ],
  matches({ url, query, category }) {
    if (url && /arxiv\.org\/(abs|pdf|html)\//i.test(url)) {
      return { matched: true, confidence: 0.99, reason: "ArXiv paper URL" };
    }
    if (category === "academic" || (query && /\barxiv:\d{4}\.\d{4,5}\b/i.test(query))) {
      return { matched: true, confidence: 0.85, reason: "Academic / ArXiv query" };
    }
    return { matched: false, confidence: 0 };
  },
  extract(input: TargetInspectInput) {
    return extractArxivFromHtml(input.url ?? "https://arxiv.org", input.html ?? "");
  },
};

export const llmsTxtTargetPlugin: CrawlTargetPlugin<LlmsTxtData> = {
  id: "llms-txt",
  name: "llms.txt & AI Documentation Indexes",
  category: "developer",
  returns: "Structured sections, doc links, summaries, and full markdown manifest for LLM context ingestion",
  requirements: "Built-in zero-key markdown manifest parser",
  examples: [
    "https://docs.anthropic.com/llms.txt",
    "https://cursor.com/llms-full.txt",
  ],
  matches({ url }) {
    if (url && /\/llms(-full)?\.txt(\?.*)?$/i.test(url)) {
      return { matched: true, confidence: 0.99, reason: "llms.txt manifest URL" };
    }
    return { matched: false, confidence: 0 };
  },
  extract(input: TargetInspectInput) {
    return extractLlmsTxt(input.url ?? "https://example.com/llms.txt", input.markdown ?? input.html ?? "");
  },
};
