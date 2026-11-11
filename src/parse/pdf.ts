/**
 * PDF to Markdown. Text pages are read locally with pdf-inspector (free, ~5 ms/page).
 * Only pages it flags as scanned go to OCR. Anything not read is reported as skipped.
 */
import { createRequire } from "node:module";
import { ocrAvailable, runOcr } from "./ocr.js";
import type { ParsedFile, PdfParseOptions, SkippedPage } from "./types.js";

type Inspector = typeof import("@firecrawl/pdf-inspector");
let inspector: Inspector | null = null;

function loadInspector(): Inspector {
  // Native addon: load with require so the bundler leaves it alone.
  if (!inspector) inspector = createRequire(import.meta.url)("@firecrawl/pdf-inspector") as Inspector;
  return inspector;
}

const DEFAULT_MAX_OCR_PAGES = Number(process.env.WEBCRAWL_PARSE_MAX_OCR_PAGES) || 50;

export interface PdfPlan {
  pageCount: number;
  /** 1-indexed pages to read natively. */
  native: number[];
  /** 1-indexed pages to OCR. */
  ocr: number[];
  skipped: SkippedPage[];
}

/**
 * Decides which pages go where. Pure, so it can be unit-tested without a PDF.
 */
export function planPdfPages(input: {
  pageCount: number;
  needsOcr: number[];
  options: PdfParseOptions;
  ocrConfigured: boolean;
}): PdfPlan {
  const { pageCount, options } = input;
  const mode = options.ocr ?? "auto";
  const maxOcr = options.maxOcrPages ?? DEFAULT_MAX_OCR_PAGES;
  const all = Array.from({ length: pageCount }, (_, i) => i + 1);
  const selected = options.pages?.length
    ? [...new Set(options.pages)].filter((p) => p >= 1 && p <= pageCount).sort((a, b) => a - b)
    : all;
  const flagged = new Set(input.needsOcr);

  const native: number[] = [];
  const wantOcr: number[] = [];
  for (const p of selected) {
    if (mode === "force" || (mode === "auto" && flagged.has(p))) wantOcr.push(p);
    else native.push(p);
  }

  const skipped: SkippedPage[] = [];
  let ocr: number[] = [];
  if (mode === "off") {
    for (const p of selected) if (flagged.has(p)) skipped.push({ page: p, reason: "ocr_disabled" });
  } else if (!input.ocrConfigured) {
    for (const p of wantOcr) skipped.push({ page: p, reason: "ocr_unavailable" });
    // In force mode, still return whatever text the page has natively.
    if (mode === "force") native.push(...wantOcr.filter((p) => !flagged.has(p)));
  } else {
    ocr = wantOcr.slice(0, maxOcr);
    for (const p of wantOcr.slice(maxOcr)) skipped.push({ page: p, reason: "page_limit" });
  }
  native.sort((a, b) => a - b);
  return { pageCount, native, ocr, skipped };
}

/** First real-looking h1/h2 (skipping arXiv/DOI stamps and page furniture), else first h3. */
export function pickTitle(markdown: string): string {
  const clean = (s: string) => s.replace(/<\/?\w+>|[*_]/g, "").trim();
  const usable = (s: string) => {
    const t = clean(s);
    return t.length >= 3 && t.length <= 160 && !/^(arxiv:|doi:|page \d|\d+$)/i.test(t);
  };
  const headings = [...markdown.matchAll(/^(#{1,3})\s+(.+)$/gm)].map((m) => ({ level: m[1].length, text: m[2] }));
  const pick = headings.find((h) => h.level <= 2 && usable(h.text)) ?? headings.find((h) => usable(h.text));
  return pick ? clean(pick.text) : "";
}

function toBuffer(bytes: Uint8Array): Buffer {
  return Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

/** Page count and pages needing OCR, without extracting text (cheap: ~1 ms/page). */
export function pdfPageInfo(bytes: Uint8Array): { pageCount: number; pagesNeedingOcr: number[]; title?: string } {
  const info = loadInspector().detectPdf(toBuffer(bytes));
  return { pageCount: info.pageCount, pagesNeedingOcr: info.pagesNeedingOcr, title: info.title?.trim() || undefined };
}

export async function parsePdf(bytes: Uint8Array, options: PdfParseOptions = {}): Promise<ParsedFile> {
  const started = Date.now();
  const buf = toBuffer(bytes);
  const pdf = loadInspector();
  const warnings: string[] = [];

  const info = pdf.detectPdf(buf);
  const plan = planPdfPages({
    pageCount: info.pageCount,
    needsOcr: info.pagesNeedingOcr,
    options,
    ocrConfigured: ocrAvailable(),
  });
  if (info.hasEncodingIssues) warnings.push("Some fonts have missing character maps; text may contain gaps.");

  const byPage = new Map<number, string>();
  const nativeRead: number[] = [];
  if (plan.native.length) {
    // extractPagesMarkdown takes and returns 0-indexed pages; detectPdf reports 1-indexed ones.
    const extracted = await pdf.extractPagesMarkdownAsync(
      buf,
      plan.native.map((p) => p - 1)
    );
    for (const raw of extracted.pages) {
      const page = raw.page + 1;
      const md = raw.markdown.trim();
      if (md) {
        byPage.set(page, md);
        nativeRead.push(page);
      } else if (!plan.ocr.includes(page) && !plan.skipped.some((s) => s.page === page)) {
        plan.skipped.push({ page, reason: "empty" });
      }
    }
  }

  const ocrRead: number[] = [];
  let ocrProvider: string | undefined;
  if (plan.ocr.length) {
    try {
      const result = await runOcr({ bytes: buf, mime: "application/pdf", pages: plan.ocr, signal: options.signal });
      ocrProvider = result.provider;
      warnings.push(...result.warnings.map((w) => `OCR fallback: ${w}`));
      const wanted = new Set(plan.ocr);
      for (const p of result.pages) {
        if (!wanted.has(p.page) || !p.markdown) continue;
        byPage.set(p.page, p.markdown);
        ocrRead.push(p.page);
      }
      for (const p of plan.ocr) if (!ocrRead.includes(p)) plan.skipped.push({ page: p, reason: "ocr_failed" });
    } catch (err) {
      warnings.push(`OCR failed: ${err instanceof Error ? err.message : String(err)}`);
      for (const p of plan.ocr) plan.skipped.push({ page: p, reason: "ocr_failed" });
    }
  }

  const ordered = [...byPage.keys()].sort((a, b) => a - b);
  const multi = ordered.length > 1;
  const markdown = ordered
    .map((p) => (multi ? `<!-- page ${p} -->\n\n${byPage.get(p)}` : byPage.get(p)!))
    .join("\n\n");
  plan.skipped.sort((a, b) => a.page - b.page);

  // Prefer document metadata, then the highest-level heading (first page banners are often ###).
  const title = info.title?.trim() || pickTitle(markdown);
  return {
    title,
    markdown,
    meta: {
      kind: "pdf",
      mime: "application/pdf",
      method: ocrRead.length > nativeRead.length ? "ocr" : "native",
      bytes: buf.byteLength,
      pages: info.pageCount,
      pagesNative: nativeRead.sort((a, b) => a - b),
      pagesOcr: ocrRead.sort((a, b) => a - b),
      pagesSkipped: plan.skipped,
      ocrProvider,
      warnings,
      processingMs: Date.now() - started,
    },
  };
}
