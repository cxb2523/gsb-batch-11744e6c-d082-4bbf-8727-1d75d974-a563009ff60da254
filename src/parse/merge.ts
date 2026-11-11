/** Pure helpers for the durable parse workflow: batch PDF pages, then merge results. */
import type { ParseMeta, SkippedPage } from "./types.js";

export interface Chunk {
  title: string;
  markdown: string;
  meta: ParseMeta;
  cached: boolean;
}

/** Splits the pages to read into fixed-size batches. */
export function pdfBatches(pageCount: number, selected: number[] | undefined, size: number): number[][] {
  const pages = selected?.length
    ? [...new Set(selected)].filter((p) => p >= 1 && p <= pageCount).sort((a, b) => a - b)
    : Array.from({ length: pageCount }, (_, i) => i + 1);
  const out: number[][] = [];
  for (let i = 0; i < pages.length; i += size) out.push(pages.slice(i, i + size));
  return out;
}

/** Merges per-batch PDF results back into one document, in page order. */
export function mergePdfChunks(chunks: Chunk[], info: { pageCount?: number; title?: string }): { title: string; markdown: string; meta: ParseMeta } {
  const nums = (pick: (m: ParseMeta) => number[] | undefined) => chunks.flatMap((c) => pick(c.meta) ?? []).sort((a, b) => a - b);
  const skipped: SkippedPage[] = chunks.flatMap((c) => c.meta.pagesSkipped ?? []).sort((a, b) => a.page - b.page);
  const pagesNative = nums((m) => m.pagesNative);
  const pagesOcr = nums((m) => m.pagesOcr);
  const parts = chunks.map((c) => c.markdown).filter(Boolean);
  // Single-page batches have no page marker; add one so the merged document is navigable.
  const markdown = chunks
    .map((c) => {
      if (!c.markdown) return "";
      if (c.markdown.startsWith("<!-- page ")) return c.markdown;
      const p = [...(c.meta.pagesNative ?? []), ...(c.meta.pagesOcr ?? [])].sort((a, b) => a - b)[0];
      return parts.length > 1 && p ? `<!-- page ${p} -->\n\n${c.markdown}` : c.markdown;
    })
    .filter(Boolean)
    .join("\n\n");
  const first = chunks[0]?.meta;
  return {
    title: info.title || chunks.find((c) => c.title)?.title || "",
    markdown,
    meta: {
      kind: "pdf",
      mime: "application/pdf",
      method: pagesOcr.length > pagesNative.length ? "ocr" : "native",
      bytes: first?.bytes ?? 0,
      pages: info.pageCount,
      pagesNative,
      pagesOcr,
      pagesSkipped: skipped,
      ocrProvider: chunks.map((c) => c.meta.ocrProvider).find(Boolean),
      warnings: [...new Set(chunks.flatMap((c) => c.meta.warnings))],
      processingMs: chunks.reduce((n, c) => n + c.meta.processingMs, 0),
    },
  };
}

