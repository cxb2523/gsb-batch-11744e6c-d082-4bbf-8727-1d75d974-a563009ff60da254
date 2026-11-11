import type { FileKind } from "./detect.js";

/** How the bulk of the content was produced. */
export type ParseMethod = "native" | "ocr" | "vision" | "transcript";

export interface SkippedPage {
  page: number;
  reason: "ocr_disabled" | "ocr_unavailable" | "ocr_failed" | "page_limit" | "empty";
}

/** Reported to the caller as `metadata.parse`, and used to charge credits. */
export interface ParseMeta {
  kind: FileKind;
  mime: string;
  method: ParseMethod;
  bytes: number;
  pages?: number;
  pagesNative?: number[];
  pagesOcr?: number[];
  pagesSkipped?: SkippedPage[];
  ocrProvider?: string;
  durationSeconds?: number;
  transcriptProvider?: string;
  visionProvider?: string;
  warnings: string[];
  processingMs: number;
}

export interface ParsedFile {
  title: string;
  markdown: string;
  meta: ParseMeta;
}

export interface PdfParseOptions {
  /** "auto": OCR only flagged pages; "force": OCR every page; "off": never OCR. */
  ocr?: "auto" | "force" | "off";
  /** 1-indexed page numbers to include. */
  pages?: number[];
  /** Hard cap on pages sent to OCR in one request. */
  maxOcrPages?: number;
  signal?: AbortSignal;
}
