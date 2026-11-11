/**
 * One entry point for binary files: detect the kind, check the size cap, route to the
 * right parser, and cache by content hash (same bytes => same result, whatever the URL).
 */
import crypto from "node:crypto";
import { getCachedPageAsync, setCachedPage } from "../engine/cache.js";
import { BINARY_KINDS, detectFileKind, type FileKind } from "./detect.js";
import { maxBytesFor } from "./limits.js";
import { parseImage } from "./image.js";
import { parseMedia } from "./media.js";
import { parseOffice } from "./office.js";
import { parsePdf } from "./pdf.js";
import type { ParsedFile, ParseMeta } from "./types.js";

export { detectFileKind, BINARY_KINDS, type FileKind } from "./detect.js";
export type { ParsedFile, ParseMeta } from "./types.js";

export interface ParseFileOptions {
  ocr?: "auto" | "force" | "off";
  pages?: number[];
  maxOcrPages?: number;
  captions?: string;
  language?: string;
  describeVideo?: boolean;
  bypassCache?: boolean;
  signal?: AbortSignal;
}

export interface ParseFileInput {
  bytes: Uint8Array;
  contentType?: string;
  fileName?: string;
}

export class FileTooLargeError extends Error {
  constructor(public readonly kind: FileKind, public readonly bytes: number, public readonly maxBytes: number) {
    super(`${kind.toUpperCase()} is ${(bytes / 1e6).toFixed(1)} MB; the limit is ${(maxBytes / 1e6).toFixed(0)} MB`);
    this.name = "FileTooLargeError";
  }
}

export class UnsupportedFileError extends Error {
  constructor(public readonly kind: FileKind) {
    super(`Not a binary file kind (${kind}); use the HTML/text pipeline`);
    this.name = "UnsupportedFileError";
  }
}

/** Converts parse metadata into billable usage. Cache hits are billed like the original parse. */
export function parseUsageFromMeta(meta: ParseMeta) {
  const isOffice = meta.kind === "docx" || meta.kind === "xlsx" || meta.kind === "pptx";
  return {
    kind: meta.kind,
    method: meta.method,
    pagesNative: meta.pagesNative?.length ?? (isOffice ? meta.pages ?? 1 : undefined),
    pagesOcr: meta.pagesOcr?.length,
    durationSeconds: meta.durationSeconds,
    transcribed: Boolean(meta.transcriptProvider && meta.transcriptProvider !== "captions"),
    transcriptProvider: meta.transcriptProvider,
    videoDescribed: meta.kind === "video" && Boolean(meta.visionProvider),
    imageDescribed: meta.kind === "image" && Boolean(meta.visionProvider),
  };
}

/** Public shape of `metadata.parse` in API responses. */
export function publicParseMeta(r: ParseFileResult): Record<string, unknown> {
  return { ...r.meta, contentHash: r.contentHash, cached: r.cached };
}

export function isBinaryKind(kind: FileKind): boolean {
  return BINARY_KINDS.has(kind);
}

export function contentHash(bytes: Uint8Array): string {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

/** Only options that change the output go into the cache key. */
export function parseCacheKey(hash: string, kind: FileKind, o: ParseFileOptions): string {
  const parts: string[] = [];
  if (kind === "pdf") {
    parts.push(`ocr=${o.ocr ?? "auto"}`);
    if (o.pages?.length) parts.push(`pages=${o.pages.join(",")}`);
    if (o.maxOcrPages) parts.push(`max=${o.maxOcrPages}`);
  }
  if (kind === "audio" || kind === "video") {
    if (o.captions) parts.push(`cap=${crypto.createHash("sha256").update(o.captions).digest("hex").slice(0, 16)}`);
    if (o.language) parts.push(`lang=${o.language}`);
    if (kind === "video" && o.describeVideo) parts.push("describe");
  }
  return `wc-parse://${hash}/${parts.join("&") || "default"}`;
}

/** A result is worth caching only if nothing failed transiently. */
function cacheable(meta: ParseMeta): boolean {
  if (meta.pagesSkipped?.some((s) => s.reason === "ocr_failed" || s.reason === "ocr_unavailable")) return false;
  return !meta.warnings.some((w) => /failed|unavailable/i.test(w));
}

export interface ParseFileResult extends ParsedFile {
  contentHash: string;
  cached: boolean;
  cacheLayer: "memory" | "disk" | "postgres" | "miss";
}

export async function parseFile(input: ParseFileInput, options: ParseFileOptions = {}): Promise<ParseFileResult> {
  const { kind, mime } = detectFileKind(input);
  if (!isBinaryKind(kind)) throw new UnsupportedFileError(kind);
  const max = maxBytesFor(kind);
  if (input.bytes.byteLength > max) throw new FileTooLargeError(kind, input.bytes.byteLength, max);

  const hash = contentHash(input.bytes);
  const key = parseCacheKey(hash, kind, options);

  if (!options.bypassCache) {
    const hit = await getCachedPageAsync(key, "parse");
    const meta = hit?.structuredData?.parse as ParseMeta | undefined;
    if (hit && meta) {
      return {
        title: hit.title,
        markdown: hit.markdown,
        meta,
        contentHash: hash,
        cached: true,
        cacheLayer: hit.cacheLayer || "postgres",
      };
    }
  }

  let parsed: ParsedFile;
  switch (kind) {
    case "pdf":
      parsed = await parsePdf(input.bytes, {
        ocr: options.ocr,
        pages: options.pages,
        maxOcrPages: options.maxOcrPages,
        signal: options.signal,
      });
      break;
    case "docx":
    case "xlsx":
    case "pptx":
      parsed = await parseOffice(input.bytes, kind, mime);
      break;
    case "image":
      parsed = await parseImage(input.bytes, mime, { fileName: input.fileName, signal: options.signal });
      break;
    case "audio":
    case "video":
      parsed = await parseMedia(input.bytes, kind, mime, {
        fileName: input.fileName,
        captions: options.captions,
        language: options.language,
        describeVideo: options.describeVideo,
        signal: options.signal,
      });
      break;
    default:
      throw new UnsupportedFileError(kind);
  }

  if (!parsed.title && input.fileName) {
    parsed.title = input.fileName.split(/[?#]/)[0].split("/").pop() || "";
  }

  if (cacheable(parsed.meta) && parsed.markdown.length > 0) {
    setCachedPage(key, "parse", {
      title: parsed.title,
      markdown: parsed.markdown,
      links: [],
      structuredData: { parse: parsed.meta as unknown as Record<string, unknown> },
      statusCode: 200,
      contentHash: hash,
    });
  }

  return { ...parsed, contentHash: hash, cached: false, cacheLayer: "miss" };
}
