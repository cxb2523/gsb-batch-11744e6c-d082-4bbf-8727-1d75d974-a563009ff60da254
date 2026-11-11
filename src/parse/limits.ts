import type { FileKind } from "./detect.js";

const MB = 1024 * 1024;

function envMb(name: string, fallbackMb: number): number {
  const raw = Number(process.env[name]);
  return (Number.isFinite(raw) && raw > 0 ? raw : fallbackMb) * MB;
}

/** Per-kind size caps. Override with WEBCRAWL_PARSE_MAX_{DOC,IMAGE,MEDIA}_MB. */
export function maxBytesFor(kind: FileKind): number {
  switch (kind) {
    case "image":
      return envMb("WEBCRAWL_PARSE_MAX_IMAGE_MB", 20);
    case "audio":
    case "video":
      // Groq's transcription upload limit.
      return envMb("WEBCRAWL_PARSE_MAX_MEDIA_MB", 100);
    default:
      return envMb("WEBCRAWL_PARSE_MAX_DOC_MB", 50);
  }
}

/** Upper bound for any download before the kind is known. */
export function maxDownloadBytes(): number {
  return Math.max(maxBytesFor("pdf"), maxBytesFor("image"), maxBytesFor("audio"));
}

/** Jobs bigger than these run as a background workflow instead of inline. */
export const ASYNC_THRESHOLDS = {
  pdfPages: Number(process.env.WEBCRAWL_PARSE_ASYNC_PAGES) || 50,
  mediaSeconds: Number(process.env.WEBCRAWL_PARSE_ASYNC_SECONDS) || 600,
  pdfBatchPages: 20,
  mediaChunkSeconds: 600,
};
