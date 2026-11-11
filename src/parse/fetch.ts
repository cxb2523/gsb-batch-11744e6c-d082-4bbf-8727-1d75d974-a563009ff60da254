/**
 * Fetch a URL as bytes and parse it if it is a binary file (PDF, Office, image, media).
 * Returns null when the URL is HTML/text so callers fall back to the HTML pipeline.
 */
import { fetchResource, type FetchedResource } from "../engine/fetcher.js";
import { detectFileKind, type FileKind } from "./detect.js";
import { maxDownloadBytes } from "./limits.js";
import { isBinaryKind, parseFile, type ParseFileOptions, type ParseFileResult } from "./index.js";

const BINARY_EXT = /\.(pdf|docx|xlsx|pptx|png|jpe?g|webp|gif|heic|avif|mp3|wav|m4a|ogg|oga|flac|opus|aac|mp4|m4v|mov|webm|mkv)$/i;

/** Cheap check before any network: does the URL path end in a binary file extension? */
export function looksLikeBinaryUrl(url: string): boolean {
  try {
    return BINARY_EXT.test(new URL(url).pathname);
  } catch {
    return BINARY_EXT.test(url.split(/[?#]/)[0]);
  }
}

/** Does a response content type mean we should take the binary path? */
export function isBinaryContentType(contentType: string | undefined): boolean {
  const ct = (contentType || "").split(";")[0].trim().toLowerCase();
  if (!ct) return false;
  const { kind } = detectFileKind({ contentType: ct });
  return isBinaryKind(kind) || ct === "application/octet-stream";
}

export interface FetchedParse {
  resource: FetchedResource;
  kind: FileKind;
  result: ParseFileResult;
}

export async function fetchAndParse(
  url: string,
  options: ParseFileOptions & { timeoutMs?: number; resource?: FetchedResource } = {}
): Promise<FetchedParse | null> {
  const resource =
    options.resource ??
    (await fetchResource(url, { timeoutMs: options.timeoutMs ?? 30_000, maxBytes: maxDownloadBytes() }));
  const fileName = new URL(resource.url || url).pathname.split("/").pop() || undefined;
  const { kind } = detectFileKind({ bytes: resource.body, contentType: resource.contentType, fileName });
  if (!isBinaryKind(kind)) return null;
  if (resource.status >= 400) {
    throw new Error(`File request failed with HTTP ${resource.status}`);
  }
  const result = await parseFile({ bytes: resource.body, contentType: resource.contentType, fileName }, options);
  return { resource, kind, result };
}
