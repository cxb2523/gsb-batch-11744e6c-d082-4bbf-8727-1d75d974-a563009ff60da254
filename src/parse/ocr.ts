/**
 * OCR for scanned PDF pages and images.
 * Primary: Mistral OCR (MISTRAL_API_KEY). Fallback: Gemini Flash-Lite via AI Gateway.
 * Each provider returns only the pages it actually read; callers report the rest as skipped.
 */
import { createGateway } from "@ai-sdk/gateway";
import { generateText } from "ai";

export interface OcrPage {
  /** 1-indexed. */
  page: number;
  markdown: string;
}

export interface OcrResult {
  provider: string;
  pages: OcrPage[];
}

export interface OcrInput {
  bytes: Uint8Array;
  mime: string;
  /** 1-indexed pages to read (PDF only). Omit for images or the whole file. */
  pages?: number[];
  signal?: AbortSignal;
}

const MISTRAL_URL = "https://api.mistral.ai/v1/ocr";
const DEFAULT_MISTRAL_MODEL = "mistral-ocr-latest";
const DEFAULT_VISION_MODEL = "google/gemini-2.5-flash-lite";

function gatewayKey(): string | undefined {
  return process.env.AI_GATEWAY_API_KEY || process.env.VERCEL_OIDC_TOKEN;
}

export function ocrAvailable(): boolean {
  return Boolean(process.env.MISTRAL_API_KEY || gatewayKey());
}

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("base64");
}

/** Mistral replaces figures with `![img-0.jpeg](img-0.jpeg)` placeholders we can't serve. */
function stripPlaceholders(md: string): string {
  return md.replace(/!\[[^\]]*\]\((img-\d+\.\w+)\)\s*/g, "").trim();
}

interface MistralPage {
  index: number;
  markdown: string;
}

export async function mistralOcr(input: OcrInput): Promise<OcrResult> {
  const key = process.env.MISTRAL_API_KEY;
  if (!key) throw new Error("MISTRAL_API_KEY not set");
  const isImage = input.mime.startsWith("image/");
  const dataUrl = `data:${input.mime};base64,${toBase64(input.bytes)}`;
  const body: Record<string, unknown> = {
    model: process.env.WEBCRAWL_OCR_MODEL || DEFAULT_MISTRAL_MODEL,
    document: isImage ? { type: "image_url", image_url: dataUrl } : { type: "document_url", document_url: dataUrl },
    include_image_base64: false,
  };
  if (!isImage && input.pages?.length) body.pages = input.pages.map((p) => p - 1);

  const res = await fetch(MISTRAL_URL, {
    method: "POST",
    headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: input.signal ?? AbortSignal.timeout(120_000),
  });
  if (!res.ok) {
    const detail = (await res.text().catch(() => "")).slice(0, 300);
    throw new Error(`Mistral OCR ${res.status}: ${detail}`);
  }
  const json = (await res.json()) as { pages?: MistralPage[] };
  return {
    provider: "mistral",
    pages: (json.pages ?? []).map((p) => ({ page: p.index + 1, markdown: stripPlaceholders(p.markdown || "") })),
  };
}

const PAGE_MARK = /<<<PAGE (\d+)>>>/g;

/** Splits "<<<PAGE n>>>" sections; keeps only pages that were asked for. */
export function splitPageMarkers(text: string, wanted?: number[]): OcrPage[] {
  const marks = [...text.matchAll(PAGE_MARK)];
  if (marks.length === 0) {
    const md = text.trim();
    return md && (!wanted || wanted.length === 1) ? [{ page: wanted?.[0] ?? 1, markdown: md }] : [];
  }
  const allowed = wanted ? new Set(wanted) : null;
  const out: OcrPage[] = [];
  marks.forEach((m, i) => {
    const page = Number(m[1]);
    const end = i + 1 < marks.length ? marks[i + 1].index : text.length;
    const md = text.slice((m.index ?? 0) + m[0].length, end).trim();
    if (md && (!allowed || allowed.has(page))) out.push({ page, markdown: md });
  });
  return out;
}

export async function geminiOcr(input: OcrInput): Promise<OcrResult> {
  const key = gatewayKey();
  if (!key) throw new Error("AI gateway credentials not set");
  const gw = createGateway({ apiKey: key });
  const isImage = input.mime.startsWith("image/");
  const pageList = input.pages?.length ? input.pages.join(", ") : "all";
  const instruction = isImage
    ? "Transcribe all text in this image as GitHub-flavoured Markdown. Keep headings, lists and tables. Output only the transcription; output nothing if there is no text."
    : `Transcribe pages ${pageList} of this PDF as GitHub-flavoured Markdown. Keep headings, lists and tables (as Markdown tables). ` +
      "Start each page with a line <<<PAGE n>>> where n is the 1-based page number. Output only the transcription. Do not summarise or invent text.";

  const { text } = await generateText({
    model: gw(process.env.WEBCRAWL_VISION_MODEL || DEFAULT_VISION_MODEL),
    maxOutputTokens: 32_000,
    abortSignal: input.signal ?? AbortSignal.timeout(120_000),
    messages: [
      {
        role: "user",
        content: [
          { type: "file", data: input.bytes, mediaType: input.mime },
          { type: "text", text: instruction },
        ],
      },
    ],
  });
  const pages = isImage ? (text.trim() ? [{ page: 1, markdown: text.trim() }] : []) : splitPageMarkers(text, input.pages);
  return { provider: "gemini-flash-lite", pages };
}

/** Tries Mistral, then Gemini. Throws only if every configured provider fails. */
export async function runOcr(input: OcrInput): Promise<OcrResult & { warnings: string[] }> {
  const warnings: string[] = [];
  const providers: Array<() => Promise<OcrResult>> = [];
  if (process.env.MISTRAL_API_KEY) providers.push(() => mistralOcr(input));
  if (gatewayKey()) providers.push(() => geminiOcr(input));
  if (providers.length === 0) throw new Error("No OCR provider configured");

  let lastErr: unknown;
  for (const run of providers) {
    try {
      return { ...(await run()), warnings };
    } catch (err) {
      lastErr = err;
      warnings.push(err instanceof Error ? err.message : String(err));
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
}
