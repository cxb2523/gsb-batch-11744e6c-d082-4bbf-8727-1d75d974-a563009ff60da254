/**
 * Images -> a short description plus any text in the image, from Gemini Flash-Lite
 * through AI Gateway. One call per image. Without credentials nothing is invented:
 * the result is empty with a warning.
 */
import { createGateway } from "@ai-sdk/gateway";
import { generateText } from "ai";
import type { ParsedFile } from "./types.js";

const DEFAULT_VISION_MODEL = "google/gemini-2.5-flash-lite";
export const VISION_PROVIDER = "gemini-flash-lite";

function gatewayKey(): string | undefined {
  return process.env.AI_GATEWAY_API_KEY || process.env.VERCEL_OIDC_TOKEN;
}

export function visionAvailable(): boolean {
  return Boolean(gatewayKey());
}

const PROMPT = [
  "Describe this image for someone who cannot see it, then transcribe any text in it.",
  "Reply in exactly this format:",
  "<<<DESCRIPTION>>>",
  "Two to four plain sentences: what the image shows, and the key facts a reader needs (numbers in charts, labels in diagrams).",
  "<<<TEXT>>>",
  "All legible text in the image as GitHub-flavoured Markdown (keep tables as tables). Write NONE if there is no text.",
  "Do not guess at text you cannot read.",
].join("\n");

/** Splits the model reply into description and text. Tolerates a missing TEXT marker. */
export function splitVisionReply(reply: string): { description: string; text: string } {
  const d = reply.indexOf("<<<DESCRIPTION>>>");
  const t = reply.indexOf("<<<TEXT>>>");
  if (d === -1 && t === -1) return { description: reply.trim(), text: "" };
  const description = (
    t === -1 ? reply.slice(d + 17) : reply.slice(d === -1 ? 0 : d + 17, t)
  ).trim();
  let text = t === -1 ? "" : reply.slice(t + 10).trim();
  if (/^none\.?$/i.test(text)) text = "";
  return { description, text };
}

export function imageMarkdown(description: string, text: string): string {
  const parts: string[] = [];
  if (description) parts.push(`## Description\n\n${description}`);
  if (text) parts.push(`## Text in image\n\n${text}`);
  return parts.join("\n\n");
}

export async function parseImage(
  bytes: Uint8Array,
  mime: string,
  options: { fileName?: string; signal?: AbortSignal } = {}
): Promise<ParsedFile> {
  const started = performance.now();
  const warnings: string[] = [];
  const base = {
    kind: "image" as const,
    mime,
    method: "vision" as const,
    bytes: bytes.byteLength,
  };
  const title = options.fileName?.split("/").pop()?.replace(/\.[a-z0-9]+$/i, "") || "";

  const key = gatewayKey();
  if (!key) {
    warnings.push("Image description unavailable: no vision model configured");
    return {
      title,
      markdown: "",
      meta: { ...base, warnings, processingMs: Math.round(performance.now() - started) },
    };
  }

  try {
    const gw = createGateway({ apiKey: key });
    const { text: reply } = await generateText({
      model: gw(process.env.WEBCRAWL_VISION_MODEL || DEFAULT_VISION_MODEL),
      maxOutputTokens: 4_000,
      abortSignal: options.signal ?? AbortSignal.timeout(60_000),
      messages: [
        {
          role: "user",
          content: [
            { type: "image", image: bytes, mediaType: mime },
            { type: "text", text: PROMPT },
          ],
        },
      ],
    });
    const { description, text } = splitVisionReply(reply);
    return {
      title,
      markdown: imageMarkdown(description, text),
      meta: {
        ...base,
        visionProvider: VISION_PROVIDER,
        warnings,
        processingMs: Math.round(performance.now() - started),
      },
    };
  } catch (err) {
    warnings.push(`Image description failed: ${err instanceof Error ? err.message : String(err)}`);
    return {
      title,
      markdown: "",
      meta: { ...base, warnings, processingMs: Math.round(performance.now() - started) },
    };
  }
}
