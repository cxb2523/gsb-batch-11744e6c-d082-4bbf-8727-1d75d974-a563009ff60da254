/**
 * Audio / video -> timestamped transcript.
 * 1. Captions first: if the caller passes captions (WebVTT or SRT), use them. No model call.
 * 2. Otherwise Groq `whisper-large-v3-turbo` if GROQ_API_KEY is set, falling back to the AI Gateway
 *    (`spacexai/grok-stt` by default, billed at 2 credits/min) when Groq is missing or fails.
 * 3. Optional visual description for video via Gemini Flash-Lite (AI Gateway).
 * Nothing is invented: without a provider the transcript is empty with a warning.
 */
import { createGateway } from "@ai-sdk/gateway";
import { experimental_transcribe, generateText } from "ai";
import type { ParsedFile } from "./types.js";

const GROQ_URL = "https://api.groq.com/openai/v1/audio/transcriptions";
const DEFAULT_TRANSCRIBE_MODEL = "whisper-large-v3-turbo";
const DEFAULT_VISION_MODEL = "google/gemini-2.5-flash-lite";
/** Gemini inline video limit through the gateway; larger videos skip the description. */
const MAX_VIDEO_DESCRIBE_BYTES = 20 * 1024 * 1024;

export interface Segment {
  start: number;
  end: number;
  text: string;
}

export interface MediaParseOptions {
  fileName?: string;
  /** WebVTT or SRT text. Used instead of transcription when present. */
  captions?: string;
  /** BCP-47 / ISO-639-1 hint for Whisper, e.g. "en". */
  language?: string;
  /** Video only: add a short description of what is on screen. */
  describeVideo?: boolean;
  signal?: AbortSignal;
}

export function transcriptionAvailable(): boolean {
  return Boolean(process.env.GROQ_API_KEY || gatewayKey());
}

function gatewayKey(): string | undefined {
  return process.env.AI_GATEWAY_API_KEY || process.env.VERCEL_OIDC_TOKEN;
}

/** ~$0.0017/min with segment timestamps; whisper-1 is $0.006/min. Override with WEBCRAWL_GATEWAY_TRANSCRIBE_MODEL. */
const DEFAULT_GATEWAY_TRANSCRIBE_MODEL = "spacexai/grok-stt";

/** Transcribes through the Vercel AI Gateway (no extra provider key needed). */
export async function gatewayTranscribe(
  bytes: Uint8Array,
  options: { language?: string; signal?: AbortSignal } = {}
): Promise<{ segments: Segment[]; duration: number; language?: string }> {
  const key = gatewayKey();
  if (!key) throw new Error("no transcription provider configured");
  const gw = createGateway({ apiKey: key });
  const r = await experimental_transcribe({
    model: gw.transcription(process.env.WEBCRAWL_GATEWAY_TRANSCRIBE_MODEL || DEFAULT_GATEWAY_TRANSCRIBE_MODEL),
    audio: bytes,
    abortSignal: options.signal ?? AbortSignal.timeout(300_000),
    ...(options.language ? { providerOptions: { openai: { language: options.language } } } : {}),
  });
  const segments = r.segments
    .map((s) => ({ start: s.startSecond, end: s.endSecond, text: s.text.trim() }))
    .filter((s) => s.text);
  if (!segments.length && r.text.trim()) segments.push({ start: 0, end: r.durationInSeconds ?? 0, text: r.text.trim() });
  return { segments, duration: r.durationInSeconds ?? segments[segments.length - 1]?.end ?? 0, language: r.language };
}

/** 3725.4 -> "1:02:05"; 65 -> "1:05". */
export function formatTimestamp(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = String(s % 60).padStart(2, "0");
  return h > 0 ? `${h}:${String(m).padStart(2, "0")}:${sec}` : `${m}:${sec}`;
}

function parseClock(t: string): number {
  const parts = t.trim().replace(",", ".").split(":").map(Number);
  return parts.reduce((acc, n) => acc * 60 + n, 0);
}

/** Parses WebVTT or SRT cues. Drops styling tags and repeated rolling-caption lines. */
export function parseCaptions(text: string): Segment[] {
  const cues: Segment[] = [];
  const blocks = text.replace(/\r/g, "").split(/\n{2,}/);
  for (const block of blocks) {
    const lines = block.split("\n");
    const i = lines.findIndex((l) => l.includes("-->"));
    if (i === -1) continue;
    const [a, b] = lines[i].split("-->");
    const body = lines
      .slice(i + 1)
      .join(" ")
      .replace(/<[^>]+>/g, "")
      .replace(/\s+/g, " ")
      .trim();
    if (!body) continue;
    const start = parseClock(a);
    const end = parseClock(b.trim().split(/\s/)[0]);
    const prev = cues[cues.length - 1];
    if (prev && prev.text === body) {
      prev.end = end;
      continue;
    }
    cues.push({ start, end, text: body });
  }
  return cues;
}

/** Groups segments into ~30 s paragraphs, each prefixed with its start time. */
export function transcriptMarkdown(segments: Segment[], paragraphSeconds = 30): string {
  const out: string[] = [];
  let buf: string[] = [];
  let bufStart = 0;
  for (const seg of segments) {
    if (buf.length === 0) bufStart = seg.start;
    buf.push(seg.text.trim());
    if (seg.end - bufStart >= paragraphSeconds) {
      out.push(`**[${formatTimestamp(bufStart)}]** ${buf.join(" ")}`);
      buf = [];
    }
  }
  if (buf.length) out.push(`**[${formatTimestamp(bufStart)}]** ${buf.join(" ")}`);
  return out.join("\n\n");
}

interface GroqVerbose {
  text?: string;
  duration?: number;
  language?: string;
  segments?: Array<{ start: number; end: number; text: string }>;
}

export async function groqTranscribe(
  bytes: Uint8Array,
  mime: string,
  options: { fileName?: string; language?: string; signal?: AbortSignal } = {}
): Promise<{ segments: Segment[]; duration: number; language?: string }> {
  const key = process.env.GROQ_API_KEY;
  if (!key) throw new Error("GROQ_API_KEY not set");
  const form = new FormData();
  const name = options.fileName?.split("/").pop() || `media.${mime.split("/")[1] || "bin"}`;
  form.append("file", new Blob([bytes as BlobPart], { type: mime }), name);
  form.append("model", process.env.WEBCRAWL_TRANSCRIBE_MODEL || DEFAULT_TRANSCRIBE_MODEL);
  form.append("response_format", "verbose_json");
  form.append("timestamp_granularities[]", "segment");
  if (options.language) form.append("language", options.language);

  const res = await fetch(GROQ_URL, {
    method: "POST",
    headers: { Authorization: `Bearer ${key}` },
    body: form,
    signal: options.signal ?? AbortSignal.timeout(300_000),
  });
  if (!res.ok) {
    const detail = (await res.text().catch(() => "")).slice(0, 300);
    throw new Error(`Groq transcription ${res.status}: ${detail}`);
  }
  const json = (await res.json()) as GroqVerbose;
  const segments = (json.segments ?? []).map((s) => ({ start: s.start, end: s.end, text: s.text.trim() }));
  if (segments.length === 0 && json.text?.trim()) {
    segments.push({ start: 0, end: json.duration ?? 0, text: json.text.trim() });
  }
  const duration = json.duration ?? segments[segments.length - 1]?.end ?? 0;
  return { segments, duration, language: json.language };
}

async function describeVideo(bytes: Uint8Array, mime: string, signal?: AbortSignal): Promise<string> {
  const key = gatewayKey();
  if (!key) throw new Error("no vision model configured");
  if (bytes.byteLength > MAX_VIDEO_DESCRIBE_BYTES) throw new Error("video too large to describe");
  const gw = createGateway({ apiKey: key });
  const { text } = await generateText({
    model: gw(process.env.WEBCRAWL_VISION_MODEL || DEFAULT_VISION_MODEL),
    maxOutputTokens: 1_500,
    abortSignal: signal ?? AbortSignal.timeout(120_000),
    // Low resolution is ~66 tokens/frame instead of ~258: plenty for a scene summary, ~4x cheaper.
    providerOptions: { google: { mediaResolution: "MEDIA_RESOLUTION_LOW" } },
    messages: [
      {
        role: "user",
        content: [
          { type: "file", data: bytes, mediaType: mime },
          {
            type: "text",
            text: "Describe what is shown on screen in this video in 3-6 plain sentences: setting, people, on-screen text, slides or charts. Do not transcribe speech.",
          },
        ],
      },
    ],
  });
  return text.trim();
}

export async function parseMedia(
  bytes: Uint8Array,
  kind: "audio" | "video",
  mime: string,
  options: MediaParseOptions = {}
): Promise<ParsedFile> {
  const started = performance.now();
  const warnings: string[] = [];
  const title = options.fileName?.split("/").pop()?.replace(/\.[a-z0-9]+$/i, "") || "";
  let segments: Segment[] = [];
  let duration: number | undefined;
  let provider: string | undefined;

  if (options.captions?.trim()) {
    segments = parseCaptions(options.captions);
    if (segments.length) {
      provider = "captions";
      duration = segments[segments.length - 1].end;
    } else {
      warnings.push("Captions were provided but contained no cues; transcribing instead");
    }
  }

  if (!provider) {
    if (!transcriptionAvailable()) {
      warnings.push("Transcript unavailable: no transcription provider configured");
    } else {
      // Groq turbo (if configured) is ~2.5x cheaper than gateway grok-stt; the gateway is billed 2 cr/min.
      const attempts: Array<{ name: string; run: () => ReturnType<typeof gatewayTranscribe> }> = [];
      if (process.env.GROQ_API_KEY) attempts.push({ name: "groq-whisper-turbo", run: () => groqTranscribe(bytes, mime, options) });
      if (gatewayKey()) attempts.push({ name: "gateway-stt", run: () => gatewayTranscribe(bytes, options) });
      const errors: string[] = [];
      for (const a of attempts) {
        try {
          const r = await a.run();
          segments = r.segments;
          duration = r.duration;
          provider = a.name;
          if (!segments.length) warnings.push("No speech detected");
          break;
        } catch (err) {
          errors.push(`${a.name}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
      if (!provider) warnings.push(`Transcription failed: ${errors.join("; ")}`);
    }
  }

  const parts: string[] = [];
  let visionProvider: string | undefined;
  if (kind === "video" && options.describeVideo) {
    try {
      const desc = await describeVideo(bytes, mime, options.signal);
      if (desc) {
        parts.push(`## What's on screen\n\n${desc}`);
        visionProvider = "gemini-flash-lite";
      }
    } catch (err) {
      warnings.push(`Video description skipped: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  if (segments.length) parts.push(`## Transcript\n\n${transcriptMarkdown(segments)}`);

  return {
    title,
    markdown: parts.join("\n\n"),
    meta: {
      kind,
      mime,
      method: "transcript",
      bytes: bytes.byteLength,
      ...(duration !== undefined ? { durationSeconds: Math.round(duration * 10) / 10 } : {}),
      ...(provider ? { transcriptProvider: provider } : {}),
      ...(visionProvider ? { visionProvider } : {}),
      warnings,
      processingMs: Math.round(performance.now() - started),
    },
  };
}
