/**
 * YouTube link -> timestamped transcript from the video's own captions.
 * No audio download and no model call: we read the caption track YouTube already publishes.
 * Videos without captions return an error rather than an empty or invented transcript.
 */
import type { Segment } from "./media.js";
import { transcriptMarkdown } from "./media.js";
import { getCachedPageAsync, setCachedPage } from "../engine/cache.js";
import type { ParsedFile, ParseMeta } from "./types.js";

const PLAYER_URL =
  "https://www.youtube.com/youtubei/v1/player?prettyPrint=false";
const MAX_ATTEMPTS = 3;
const UA = "com.google.android.youtube/20.10.38 (Linux; U; Android 11) gzip";

/** Tried in order; YouTube blocks some clients from datacenter IPs, so we fall through. */
const CLIENTS: Array<{
  context: Record<string, unknown>;
  ua: string;
  thirdParty?: boolean;
}> = [
  {
    context: {
      client: {
        clientName: "ANDROID",
        clientVersion: "20.10.38",
        androidSdkVersion: 30,
        hl: "en",
      },
    },
    ua: UA,
  },
  {
    context: {
      client: {
        clientName: "TVHTML5_SIMPLY_EMBEDDED_PLAYER",
        clientVersion: "2.0",
        hl: "en",
      },
      thirdParty: { embedUrl: "https://www.youtube.com/" },
    },
    ua: "Mozilla/5.0 (SMART-TV; Linux; Tizen 6.5) AppleWebKit/537.36 (KHTML, like Gecko) 85.0.4183.93/6.5 TV Safari/537.36",
  },
  {
    context: {
      client: {
        clientName: "WEB_EMBEDDED_PLAYER",
        clientVersion: "1.20250310.01.00",
        hl: "en",
      },
      thirdParty: { embedUrl: "https://www.google.com/" },
    },
    ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36",
  },
  {
    context: {
      client: {
        clientName: "IOS",
        clientVersion: "20.10.4",
        deviceMake: "Apple",
        deviceModel: "iPhone16,2",
        osName: "iPhone",
        osVersion: "18.3.2.22D82",
        hl: "en",
      },
    },
    ua: "com.google.ios.youtube/20.10.4 (iPhone16,2; U; CPU iOS 18_3_2 like Mac OS X;)",
  },
];

/**
 * YouTube refuses most cloud-hosting IP ranges. When YOUTUBE_RELAY_URL and YOUTUBE_RELAY_TOKEN are set,
 * requests go through a relay on a network YouTube accepts; otherwise they go straight out.
 */
function youtubeFetch(
  url: string,
  init: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    signal?: AbortSignal;
  }
): Promise<Response> {
  const relay = process.env.YOUTUBE_RELAY_URL;
  const token = process.env.YOUTUBE_RELAY_TOKEN;
  if (!relay || !token) return fetch(url, init);
  return fetch(relay, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      url,
      method: init.method,
      headers: init.headers,
      body: init.body,
    }),
    signal: init.signal,
  });
}

export class YouTubeError extends Error {
  constructor(
    message: string,
    public readonly status = 422
  ) {
    super(message);
    this.name = "YouTubeError";
  }
}

/** Returns the 11-character video id for watch, short, embed, shorts, live and youtu.be links. */
export function youtubeVideoId(input: string): string | undefined {
  let u: URL;
  try {
    u = new URL(input);
  } catch {
    return undefined;
  }
  const host = u.hostname.replace(/^(www|m|music)\./, "");
  const ok = (s: string | null | undefined) =>
    s && /^[A-Za-z0-9_-]{11}$/.test(s) ? s : undefined;
  if (host === "youtu.be") return ok(u.pathname.slice(1).split("/")[0]);
  if (host !== "youtube.com" && host !== "youtube-nocookie.com")
    return undefined;
  if (u.pathname === "/watch") return ok(u.searchParams.get("v"));
  const m = /^\/(?:embed|shorts|live|v)\/([^/?#]+)/.exec(u.pathname);
  return m ? ok(m[1]) : undefined;
}

function decodeEntities(s: string): string {
  return s
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, n) =>
      String.fromCodePoint(parseInt(n, 16))
    )
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

/** Parses YouTube's timedtext XML (`<p t= d=>` in ms, optional `<s>` children). */
export function parseTimedText(xml: string): Segment[] {
  const out: Segment[] = [];
  for (const m of xml.matchAll(/<p\s([^>]*)>([\s\S]*?)<\/p>/g)) {
    const t = /\bt="(\d+)"/.exec(m[1]);
    if (!t) continue;
    const d = /\bd="(\d+)"/.exec(m[1]);
    const text = decodeEntities(m[2].replace(/<[^>]+>/g, ""))
      .replace(/\s+/g, " ")
      .trim();
    if (!text) continue;
    const start = Number(t[1]) / 1000;
    out.push({
      start,
      end: Math.round((start + (d ? Number(d[1]) / 1000 : 0)) * 1000) / 1000,
      text,
    });
  }
  return out;
}

interface CaptionTrack {
  baseUrl: string;
  languageCode: string;
  kind?: string;
}

function pickTrack(tracks: CaptionTrack[], language?: string): CaptionTrack {
  const want = (language || "en").toLowerCase().split("-")[0];
  const byLang = tracks.filter(
    (t) => t.languageCode.toLowerCase().split("-")[0] === want
  );
  const pool = byLang.length ? byLang : tracks;
  // Human-written captions beat auto-generated ones.
  return pool.find((t) => t.kind !== "asr") ?? pool[0];
}

export async function parseYouTube(
  videoId: string,
  options: { language?: string; signal?: AbortSignal } = {}
): Promise<ParsedFile> {
  const started = performance.now();
  const signal = options.signal ?? AbortSignal.timeout(25_000);
  type Player = {
    playabilityStatus?: { status?: string; reason?: string };
    videoDetails?: { title?: string; lengthSeconds?: string };
    captions?: {
      playerCaptionsTracklistRenderer?: { captionTracks?: CaptionTrack[] };
    };
  };
  let player: Player | undefined;
  let ua = UA;
  let lastReason = "";
  // The relay's addresses are shared, so YouTube occasionally flags one with a bot check.
  // A retry usually leaves from a different address, so retry only that case.
  for (let attempt = 0; attempt < MAX_ATTEMPTS && !player; attempt++) {
    if (attempt > 0 && !/not a bot/i.test(lastReason)) break;
    if (attempt > 0) await new Promise((r) => setTimeout(r, 400 * attempt));
    for (const c of CLIENTS) {
      try {
        const res = await youtubeFetch(PLAYER_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json", "User-Agent": c.ua },
          body: JSON.stringify({
            context: c.context,
            videoId,
            contentCheckOk: true,
            racyCheckOk: true,
          }),
          signal,
        });
        if (!res.ok) {
          lastReason = `HTTP ${res.status}`;
          continue;
        }
        const p = (await res.json()) as Player;
        if (p.playabilityStatus?.status === "OK") {
          player = p;
          ua = c.ua;
          break;
        }
        lastReason =
          p.playabilityStatus?.reason ||
          p.playabilityStatus?.status?.toLowerCase() ||
          "unavailable";
      } catch (err) {
        lastReason = err instanceof Error ? err.message : String(err);
      }
    }
  }
  if (!player)
    throw new YouTubeError(`This video can't be read (${lastReason})`);
  const tracks =
    player.captions?.playerCaptionsTracklistRenderer?.captionTracks ?? [];
  if (!tracks.length)
    throw new YouTubeError(
      "This video has no captions, so there is no transcript to read"
    );

  const track = pickTrack(tracks, options.language);
  const cap = await youtubeFetch(track.baseUrl, {
    headers: { "User-Agent": ua },
    signal,
  });
  if (!cap.ok)
    throw new YouTubeError(
      `Could not load the captions (HTTP ${cap.status})`,
      502
    );
  const segments = parseTimedText(await cap.text());
  if (!segments.length)
    throw new YouTubeError("The captions for this video were empty");

  const lengthSeconds = Number(player.videoDetails?.lengthSeconds);
  const duration =
    Number.isFinite(lengthSeconds) && lengthSeconds > 0
      ? lengthSeconds
      : segments[segments.length - 1].end;
  const warnings: string[] = [];
  if (track.kind === "asr")
    warnings.push(
      "Captions are auto-generated by YouTube and may contain errors"
    );

  return {
    title: player.videoDetails?.title || "",
    markdown: `## Transcript\n\n${transcriptMarkdown(segments)}`,
    meta: {
      kind: "video",
      mime: "video/youtube",
      method: "transcript",
      bytes: 0,
      durationSeconds: duration,
      transcriptProvider: "captions",
      warnings,
      processingMs: Math.round(performance.now() - started),
    },
  };
}

export interface YouTubeResult extends ParsedFile {
  contentHash: string;
  cached: boolean;
  cacheLayer: "memory" | "disk" | "postgres" | "miss";
}

/** Same transcript for the same video and language, so successful reads are kept for 24 hours. Failures are never cached. */
export async function parseYouTubeCached(
  videoId: string,
  options: {
    language?: string;
    signal?: AbortSignal;
    bypassCache?: boolean;
  } = {}
): Promise<YouTubeResult> {
  const key = `wc-parse://youtube:${videoId}/lang=${options.language ?? "default"}`;
  if (!options.bypassCache) {
    const hit = await getCachedPageAsync(key, "parse");
    const meta = hit?.structuredData?.parse as ParseMeta | undefined;
    if (hit && meta) {
      return {
        title: hit.title,
        markdown: hit.markdown,
        meta,
        contentHash: `youtube:${videoId}`,
        cached: true,
        cacheLayer: hit.cacheLayer || "postgres",
      };
    }
  }
  const parsed = await parseYouTube(videoId, options);
  setCachedPage(key, "parse", {
    title: parsed.title,
    markdown: parsed.markdown,
    links: [],
    structuredData: {
      parse: parsed.meta as unknown as Record<string, unknown>,
    },
    statusCode: 200,
    contentHash: `youtube:${videoId}`,
  });
  return {
    ...parsed,
    contentHash: `youtube:${videoId}`,
    cached: false,
    cacheLayer: "miss",
  };
}
