/**
 * Generic render-provider tier (Tier R): a server-side JS-rendering provider
 * for pages the native fetch ladder cannot render (JS SPAs, challenge shells).
 *
 * Same pattern as the residential-proxy tier: the provider URL comes from
 * `WEBCRAWL_RENDER_URL` and is unset in the open-source repo — `null` disables
 * the tier entirely, so the OSS build never requires a provider. The hosted
 * webcrawl.app server sets the env (and the optional key), so cloud-mode calls
 * render JS pages through the provider while local zero-key mode degrades to
 * the `webcrawl login` prompt.
 *
 * The wire format parsed here is the de-facto standard "reader" text format
 * (`Title:` / `URL Source:` / `Markdown Content:` headers), so any compatible
 * provider works without code changes.
 */

/** Render-provider endpoint base URL, or null when the tier is disabled. */
export function renderProviderUrl(): string | null {
  const url = (process.env.WEBCRAWL_RENDER_URL ?? "").trim();
  return url.length > 0 ? url : null;
}

/** Optional bearer key for the render provider (hosted tier). */
export function renderProviderKey(): string | null {
  const key = (process.env.WEBCRAWL_RENDER_KEY ?? "").trim();
  return key.length > 0 ? key : null;
}

/** Whether the render-provider tier is configured and usable at all. */
export function isRenderProviderEnabled(): boolean {
  return renderProviderUrl() !== null;
}

export interface RenderedPage {
  title: string;
  markdown: string;
  sourceUrl: string;
  warnings: string[];
}

/** Default provider rate limit (requests/min) when no key is configured. */
const KEYLESS_RATE_LIMIT_PER_MIN = 15;
/** Provider rate limit (requests/min) assumed with a key configured. */
const KEYED_RATE_LIMIT_PER_MIN = 60;
/** Hard timeout for a single render request. */
const RENDER_TIMEOUT_MS = 45_000;
/** Max bytes accepted from the provider (matches the fetch ladder cap). */
const RENDER_MAX_BYTES = 2 * 1024 * 1024;

const rateWindow: number[] = [];

function withinRateLimit(): boolean {
  const now = Date.now();
  while (rateWindow.length > 0 && rateWindow[0] <= now - 60_000) rateWindow.shift();
  const limit = renderProviderKey() ? KEYED_RATE_LIMIT_PER_MIN : KEYLESS_RATE_LIMIT_PER_MIN;
  if (rateWindow.length >= limit) return false;
  rateWindow.push(now);
  return true;
}

/**
 * Failure markers providers prepend/emit when the target page could not be
 * rendered (challenge, CAPTCHA, upstream error). A matching response is not
 * rendered content and must not be returned as such.
 */
const RENDER_FAILURE_MARKERS = [
  "target url returned error",
  "may be requiring captcha",
  "maybe requiring captcha",
  "please make sure you are authorized",
];

/** Splits a reader-format response body into its header fields and markdown. */
export function parseRenderedResponse(
  body: string
): { title: string; sourceUrl: string; markdown: string } {
  const lines = body.split("\n");
  let title = "";
  let sourceUrl = "";
  let markdownStart = lines.length;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.startsWith("Title:")) {
      title = line.slice("Title:".length).trim();
      continue;
    }
    if (line.startsWith("URL Source:")) {
      sourceUrl = line.slice("URL Source:".length).trim();
      continue;
    }
    if (/^Markdown Content:?\s*$/.test(line)) {
      markdownStart = i + 1;
      break;
    }
  }

  let markdown = lines.slice(markdownStart).join("\n").trim();
  if (markdownStart === lines.length && title) {
    // No "Markdown Content:" separator: treat the whole body after the header
    // block as markdown (some providers omit the separator).
    markdown = lines
      .filter((l) => !l.startsWith("Title:") && !l.startsWith("URL Source:"))
      .join("\n")
      .trim();
  }
  return { title, sourceUrl, markdown };
}

/** Test helper: clears the in-memory rate-limit window (external env untouched). */
export function resetRenderStateForTests(): void {
  rateWindow.length = 0;
}

/**
 * Renders `url` through the configured render provider. Returns null when the
 * tier is disabled, rate-limited, times out, or the provider itself reports a
 * failed render — the caller then keeps its native result.
 */
export async function renderViaProvider(url: string): Promise<RenderedPage | null> {
  const base = renderProviderUrl();
  if (!base) return null;
  if (!withinRateLimit()) return null;

  const key = renderProviderKey();
  const headers: Record<string, string> = {
    Accept: "text/plain",
    ...(key ? { Authorization: `Bearer ${key}` } : {}),
  };

  let res: Response;
  try {
    res = await fetch(`${base}${url}`, {
      headers,
      signal: AbortSignal.timeout(RENDER_TIMEOUT_MS),
      redirect: "follow",
    });
  } catch {
    return null; // network error / timeout / DNS — keep native result
  }

  if (!res.ok) return null;
  const body = (await res.text()).slice(0, RENDER_MAX_BYTES);
  const lower = body.slice(0, 2000).toLowerCase();
  if (RENDER_FAILURE_MARKERS.some((m) => lower.includes(m))) return null;

  const { title, sourceUrl, markdown } = parseRenderedResponse(body);
  if (markdown.trim().length < 40) return null; // nothing real came back

  return {
    title,
    markdown,
    sourceUrl: sourceUrl || url,
    warnings: [],
  };
}
