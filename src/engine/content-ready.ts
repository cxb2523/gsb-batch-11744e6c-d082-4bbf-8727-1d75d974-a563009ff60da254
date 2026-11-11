/**
 * Shared "page content looks stable" readiness helpers for JS rendering.
 *
 * Used by the local Chrome CDP path and the Playwright stealth/vm render
 * path. Static (non-JS) fetch is unaffected.
 *
 * Strategy after document load:
 *   1. Poll main-content text length and DOM size (including open shadow
 *      roots; same-origin iframes when readable).
 *   2. Treat visible loading placeholders / skeleton UI as not ready, but
 *      allow legitimately tiny pages and real articles that merely mention
 *      "loading".
 *   3. Return once content is stable for a short window (~500ms), or when
 *      the hard overall cap is hit so never-settling pages cannot hang.
 */

/** How long main content must stay unchanged before we call it ready. */
export const CONTENT_STABLE_MS = 500;

/**
 * After content has grown at least once, require a longer quiet window so
 * staggered chunk fetches (e.g. 1s apart) are not cut off mid-stream.
 */
export const CONTENT_STABLE_AFTER_GROWTH_MS = 1_500;

/** Poll interval while waiting for content to settle. */
export const CONTENT_POLL_MS = 120;

/**
 * Hard cap on the post-load readiness wait. Kept well under the default
 * Chrome page budget (18s) so a hung SPA cannot burn the whole attempt.
 * Override via `maxWaitMs` on the browser expression builder.
 */
export const CONTENT_READY_MAX_WAIT_MS = 10_000;

/** Soft floor: short pages without loading UI may still be ready. */
export const CONTENT_MIN_TEXT_LEN = 40;

/** Meaningful growth thresholds (ignore tiny clock/ticker updates). */
export const CONTENT_TEXT_GROWTH = 24;
export const CONTENT_ELEM_GROWTH = 3;

const LOADING_ONLY_RE =
  /^(loading|please wait|spinner|skeleton|fetching|coming soon)([\s.…!]*)$/i;

/** UI-ish phrases only; bare "loading" in prose must not match. */
const LOADING_PHRASE_RE =
  /\b(please\s+wait|still\s+loading|content\s+is\s+loading|loading\s+(please\s+)?wait|loading\s+your\s+\w+|fetching(\s+data)?|loading\.\.\.|loading…)\b/i;

const LOADING_UI_SELECTOR =
  '[aria-busy="true"], [data-loading="true"], [role="progressbar"], .skeleton, .spinner, .loading-spinner, .animate-pulse';

/**
 * True when visible text still looks like a loading shell rather than real
 * page content. Exported for unit tests. `hasVisibleLoadingUi` should reflect
 * whether a visible skeleton/spinner is present in the live DOM.
 */
export function looksLikeLoadingPlaceholder(
  text: string,
  opts: { minTextLen?: number; hasVisibleLoadingUi?: boolean } = {}
): boolean {
  const minTextLen = opts.minTextLen ?? CONTENT_MIN_TEXT_LEN;
  const trimmed = String(text || "").replace(/\s+/g, " ").trim();
  if (LOADING_ONLY_RE.test(trimmed)) return true;
  if (opts.hasVisibleLoadingUi && trimmed.length < 240) return true;
  // Short shells that are mostly a loading phrase are not ready yet.
  if (trimmed.length < 160 && LOADING_PHRASE_RE.test(trimmed)) return true;
  // Near-empty with an active loading UI is not ready; bare tiny pages are OK.
  if (trimmed.length < minTextLen && opts.hasVisibleLoadingUi) return true;
  return false;
}

export interface ContentReadySnapshot {
  html: string;
  title: string;
  textLen: number;
  readyState: string;
  elemCount: number;
  loading: boolean;
}

export interface ContentReadyOptions {
  /** Overall post-load wait cap in ms (default CONTENT_READY_MAX_WAIT_MS). */
  maxWaitMs?: number;
  stableMs?: number;
  pollMs?: number;
  minTextLen?: number;
}

/**
 * Page-side function returning the document HTML. Uses native `outerHTML`
 * (correct escaping, void elements, attributes) and only splices in open
 * shadow-root / same-origin iframe content, inside marker wrappers, when any
 * exist. Shared by the readiness wait and the CDP fallback snapshot.
 */
export const SERIALIZE_DOC_FN = String.raw`() => {
  const root = document.documentElement;
  if (!root) return "";
  const needsExpand = (el) => {
    for (const n of [el, ...el.querySelectorAll("*")]) {
      if (n.shadowRoot) return true;
      if (n.tagName === "IFRAME") {
        try { if (n.contentDocument && n.contentDocument.documentElement) return true; } catch (_) {}
      }
    }
    return false;
  };
  if (!needsExpand(root)) return root.outerHTML;
  const expand = (el) => {
    const clone = el.cloneNode(true);
    const orig = [el, ...el.querySelectorAll("*")];
    const cl = [clone, ...clone.querySelectorAll("*")];
    for (let i = 0; i < orig.length; i++) {
      const o = orig[i];
      const c = cl[i];
      if (!c) continue;
      if (o.shadowRoot) {
        const w = document.createElement("div");
        w.setAttribute("data-shadow-root", "");
        for (const n of o.shadowRoot.childNodes) {
          w.appendChild(n.nodeType === 1 ? expand(n) : n.cloneNode(true));
        }
        c.insertBefore(w, c.firstChild);
      }
      if (o.tagName === "IFRAME") {
        try {
          const d = o.contentDocument;
          if (d && d.documentElement) {
            const w = document.createElement("div");
            w.setAttribute("data-iframe-content", "");
            w.appendChild(expand(d.documentElement));
            c.appendChild(w);
          }
        } catch (_) { /* cross-origin */ }
      }
    }
    return clone;
  };
  return expand(root).outerHTML;
}`;

/**
 * Async function source evaluated inside the page (CDP Runtime.evaluate or
 * Playwright page.evaluate). Takes maxWaitMs as its sole argument.
 */
export const WAIT_FOR_CONTENT_READY_FN = String.raw`async (maxWaitMs) => {
  const STABLE_MS = 500;
  const STABLE_AFTER_GROWTH_MS = 1500;
  const POLL_MS = 120;
  const MIN_TEXT = 40;
  const TEXT_GROWTH = 24;
  const ELEM_GROWTH = 3;
  const loadingOnly = /^(loading|please wait|spinner|skeleton|fetching|coming soon)([\s.…!]*)$/i;
  const loadingPhrase = /\b(please\s+wait|still\s+loading|content\s+is\s+loading|loading\s+(please\s+)?wait|loading\s+your\s+\w+|fetching(\s+data)?|loading\.\.\.|loading…)\b/i;
  const uiSelector = '[aria-busy="true"], [data-loading="true"], [role="progressbar"], .skeleton, .spinner, .loading-spinner, .animate-pulse';
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  const isVisible = (el) => {
    try {
      if (!el || el.hidden || el.getAttribute("aria-hidden") === "true") return false;
      const st = window.getComputedStyle(el);
      if (!st || st.display === "none" || st.visibility === "hidden" || Number(st.opacity) === 0) return false;
      return true;
    } catch (_) { return false; }
  };

  const hasVisibleLoadingUi = (root) => {
    try {
      const nodes = (root || document).querySelectorAll(uiSelector);
      for (const n of nodes) if (isVisible(n)) return true;
    } catch (_) { /* ignore */ }
    return false;
  };

  const collectTextAndCount = () => {
    // Prefer native innerText / getElementsByTagName for light DOM (fast on
    // huge pages), then pierce open shadow roots and same-origin iframes.
    let text = document.body && typeof document.body.innerText === "string"
      ? document.body.innerText.trim()
      : "";
    let count = document.getElementsByTagName("*").length;
    const pierce = (root) => {
      let hosts;
      try { hosts = root.querySelectorAll("*"); } catch (_) { return; }
      for (const el of hosts) {
        if (el.shadowRoot) {
          try { count += el.shadowRoot.querySelectorAll("*").length; } catch (_) {}
          try {
            const st = el.shadowRoot.textContent || "";
            if (st.trim()) text += " " + st.trim();
          } catch (_) {}
          pierce(el.shadowRoot);
        }
        if (String(el.tagName || "").toUpperCase() === "IFRAME") {
          try {
            const doc = el.contentDocument;
            if (doc && doc.body) {
              count += doc.getElementsByTagName("*").length;
              const it = doc.body.innerText || "";
              if (it.trim()) text += " " + it.trim();
            }
          } catch (_) { /* cross-origin */ }
        }
      }
    };
    try { if (document.body) pierce(document.body); } catch (_) {}
    return {
      text: text.replace(/\s+/g, " ").trim(),
      elemCount: count,
    };
  };

  const isLoading = (text, loadingUi) => {
    const trimmed = String(text || "").replace(/\s+/g, " ").trim();
    if (loadingOnly.test(trimmed)) return true;
    if (loadingUi && trimmed.length < 240) return true;
    if (trimmed.length < 160 && loadingPhrase.test(trimmed)) return true;
    if (trimmed.length < MIN_TEXT && loadingUi) return true;
    return false;
  };

  const hasPendingMount = () => {
    try {
      // Explicit "still expecting content" marker (e.g. streamed chunks).
      if (document.querySelector("[data-expect-content]")) return true;
      // Empty content slots mean a SPA is still expecting hydration/chunks.
      if (document.querySelector("#chunks:empty, #content:empty, #app:empty, #root:empty")) {
        return true;
      }
    } catch (_) { /* ignore */ }
    return false;
  };

  const snap = () => {
    const collected = collectTextAndCount();
    const loadingUi = hasVisibleLoadingUi(document);
    const pending = hasPendingMount();
    return {
      html: "",
      title: document.title || "",
      textLen: collected.text.length,
      readyState: document.readyState || "",
      elemCount: collected.elemCount,
      loading: isLoading(collected.text, loadingUi) || pending,
      loadingUi,
      pending,
    };
  };

  const budget = Math.max(500, Math.min(Number(maxWaitMs) || 10000, 20000));
  const start = Date.now();
  let last = snap();
  let stableMs = 0;
  let sawGrowth = false;
  while (Date.now() - start < budget) {
    await sleep(POLL_MS);
    const now = snap();
    const grown =
      now.elemCount > last.elemCount + ELEM_GROWTH ||
      now.textLen > last.textLen + TEXT_GROWTH ||
      now.textLen + TEXT_GROWTH < last.textLen;
    // Treat the loading→ready transition as growth so the first hydrated
    // chunk (or SPA paint) gets the longer post-growth quiet window.
    if (grown || (last.loading && !now.loading)) sawGrowth = true;
    if (now.loading || grown) stableMs = 0;
    else stableMs += POLL_MS;
    last = now;
    // Ready when stable and either we have enough text, or a tiny finished
    // page with no loading UI and no empty content mounts (404 / OK / image).
    let hasMedia = false;
    try {
      hasMedia = Boolean(
        document.querySelector("img[src], img[alt], video, svg, canvas, picture")
      );
    } catch (_) { /* ignore */ }
    const tinyDone =
      !now.loading &&
      !now.loadingUi &&
      !now.pending &&
      now.textLen < MIN_TEXT &&
      (now.textLen > 0 || hasMedia);
    const enough = now.textLen >= MIN_TEXT && !now.loading;
    const needStable = sawGrowth ? STABLE_AFTER_GROWTH_MS : STABLE_MS;
    if (
      now.readyState === "complete" &&
      (enough || tinyDone) &&
      stableMs >= needStable
    ) break;
  }
  // Serialize once at the end; polling only needs text length / element count.
  let html = "";
  try { html = (${SERIALIZE_DOC_FN})(); } catch (_) {
    html = document.documentElement ? document.documentElement.outerHTML : "";
  }
  last.html = html;
  return last;
}`;

/** Build a `(async (maxWaitMs) => ...)(N)` expression for CDP evaluate. */
export function buildWaitForContentReadyExpression(maxWaitMs: number): string {
  const budget = Math.max(
    500,
    Math.min(Math.floor(maxWaitMs), CONTENT_READY_MAX_WAIT_MS, 20_000)
  );
  return `(${WAIT_FOR_CONTENT_READY_FN})(${budget})`;
}

/**
 * Decide whether a polled snapshot is ready. Node-side mirror of the
 * browser loop exit condition, used by unit tests.
 */
export function isContentReadySnapshot(
  snap: ContentReadySnapshot,
  prev: ContentReadySnapshot | null,
  opts: {
    quietMs: number;
    stableMs: number;
    minTextLen?: number;
    loadingUi?: boolean;
  }
): boolean {
  const minTextLen = opts.minTextLen ?? CONTENT_MIN_TEXT_LEN;
  if (snap.readyState !== "complete") return false;
  if (snap.loading) return false;
  if (opts.quietMs < opts.stableMs) return false;
  if (!prev) return false;
  const grown =
    snap.elemCount > prev.elemCount + CONTENT_ELEM_GROWTH ||
    snap.textLen > prev.textLen + CONTENT_TEXT_GROWTH ||
    snap.textLen + CONTENT_TEXT_GROWTH < prev.textLen;
  if (grown) return false;
  if (snap.textLen >= minTextLen) return true;
  // Tiny finished page: allow when there is no loading UI.
  return opts.loadingUi !== true;
}
