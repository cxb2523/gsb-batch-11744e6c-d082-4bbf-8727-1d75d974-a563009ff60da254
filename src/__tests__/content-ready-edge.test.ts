/**
 * Edge-case coverage for JS content readiness (Ajain review cases).
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  CONTENT_READY_MAX_WAIT_MS,
  buildWaitForContentReadyExpression,
  looksLikeLoadingPlaceholder,
} from "../engine/content-ready.js";
import { EDGE_MARKERS, startSpaEdgeServer } from "./fixtures/spa-edge-cases.js";
import { startSpaLateLoadServer, SPA_MARKER } from "./fixtures/spa-late-load.js";
import {
  isLocalChromeAvailable,
  renderViaLocalChromeDetailed,
  resolveChromeTimeoutMs,
} from "../engine/chrome.js";
import { fastHtmlToMarkdown } from "../engine/markdown.js";

type CaseResult = {
  case: string;
  pass: boolean;
  ms: number;
  detail: string;
};

const results: CaseResult[] = [];

function record(caseName: string, pass: boolean, ms: number, detail: string) {
  results.push({ case: caseName, pass, ms, detail });
  console.log(JSON.stringify({ case: caseName, pass, ms, detail }));
}

async function render(
  url: string,
  opts: { timeoutMs?: number; connectTimeoutMs?: number } = {}
) {
  return renderViaLocalChromeDetailed(url, {
    timeoutMs: opts.timeoutMs ?? 18_000,
    connectTimeoutMs: opts.connectTimeoutMs ?? 4_000,
  });
}

describe("content-ready edge cases", () => {
  it("unit: tiny pages and false-positive loading words are not placeholders", () => {
    assert.equal(looksLikeLoadingPlaceholder("OK"), false);
    assert.equal(looksLikeLoadingPlaceholder("404 Not Found"), false);
    assert.equal(
      looksLikeLoadingPlaceholder("Loading...", { hasVisibleLoadingUi: false }),
      true
    );
    assert.equal(
      looksLikeLoadingPlaceholder(
        "This essay discusses loading docks, skeleton crews, and spinner dolphins in maritime folklore. The loading process at the harbor is a metaphor.",
        { hasVisibleLoadingUi: false }
      ),
      false
    );
    assert.equal(
      looksLikeLoadingPlaceholder("Short", { hasVisibleLoadingUi: true }),
      true
    );
  });

  it("unit: timeout option caps the wait expression", () => {
    assert.match(buildWaitForContentReadyExpression(2_000), /\(2000\)$/);
    assert.match(buildWaitForContentReadyExpression(50_000), /\(10000\)$/);
    assert.equal(resolveChromeTimeoutMs(7_000), 7_000);
    assert.ok(CONTENT_READY_MAX_WAIT_MS <= 10_000);
  });

  it("chrome edge matrix", async (t) => {
    if (!isLocalChromeAvailable()) {
      t.skip("local Chrome not available");
      return;
    }
    const server = await startSpaEdgeServer();
    const late = await startSpaLateLoadServer();
    try {
      // 1. Never settle
      for (const [variant, marker, maxMs] of [
        // Tickers should settle early; sticky spinner may burn the ~10s cap.
        // Leave headroom for cold Chrome start on CI runners.
        ["clock", EDGE_MARKERS.clock, 8_000],
        ["carousel", EDGE_MARKERS.carousel, 8_000],
        ["animation", EDGE_MARKERS.animation, 8_000],
        ["spinner-stay", EDGE_MARKERS.spinnerStay, 16_000],
      ] as const) {
        const t0 = Date.now();
        const out = await render(server.urlFor(variant));
        const ms = Date.now() - t0;
        const pass =
          Boolean(out.html) &&
          out.html!.includes(marker) &&
          ms < maxMs;
        record(
          `1-never-settle:${variant}`,
          pass,
          ms,
          pass ? "returned content under cap" : out.error || "missing marker or hung"
        );
        assert.ok(pass, `${variant}: ${out.error || ms}`);
      }

      // 2. Long-lived network
      for (const [variant, marker] of [
        ["long-poll", EDGE_MARKERS.longPoll],
        ["websocket", EDGE_MARKERS.websocket],
        ["sse", EDGE_MARKERS.sse],
      ] as const) {
        const t0 = Date.now();
        const out = await render(server.urlFor(variant));
        const ms = Date.now() - t0;
        const pass = Boolean(out.html) && out.html!.includes(marker) && ms < 12_000;
        record(`2-busy-network:${variant}`, pass, ms, pass ? "ok" : out.error || "fail");
        assert.ok(pass, `${variant}: ${out.error || ms}`);
      }

      // 3. Streamed chunks
      {
        const t0 = Date.now();
        const out = await render(server.urlFor("stream"));
        const ms = Date.now() - t0;
        const html = out.html || "";
        const pass =
          html.includes(`${EDGE_MARKERS.stream}_1`) &&
          html.includes(`${EDGE_MARKERS.stream}_2`) &&
          html.includes(`${EDGE_MARKERS.stream}_3`) &&
          ms < 12_000;
        record("3-stream-chunks", pass, ms, pass ? "all 3 chunks" : out.error || "incomplete");
        assert.ok(pass, out.error || html.slice(0, 300));
      }

      // 4. After cap
      {
        const t0 = Date.now();
        const out = await render(server.urlFor("after-cap"), { timeoutMs: 16_000 });
        const ms = Date.now() - t0;
        const html = out.html || "";
        // Marker also appears inside the delayed script source; require the
        // rendered article node, not a raw string match.
        const renderedLate = /data-content-ready="true"/.test(html);
        const pass =
          Boolean(out.html) &&
          !renderedLate &&
          /Still loading shell|id="status">Loading/i.test(html) &&
          ms < 16_000;
        record(
          "4-after-cap",
          pass,
          ms,
          pass ? "returned shell at cap" : out.error || `renderedLate=${renderedLate}`
        );
        assert.ok(pass, out.error || `ms=${ms} renderedLate=${renderedLate}`);
      }

      // 5. Tiny pages
      for (const [variant, needle] of [
        ["tiny-404", EDGE_MARKERS.tiny404],
        ["tiny-ok", EDGE_MARKERS.tinyOk],
        ["tiny-image", EDGE_MARKERS.tinyImage],
      ] as const) {
        const t0 = Date.now();
        const out = await render(server.urlFor(variant));
        const ms = Date.now() - t0;
        const html = out.html || "";
        const pass = Boolean(out.html) && html.includes(needle) && ms < 6_000;
        record(`5-tiny:${variant}`, pass, ms, pass ? "fast" : out.error || "slow/missing");
        assert.ok(pass, `${variant}: ${out.error || ms}`);
      }

      // 6. False-positive loading words
      {
        const t0 = Date.now();
        const out = await render(server.urlFor("false-loading"));
        const ms = Date.now() - t0;
        const pass =
          Boolean(out.html) &&
          out.html!.includes(EDGE_MARKERS.falseLoading) &&
          ms < 6_000;
        record("6-false-loading-words", pass, ms, pass ? "did not stall" : out.error || "stall");
        assert.ok(pass, out.error || String(ms));
      }

      // 7. Client redirect
      {
        const t0 = Date.now();
        const out = await render(server.urlFor("redirect"));
        const ms = Date.now() - t0;
        const html = out.html || "";
        const pass = Boolean(out.html) && html.includes(EDGE_MARKERS.redirect) && ms < 10_000;
        record(
          "7-client-redirect",
          pass,
          ms,
          pass ? "followed redirect" : `got=${html.slice(0, 120)} err=${out.error || ""}`
        );
        assert.ok(pass, out.error || html.slice(0, 200));
      }

      // 8. Shadow DOM + iframe
      {
        const t0 = Date.now();
        const out = await render(server.urlFor("shadow"));
        const ms = Date.now() - t0;
        const html = out.html || "";
        // Require the marker outside <script> so we know shadow was serialized.
        const withoutScripts = html.replace(/<script[\s\S]*?<\/script>/gi, "");
        const pass =
          Boolean(out.html) &&
          withoutScripts.includes(EDGE_MARKERS.shadow) &&
          ms < 8_000;
        record("8-shadow-dom", pass, ms, pass ? "serialized open shadow" : out.error || "missing");
        assert.ok(pass, out.error || "shadow missing");
      }
      {
        const t0 = Date.now();
        const out = await render(server.urlFor("iframe"));
        const ms = Date.now() - t0;
        const html = out.html || "";
        const withoutScripts = html.replace(/<script[\s\S]*?<\/script>/gi, "");
        const hasChild = withoutScripts.includes(EDGE_MARKERS.iframe);
        const pass = Boolean(out.html) && hasChild && ms < 10_000;
        record(
          "8-iframe",
          pass,
          ms,
          hasChild ? "included same-origin iframe content" : "parent only"
        );
        assert.ok(pass, out.error || "iframe content missing");
      }

      // 9. Lazy scroll (document current behaviour: no auto-scroll)
      {
        const t0 = Date.now();
        const out = await render(server.urlFor("lazy"));
        const ms = Date.now() - t0;
        const html = out.html || "";
        // Marker also lives in the script source; require the IO callback attr.
        const loaded = /data-lazy-ready="true"/.test(html);
        // Headless Chrome may still fire IntersectionObserver for far-below
        // content depending on viewport; record that without failing the suite
        // when it does. We intentionally do not auto-scroll.
        const pass = Boolean(out.html) && ms < 8_000;
        record(
          "9-lazy-scroll",
          pass,
          ms,
          loaded
            ? "IO fired without scroll in this headless viewport (no auto-scroll added)"
            : "above-the-fold only (no auto-scroll)"
        );
        assert.ok(pass, out.error || "lazy hang");
      }

      // 10. JS error + API 500
      {
        const t0 = Date.now();
        const out = await render(server.urlFor("js-error"));
        const ms = Date.now() - t0;
        const pass =
          Boolean(out.html) && out.html!.includes(EDGE_MARKERS.jsError) && ms < 8_000;
        record("10-js-error", pass, ms, pass ? "returned shell" : out.error || "fail");
        assert.ok(pass, out.error || "js-error");
      }
      {
        const t0 = Date.now();
        const out = await render(server.urlFor("api-500"));
        const ms = Date.now() - t0;
        const pass =
          Boolean(out.html) && out.html!.includes(EDGE_MARKERS.api500) && ms < 8_000;
        record("10-api-500", pass, ms, pass ? "fallback rendered" : out.error || "fail");
        assert.ok(pass, out.error || "api-500");
      }

      // 11. Huge DOM
      {
        const t0 = Date.now();
        const out = await render(server.urlFor("huge"), { timeoutMs: 30_000 });
        const ms = Date.now() - t0;
        const pass =
          Boolean(out.html) && out.html!.includes(EDGE_MARKERS.huge) && ms < 25_000;
        record("11-huge-dom", pass, ms, pass ? "poll overhead ok" : out.error || "too slow");
        assert.ok(pass, out.error || `huge ${ms}`);
      }

      // 12. Concurrency
      {
        const urls = Array.from({ length: 10 }, () => server.urlFor("concurrency-static"));
        const t0 = Date.now();
        const outs = await Promise.all(urls.map((u) => render(u, { timeoutMs: 18_000 })));
        const ms = Date.now() - t0;
        const pass =
          outs.every((o) => o.html && o.html.includes("CONCURRENCY_STATIC_OK")) &&
          ms < 45_000;
        record(
          "12-concurrency-10",
          pass,
          ms,
          pass ? `parallel ok n=${outs.length}` : outs.find((o) => !o.html)?.error || "fail"
        );
        assert.ok(pass, "concurrency failed");
      }

      // 13. Timeout overrides + non-JS path untouched
      {
        const prev = process.env.WEBCRAWL_CHROME_TIMEOUT_MS;
        process.env.WEBCRAWL_CHROME_TIMEOUT_MS = "6000";
        try {
          assert.equal(resolveChromeTimeoutMs(), 6_000);
          const t0 = Date.now();
          const out = await render(late.urlFor("long"), { timeoutMs: 6_000 });
          const ms = Date.now() - t0;
          // 4.5s content + connect may still succeed near budget; must not exceed much past override.
          const pass = ms < 14_000 && Boolean(out.html || out.error);
          record(
            "13-timeout-override",
            pass,
            ms,
            out.html?.includes(SPA_MARKER)
              ? "got content under override"
              : `ended with ${out.error || "empty"}`
          );
          assert.ok(pass);
        } finally {
          if (prev === undefined) delete process.env.WEBCRAWL_CHROME_TIMEOUT_MS;
          else process.env.WEBCRAWL_CHROME_TIMEOUT_MS = prev;
        }
      }
      {
        const url = late.urlFor("static");
        const t0 = Date.now();
        const res = await fetch(url, { signal: AbortSignal.timeout(3_000) });
        const html = await res.text();
        const ms = Date.now() - t0;
        const md = fastHtmlToMarkdown(html, url);
        const pass =
          html.includes("STATIC_PAGE_MARKER") &&
          md.markdown.includes("STATIC_PAGE_MARKER") &&
          ms < 500;
        record("13-non-js-fetch", pass, ms, pass ? "untouched" : "regressed");
        assert.ok(pass);
      }
    } finally {
      await server.close().catch(() => {});
      await late.close().catch(() => {});
      console.log(JSON.stringify({ edgeCaseSummary: results }, null, 2));
    }
  });
});
