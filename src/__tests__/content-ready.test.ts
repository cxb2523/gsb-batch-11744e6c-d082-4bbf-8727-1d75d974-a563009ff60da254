import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  CONTENT_READY_MAX_WAIT_MS,
  CONTENT_STABLE_MS,
  WAIT_FOR_CONTENT_READY_FN,
  buildWaitForContentReadyExpression,
  isContentReadySnapshot,
  looksLikeLoadingPlaceholder,
  type ContentReadySnapshot,
} from "../engine/content-ready.js";
import {
  SPA_MARKER,
  startSpaLateLoadServer,
} from "./fixtures/spa-late-load.js";
import {
  isLocalChromeAvailable,
  renderViaLocalChromeDetailed,
} from "../engine/chrome.js";
import { fastHtmlToMarkdown } from "../engine/markdown.js";

describe("content-ready helpers", () => {
  it("treats loading placeholders and near-empty bodies as not ready", () => {
    assert.equal(looksLikeLoadingPlaceholder("Loading..."), true);
    assert.equal(looksLikeLoadingPlaceholder("Please wait"), true);
    assert.equal(looksLikeLoadingPlaceholder("", { hasVisibleLoadingUi: true }), true);
    assert.equal(looksLikeLoadingPlaceholder("hi", { hasVisibleLoadingUi: true }), true);
    // Bare tiny pages without loading UI are allowed to finish.
    assert.equal(looksLikeLoadingPlaceholder("OK"), false);
    assert.equal(
      looksLikeLoadingPlaceholder("Welcome to the dashboard. Loading your data…", {
        hasVisibleLoadingUi: true,
      }),
      true
    );
    assert.equal(
      looksLikeLoadingPlaceholder(
        `The delayed API finally rendered this paragraph. ${SPA_MARKER}`
      ),
      false
    );
  });

  it("requires a stable quiet window before declaring content ready", () => {
    const loading: ContentReadySnapshot = {
      html: '<div id="root">Loading...</div>',
      title: "t",
      textLen: 10,
      readyState: "complete",
      elemCount: 5,
      loading: true,
    };
    const ready: ContentReadySnapshot = {
      html: `<article>${SPA_MARKER}</article>`,
      title: "t",
      textLen: 120,
      readyState: "complete",
      elemCount: 12,
      loading: false,
    };
    assert.equal(
      isContentReadySnapshot(loading, null, { quietMs: 500, stableMs: CONTENT_STABLE_MS }),
      false
    );
    assert.equal(
      isContentReadySnapshot(ready, ready, { quietMs: 200, stableMs: CONTENT_STABLE_MS }),
      false
    );
    assert.equal(
      isContentReadySnapshot(ready, ready, { quietMs: 500, stableMs: CONTENT_STABLE_MS }),
      true
    );
  });

  it("builds a capped wait expression for CDP evaluate", () => {
    assert.ok(WAIT_FOR_CONTENT_READY_FN.includes("stableMs"));
    assert.ok(WAIT_FOR_CONTENT_READY_FN.includes("loading"));
    const expr = buildWaitForContentReadyExpression(12_000);
    assert.match(expr, /\(10000\)$/);
    assert.ok(CONTENT_READY_MAX_WAIT_MS >= 8_000);
  });
});

describe("SPA late-load Chrome readiness", () => {
  it("waits for short, long, and quiet-then-fetch SPA content", async (t) => {
    if (!isLocalChromeAvailable()) {
      t.skip("local Chrome not available");
      return;
    }
    const server = await startSpaLateLoadServer();
    try {
      for (const variant of ["short", "long", "quiet-then-fetch"] as const) {
        const url = server.urlFor(variant);
        const t0 = Date.now();
        const out = await renderViaLocalChromeDetailed(url, {
          timeoutMs: 18_000,
          connectTimeoutMs: 4_000,
        });
        const ms = Date.now() - t0;
        assert.ok(out.html, `${variant}: ${out.error}`);
        assert.match(out.html!, new RegExp(SPA_MARKER));
        assert.match(out.html!, /data-content-ready="true"/);
        // Long / quiet-then-fetch must wait past the old ~2.5s networkidle cap.
        if (variant === "short") {
          assert.ok(
            ms < 16_000,
            `${variant} should settle after 1.5s fetch without hanging, took ${ms}ms`
          );
        } else {
          assert.ok(ms > 3_000, `${variant} finished too fast (${ms}ms)`);
          assert.ok(ms < 16_000, `${variant} should not hang past the hard cap, took ${ms}ms`);
        }
      }
    } finally {
      await server.close();
    }
  });

  it("keeps static pages fast and leaves the non-JS fetch path alone", async (t) => {
    if (!isLocalChromeAvailable()) {
      t.skip("local Chrome not available");
      return;
    }
    const server = await startSpaLateLoadServer();
    try {
      const staticUrl = server.urlFor("static");

      // Non-JS fetch path: plain HTTP, no Chrome, no readiness wait.
      const fetchT0 = Date.now();
      const res = await fetch(staticUrl, { signal: AbortSignal.timeout(5_000) });
      const html = await res.text();
      const fetchMs = Date.now() - fetchT0;
      assert.match(html, /STATIC_PAGE_MARKER/);
      assert.ok(fetchMs < 500, `static fetch took ${fetchMs}ms`);
      const md = fastHtmlToMarkdown(html, staticUrl);
      assert.match(md.markdown, /STATIC_PAGE_MARKER/);

      // Chrome render of an already-complete static page should settle quickly
      // (well under the SPA long-wait budget).
      const chromeT0 = Date.now();
      const out = await renderViaLocalChromeDetailed(staticUrl, {
        timeoutMs: 12_000,
        connectTimeoutMs: 4_000,
      });
      const chromeMs = Date.now() - chromeT0;
      assert.ok(out.html, out.error);
      assert.match(out.html!, /STATIC_PAGE_MARKER/);
      assert.ok(
        chromeMs < 6_000,
        `static Chrome render should stay fast, took ${chromeMs}ms`
      );
      console.log(
        JSON.stringify({
          timing: {
            staticFetchMs: fetchMs,
            staticChromeMs: chromeMs,
          },
        })
      );
    } finally {
      await server.close();
    }
  });
});
