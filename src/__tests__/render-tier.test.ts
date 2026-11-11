import { test } from "node:test";
import assert from "node:assert/strict";
import {
  renderProviderUrl,
  renderProviderKey,
  isRenderProviderEnabled,
  renderViaProvider,
  parseRenderedResponse,
  resetRenderStateForTests,
} from "../engine/render.js";
import {
  markDomainRenderNeeded,
  isDomainRenderNeeded,
  registerExternalSessionStore,
  resetSessionStateForTests,
  RENDER_MEMO_TTL_MS,
} from "../engine/session.js";
import { needsBrowserEscalation } from "../engine/fetcher.js";
import { installedChromePath, isLocalChromeAvailable } from "../engine/chrome.js";

const readerResponse = (title: string, markdown: string) =>
  `Title: ${title}\n\nURL Source: https://example.com/page\n\nMarkdown Content:\n\n${markdown}\n`;

const REAL_MARKDOWN = "# Heading\n\nBody text here, long enough to pass the provider floor check.";

const ENV_NAMES = ["WEBCRAWL_RENDER_URL", "WEBCRAWL_RENDER_KEY"] as const;

function withRenderEnv<T>(
  env: Record<string, string | undefined>,
  fn: () => Promise<T> | T
): Promise<T> | T {
  const prev: Record<string, string | undefined> = {};
  for (const n of ENV_NAMES) prev[n] = process.env[n];
  for (const n of ENV_NAMES) {
    if (env[n] === undefined) delete process.env[n];
    else process.env[n] = env[n];
  }
  try {
    return fn();
  } finally {
    for (const n of ENV_NAMES) {
      if (prev[n] === undefined) delete process.env[n];
      else process.env[n] = prev[n];
    }
  }
}

test("renderProviderUrl/key resolve env vars; unset disables the tier", () => {
  withRenderEnv({ WEBCRAWL_RENDER_URL: undefined, WEBCRAWL_RENDER_KEY: undefined }, () => {
    assert.equal(renderProviderUrl(), null);
    assert.equal(renderProviderKey(), null);
    assert.equal(isRenderProviderEnabled(), false);
  });
  withRenderEnv(
    { WEBCRAWL_RENDER_URL: "https://render.example.com/", WEBCRAWL_RENDER_KEY: "sekret" },
    () => {
      assert.equal(renderProviderUrl(), "https://render.example.com/");
      assert.equal(renderProviderKey(), "sekret");
      assert.equal(isRenderProviderEnabled(), true);
    }
  );
  // whitespace-only is unset
  withRenderEnv({ WEBCRAWL_RENDER_URL: "   " }, () => {
    assert.equal(renderProviderUrl(), null);
    assert.equal(isRenderProviderEnabled(), false);
  });
});

test("parseRenderedResponse splits reader-format headers from markdown", () => {
  const { title, sourceUrl, markdown } = parseRenderedResponse(
    readerResponse("Example Title", REAL_MARKDOWN)
  );
  assert.equal(title, "Example Title");
  assert.equal(sourceUrl, "https://example.com/page");
  assert.equal(markdown, REAL_MARKDOWN);
});

test("renderViaProvider renders through a configured provider with the bearer key", async () => {
  const realFetch = globalThis.fetch;
  resetRenderStateForTests();
  let seenUrl = "";
  let seenAuth = "";
  try {
    globalThis.fetch = (async (input: string | URL, init?: RequestInit) => {
      seenUrl = String(input);
      seenAuth = String(new Headers(init?.headers).get("Authorization") ?? "");
      return new Response(readerResponse("Rendered Title", "# Rendered\n\nReal listing content appears here."));
    }) as typeof fetch;
    const out = await withRenderEnv(
      { WEBCRAWL_RENDER_URL: "https://render.example.com/", WEBCRAWL_RENDER_KEY: "sekret" },
      () => renderViaProvider("https://example.com/page")
    );
    assert.ok(out);
    assert.equal(seenUrl, "https://render.example.com/https://example.com/page");
    assert.equal(seenAuth, "Bearer sekret");
    assert.equal(out.title, "Rendered Title");
    assert.equal(out.sourceUrl, "https://example.com/page");
    assert.match(out.markdown, /Real listing content/);
  } finally {
    globalThis.fetch = realFetch;
    resetRenderStateForTests();
  }
});

test("renderViaProvider sends no Authorization header when keyless", async () => {
  const realFetch = globalThis.fetch;
  resetRenderStateForTests();
  let seenAuth = "SENTINEL";
  try {
    globalThis.fetch = (async (_input: string | URL, init?: RequestInit) => {
      seenAuth = String(new Headers(init?.headers).get("Authorization") ?? "ABSENT");
      return new Response(readerResponse("T", "# Rendered\n\nReal listing content appears here too."));
    }) as typeof fetch;
    const out = await withRenderEnv(
      { WEBCRAWL_RENDER_URL: "https://render.example.com/" },
      () => renderViaProvider("https://example.com/page")
    );
    assert.ok(out);
    assert.equal(seenAuth, "ABSENT");
  } finally {
    globalThis.fetch = realFetch;
    resetRenderStateForTests();
  }
});

test("renderViaProvider returns null on provider failure markers and errors", async () => {
  const realFetch = globalThis.fetch;
  resetRenderStateForTests();
  const prev: Record<string, string | undefined> = {};
  for (const n of ENV_NAMES) prev[n] = process.env[n];
  process.env.WEBCRAWL_RENDER_URL = "https://render.example.com/";
  delete process.env.WEBCRAWL_RENDER_KEY;
  const restore = () => {
    for (const n of ENV_NAMES) {
      if (prev[n] === undefined) delete process.env[n];
      else process.env[n] = prev[n];
    }
  };
  try {
    // upstream target error
    globalThis.fetch = (async () =>
      new Response(
        "Title: stubhub.com\n\nURL Source: https://example.com/x\n\nWarning: Target URL returned error 404: Not Found\n\nMarkdown Content:\n\n"
      )) as typeof fetch;
    assert.equal(await renderViaProvider("https://example.com/x"), null);

    // CAPTCHA warning
    globalThis.fetch = (async () =>
      new Response(
        "Title: stubhub.com\n\nURL Source: https://example.com/x\n\nWarning: This page maybe requiring CAPTCHA, please make sure you are authorized to access this page.\n\nMarkdown Content:\n\n"
      )) as typeof fetch;
    assert.equal(await renderViaProvider("https://example.com/x"), null);

    // non-ok status
    globalThis.fetch = (async () => new Response("nope", { status: 503 })) as typeof fetch;
    assert.equal(await renderViaProvider("https://example.com/x"), null);

    // network error / timeout
    globalThis.fetch = (async () => {
      throw new Error("network down");
    }) as typeof fetch;
    assert.equal(await renderViaProvider("https://example.com/x"), null);

    // empty markdown is not rendered content
    globalThis.fetch = (async () =>
      new Response(
        "Title: T\n\nURL Source: https://example.com/x\n\nMarkdown Content:\n\nshort"
      )) as typeof fetch;
    assert.equal(await renderViaProvider("https://example.com/x"), null);
  } finally {
    globalThis.fetch = realFetch;
    restore();
    resetRenderStateForTests();
  }
});

test("renderViaProvider keyless rate guard caps at 15 requests/min", async () => {
  const realFetch = globalThis.fetch;
  resetRenderStateForTests();
  const prev: Record<string, string | undefined> = {};
  for (const n of ENV_NAMES) prev[n] = process.env[n];
  process.env.WEBCRAWL_RENDER_URL = "https://render.example.com/";
  delete process.env.WEBCRAWL_RENDER_KEY;
  const restore = () => {
    for (const n of ENV_NAMES) {
      if (prev[n] === undefined) delete process.env[n];
      else process.env[n] = prev[n];
    }
  };
  try {
    let calls = 0;
    globalThis.fetch = (async () => {
      calls++;
      return new Response(
        readerResponse(`Title ${calls}`, `# Rendered ${calls}\n\nReal listing content ${calls} here.`)
      );
    }) as typeof fetch;
    let ok = 0;
    let throttled = 0;
    for (let i = 0; i < 20; i++) {
      const out = await renderViaProvider("https://example.com/page");
      if (out) ok++;
      else throttled++;
    }
    assert.equal(ok, 15);
    assert.equal(throttled, 5);
    assert.ok(calls <= 15, "provider must not be called beyond the keyless rate limit");
  } finally {
    globalThis.fetch = realFetch;
    restore();
    resetRenderStateForTests();
  }
});

test("needsBrowserEscalation detects quotes.toscrape.com/js header-only script pages", () => {
  const html = `<html><body><h1>Quotes to Scrape</h1>
<script>
var data = [{"author":{"name":"Albert Einstein"},"text":"The world as we have created it."}];
for (var i in data) { document.write("<div class='quote'>"+data[i].text+"</div>"); }
</script></body></html>`;
  const markdown = "# Quotes to Scrape\n\nLogin\n\nNext";
  assert.ok(markdown.length < 120);
  assert.equal(needsBrowserEscalation(200, html, markdown), true);
});

test("needsBrowserEscalation detects challenge shells and empty SPA shells", () => {
  // StubHub-style IP-reputation shell (status 200, text marker)
  assert.equal(
    needsBrowserEscalation(
      200,
      "<html><body>Please enable JavaScript and disable any ad blocker</body></html>",
      "Please enable JavaScript and disable any ad blocker"
    ),
    true
  );
  // 403 challenge
  assert.equal(
    needsBrowserEscalation(403, "<html><body>Access denied</body></html>", "Access denied"),
    true
  );
  // empty SPA shell
  assert.equal(
    needsBrowserEscalation(200, '<html><body><div id="root"></div></body></html>', ""),
    true
  );
  // big-HTML/no-content SPA shell (StubHub-style: ~3MB markup, tagline-only markdown)
  assert.equal(
    needsBrowserEscalation(
      200,
      `<html><body>${'<script>var x=1;</script>'.repeat(30_000)}</body></html>`,
      "> Concert Tickets tickets for the upcoming concert tour are on sale at StubHub."
    ),
    true
  );
  // real rendered page
  assert.equal(
    needsBrowserEscalation(
      200,
      "<html><body><h1>Real Title</h1><p>Real content</p></body></html>",
      "# Real Title\n\nReal content"
    ),
    false
  );
  // empty body (Reddit-style 200 with no readable text)
  assert.equal(needsBrowserEscalation(200, "<html><body></body></html>", ""), true);
});

test("installedChromePath honours WEBCRAWL_CHROME_PATH", () => {
  const prev = process.env.WEBCRAWL_CHROME_PATH;
  process.env.WEBCRAWL_CHROME_PATH = "/tmp/does-not-need-to-exist-chrome";
  try {
    assert.equal(installedChromePath(), "/tmp/does-not-need-to-exist-chrome");
    assert.equal(isLocalChromeAvailable(), true);
  } finally {
    if (prev === undefined) delete process.env.WEBCRAWL_CHROME_PATH;
    else process.env.WEBCRAWL_CHROME_PATH = prev;
  }
});

test("render-needed memo marks and expires domains", async () => {
  resetSessionStateForTests();
  assert.equal(await isDomainRenderNeeded("www.stubhub.com"), false);
  await markDomainRenderNeeded("www.stubhub.com");
  assert.equal(await isDomainRenderNeeded("www.stubhub.com"), true);
  assert.equal(await isDomainRenderNeeded("www.expedia.com"), false);
  resetSessionStateForTests();
  assert.equal(await isDomainRenderNeeded("www.stubhub.com"), false);
  assert.ok(RENDER_MEMO_TTL_MS >= 60 * 60_000);
});

test("render-needed memo persists through an external store (optional methods)", async () => {
  resetSessionStateForTests();
  const stored = new Set<string>();
  registerExternalSessionStore({
    getWarmSession: async () => null,
    saveWarmSession: async () => {},
    deleteWarmSession: async () => {},
    markDomainChallenged: async () => {},
    isDomainChallenged: async () => false,
    markDomainRenderNeeded: async (d: string) => {
      stored.add(d);
    },
    isDomainRenderNeeded: async (d: string) => stored.has(d),
  });
  try {
    resetSessionStateForTests(); // clears in-memory, external survives
    assert.equal(await isDomainRenderNeeded("www.stubhub.com"), false);
    await markDomainRenderNeeded("www.stubhub.com");
    assert.ok(stored.has("www.stubhub.com"));
    resetSessionStateForTests();
    assert.equal(await isDomainRenderNeeded("www.stubhub.com"), true);
  } finally {
    registerExternalSessionStore({
      getWarmSession: async () => null,
      saveWarmSession: async () => {},
      deleteWarmSession: async () => {},
      markDomainChallenged: async () => {},
      isDomainChallenged: async () => false,
    });
    resetSessionStateForTests();
  }
});
