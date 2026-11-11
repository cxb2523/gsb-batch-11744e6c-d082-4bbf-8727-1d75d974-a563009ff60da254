import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import { clearLocalCacheForTests } from "../engine/cache.js";
import { parseTimedText, parseYouTubeCached, youtubeVideoId } from "../parse/youtube.js";

describe("youtubeVideoId", () => {
  it("reads watch, short, embed, shorts and live links", () => {
    const id = "jNQXAC9IVRw";
    assert.equal(youtubeVideoId(`https://www.youtube.com/watch?v=${id}&t=5s`), id);
    assert.equal(youtubeVideoId(`https://youtu.be/${id}?si=x`), id);
    assert.equal(youtubeVideoId(`https://m.youtube.com/watch?v=${id}`), id);
    assert.equal(youtubeVideoId(`https://www.youtube.com/embed/${id}`), id);
    assert.equal(youtubeVideoId(`https://www.youtube.com/shorts/${id}`), id);
    assert.equal(youtubeVideoId(`https://www.youtube.com/live/${id}`), id);
  });

  it("ignores non-video YouTube pages and other sites", () => {
    assert.equal(youtubeVideoId("https://www.youtube.com/"), undefined);
    assert.equal(youtubeVideoId("https://www.youtube.com/@channel"), undefined);
    assert.equal(youtubeVideoId("https://www.youtube.com/watch?v=short"), undefined);
    assert.equal(youtubeVideoId("https://notyoutube.com/watch?v=jNQXAC9IVRw"), undefined);
    assert.equal(youtubeVideoId("not a url"), undefined);
  });
});

describe("parseTimedText", () => {
  it("parses cues, decodes entities and joins wrapped lines", () => {
    const xml = `<?xml version="1.0"?><timedtext format="3"><body>
<p t="1200" d="2160">All right, so here we are, in front of the
elephants</p>
<p t="12616" d="1751">and that&#39;s cool</p>
<p t="14421" d="1312">  </p>
</body></timedtext>`;
    const segs = parseTimedText(xml);
    assert.equal(segs.length, 2);
    assert.deepEqual(segs[0], { start: 1.2, end: 3.36, text: "All right, so here we are, in front of the elephants" });
    assert.equal(segs[1].text, "and that's cool");
  });

  it("strips word-level tags", () => {
    const segs = parseTimedText(`<p t="0" d="1000"><s>Hello</s><s> world</s></p>`);
    assert.equal(segs[0].text, "Hello world");
  });
});

describe("parseYouTubeCached", () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
    clearLocalCacheForTests();
  });

  const player = (status: string, reason?: string) =>
    JSON.stringify({
      playabilityStatus: { status, reason },
      videoDetails: { title: "T", lengthSeconds: "5" },
      captions: { playerCaptionsTracklistRenderer: { captionTracks: [{ baseUrl: "https://www.youtube.com/api/timedtext?x=1", languageCode: "en" }] } },
    });
  const captions = '<timedtext format="3"><body><p t="1000" d="1000">hello</p></body></timedtext>';

  /** Fails the first `blocked` player calls with the bot check, then succeeds. */
  function stub(blocked: number) {
    const calls = { player: 0, captions: 0 };
    globalThis.fetch = (async (url: string) => {
      if (String(url).includes("/youtubei/")) {
        calls.player++;
        return new Response(calls.player <= blocked ? player("LOGIN_REQUIRED", "Sign in to confirm you\u2019re not a bot") : player("OK"));
      }
      calls.captions++;
      return new Response(captions);
    }) as typeof fetch;
    return calls;
  }

  it("retries when YouTube shows the bot check", async () => {
    const calls = stub(4); // every client on the first attempt is refused
    const r = await parseYouTubeCached("retryVid_01");
    assert.match(r.markdown, /hello/);
    assert.ok(calls.player > 4);
  });

  it("does not retry other failures", async () => {
    globalThis.fetch = (async () => new Response(player("ERROR", "Video unavailable"))) as typeof fetch;
    await assert.rejects(() => parseYouTubeCached("noRetry_001"), /Video unavailable/);
  });

  it("serves a repeat request from cache without calling YouTube", async () => {
    const calls = stub(0);
    const first = await parseYouTubeCached("cacheVid_01");
    const second = await parseYouTubeCached("cacheVid_01");
    assert.equal(first.cached, false);
    assert.equal(second.cached, true);
    assert.equal(second.markdown, first.markdown);
    assert.equal(calls.player, 1);
  });

  it("skips the cache when asked and never caches failures", async () => {
    stub(0);
    await parseYouTubeCached("bypass_0001");
    const calls = stub(0);
    const again = await parseYouTubeCached("bypass_0001", { bypassCache: true });
    assert.equal(again.cached, false);
    assert.equal(calls.player, 1);

    globalThis.fetch = (async () => new Response(player("ERROR", "Video unavailable"))) as typeof fetch;
    await assert.rejects(() => parseYouTubeCached("failure_001"));
    const ok = stub(0);
    await parseYouTubeCached("failure_001");
    assert.equal(ok.player, 1);
  });
});
