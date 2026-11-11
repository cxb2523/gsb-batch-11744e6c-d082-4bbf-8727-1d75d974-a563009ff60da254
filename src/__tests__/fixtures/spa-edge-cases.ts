/**
 * Edge-case SPA fixtures for JS content-readiness.
 *
 * Covers never-settling UIs, long-lived network, streamed chunks, post-cap
 * arrivals, tiny pages, false-positive loading words, client redirects,
 * shadow DOM / iframe, lazy scroll, JS/API failures, and huge DOMs.
 */
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

export const EDGE_MARKERS = {
  clock: "EDGE_CLOCK_CONTENT",
  carousel: "EDGE_CAROUSEL_CONTENT",
  animation: "EDGE_ANIM_CONTENT",
  spinnerStay: "EDGE_SPINNER_STAY_CONTENT",
  longPoll: "EDGE_LONGPOLL_CONTENT",
  websocket: "EDGE_WS_CONTENT",
  sse: "EDGE_SSE_CONTENT",
  stream: "EDGE_STREAM_CHUNK",
  afterCap: "EDGE_AFTER_CAP_CONTENT",
  tiny404: "404 Not Found",
  tinyOk: "OK",
  tinyImage: "EDGE_TINY_IMAGE",
  falseLoading: "EDGE_FALSE_LOADING_ARTICLE",
  redirect: "EDGE_REDIRECT_TARGET",
  shadow: "EDGE_SHADOW_CONTENT",
  iframe: "EDGE_IFRAME_CONTENT",
  lazy: "EDGE_LAZY_BELOW_FOLD",
  jsError: "EDGE_JS_ERROR_SHELL",
  api500: "EDGE_API_500_FALLBACK",
  huge: "EDGE_HUGE_DOM_CONTENT",
} as const;

export type SpaEdgeVariant = keyof typeof EDGE_MARKERS | "stream" | "concurrency-static";

function html(title: string, body: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"/><title>${title}</title></head><body>${body}</body></html>`;
}

function pageNeverSettleClock(): string {
  return html(
    "Live clock",
    `<main>
      <h1>${EDGE_MARKERS.clock}</h1>
      <p>Article body that is otherwise complete.</p>
      <p id="clock">00:00:00</p>
    </main>
    <script>
      (function () {
        var el = document.getElementById("clock");
        setInterval(function () {
          el.textContent = new Date().toISOString();
        }, 250);
      })();
    </script>`
  );
}

function pageCarousel(): string {
  return html(
    "Carousel",
    `<main>
      <h1>${EDGE_MARKERS.carousel}</h1>
      <p>Main product description stays put.</p>
      <div id="slide">slide-0</div>
    </main>
    <script>
      (function () {
        var i = 0;
        var el = document.getElementById("slide");
        setInterval(function () {
          i = (i + 1) % 5;
          el.textContent = "slide-" + i + " promo copy " + i;
        }, 400);
      })();
    </script>`
  );
}

function pageInfiniteAnimation(): string {
  return html(
    "Infinite animation",
    `<main>
      <h1>${EDGE_MARKERS.animation}</h1>
      <p>Readable content above the animated log.</p>
      <ul id="log"></ul>
    </main>
    <script>
      (function () {
        var log = document.getElementById("log");
        var n = 0;
        setInterval(function () {
          n++;
          var li = document.createElement("li");
          li.textContent = "tick-" + n;
          log.appendChild(li);
          if (log.children.length > 20) log.removeChild(log.firstChild);
        }, 300);
      })();
    </script>`
  );
}

function pageSpinnerNeverGoesAway(): string {
  return html(
    "Sticky spinner",
    `<style>.spinner{width:16px;height:16px;border:2px solid #ccc;border-top-color:#000;border-radius:50%;animation:spin 1s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}</style>
    <main>
      <h1>${EDGE_MARKERS.spinnerStay}</h1>
      <p>Full article text is already here while a decorative spinner keeps spinning in the corner.</p>
      <div class="spinner" role="progressbar" aria-label="Loading" aria-busy="true" data-loading="true"></div>
    </main>`
  );
}

function pageLongPoll(): string {
  return html(
    "Long poll",
    `<main id="root"><h1>Long poll shell</h1><p id="status">Waiting</p></main>
    <script>
      (function () {
        fetch("/api/long-poll").then(function () {}).catch(function () {});
        setTimeout(function () {
          document.getElementById("root").innerHTML =
            "<article><h1>${EDGE_MARKERS.longPoll}</h1><p>Content arrived while long-poll stayed open.</p></article>";
        }, 800);
      })();
    </script>`
  );
}

function pageWebsocket(): string {
  return html(
    "Websocket busy",
    `<main id="root"><h1>WS shell</h1><p>Connecting</p></main>
    <script>
      (function () {
        try {
          var proto = location.protocol === "https:" ? "wss:" : "ws:";
          var ws = new WebSocket(proto + "//" + location.host + "/ws");
          ws.onopen = function () { ws.send("ping"); };
        } catch (e) {}
        setTimeout(function () {
          document.getElementById("root").innerHTML =
            "<article><h1>${EDGE_MARKERS.websocket}</h1><p>Rendered despite open websocket.</p></article>";
        }, 700);
      })();
    </script>`
  );
}

function pageSse(): string {
  return html(
    "SSE busy",
    `<main id="root"><h1>SSE shell</h1><p>Streaming</p></main>
    <script>
      (function () {
        try { new EventSource("/api/sse"); } catch (e) {}
        setTimeout(function () {
          document.getElementById("root").innerHTML =
            "<article><h1>${EDGE_MARKERS.sse}</h1><p>Rendered despite open SSE.</p></article>";
        }, 700);
      })();
    </script>`
  );
}

function pageStreamChunks(): string {
  return html(
    "Stream chunks",
    `<main id="root"><h1>Streaming</h1><div id="chunks" data-expect-content></div></main>
    <script>
      (function () {
        var box = document.getElementById("chunks");
        var delays = [1000, 2000, 3000];
        var left = delays.length;
        delays.forEach(function (ms, idx) {
          setTimeout(function () {
            fetch("/api/chunk?n=" + (idx + 1))
              .then(function (r) { return r.json(); })
              .then(function (data) {
                var p = document.createElement("p");
                p.setAttribute("data-chunk", String(idx + 1));
                p.textContent = data.body;
                box.appendChild(p);
                left--;
                if (left <= 0) box.removeAttribute("data-expect-content");
              });
          }, ms);
        });
      })();
    </script>`
  );
}

function pageAfterCap(): string {
  return html(
    "After cap",
    `<main id="root" aria-busy="true" data-loading="true">
      <h1>Still loading shell</h1>
      <div id="status">Loading...</div>
    </main>
    <script>
      setTimeout(function () {
        document.getElementById("root").innerHTML =
          "<article data-content-ready=\\"true\\"><h1>${EDGE_MARKERS.afterCap}</h1><p>Arrived after the readiness cap.</p></article>";
      }, 15000);
    </script>`
  );
}

function pageTiny404(): string {
  return html("Not Found", `<main><h1>404 Not Found</h1></main>`);
}

function pageTinyOk(): string {
  return html("OK", `<main><p>OK</p></main>`);
}

function pageTinyImage(): string {
  // 1x1 PNG
  const png =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
  return html(
    "Image only",
    `<main><img src="data:image/png;base64,${png}" alt="${EDGE_MARKERS.tinyImage}" width="1" height="1"/></main>`
  );
}

function pageFalseLoadingWords(): string {
  return html(
    "Article about loading",
    `<main>
      <article>
        <h1>${EDGE_MARKERS.falseLoading}</h1>
        <p>This essay discusses loading docks, skeleton crews, and spinner dolphins in maritime folklore.</p>
        <p>The loading process at the harbor is a metaphor, not a UI placeholder. Real paragraph content continues with enough length to clear short-shell heuristics.</p>
        <div class="spinner" hidden aria-hidden="true" style="display:none"></div>
      </article>
    </main>`
  );
}

function pageClientRedirect(): string {
  return html(
    "Redirector",
    `<main><p>Redirecting…</p></main>
    <script>
      setTimeout(function () {
        location.replace("/redirect-target");
      }, 400);
    </script>`
  );
}

function pageRedirectTarget(): string {
  return html(
    "Redirect target",
    `<main><h1>${EDGE_MARKERS.redirect}</h1><p>Landed after client redirect.</p></main>`
  );
}

function pageShadowDom(): string {
  return html(
    "Shadow DOM",
    `<main id="host"></main>
    <script>
      (function () {
        var host = document.getElementById("host");
        var root = host.attachShadow({ mode: "open" });
        root.innerHTML = "<article><h1>${EDGE_MARKERS.shadow}</h1><p>Rendered inside an open shadow root.</p></article>";
      })();
    </script>`
  );
}

function pageIframe(): string {
  return html(
    "Iframe parent",
    `<main>
      <h1>Parent shell</h1>
      <iframe id="child" src="/iframe-child" title="child"></iframe>
    </main>`
  );
}

function pageIframeChild(): string {
  return html(
    "Iframe child",
    `<main><h1>${EDGE_MARKERS.iframe}</h1><p>Inside the iframe document.</p></main>`
  );
}

function pageLazyScroll(): string {
  return html(
    "Lazy scroll",
    `<main>
      <h1>Above the fold</h1>
      <p>Visible without scrolling.</p>
      <div style="height: 2500px"></div>
      <div id="lazy">not-loaded</div>
    </main>
    <script>
      (function () {
        var el = document.getElementById("lazy");
        var io = new IntersectionObserver(function (entries) {
          entries.forEach(function (e) {
            if (e.isIntersecting) {
              el.textContent = "${EDGE_MARKERS.lazy}";
              el.setAttribute("data-lazy-ready", "true");
              io.disconnect();
            }
          });
        });
        io.observe(el);
      })();
    </script>`
  );
}

function pageJsError(): string {
  return html(
    "JS error",
    `<main id="root"><h1>${EDGE_MARKERS.jsError}</h1><p>Shell before the throw.</p></main>
    <script>
      // Hydrate fails; leave the server-rendered shell in place.
      throw new Error("intentional fixture failure before hydrate");
    </script>`
  );
}

function pageApi500(): string {
  return html(
    "API 500",
    `<main id="root"><h1>Loading...</h1></main>
    <script>
      fetch("/api/fail")
        .then(function (r) {
          if (!r.ok) throw new Error("HTTP " + r.status);
          return r.json();
        })
        .then(function () {})
        .catch(function () {
          document.getElementById("root").innerHTML =
            "<article><h1>${EDGE_MARKERS.api500}</h1><p>API failed with 500; showing fallback.</p></article>";
        });
    </script>`
  );
}

function pageHugeDom(): string {
  return html(
    "Huge DOM",
    `<main id="root"><h1>${EDGE_MARKERS.huge}</h1><div id="grid"></div></main>
    <script>
      (function () {
        var grid = document.getElementById("grid");
        var frag = document.createDocumentFragment();
        for (var i = 0; i < 50000; i++) {
          var d = document.createElement("div");
          d.className = "cell";
          d.textContent = "c" + i;
          frag.appendChild(d);
        }
        grid.appendChild(frag);
      })();
    </script>`
  );
}

function pageConcurrencyStatic(): string {
  return html(
    "Concurrency static",
    `<main><h1>Concurrency static</h1><p>Marker CONCURRENCY_STATIC_OK for parallel renders.</p></main>`
  );
}

export interface SpaEdgeServer {
  baseUrl: string;
  port: number;
  close: () => Promise<void>;
  urlFor: (variant: string) => string;
}

/** Start a loopback server with readiness edge-case routes. */
export async function startSpaEdgeServer(): Promise<SpaEdgeServer> {
  const server: Server = createServer((req, res) => {
    const rawUrl = String(req.url || "/");
    const path = rawUrl.split("?")[0];
    const write = (code: number, type: string, body: string | Buffer) => {
      res.writeHead(code, {
        "content-type": type,
        "cache-control": "no-store",
        "access-control-allow-origin": "*",
      });
      res.end(body);
    };

    if (path === "/api/long-poll") {
      // Keep the connection open well past the readiness cap.
      res.writeHead(200, {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
      });
      const timer = setTimeout(() => {
        try {
          res.end('{"ok":true}');
        } catch {
          /* closed */
        }
      }, 60_000);
      res.on("close", () => clearTimeout(timer));
      return;
    }

    if (path === "/api/sse") {
      res.writeHead(200, {
        "content-type": "text/event-stream; charset=utf-8",
        "cache-control": "no-store",
        connection: "keep-alive",
      });
      res.write("data: hello\n\n");
      const timer = setInterval(() => {
        try {
          res.write(`data: tick ${Date.now()}\n\n`);
        } catch {
          clearInterval(timer);
        }
      }, 1000);
      res.on("close", () => clearInterval(timer));
      return;
    }

    if (path === "/api/chunk") {
      const n = new URL(rawUrl, "http://127.0.0.1").searchParams.get("n") || "0";
      write(
        200,
        "application/json; charset=utf-8",
        JSON.stringify({ body: `${EDGE_MARKERS.stream}_${n}` })
      );
      return;
    }

    if (path === "/api/fail") {
      write(500, "application/json; charset=utf-8", '{"error":"fixture boom"}');
      return;
    }

    if (path === "/ws") {
      // Minimal reject: browsers will fail WS upgrade; page still renders via timer.
      write(400, "text/plain; charset=utf-8", "websocket fixture uses timer fallback");
      return;
    }

    const pages: Record<string, string> = {
      "/clock": pageNeverSettleClock(),
      "/carousel": pageCarousel(),
      "/animation": pageInfiniteAnimation(),
      "/spinner-stay": pageSpinnerNeverGoesAway(),
      "/long-poll": pageLongPoll(),
      "/websocket": pageWebsocket(),
      "/sse": pageSse(),
      "/stream": pageStreamChunks(),
      "/after-cap": pageAfterCap(),
      "/tiny-404": pageTiny404(),
      "/tiny-ok": pageTinyOk(),
      "/tiny-image": pageTinyImage(),
      "/false-loading": pageFalseLoadingWords(),
      "/redirect": pageClientRedirect(),
      "/redirect-target": pageRedirectTarget(),
      "/shadow": pageShadowDom(),
      "/iframe": pageIframe(),
      "/iframe-child": pageIframeChild(),
      "/lazy": pageLazyScroll(),
      "/js-error": pageJsError(),
      "/api-500": pageApi500(),
      "/huge": pageHugeDom(),
      "/concurrency-static": pageConcurrencyStatic(),
    };

    const page = pages[path];
    if (!page) {
      write(404, "text/plain; charset=utf-8", "not found");
      return;
    }
    write(200, "text/html; charset=utf-8", page);
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const addr = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${addr.port}`;
  return {
    baseUrl,
    port: addr.port,
    urlFor: (variant: string) => `${baseUrl}/${variant}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}
