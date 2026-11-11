/**
 * Local SPA fixture whose shell stays quiet while a delayed API call loads
 * the real content. Used to regress JS readiness waits that return a clean
 * but incomplete page too early.
 */
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

export const SPA_MARKER = "SPA_LATE_LOAD_CONTENT_READY_MARKER";
export const SPA_TITLE = "Late Load SPA Fixture";

export type SpaLateLoadVariant = "short" | "long" | "quiet-then-fetch" | "static";

const CONTENT_JSON = JSON.stringify({
  title: "Hydrated article",
  body: `The delayed API finally rendered this paragraph. ${SPA_MARKER}`,
});

function spaPage(opts: {
  delayMs: number;
  quietFirst?: boolean;
}): string {
  const delayMs = opts.delayMs;
  const quietFirst = Boolean(opts.quietFirst);
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>${SPA_TITLE}</title>
  <style>
    .skeleton { height: 1rem; margin: 0.5rem 0; background: #ddd; }
    .spinner { width: 1.5rem; height: 1.5rem; border: 2px solid #ccc; border-top-color: #333; border-radius: 50%; }
  </style>
</head>
<body>
  <main id="root" aria-busy="true" data-loading="true">
    <h1>${SPA_TITLE}</h1>
    <div class="spinner" role="progressbar" aria-label="Loading"></div>
    <div id="status">Loading...</div>
    <div class="skeleton"></div>
    <div class="skeleton"></div>
  </main>
  <script>
    (function () {
      var delayMs = ${delayMs};
      var quietFirst = ${quietFirst ? "true" : "false"};
      var root = document.getElementById("root");
      var status = document.getElementById("status");
      function render(data) {
        root.setAttribute("aria-busy", "false");
        root.setAttribute("data-loading", "false");
        root.innerHTML =
          "<article data-content-ready=\\"true\\">" +
          "<h1>" + data.title + "</h1>" +
          "<p>" + data.body + "</p>" +
          "</article>";
      }
      function startFetch() {
        status.textContent = "Loading...";
        fetch("/api/content")
          .then(function (r) { return r.json(); })
          .then(render)
          .catch(function (err) {
            status.textContent = "Failed: " + String(err && err.message || err);
          });
      }
      if (quietFirst) {
        // Let the network go idle first, then fire a timer-driven fetch.
        // This catches readiness checks that stop at networkidle / short
        // mutation-idle windows and miss content that arrives later.
        setTimeout(startFetch, delayMs);
      } else {
        setTimeout(startFetch, delayMs);
      }
    })();
  </script>
</body>
</html>`;
}

function staticPage(): string {
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8" /><title>Static Fixture</title></head>
<body>
  <main>
    <h1>Static Fixture</h1>
    <p>Immediate HTML with no client fetch. Marker: STATIC_PAGE_MARKER</p>
  </main>
</body>
</html>`;
}

export interface SpaLateLoadServer {
  baseUrl: string;
  port: number;
  close: () => Promise<void>;
  urlFor: (variant: SpaLateLoadVariant) => string;
}

/** Start a loopback HTTP server serving the late-load SPA variants. */
export async function startSpaLateLoadServer(): Promise<SpaLateLoadServer> {
  const server: Server = createServer((req, res) => {
    const path = String(req.url || "/").split("?")[0];
    if (path === "/api/content") {
      res.writeHead(200, {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
      });
      res.end(CONTENT_JSON);
      return;
    }
    let html = "";
    if (path === "/short" || path === "/spa/short") {
      // ~1.5s: within the old 2.5s networkidle-ish window, but still needs
      // placeholder rejection so a quiet Loading shell is not returned early.
      html = spaPage({ delayMs: 1500 });
    } else if (path === "/long" || path === "/spa/long") {
      // ~4.5s: beyond the old hard 2.5s wait cap.
      html = spaPage({ delayMs: 4500 });
    } else if (path === "/quiet-then-fetch" || path === "/spa/quiet-then-fetch") {
      // Network goes quiet on the shell, then a timer triggers the fetch.
      html = spaPage({ delayMs: 3500, quietFirst: true });
    } else if (path === "/static" || path === "/") {
      html = staticPage();
    } else {
      res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      res.end("not found");
      return;
    }
    res.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    });
    res.end(html);
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
    urlFor: (variant) => {
      if (variant === "static") return `${baseUrl}/static`;
      return `${baseUrl}/${variant}`;
    },
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}
