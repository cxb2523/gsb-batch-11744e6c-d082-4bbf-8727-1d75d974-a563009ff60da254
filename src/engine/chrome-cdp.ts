/**
 * Minimal Chrome DevTools Protocol client for local JS rendering.
 *
 * Drive a real Chrome over CDP instead of dump-dom, wait until the DOM is
 * actually ready, and always bound the session with a hard timeout. No
 * puppeteer/playwright dependency.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  chromeCdpArgs,
  killProcessGroup,
  resolveChromeConnectTimeoutMs,
  type ChromeHeadlessMode,
} from "./chrome-launch.js";
import {
  CONTENT_READY_MAX_WAIT_MS,
  SERIALIZE_DOC_FN,
  buildWaitForContentReadyExpression,
} from "./content-ready.js";

/** Chrome spawned but CDP never became ready. `hung` is true when the process was still alive. */
export class ChromeConnectError extends Error {
  readonly hung: boolean;
  constructor(message: string, hung = false) {
    super(message);
    this.name = "ChromeConnectError";
    this.hung = hung;
  }
}

export interface CdpSnapshot {
  html: string;
  title: string;
  textLen: number;
  readyState: string;
}

export interface CdpRenderOptions {
  timeoutMs: number;
  /** CDP launch/connect budget. Defaults to 4s (`WEBCRAWL_CHROME_CONNECT_TIMEOUT_MS`). */
  connectTimeoutMs?: number;
  headless: ChromeHeadlessMode;
  /** Injected for tests. */
  spawnChrome?: typeof spawn;
}

type CdpMessage = {
  id?: number;
  method?: string;
  params?: Record<string, unknown>;
  result?: Record<string, unknown>;
  error?: { message?: string; code?: number };
  sessionId?: string;
};

const SNAPSHOT_JS = `(() => {
  const body = document.body;
  let text = body && typeof body.innerText === "string" ? body.innerText.trim() : "";
  let html = "";
  try { html = (${SERIALIZE_DOC_FN})(); } catch (_) {
    html = document.documentElement ? document.documentElement.outerHTML : "";
  }
  try {
    if (body) {
      for (const el of body.querySelectorAll("*")) {
        if (el.shadowRoot) text += " " + (el.shadowRoot.textContent || "");
        if (String(el.tagName || "").toUpperCase() === "IFRAME") {
          try {
            const doc = el.contentDocument;
            if (doc && doc.body) text += " " + (doc.body.innerText || "");
          } catch (_) {}
        }
      }
    }
  } catch (_) {}
  return {
    html,
    title: document.title || "",
    textLen: text.replace(/\\s+/g, " ").trim().length,
    readyState: document.readyState || "",
  };
})()`;

function childStillRunning(child?: ChildProcess): boolean {
  return Boolean(child && child.pid && child.exitCode == null && !child.killed);
}

export async function renderUrlViaCdp(
  chromePath: string,
  url: string,
  opts: CdpRenderOptions
): Promise<CdpSnapshot> {
  const timeoutMs = Math.max(1_500, opts.timeoutMs);
  const connectTimeoutMs = resolveChromeConnectTimeoutMs(opts.connectTimeoutMs);
  const profile = mkdtempSync(join(tmpdir(), "wc-cdp-"));
  const port = 40000 + Math.floor(Math.random() * 20000);
  const spawnFn = opts.spawnChrome ?? spawn;
  const args = chromeCdpArgs({
    port,
    profile,
    headless: opts.headless,
    binaryPath: chromePath,
  });
  let child: ChildProcess | undefined;
  let cdpReady = false;
  const ac = new AbortController();
  // Page budget covers navigation after connect; connect has its own deadline.
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  try {
    child = spawnFn(chromePath, args, {
      stdio: ["ignore", "ignore", "pipe"],
      detached: true,
    });
    if (!child.pid) {
      throw new Error("Chrome failed to start (no pid)");
    }
    child.once("exit", () => {
      if (!cdpReady && !ac.signal.aborted) ac.abort();
    });
    const wsUrl = await waitForPageWebSocket(port, connectTimeoutMs, ac.signal);
    cdpReady = true;
    const snapshot = await withCdpSession(wsUrl, url, timeoutMs, ac.signal);
    if (!snapshot.html || snapshot.html.length < 40) {
      throw new Error("CDP returned empty HTML");
    }
    return snapshot;
  } catch (err) {
    if (!cdpReady) {
      const hung = childStillRunning(child);
      const detail = err instanceof Error ? err.message : String(err);
      throw new ChromeConnectError(
        hung
          ? `Chrome did not respond over CDP within ${connectTimeoutMs}ms`
          : `Chrome CDP failed to start (${detail})`,
        hung
      );
    }
    if (ac.signal.aborted) {
      throw new Error(`CDP timed out after ${timeoutMs}ms`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
    if (child?.pid) killProcessGroup(child.pid, child);
    try {
      rmSync(profile, { recursive: true, force: true });
    } catch {
      /* leftover profile is in /tmp */
    }
  }
}

async function waitForPageWebSocket(
  port: number,
  connectTimeoutMs: number,
  signal: AbortSignal
): Promise<string> {
  const deadline = Date.now() + connectTimeoutMs;
  let lastErr = "CDP HTTP endpoint never became ready";
  while (Date.now() < deadline) {
    if (signal.aborted) throw new Error("Chrome CDP timed out while starting");
    try {
      const res = await fetch(`http://127.0.0.1:${port}/json/list`, {
        signal: AbortSignal.timeout(400),
      });
      if (res.ok) {
        const json = (await res.json()) as Array<{
          type?: string;
          webSocketDebuggerUrl?: string;
        }>;
        const page = (Array.isArray(json) ? json : []).find(
          (t) => t.webSocketDebuggerUrl && (t.type === "page" || !t.type)
        );
        if (page?.webSocketDebuggerUrl) return page.webSocketDebuggerUrl;
        lastErr = "CDP /json/list had no page websocket";
      } else {
        lastErr = `CDP /json/list HTTP ${res.status}`;
      }
    } catch (err) {
      lastErr = err instanceof Error ? err.message : String(err);
    }
    await delay(80, signal);
  }
  throw new Error(lastErr);
}

async function withCdpSession(
  wsUrl: string,
  url: string,
  timeoutMs: number,
  signal: AbortSignal
): Promise<CdpSnapshot> {
  const client = await CdpClient.connect(wsUrl, signal);
  const onAbort = () => client.close();
  signal.addEventListener("abort", onAbort);
  try {
    await client.send("Page.enable");
    await client.send("Runtime.enable");
    const load = client.waitForEvent("Page.loadEventFired", Math.min(timeoutMs, 12_000));
    const nav = await client.send("Page.navigate", { url });
    if (nav.errorText) {
      throw new Error(`Page.navigate failed: ${String(nav.errorText)}`);
    }
    try {
      await load;
    } catch {
      /* take a snapshot anyway if navigation load times out */
    }
    // Leave headroom for the final snapshot evaluate inside the page budget.
    const readyBudget = Math.max(
      1_500,
      Math.min(CONTENT_READY_MAX_WAIT_MS, timeoutMs - 1_000)
    );
    const deadline = Date.now() + readyBudget;
    let snapshot: CdpSnapshot | null = null;
    // Client-side redirects destroy the execution context mid-wait. Retry only
    // after an evaluate failure (not by racing loadEventFired, which can fire
    // spuriously in CI and restart a healthy wait until the budget is gone).
    while (Date.now() < deadline) {
      const remaining = Math.max(400, deadline - Date.now());
      try {
        snapshot = await evaluateSnapshot(
          client,
          buildWaitForContentReadyExpression(remaining)
        );
        break;
      } catch {
        try {
          await client.waitForEvent(
            "Page.loadEventFired",
            Math.min(remaining, 5_000)
          );
        } catch {
          /* take a snapshot on the current document anyway */
        }
        await delay(120, signal).catch(() => {});
      }
    }
    if (!snapshot || snapshot.textLen < 40 || snapshot.html.length < 80) {
      snapshot = await evaluateSnapshot(client, SNAPSHOT_JS);
    }
    if (!snapshot) throw new Error("Runtime.evaluate returned no snapshot");
    return snapshot;
  } finally {
    signal.removeEventListener("abort", onAbort);
    client.close();
  }
}

async function evaluateSnapshot(
  client: CdpClient,
  expression: string
): Promise<CdpSnapshot | null> {
  const result = await client.send(
    "Runtime.evaluate",
    { expression, returnByValue: true, awaitPromise: true }
  );
  const value = (result.result as { value?: CdpSnapshot } | undefined)?.value;
  if (!value || typeof value.html !== "string") return null;
  return {
    html: value.html,
    title: String(value.title ?? ""),
    textLen: Number(value.textLen ?? 0),
    readyState: String(value.readyState ?? ""),
  };
}

class CdpClient {
  private ws: WebSocket;
  private nextId = 0;
  private pending = new Map<
    number,
    { resolve: (v: Record<string, unknown>) => void; reject: (e: Error) => void }
  >();
  private eventWaiters: Array<{
    method: string;
    resolve: () => void;
    reject: (err: Error) => void;
  }> = [];

  private constructor(ws: WebSocket) {
    this.ws = ws;
    ws.addEventListener("message", (ev) => {
      let msg: CdpMessage;
      try {
        msg = JSON.parse(String(ev.data)) as CdpMessage;
      } catch {
        return;
      }
      if (msg.id != null) {
        const p = this.pending.get(msg.id);
        if (p) {
          this.pending.delete(msg.id);
          if (msg.error) {
            p.reject(new Error(msg.error.message || `CDP error ${msg.error.code ?? ""}`));
          } else {
            p.resolve(msg.result ?? {});
          }
        }
        return;
      }
      if (msg.method) {
        for (const w of [...this.eventWaiters]) {
          if (w.method === msg.method) {
            this.eventWaiters = this.eventWaiters.filter((x) => x !== w);
            w.resolve();
          }
        }
      }
    });
  }

  static connect(url: string, signal: AbortSignal): Promise<CdpClient> {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(url);
      const onAbort = () => {
        try {
          ws.close();
        } catch {
          /* ignore */
        }
        reject(new Error("Chrome CDP websocket timed out"));
      };
      if (signal.aborted) {
        onAbort();
        return;
      }
      signal.addEventListener("abort", onAbort, { once: true });
      ws.addEventListener("open", () => {
        signal.removeEventListener("abort", onAbort);
        resolve(new CdpClient(ws));
      });
      ws.addEventListener("error", () => {
        signal.removeEventListener("abort", onAbort);
        reject(new Error("Chrome CDP websocket failed"));
      });
    });
  }

  send(method: string, params: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    const id = ++this.nextId;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      try {
        this.ws.send(JSON.stringify({ id, method, params }));
      } catch (err) {
        this.pending.delete(id);
        reject(err instanceof Error ? err : new Error(String(err)));
      }
    });
  }

  waitForEvent(method: string, timeoutMs: number): Promise<void> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.eventWaiters = this.eventWaiters.filter((w) => w !== waiter);
        reject(new Error(`Timed out waiting for ${method}`));
      }, timeoutMs);
      const waiter = {
        method,
        resolve: () => {
          clearTimeout(timer);
          resolve();
        },
        reject: (err: Error) => {
          clearTimeout(timer);
          reject(err);
        },
      };
      this.eventWaiters.push(waiter);
    });
  }

  close(): void {
    for (const p of this.pending.values()) {
      p.reject(new Error("CDP session closed"));
    }
    this.pending.clear();
    for (const w of this.eventWaiters) {
      w.reject(new Error("CDP session closed"));
    }
    this.eventWaiters = [];
    try {
      this.ws.close();
    } catch {
      /* ignore */
    }
  }
}

function delay(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(new Error("aborted"));
      return;
    }
    const t = setTimeout(resolve, ms);
    signal.addEventListener(
      "abort",
      () => {
        clearTimeout(t);
        reject(new Error("aborted"));
      },
      { once: true }
    );
  });
}
