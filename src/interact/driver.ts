/**
 * Browser driver for interact runs. Node-only: called from workflow steps.
 *
 * Two backends share one step runner (STEP_SCRIPT):
 * - sandbox: Chromium inside a Vercel Sandbox, reached by sandboxId so any
 *   step invocation (on any function instance) can reattach.
 * - local:   Chromium on this machine for dev (INTERACT_LOCAL_PLAYWRIGHT=true).
 *            Only works while steps run in the same long-lived process
 *            (Local World / `next dev`).
 */
import { execFile, spawn } from "node:child_process";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { Sandbox } from "@vercel/sandbox";
import {
  CDP_PORT,
  SETUP_SCRIPT,
  STEP_SCRIPT,
  STEP_SCRIPT_PATH,
  VM_ROOT,
  WAIT_FOR_CDP_SCRIPT,
  chromeArgs,
  parseStepOutput,
  type StepResultLine,
} from "./vm.js";
import { startRemoteSession, stopRemoteSession, type RemoteProvider, type RemoteSessionCost } from "./remote.js";
import { WARM_SANDBOX_TIMEOUT_MS, WARM_TTL_MS } from "../engine/session.js";

/** Where STEP_SCRIPT runs when the browser itself is hosted by a remote provider. */
export type StepRunner = { kind: "sandbox"; sandboxId: string } | { kind: "local"; scriptPath: string; playwright: string };

export type BrowserHandle =
  | { kind: "sandbox"; sandboxId: string }
  | { kind: "local"; cdp: string; pid: number; scriptPath: string; playwright: string }
  | {
      kind: "remote";
      provider: RemoteProvider;
      sessionId: string;
      cdpUrl: string;
      /** Headers the CDP websocket needs (e.g. Cloudflare bearer auth). */
      cdpHeaders?: Record<string, string>;
      startedAt: number;
      runner: StepRunner;
    };

export type StepAction = Record<string, unknown> & { type: string };

const snapshotId = () => process.env.WEBCRAWL_INTERACT_SNAPSHOT_ID || process.env.INTERACT_SNAPSHOT_ID || "";
const localMode = () => process.env.INTERACT_LOCAL_PLAYWRIGHT === "true";

/**
 * True when some browser backend can run. Checked before starting a run so we never fake success.
 * On Vercel (VERCEL=1) the OIDC token is not in env at request time: it arrives in the
 * `x-vercel-oidc-token` request header, which @vercel/sandbox reads via @vercel/oidc.
 */
export function interactBrowserAvailable(): boolean {
  if (localMode()) return true;
  return Boolean(
    process.env.VERCEL === "1" ||
      process.env.VERCEL_OIDC_TOKEN ||
      (process.env.VERCEL_TOKEN && process.env.VERCEL_TEAM_ID && process.env.VERCEL_PROJECT_ID)
  );
}

export function interactBackend(): "local" | "sandbox" | "none" {
  if (localMode()) return "local";
  return interactBrowserAvailable() ? "sandbox" : "none";
}

/* ----------------------------- sandbox backend ---------------------------- */

async function sh(sandbox: Sandbox, script: string, sudo = true) {
  const r = await sandbox.runCommand({ cmd: "bash", args: ["-lc", script], sudo });
  return { exitCode: r.exitCode, stdout: await r.stdout(), stderr: await r.stderr() };
}

const SANDBOX_RESOURCES = { vcpus: 2 } as const;

/**
 * Boots from the prebuilt snapshot (Chromium + Playwright already installed,
 * see scripts/build-interact-snapshot.ts). If the snapshot is unset, expired
 * or deleted, falls back to a cold VM and runs the full setup.
 */
async function createBrowserSandbox(timeoutMs: number): Promise<{ sandbox: Sandbox; fromSnapshot: boolean }> {
  const snap = snapshotId();
  if (snap) {
    try {
      const sandbox = await Sandbox.create({
        source: { type: "snapshot", snapshotId: snap },
        timeout: timeoutMs,
        resources: SANDBOX_RESOURCES,
      });
      return { sandbox, fromSnapshot: true };
    } catch (err) {
      console.warn("[interact] snapshot boot failed, using cold setup", {
        snapshotId: snap,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }
  const sandbox = await Sandbox.create({ runtime: "node22", timeout: timeoutMs, resources: SANDBOX_RESOURCES });
  return { sandbox, fromSnapshot: false };
}

async function startSandboxBrowser(opts: { timeoutMs: number; userAgent?: string; proxy?: string }): Promise<BrowserHandle> {
  const { sandbox, fromSnapshot } = await createBrowserSandbox(opts.timeoutMs);
  try {
    if (!fromSnapshot) {
      const setup = await sh(sandbox, SETUP_SCRIPT);
      if (setup.exitCode !== 0) throw new Error(`Browser setup failed: ${(setup.stderr || setup.stdout).slice(-300)}`);
    }
    // Always write the current step runner so a snapshot built from older code
    // never runs a stale copy. It is a few KB, so this costs one round trip.
    await sandbox.writeFiles([{ path: STEP_SCRIPT_PATH, content: Buffer.from(STEP_SCRIPT) }]);
    const exe = (await sh(sandbox, `cat ${VM_ROOT}/chrome-path`)).stdout.trim().split("\n").pop();
    if (!exe) throw new Error("Browser binary not found in sandbox");
    await sandbox.runCommand({ cmd: exe, args: chromeArgs({ userAgent: opts.userAgent, proxy: opts.proxy }), detached: true, sudo: true });
    const ready = await sh(sandbox, WAIT_FOR_CDP_SCRIPT, false);
    if (ready.exitCode !== 0) throw new Error("Browser did not start");
    return { kind: "sandbox", sandboxId: sandbox.sandboxId };
  } catch (err) {
    await sandbox.stop().catch(() => {});
    throw err;
  }
}

/** True when the sandbox's Chromium still answers on CDP (warm reconnect check). */
async function sandboxChromeAlive(sandbox: Sandbox): Promise<boolean> {
  const ping = await sh(sandbox, `curl -sf -m 3 http://127.0.0.1:${CDP_PORT}/json/version >/dev/null && echo alive`, false);
  return ping.exitCode === 0 && ping.stdout.includes("alive");
}

/**
 * Warm reconnect: fetch the sandbox this domain solved its challenge in, verify
 * Chromium still lives, and reuse it (same IP, same UA, same cleared cookies).
 * Returns null when no warm entry exists or the sandbox is gone (cold boot).
 */
async function startWarmSandboxBrowser(domain: string): Promise<BrowserHandle | null> {
  if (!domain) return null;
  const { getWarmSession } = await import("../engine/session.js");
  let warm: Awaited<ReturnType<typeof getWarmSession>>;
  try {
    warm = await getWarmSession(domain);
  } catch {
    return null;
  }
  if (!warm || !warm.sandboxId) return null;
  try {
    const sandbox = await Sandbox.get({ sandboxId: warm.sandboxId });
    if (!(await sandboxChromeAlive(sandbox))) {
      await sandbox.stop().catch(() => {});
      return null;
    }
    // Refresh the step runner in case this instance ships newer code.
    await sandbox.writeFiles([{ path: STEP_SCRIPT_PATH, content: Buffer.from(STEP_SCRIPT) }]).catch(() => {});
    console.info("[stealth] warm reconnect", { domain, sandboxId: warm.sandboxId });
    return { kind: "sandbox", sandboxId: warm.sandboxId };
  } catch {
    return null;
  }
}

/* ------------------------------ local backend ----------------------------- */

/**
 * Path to a real, user-installed Chrome when one exists, else null.
 * Anti-bot vendors (DataDome, Akamai) fingerprint the automation build of
 * Chromium and serve degraded pages to it, while the same engine driving a
 * real installed Chrome gets full content — practitioner reports confirm
 * this on DataDome-protected sites. Priority: explicit env override, then
 * the standard per-OS install locations.
 */
export function installedChromePath(): string | null {
  if (process.env.INTERACT_CHROME_PATH) return process.env.INTERACT_CHROME_PATH;
  const candidates: string[] = [];
  if (process.platform === "darwin") {
    candidates.push(
      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
      `${process.env.HOME || ""}/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`,
    );
  } else if (process.platform === "win32") {
    candidates.push(
      `${process.env["ProgramFiles"] || "C:\\Program Files"}\\Google\\Chrome\\Application\\chrome.exe`,
      `${process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)"}\\Google\\Chrome\\Application\\chrome.exe`,
    );
  } else {
    candidates.push(
      "/usr/bin/google-chrome",
      "/usr/bin/google-chrome-stable",
      "/usr/bin/chromium-browser",
      "/usr/bin/chromium",
      "/snap/bin/chromium",
    );
  }
  for (const p of candidates) {
    try {
      if (existsSync(p)) return p;
    } catch {
      /* not installed here */
    }
  }
  return null;
}

async function resolveLocalPlaywright(): Promise<{ playwright: string; chrome: string }> {
  const candidates = [
    process.env.WC_PLAYWRIGHT,
    path.join(process.cwd(), "node_modules/playwright/index.mjs"),
    path.join(process.cwd(), "../node_modules/playwright/index.mjs"),
  ].filter(Boolean) as string[];
  for (const p of candidates) {
    try {
      const mod = (await import(/* webpackIgnore: true */ p)) as {
        chromium: { executablePath(): string };
      };
      // Prefer a real installed Chrome over playwright's bundled automation
      // Chromium (see installedChromePath); fall back to the bundle when the
      // host has no Chrome (CI, containers, minimal servers).
      const chrome = installedChromePath() || mod.chromium.executablePath();
      return { playwright: p, chrome };
    } catch {
      /* try next */
    }
  }
  throw new Error("Local browser unavailable: install playwright or set WC_PLAYWRIGHT");
}

async function startLocalBrowser(opts: { userAgent?: string; proxy?: string }): Promise<BrowserHandle> {
  const { playwright, chrome } = await resolveLocalPlaywright();
  const port = 9300 + Math.floor(Math.random() * 600);
  const dir = mkdtempSync(path.join(tmpdir(), "wc-interact-"));
  const args = chromeArgs({ userAgent: opts.userAgent, proxy: opts.proxy })
    .map((a) => (a.startsWith("--remote-debugging-port=") ? `--remote-debugging-port=${port}` : a))
    .map((a) => (a.startsWith("--user-data-dir=") ? `--user-data-dir=${dir}/profile` : a));
  args.unshift("--disable-crash-reporter", "--disable-breakpad");
  const child = spawn(chrome, args, { detached: true, stdio: "ignore" });
  child.unref();
  const cdp = `http://127.0.0.1:${port}`;
  // A cold first launch (new profile) can take over 10s on macOS.
  for (let i = 0; i < 75; i++) {
    try {
      const r = await fetch(`${cdp}/json/version`);
      if (r.ok) break;
    } catch {
      /* not up yet */
    }
    if (i === 74) {
      try { process.kill(child.pid!); } catch { /* gone */ }
      throw new Error("Local browser did not start");
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  const scriptPath = path.join(dir, "step.mjs");
  writeFileSync(scriptPath, STEP_SCRIPT);
  return { kind: "local", cdp, pid: child.pid!, scriptPath, playwright };
}

/* ------------------------------ remote backend ---------------------------- */

/**
 * A place to run STEP_SCRIPT without starting Chromium: the provider hosts the
 * browser. Local Playwright when installed (dev), else a sandbox VM.
 */
async function startStepRunner(timeoutMs: number): Promise<StepRunner> {
  if (localMode()) {
    const { playwright } = await resolveLocalPlaywright();
    const dir = mkdtempSync(path.join(tmpdir(), "wc-remote-"));
    const scriptPath = path.join(dir, "step.mjs");
    writeFileSync(scriptPath, STEP_SCRIPT);
    return { kind: "local", scriptPath, playwright };
  }
  const { sandbox, fromSnapshot } = await createBrowserSandbox(timeoutMs);
  try {
    if (!fromSnapshot) {
      const setup = await sh(sandbox, SETUP_SCRIPT);
      if (setup.exitCode !== 0) throw new Error(`Step runner setup failed: ${(setup.stderr || setup.stdout).slice(-300)}`);
    }
    await sandbox.writeFiles([{ path: STEP_SCRIPT_PATH, content: Buffer.from(STEP_SCRIPT) }]);
    return { kind: "sandbox", sandboxId: sandbox.sandboxId };
  } catch (err) {
    await sandbox.stop().catch(() => {});
    throw err;
  }
}

async function startRemoteBrowser(provider: RemoteProvider, timeoutMs: number): Promise<BrowserHandle> {
  // Both start in parallel; the provider bills from session start, so stop it if the runner fails.
  const [session, runner] = await Promise.allSettled([startRemoteSession({ provider, timeoutMs }), startStepRunner(timeoutMs)]);
  if (session.status === "fulfilled" && runner.status === "fulfilled") {
    const s = session.value;
    return {
      kind: "remote",
      provider,
      sessionId: s.sessionId,
      cdpUrl: s.cdpUrl,
      ...(s.cdpHeaders ? { cdpHeaders: s.cdpHeaders } : {}),
      startedAt: s.startedAt,
      runner: runner.value,
    };
  }
  if (session.status === "fulfilled") await stopRemoteSession(session.value);
  if (runner.status === "fulfilled") await stopRunner(runner.value);
  const reason = session.status === "rejected" ? session.reason : (runner as PromiseRejectedResult).reason;
  throw reason instanceof Error ? reason : new Error(String(reason));
}

async function stopRunner(runner: StepRunner): Promise<void> {
  if (runner.kind === "local") return;
  try {
    const sandbox = await Sandbox.get({ sandboxId: runner.sandboxId });
    await sandbox.stop();
  } catch {
    /* already stopped or expired */
  }
}

/* --------------------------------- public --------------------------------- */

export async function startBrowser(
  opts: { timeoutMs?: number; userAgent?: string; remote?: RemoteProvider | null; domain?: string; proxy?: string } = {}
): Promise<BrowserHandle> {
  if (opts.remote) return startRemoteBrowser(opts.remote, opts.timeoutMs ?? 5 * 60_000);
  if (localMode()) return startLocalBrowser(opts);
  if (!interactBrowserAvailable()) throw new Error("browser_unavailable");
  // Warm reconnect first: a sandbox that already solved this domain's bot check
  // keeps its IP / UA / cleared cookies — reusing it skips boot + re-solve.
  // Never warm-reconnect when proxying: the warm sandbox egresses direct.
  if (opts.domain && !opts.proxy) {
    const warm = await startWarmSandboxBrowser(opts.domain).catch(() => null);
    if (warm) return warm;
  }
  return startSandboxBrowser({
    // Long VM timeout headroom so the sandbox can stay warm after this call.
    timeoutMs: Math.max(opts.timeoutMs ?? 5 * 60_000, WARM_SANDBOX_TIMEOUT_MS),
    userAgent: opts.userAgent,
    proxy: opts.proxy,
  });
}

function runLocalStep(
  scriptPath: string,
  playwright: string,
  cdp: string,
  action: StepAction,
  extraEnv: Record<string, string> = {}
): Promise<StepResultLine> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [scriptPath, JSON.stringify(action)],
      {
        env: { ...process.env, WC_PLAYWRIGHT: playwright, WC_CDP: cdp, ...extraEnv },
        // A stealth fetchMany reads many documents in one step.
        timeout: action.type === "fetchMany" ? 300_000 : 45_000,
        maxBuffer: 16 * 1024 * 1024,
      },
      (_err, stdout, stderr) => resolve(parseStepOutput(String(stdout ?? ""), String(stderr ?? "")))
    );
  });
}

async function runSandboxStep(sandboxId: string, action: StepAction, env?: Record<string, string>): Promise<StepResultLine> {
  const sandbox = await Sandbox.get({ sandboxId });
  const r = await sandbox.runCommand({ cmd: "node", args: [STEP_SCRIPT_PATH, JSON.stringify(action)], sudo: true, ...(env ? { env } : {}) });
  return parseStepOutput(await r.stdout(), await r.stderr());
}

export async function runBrowserStep(handle: BrowserHandle, action: StepAction): Promise<StepResultLine> {
  if (handle.kind === "local") return runLocalStep(handle.scriptPath, handle.playwright, handle.cdp, action);
  if (handle.kind === "remote") {
    // The provider's browser carries its own fingerprint; overriding it would undo that.
    const remoteAction = { ...action, keepFingerprint: true, lightweight: true };
    const headerEnv: Record<string, string> = handle.cdpHeaders ? { WC_CDP_HEADERS: JSON.stringify(handle.cdpHeaders) } : {};
    return handle.runner.kind === "local"
      ? runLocalStep(handle.runner.scriptPath, handle.runner.playwright, handle.cdpUrl, remoteAction, headerEnv)
      : runSandboxStep(handle.runner.sandboxId, remoteAction, { WC_CDP: handle.cdpUrl, ...headerEnv });
  }
  return runSandboxStep(handle.sandboxId, action);
}

/**
 * Stops the browser. For a remote provider, returns what the session cost (null
 * when unknown). With `keepWarm`, a sandbox browser is left running and
 * registered (domain + sandboxId + UA) so the next call reconnects to it via
 * `Sandbox.get` instead of cold-booting — the caller must pass `domain`.
 * Evicted warm entries (over the cap) are stopped here so idle compute
 * does not linger.
 */
export async function stopBrowser(
  handle: BrowserHandle,
  opts: { keepWarm?: boolean; domain?: string; userAgent?: string; cookieHeader?: string } = {}
): Promise<RemoteSessionCost | null> {
  if (handle.kind === "local") {
    try {
      process.kill(handle.pid);
    } catch {
      /* already gone */
    }
    return null;
  }
  if (handle.kind === "remote") {
    const [cost] = await Promise.all([stopRemoteSession(handle), stopRunner(handle.runner)]);
    return cost;
  }
  if (opts.keepWarm && opts.domain) {
    const { saveWarmSession } = await import("../engine/session.js");
    try {
      const evicted = await saveWarmSession({
        domain: opts.domain,
        sandboxId: handle.sandboxId,
        userAgent: opts.userAgent ?? "",
        cookieHeader: opts.cookieHeader ?? "",
        expiresAt: Date.now() + WARM_TTL_MS,
      });
      await Promise.all(
        evicted.map(async (id) => {
          try {
            const sandbox = await Sandbox.get({ sandboxId: id });
            await sandbox.stop();
          } catch {
            /* already stopped */
          }
        })
      );
      console.info("[stealth] kept warm", { domain: opts.domain, sandboxId: handle.sandboxId, evicted: evicted.length });
      return null;
    } catch {
      /* registry unavailable — fall through to full stop */
    }
  }
  await stopRunner(handle);
  return null;
}

export { CDP_PORT };
