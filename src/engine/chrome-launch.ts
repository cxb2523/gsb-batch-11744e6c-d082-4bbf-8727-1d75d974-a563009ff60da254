/**
 * Chrome process helpers shared by the CDP driver and the dump-dom fallback.
 */
import { existsSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { ChildProcess } from "node:child_process";

export const DUMP_MAX_BYTES = 2 * 1024 * 1024;
/** Page navigation + DOM-wait budget once Chrome is answering over CDP. */
export const DEFAULT_TIMEOUT_MS = 18_000;
/**
 * How long to wait for Chrome to accept CDP after spawn. Kept short and
 * separate from `DEFAULT_TIMEOUT_MS` so a hung binary fails fast while a
 * slow but working JS page (often ~7s) still has time to render.
 */
export const DEFAULT_CONNECT_TIMEOUT_MS = 4_000;
export const VIRTUAL_TIME_MS = 10_000;

function envPositiveMs(name: string, fallback: number, min: number): number {
  const raw = process.env[name];
  if (raw == null || raw.trim() === "") return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.max(min, n);
}

/** `opts.timeoutMs`, else `WEBCRAWL_CHROME_TIMEOUT_MS`, else 18s. */
export function resolveChromeTimeoutMs(override?: number): number {
  if (typeof override === "number" && Number.isFinite(override) && override > 0) {
    return Math.max(1_500, override);
  }
  return envPositiveMs("WEBCRAWL_CHROME_TIMEOUT_MS", DEFAULT_TIMEOUT_MS, 1_500);
}

/** `opts.connectTimeoutMs`, else `WEBCRAWL_CHROME_CONNECT_TIMEOUT_MS`, else 4s. */
export function resolveChromeConnectTimeoutMs(override?: number): number {
  if (typeof override === "number" && Number.isFinite(override) && override > 0) {
    return Math.max(500, override);
  }
  return envPositiveMs("WEBCRAWL_CHROME_CONNECT_TIMEOUT_MS", DEFAULT_CONNECT_TIMEOUT_MS, 500);
}

export type ChromeHeadlessMode = "new" | "old" | "shell";

export function killProcessGroup(
  pid: number | undefined,
  child?: Pick<ChildProcess, "kill">
): void {
  if (pid && pid > 0) {
    try {
      process.kill(-pid, "SIGKILL");
      return;
    } catch {
      /* process group kill is Unix-only; fall through */
    }
    try {
      process.kill(pid, "SIGKILL");
      return;
    } catch {
      /* already gone */
    }
  }
  try {
    child?.kill("SIGKILL");
  } catch {
    /* already gone */
  }
}

const COMMON_CHROME_ARGS = [
  "--no-sandbox",
  "--disable-gpu",
  "--disable-dev-shm-usage",
  "--no-first-run",
  "--no-default-browser-check",
  "--disable-crash-reporter",
  "--disable-breakpad",
  "--disable-background-networking",
  "--disable-sync",
  "--disable-extensions",
  "--disable-popup-blocking",
  "--mute-audio",
  "--hide-scrollbars",
  "--disable-blink-features=AutomationControlled",
];

export function headlessFlag(mode: ChromeHeadlessMode, binaryPath: string): string[] {
  const isShell = /headless[-_]?shell/i.test(binaryPath);
  if (isShell || mode === "shell") {
    // chrome-headless-shell is already a headless binary; --headless=new hangs
    // on some Chrome 156 installs (the v1.4.3 smoke-test failure).
    return ["--headless"];
  }
  if (mode === "old") return ["--headless=old"];
  return ["--headless=new"];
}

export function chromeCdpArgs(opts: {
  port: number;
  profile: string;
  headless: ChromeHeadlessMode;
  binaryPath?: string;
}): string[] {
  return [
    ...headlessFlag(opts.headless, opts.binaryPath ?? ""),
    ...COMMON_CHROME_ARGS,
    `--remote-debugging-port=${opts.port}`,
    "--remote-debugging-address=127.0.0.1",
    `--user-data-dir=${opts.profile}`,
    `--window-size=1280,800`,
    "about:blank",
  ];
}

export function chromeDumpDomArgs(opts: {
  profile: string;
  headless: ChromeHeadlessMode;
  url: string;
  timeoutMs: number;
  binaryPath?: string;
}): string[] {
  return [
    ...headlessFlag(opts.headless, opts.binaryPath ?? ""),
    ...COMMON_CHROME_ARGS,
    `--user-data-dir=${opts.profile}`,
    `--virtual-time-budget=${VIRTUAL_TIME_MS}`,
    `--timeout=${opts.timeoutMs}`,
    "--dump-dom",
    opts.url,
  ];
}

/**
 * First line of Chrome's DevToolsActivePort file is the chosen port when
 * `--remote-debugging-port=0`.
 */
export function parseDevToolsActivePort(text: string): number | null {
  const line = String(text ?? "")
    .split(/\r?\n/)
    .map((s) => s.trim())
    .find(Boolean);
  if (!line) return null;
  const port = Number(line);
  return Number.isInteger(port) && port > 0 && port < 65536 ? port : null;
}

function envChromePath(): string | null {
  const fromEnv =
    process.env.WEBCRAWL_CHROME_PATH?.trim() ||
    process.env.INTERACT_CHROME_PATH?.trim() ||
    process.env.CHROME_PATH?.trim();
  return fromEnv || null;
}

export function defaultChromeInstallPaths(): string[] {
  if (process.platform === "darwin") {
    return [
      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
      `${process.env.HOME || homedir()}/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`,
      "/Applications/Chromium.app/Contents/MacOS/Chromium",
    ];
  }
  if (process.platform === "win32") {
    return [
      `${process.env["ProgramFiles"] || "C:\\Program Files"}\\Google\\Chrome\\Application\\chrome.exe`,
      `${process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)"}\\Google\\Chrome\\Application\\chrome.exe`,
    ];
  }
  return [
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium-browser",
    "/usr/bin/chromium",
    "/snap/bin/chromium",
  ];
}

/** Playwright's chrome-headless-shell, if a previous `playwright install` left it on disk. */
export function findPlaywrightHeadlessShell(): string[] {
  const roots = [
    process.env.PLAYWRIGHT_BROWSERS_PATH,
    join(homedir(), ".cache", "ms-playwright"),
    join(homedir(), "Library", "Caches", "ms-playwright"),
    process.env.LOCALAPPDATA
      ? join(process.env.LOCALAPPDATA, "ms-playwright")
      : "",
  ].filter(Boolean) as string[];
  const out: string[] = [];
  for (const root of roots) {
    if (!existsSync(root)) continue;
    let entries: string[] = [];
    try {
      entries = readdirSync(root);
    } catch {
      continue;
    }
    for (const name of entries) {
      if (!name.startsWith("chromium_headless_shell") && !name.startsWith("chromium-headless-shell")) {
        continue;
      }
      const dir = join(root, name);
      const candidates = [
        join(dir, "chrome-headless-shell-linux64", "chrome-headless-shell"),
        join(dir, "chrome-headless-shell-linux-arm64", "chrome-headless-shell"),
        join(dir, "chrome-headless-shell-mac-arm64", "chrome-headless-shell"),
        join(dir, "chrome-headless-shell-mac-x64", "chrome-headless-shell"),
        join(dir, "chrome-headless-shell-win64", "chrome-headless-shell.exe"),
      ];
      for (const c of candidates) {
        if (existsSync(c)) out.push(c);
      }
    }
  }
  return out;
}

/**
 * Path to a real installed Chrome/Chromium, or null.
 * Priority: WEBCRAWL_CHROME_PATH, INTERACT_CHROME_PATH, CHROME_PATH, then per-OS
 * defaults (same locations `webcrawl doctor` checks). Env overrides are returned
 * even if the file is missing so tests can point at a stub binary.
 */
export function installedChromePath(): string | null {
  const fromEnv = envChromePath();
  if (fromEnv) return fromEnv;
  for (const p of defaultChromeInstallPaths()) {
    try {
      if (p && existsSync(p)) return p;
    } catch {
      /* not installed here */
    }
  }
  const shells = findPlaywrightHeadlessShell();
  return shells[0] ?? null;
}

export function isLocalChromeAvailable(): boolean {
  return installedChromePath() !== null;
}

/** Distinct binaries to try, env override first, then system Chrome, then headless-shell. */
export function discoverChromeBinaries(): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  const add = (p: string | null | undefined) => {
    if (!p || seen.has(p)) return;
    seen.add(p);
    out.push(p);
  };
  add(envChromePath());
  for (const p of defaultChromeInstallPaths()) {
    try {
      if (p && existsSync(p)) add(p);
    } catch {
      /* skip */
    }
  }
  for (const p of findPlaywrightHeadlessShell()) add(p);
  return out;
}
