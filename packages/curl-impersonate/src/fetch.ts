/**
 * Spawn-based impersonate fetch: one GET hop through the pinned
 * lexiforest curl-impersonate binary with a Chrome TLS/HTTP2 fingerprint.
 *
 * Redirects are NOT followed (-L off) so every hop goes through the
 * caller's SSRF guard — same contract as `rawGet` in the engine fetcher.
 */

import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DEFAULT_IMPERSONATE_PROFILE,
  ImpersonateProfile,
  profileHeaders,
} from "./profiles.js";
import { ensureBinary } from "./binary.js";

export interface ImpersonateFetchResult {
  status: number;
  headers: Record<string, string>;
  contentType: string;
  /** Decompressed body bytes (the binary handles gzip/br/zstd itself). */
  body: Uint8Array;
  /** Decompressed body size in bytes (body.length) — for bandwidth accounting. */
  bytes: number;
}

export class ResourceTooLargeError extends Error {
  constructor(public readonly bytes: number, public readonly maxBytes: number) {
    super(
      `File is ${(bytes / 1e6).toFixed(1)} MB; the limit is ${(maxBytes / 1e6).toFixed(0)} MB`
    );
    this.name = "ResourceTooLargeError";
  }
}

export class ImpersonateUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ImpersonateUnavailableError";
  }
}

export class ImpersonateTimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ImpersonateTimeoutError";
  }
}

export interface ImpersonateFetchOptions {
  /** Impersonation preset (default chrome150). */
  profile?: ImpersonateProfile;
  /** Per-request headers merged over the profile navigation set. */
  headers?: Record<string, string>;
  /** Total timeout for the spawn (default 12s). */
  timeoutMs?: number;
  /** Declared-length guard before the body is accepted. */
  maxBytes?: number;
  /**
   * HTTP(S) proxy URL (credentials embedded, `http://user:pass@host:port`).
   * Routes the hop through e.g. a residential proxy so the target sees a
   * clean egress IP while the TLS fingerprint stays a real Chrome's.
   */
  proxy?: string;
}

let cachedBinary: string | null | undefined;
let binaryProbe: Promise<string | null> | null = null;

/** Resolved binary path or null when the tier is unavailable. Memoized. */
export async function resolveBinary(): Promise<string | null> {
  if (cachedBinary !== undefined) return cachedBinary;
  if (!binaryProbe) {
    binaryProbe = ensureBinary().finally(() => {
      binaryProbe = null;
    });
  }
  return (cachedBinary = await binaryProbe);
}

/** Pre-warm the binary (download if missing) for CLI/MCP startup. */
export async function ensureImpersonate(): Promise<string | null> {
  cachedBinary = undefined;
  binaryProbe = null;
  return resolveBinary();
}

/** True when the binary resolved (cached or downloaded). */
export async function isImpersonateAvailable(): Promise<boolean> {
  return (await resolveBinary()) !== null;
}

/** Parse a `-D` header dump (all blocks; the final block wins per header). */
export function parseHeaderDump(dump: string): {
  status: number;
  headers: Record<string, string>;
} {
  const headers: Record<string, string> = {};
  let status = 0;
  const lines = String(dump ?? "").split(/\r?\n/);
  for (const line of lines) {
    const statusMatch = line.match(/^HTTP\/[\d.]+\s+(\d{3})/i);
    if (statusMatch) {
      status = Number(statusMatch[1]);
      continue;
    }
    const idx = line.indexOf(":");
    if (idx <= 0) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const val = line.slice(idx + 1).trim();
    if (key === "set-cookie") {
      // keep the first cookie of the final block; callers replay per-domain
      if (!(key in headers)) headers[key] = val.split(";")[0];
    } else {
      headers[key] = val;
    }
  }
  return { status, headers };
}

/** One GET hop through curl-impersonate. Throws only on setup/size/timeout errors. */
export async function impersonateFetch(
  url: string,
  options: ImpersonateFetchOptions = {}
): Promise<ImpersonateFetchResult> {
  const bin = await resolveBinary();
  if (!bin) {
    throw new ImpersonateUnavailableError("curl-impersonate binary unavailable");
  }

  const {
    profile = DEFAULT_IMPERSONATE_PROFILE,
    headers = {},
    timeoutMs = 12_000,
    maxBytes,
    proxy,
  } = options;

  const navHeaders = profileHeaders(profile, headers);
  const headerArgs = Object.entries(navHeaders).flatMap(([k, v]) => ["-H", `${k}: ${v}`]);

  const dir = mkdtempSync(join(tmpdir(), "webcrawl-imp-"));
  const headerFile = join(dir, "headers");
  const bodyFile = join(dir, "body");
  try {
    const { exitCode, stdout, stderr } = await new Promise<{
      exitCode: number;
      stdout: string;
      stderr: string;
    }>((resolve, reject) => {
      const child = spawn(
        bin,
        [
          "-sS",
          "--compressed",
          "--impersonate", profile,
          "-m", String(Math.ceil(timeoutMs / 1000)),
          "-D", headerFile,
          "-o", bodyFile,
          "-w", "%{http_code}",
          url,
          ...headerArgs,
          ...(proxy ? ["-x", proxy] : []),
        ],
        { stdio: ["ignore", "pipe", "pipe"] }
      );
      let stdout = "";
      let stderr = "";
      let settled = false;
      const timer = setTimeout(() => {
        settled = true;
        child.kill("SIGKILL");
        reject(new ImpersonateTimeoutError(`timed out after ${timeoutMs}ms`));
      }, timeoutMs + 2000);
      child.stdout.on("data", (c: Buffer) => (stdout += c.toString()));
      child.stderr.on("data", (c: Buffer) => (stderr += c.toString()));
      child.on("error", (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(err);
      });
      child.on("close", (code) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        // 0 = clean exit. Partial fetches (timeouts) still parse best-effort.
        resolve({ exitCode: code ?? -1, stdout, stderr });
      });
    });

    if (exitCode !== 0 && stderr.trim() && !existsFile(headerFile)) {
      throw new Error(`curl-impersonate exited ${exitCode}: ${stderr.slice(0, 400)}`);
    }
    void stdout; // %{http_code} — kept for debugging; status comes from the dump

    const { status: parsedStatus, headers: responseHeaders } = parseHeaderDump(
      safeRead(headerFile)
    );
    const status = parsedStatus || Number(stdout.trim()) || 0;
    const body = safeReadBytes(bodyFile);

    if (maxBytes !== undefined) {
      const declared = Number(responseHeaders["content-length"]);
      if (Number.isFinite(declared) && declared > maxBytes) {
        throw new ResourceTooLargeError(declared, maxBytes);
      }
      if (body.byteLength > maxBytes) {
        throw new ResourceTooLargeError(body.byteLength, maxBytes);
      }
    }
    return {
      status,
      headers: responseHeaders,
      contentType: (responseHeaders["content-type"] || "")
        .split(";")[0]
        .trim()
        .toLowerCase(),
      body,
      bytes: body.byteLength,
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function existsFile(path: string): boolean {
  try {
    readFileSync(path);
    return true;
  } catch {
    return false;
  }
}

function safeRead(path: string): string {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return "";
  }
}

function safeReadBytes(path: string): Uint8Array {
  try {
    return new Uint8Array(readFileSync(path));
  } catch {
    return new Uint8Array(0);
  }
}
