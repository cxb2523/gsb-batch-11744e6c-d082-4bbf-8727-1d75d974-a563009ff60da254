/**
 * Binary acquisition for @webcrawl/curl-impersonate.
 *
 * Resolves a pinned lexiforest/curl-impersonate binary for the current
 * platform, downloading it on first use into a cache dir. All failures
 * degrade to `null` (tier unavailable, caller falls back) — never throw
 * into the fetch path.
 *
 * Resolution order:
 *   1. WEBCRAWL_IMPERSONATE_BIN env var (path to a curl-impersonate binary)
 *   2. Cached binary under <cacheRoot>/webcrawl-impersonate/v2.3.2/<asset>/
 *   3. First-use download from the pinned GitHub release asset (sha256-verified)
 */

import { createHash } from "node:crypto";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, chmodSync, renameSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import * as https from "node:https";

export const IMPERSONATE_VERSION = "v2.3.2";

const RELEASE_BASE = `https://github.com/lexiforest/curl-impersonate/releases/download/${IMPERSONATE_VERSION}`;

/** Asset name (without `curl-impersonate-v2.3.2.` prefix) -> sha256. */
export const ASSET_SHA256: Record<string, string> = {
  "arm64-macos": "638ed43cc93cb5da91f794ff23fce1735fec3dc5c09ee87cc499d802c25d2d35",
  "x86_64-macos": "4e9fe855a34d011de88bf216c196f6957624526678b99b4f2135acc9ffa8c156",
  "x86_64-linux-gnu": "bc9bd2522fe1850dd54c0fff189c8dd606df3f222ab2a905f2dd255123c3f495",
  "aarch64-linux-gnu": "35a351db883f5ce82945bd8280c727b08e27aa48594d4eb9e091d8c80e936d52",
  "x86_64-linux-musl": "ce79849f3be2e15d06364f89aeebb901b6be7b48947e2af8dae0616bbc87731f",
  "aarch64-linux-musl": "1519bcee11f9c93a7ed95026bd951d53e8c7cd093f3ac53651b143e5a1e2098f",
};

/** Node platform/arch -> release asset name. Null when unsupported. */
export function assetForPlatform(
  platform: string = process.platform,
  arch: string = process.arch
): string | null {
  if (platform === "darwin") {
    if (arch === "arm64") return "arm64-macos";
    if (arch === "x64") return "x86_64-macos";
    return null;
  }
  if (platform === "linux") {
    const isMusl = detectMusl();
    if (arch === "arm64") return isMusl ? "aarch64-linux-musl" : "aarch64-linux-gnu";
    if (arch === "x64") return isMusl ? "x86_64-linux-musl" : "x86_64-linux-gnu";
    return null;
  }
  return null;
}

function detectMusl(): boolean {
  // `ldd --version` prints "musl" on musl hosts; glibc prints "glibc"/"GNU".
  // ldd missing or failing → assume glibc (the serverless default).
  try {
    const out = execFileSync("ldd", ["--version"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    return /musl/i.test(out);
  } catch {
    return false;
  }
}

function cacheRoot(): string {
  const home = process.env.HOME || process.env.USERPROFILE || "";
  const base = home ? join(home, ".cache") : tmpdir();
  const root = join(base, "webcrawl-impersonate");
  // Writable probe — HOME caches can be root-owned/EPERM (serverless, managed
  // Macs); fall back to tmpdir() so the tier stays available.
  try {
    mkdirSync(root, { recursive: true });
    return root;
  } catch {
    return join(tmpdir(), "webcrawl-impersonate");
  }
}

export function binaryCachePath(asset: string): string {
  return join(cacheRoot(), IMPERSONATE_VERSION, asset, "curl-impersonate");
}

function httpsGet(url: string, redirects = 0): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    if (redirects > 5) {
      reject(new Error("too many redirects"));
      return;
    }
    const req = https.get(url, (res) => {
      const status = res.statusCode ?? 0;
      const location = res.headers.location;
      if (status >= 300 && status < 400 && location) {
        res.resume();
        resolve(httpsGet(new URL(location, url).href, redirects + 1));
        return;
      }
      if (status !== 200) {
        res.resume();
        reject(new Error(`HTTP ${status} for ${url}`));
        return;
      }
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve(Buffer.concat(chunks)));
      res.on("error", reject);
    });
    req.on("error", reject);
  });
}

/**
 * Resolve the impersonate binary path, downloading on first use.
 * Returns null when unavailable — never throws.
 */
export async function ensureBinary(): Promise<string | null> {
  const override = process.env.WEBCRAWL_IMPERSONATE_BIN;
  if (override) {
    return existsSync(override) ? override : null;
  }
  const asset = assetForPlatform();
  if (!asset) return null;
  const cached = binaryCachePath(asset);
  if (existsSync(cached)) return cached;
  try {
    await downloadAndExtract(asset, cached);
    return cached;
  } catch {
    return null;
  }
}

async function downloadAndExtract(asset: string, destPath: string): Promise<void> {
  const url = `${RELEASE_BASE}/curl-impersonate-${IMPERSONATE_VERSION}.${asset}.tar.gz`;
  const expected = ASSET_SHA256[asset];
  if (!expected) throw new Error(`no pinned sha256 for ${asset}`);
  const tarball = await httpsGet(url);
  const actual = createHash("sha256").update(tarball).digest("hex");
  if (actual !== expected) {
    throw new Error(`sha256 mismatch for ${asset}: ${actual}`);
  }
  const dir = dirname(destPath);
  mkdirSync(dir, { recursive: true });
  // Extract only the binary entry into a scratch dir, then move into place.
  const scratch = join(dir, ".extract");
  rmSync(scratch, { recursive: true, force: true });
  mkdirSync(scratch, { recursive: true });
  await new Promise<void>((resolve, reject) => {
    const tar = spawn("tar", ["-xzf", "-", "-C", scratch, "curl-impersonate"], {
      stdio: ["pipe", "ignore", "pipe"],
    });
    tar.on("error", reject);
    tar.on("close", (code) =>
      code === 0 ? resolve() : reject(new Error(`tar exited ${code}`))
    );
    tar.stdin.on("error", reject);
    tar.stdin.end(tarball);
    tar.stderr.on("data", () => {}); // drain
  });
  const extracted = join(scratch, "curl-impersonate");
  chmodSync(extracted, 0o755);
  renameSync(extracted, destPath);
  rmSync(scratch, { recursive: true, force: true });
}

/** Synchronous availability probe (CLI startup, no network). */
export function isBinaryCached(): boolean {
  const override = process.env.WEBCRAWL_IMPERSONATE_BIN;
  if (override) return existsSync(override);
  const asset = assetForPlatform();
  if (!asset) return false;
  return existsSync(binaryCachePath(asset));
}

/** Best-effort liveness check: binary runs and reports a version. */
export function isBinaryHealthy(path: string): boolean {
  try {
    const r = spawnSync(path, ["--version"], { encoding: "utf8", timeout: 5000 });
    return r.status === 0 && /curl/i.test(String(r.stdout));
  } catch {
    return false;
  }
}
