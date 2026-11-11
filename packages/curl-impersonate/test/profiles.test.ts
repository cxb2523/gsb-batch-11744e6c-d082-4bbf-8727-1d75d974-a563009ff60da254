import { test } from "node:test";
import assert from "node:assert/strict";

import {
  DEFAULT_IMPERSONATE_PROFILE,
  profileHeaders,
  profileUserAgent,
} from "../src/profiles.js";
import { assetForPlatform, binaryCachePath } from "../src/binary.js";
import { parseHeaderDump } from "../src/fetch.js";

test("default profile is chrome150 (the newest profile that passes both stubhub and expedia)", () => {
  assert.equal(DEFAULT_IMPERSONATE_PROFILE, "chrome150");
});

test("profile headers are fingerprint-coherent", () => {
  for (const profile of ["chrome142", "chrome150", "chrome151_macos", "chrome152"] as const) {
    const h = profileHeaders(profile);
    const v = h["sec-ch-ua"].match(/v="(\d+)"/)![1];
    assert.ok(h["User-Agent"].includes(`Chrome/${v}.`), `${profile}: UA major matches sec-ch-ua`);
    assert.equal(h["sec-ch-ua-mobile"], "?0");
    assert.equal(h["sec-ch-ua-platform"], '"macOS"');
    assert.equal(h["Sec-Fetch-Mode"], "navigate");
    assert.equal(h["Sec-Fetch-Dest"], "document");
    assert.ok(h["Accept"].startsWith("text/html"));
    assert.ok(h["Accept-Language"].startsWith("en-US"));
  }
});

test("profile headers merge extras last", () => {
  const h = profileHeaders("chrome150", { "X-Custom": "yes", Accept: "*/*" });
  assert.equal(h["X-Custom"], "yes");
  assert.equal(h.Accept, "*/*");
});

test("profileUserAgent returns the UA string", () => {
  assert.match(profileUserAgent("chrome150"), /^Mozilla\/5\.0 \(Macintosh/);
});

test("assetForPlatform maps node platform/arch to release assets", () => {
  assert.equal(assetForPlatform("darwin", "arm64"), "arm64-macos");
  assert.equal(assetForPlatform("darwin", "x64"), "x86_64-macos");
  assert.equal(assetForPlatform("linux", "arm64"), "aarch64-linux-gnu");
  assert.equal(assetForPlatform("linux", "x64"), "x86_64-linux-gnu");
  // unsupported
  assert.equal(assetForPlatform("win32", "x64"), null);
  assert.equal(assetForPlatform("darwin", "ia32"), null);
});

test("assetForPlatform defaults to the current platform", () => {
  const asset = assetForPlatform();
  if (process.platform === "darwin") {
    assert.ok(asset!.endsWith("-macos"));
  } else if (process.platform === "linux") {
    assert.ok(/linux-(gnu|musl)/.test(asset ?? ""));
  }
});

test("binaryCachePath nests under version + asset", () => {
  const p = binaryCachePath("arm64-macos");
  assert.ok(p.includes("webcrawl-impersonate"));
  assert.ok(p.includes("v2.3.2"));
  assert.ok(p.includes("arm64-macos"));
  assert.ok(p.endsWith("curl-impersonate"));
});

test("parseHeaderDump reads status, headers, and first set-cookie", () => {
  const dump = [
    "HTTP/1.1 301 Moved Permanently",
    "Location: https://example.com/",
    "",
    "HTTP/2 200",
    "content-type: text/html; charset=utf-8",
    "content-length: 12345",
    "set-cookie: abc=1; Path=/; Secure",
    "set-cookie: def=2; Path=/",
    "",
  ].join("\r\n");
  const { status, headers } = parseHeaderDump(dump);
  assert.equal(status, 200); // last block wins
  assert.equal(headers["content-type"], "text/html; charset=utf-8");
  assert.equal(headers["content-length"], "12345");
  assert.equal(headers["set-cookie"], "abc=1");
  assert.equal(headers["location"], "https://example.com/");
});

test("parseHeaderDump handles a single-block dump and an empty dump", () => {
  const single = parseHeaderDump("HTTP/2 403\r\nserver: awswaf\r\n\r\n");
  assert.equal(single.status, 403);
  assert.equal(single.headers["server"], "awswaf");
  const empty = parseHeaderDump("");
  assert.equal(empty.status, 0);
  assert.deepEqual(empty.headers, {});
});
