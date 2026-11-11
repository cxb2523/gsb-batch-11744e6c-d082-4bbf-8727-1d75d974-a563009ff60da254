import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { assertSafeUrl, followSafely, isFakeIpAddress, UnsafeUrlError } from "../engine/safe-url.js";

const pub = async () => ["93.184.216.34"];
const priv = async () => ["10.0.0.5"];

describe("assertSafeUrl", () => {
  it("rejects private, loopback, metadata and non-http targets", async () => {
    for (const u of [
      "http://localhost/",
      "http://127.0.0.1/",
      "http://169.254.169.254/latest/meta-data",
      "http://[::1]/",
      "http://foo.internal/",
      "file:///etc/passwd",
      "ftp://example.com/",
    ]) {
      await assert.rejects(assertSafeUrl(u, pub), UnsafeUrlError, u);
    }
  });
  it("rejects hosts that resolve to private addresses", async () => {
    await assert.rejects(assertSafeUrl("https://evil.example/", priv), UnsafeUrlError);
  });
  it("explains fake-IP proxy DNS (198.18.0.0/15) and names the workaround", async () => {
    const fake = async () => ["198.18.0.42"];
    await assert.rejects(assertSafeUrl("https://example.com/", fake), (e: Error) => {
      assert.ok(e instanceof UnsafeUrlError);
      assert.match(e.message, /fake-IP/);
      assert.match(e.message, /WEBCRAWL_ALLOW_PRIVATE_URLS=true/);
      return true;
    });
    // A real private address keeps the plain message.
    await assert.rejects(assertSafeUrl("https://evil.example/", priv), (e: Error) => {
      assert.doesNotMatch(e.message, /fake-IP/);
      return true;
    });
    assert.equal(isFakeIpAddress("198.19.255.1"), true);
    assert.equal(isFakeIpAddress("::ffff:198.18.0.1"), true);
    assert.equal(isFakeIpAddress("198.20.0.1"), false);
  });
  it("still allows fake-IP addresses when WEBCRAWL_ALLOW_PRIVATE_URLS=true", async () => {
    process.env.WEBCRAWL_ALLOW_PRIVATE_URLS = "true";
    try {
      const u = await assertSafeUrl("https://example.com/", async () => ["198.18.0.42"]);
      assert.equal(u.hostname, "example.com");
    } finally {
      delete process.env.WEBCRAWL_ALLOW_PRIVATE_URLS;
    }
  });
  it("accepts public hosts", async () => {
    const u = await assertSafeUrl("https://example.com/a", pub);
    assert.equal(u.hostname, "example.com");
  });
});

describe("followSafely", () => {
  it("blocks a redirect hop to an internal address", async () => {
    const calls: string[] = [];
    await assert.rejects(
      followSafely(
        "https://example.com/",
        async (u) => {
          calls.push(u);
          return { status: 302, headers: { location: "http://169.254.169.254/" } };
        },
        async (h) => (h === "example.com" ? ["93.184.216.34"] : [h])
      ),
      UnsafeUrlError
    );
    assert.deepEqual(calls, ["https://example.com/"]);
  });
  it("follows safe redirects and returns the final URL", async () => {
    const { res, finalUrl } = await followSafely(
      "https://a.example/",
      async (u): Promise<{ status: number; headers: Record<string, string> }> =>
        u === "https://a.example/"
          ? { status: 301, headers: { location: "/b" } }
          : { status: 200, headers: {} },
      pub
    );
    assert.equal(res.status, 200);
    assert.equal(finalUrl, "https://a.example/b");
  });
  it("stops redirect loops", async () => {
    await assert.rejects(
      followSafely("https://a.example/", async () => ({ status: 302, headers: { location: "/" } }), pub),
      /Too many redirects/
    );
  });
});
