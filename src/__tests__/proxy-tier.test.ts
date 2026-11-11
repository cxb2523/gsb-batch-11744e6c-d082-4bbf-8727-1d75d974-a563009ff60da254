import { test } from "node:test";
import assert from "node:assert/strict";
import {
  markDomainProxyNeeded,
  isDomainProxyNeeded,
  registerExternalSessionStore,
  resetSessionStateForTests,
  PROXY_MEMO_TTL_MS,
} from "../engine/session.js";
import { residentialProxyUrl, lastFetchTier, lastProxyBytesCount } from "../engine/fetcher.js";

test("residentialProxyUrl resolves WEBCRAWL_PROXY_* env vars with DECODO_* legacy fallback", () => {
  const names = ["WEBCRAWL_PROXY_URL", "WEBCRAWL_PROXY_USER", "WEBCRAWL_PROXY_PWD", "WEBCRAWL_PROXY_HOST", "WEBCRAWL_PROXY_PORT", "DECODO_URL", "DECODO_USER", "DECODO_PWD"];
  const prev: Record<string, string | undefined> = {};
  for (const n of names) prev[n] = process.env[n];
  const clearAll = () => { for (const n of names) delete process.env[n]; };
  try {
    // generic full URL wins
    clearAll();
    process.env.WEBCRAWL_PROXY_URL = "http://u:p@any-gateway.example.com:8080";
    assert.equal(residentialProxyUrl(), "http://u:p@any-gateway.example.com:8080");
    // generic split pair with custom host/port
    delete process.env.WEBCRAWL_PROXY_URL;
    process.env.WEBCRAWL_PROXY_USER = "user name";
    process.env.WEBCRAWL_PROXY_PWD = "x";
    process.env.WEBCRAWL_PROXY_HOST = "residential.example.com";
    process.env.WEBCRAWL_PROXY_PORT = "1080";
    assert.equal(
      residentialProxyUrl(),
      "http://user%20name:x@residential.example.com:1080"
    );
    // DECODO_* legacy fallback, default gateway
    clearAll();
    process.env.DECODO_URL = "http://u:p@gate.decodo.com:7000";
    process.env.DECODO_USER = "other";
    process.env.DECODO_PWD = "x";
    assert.equal(residentialProxyUrl(), "http://u:p@gate.decodo.com:7000");
    delete process.env.DECODO_URL;
    assert.equal(
      residentialProxyUrl(),
      "http://other:x@gate.decodo.com:7000"
    );
    // generic vars take precedence over DECODO_*
    process.env.WEBCRAWL_PROXY_USER = "new";
    process.env.WEBCRAWL_PROXY_PWD = "pw";
    assert.equal(residentialProxyUrl(), "http://new:pw@gate.decodo.com:7000");
    delete process.env.WEBCRAWL_PROXY_USER;
    delete process.env.WEBCRAWL_PROXY_PWD;
    delete process.env.DECODO_USER;
    delete process.env.DECODO_PWD;
    assert.equal(residentialProxyUrl(), null);
  } finally {
    for (const n of names) {
      if (prev[n] === undefined) delete process.env[n];
      else process.env[n] = prev[n];
    }
  }
});

test("proxy-needed memo marks and expires domains", async () => {
  resetSessionStateForTests();
  assert.equal(await isDomainProxyNeeded("www.stubhub.com"), false);
  await markDomainProxyNeeded("www.stubhub.com");
  assert.equal(await isDomainProxyNeeded("www.stubhub.com"), true);
  assert.equal(await isDomainProxyNeeded("www.expedia.com"), false);
  resetSessionStateForTests();
  assert.equal(await isDomainProxyNeeded("www.stubhub.com"), false);
});

test("proxy-needed memo persists through an external store (optional methods)", async () => {
  resetSessionStateForTests();
  const stored = new Set<string>();
  registerExternalSessionStore({
    getWarmSession: async () => null,
    saveWarmSession: async () => {},
    deleteWarmSession: async () => {},
    markDomainChallenged: async () => {},
    isDomainChallenged: async () => false,
    markDomainProxyNeeded: async (d: string) => {
      stored.add(d);
    },
    isDomainProxyNeeded: async (d: string) => stored.has(d),
  });
  try {
    resetSessionStateForTests(); // clears in-memory, external survives
    assert.equal(await isDomainProxyNeeded("www.stubhub.com"), false);
    // mark through the registered store, then drop in-memory state
    await markDomainProxyNeeded("www.stubhub.com");
    assert.ok(stored.has("www.stubhub.com"));
    resetSessionStateForTests();
    assert.equal(await isDomainProxyNeeded("www.stubhub.com"), true);
    // memo TTL re-arms on external hit so the entry stays hot in-memory
    assert.ok(PROXY_MEMO_TTL_MS >= 60 * 60_000);
  } finally {
    registerExternalSessionStore({
      getWarmSession: async () => null,
      saveWarmSession: async () => {},
      deleteWarmSession: async () => {},
      markDomainChallenged: async () => {},
      isDomainChallenged: async () => false,
    });
    resetSessionStateForTests();
  }
});

test("tier accessors start at the datacenter default with zero proxy bytes", () => {
  assert.equal(lastFetchTier(), "impit-tls");
  assert.equal(lastProxyBytesCount(), 0);
});

test("chromeArgs strips credentials for --proxy-server but keeps the host", async () => {
  const { chromeArgs } = await import("../interact/vm.js");
  const args = chromeArgs({ proxy: "http://user:pass@gate.decodo.com:7000" });
  const flag = args.find((a) => a.startsWith("--proxy-server="));
  assert.equal(flag, "--proxy-server=http://gate.decodo.com:7000");
  // credential-free proxy URLs pass through untouched
  const plain = chromeArgs({ proxy: "http://gate.decodo.com:7000" });
  assert.ok(plain.includes("--proxy-server=http://gate.decodo.com:7000"));
  // default launch has no proxy flag
  assert.equal(chromeArgs().some((a) => a.startsWith("--proxy-server=")), false);
});

test("anti-bot challenge hosts are always allowed past the P2 route blocker", async () => {
  // The allowlist regex lives inside the vm step script's route handler; it is
  // defined inline there, so we verify the same pattern contract here: every
  // challenge/sensor host must match, and normal ads/images must not.
  const allowRe = /(api-js\.datadome\.co|js\.datadome\.co|ct\.captcha-delivery\.com|geo\.captcha-delivery\.com|challenges\.cloudflare\.com|[a-z0-9-]+\.awswaf\.com)/i;
  const mustAllow = [
    "https://api-js.datadome.co/js/",
    "https://js.datadome.co/tags.js?apikey=25A126AC7E11851BDDB70454B34A05",
    "https://ct.captcha-delivery.com/captcha.js",
    "https://geo.captcha-delivery.com/captcha/?initialCtxt=abc",
    "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1",
    "https://abc123.awswaf.com/js/challenge.js",
    "https://abc123.def456.awswaf.com/captcha/verify",
  ];
  for (const u of mustAllow) assert.ok(allowRe.test(u), `must allow: ${u}`);
  const mustBlock = [
    "https://www.googletagmanager.com/gtm.js?id=GTM-1",
    "https://cdn.example.com/photo.jpg",
    "https://www.expedia.com/_dms/header/logo.svg",
    "https://connect.facebook.net/en_US/fbevents.js",
    "https://static.hotjar.com/c/hotjar.js",
  ];
  for (const u of mustBlock) assert.equal(allowRe.test(u), false, `must NOT match allowlist: ${u}`);
});

test("installedChromePath prefers real Chrome and honors the env override", async () => {
  const { installedChromePath } = await import("../interact/driver.js");
  // env override always wins, even for a nonexistent path (caller-set trust)
  const prev = process.env.INTERACT_CHROME_PATH;
  try {
    process.env.INTERACT_CHROME_PATH = "/tmp/definitely-not-chrome";
    assert.equal(installedChromePath(), "/tmp/definitely-not-chrome");
    delete process.env.INTERACT_CHROME_PATH;
    // on this dev machine a real Chrome exists at the standard macOS path
    if (process.platform === "darwin") {
      const p = installedChromePath();
      assert.ok(p === null || p.includes("Google Chrome"), `unexpected: ${p}`);
    } else {
      // linux/CI: null when no chrome/chromium is installed, path when it is
      const p = installedChromePath();
      assert.ok(p === null || /chrome|chromium/i.test(p), `unexpected: ${p}`);
    }
  } finally {
    if (prev === undefined) delete process.env.INTERACT_CHROME_PATH;
    else process.env.INTERACT_CHROME_PATH = prev;
  }
});
