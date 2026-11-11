# @webcrawl/curl-impersonate

Zero-dependency curl-impersonate fetch for Node.js.

One GET hop through a pinned [lexiforest/curl-impersonate](https://github.com/lexiforest/curl-impersonate) binary with a **real-Chrome TLS/HTTP2 fingerprint** — the layer anti-bot WAFs (AWS WAF, Cloudflare Bot Management) judge before any HTML is served. Verified live against AWS-WAF-protected sites where Chrome-136-era fingerprints (`impit`, plain Node `fetch`) get 403/429.

## Why

Anti-bot WAFs fingerprint the TLS ClientHello (JA3/JA4) and HTTP/2 SETTINGS frame — Node's TLS stack matches none of them. curl-impersonate patches BoringSSL (Chrome's TLS library) so the handshake is byte-for-byte a real Chrome. We validated this against live AWS WAF targets: `chrome150` passes where `chrome136` is blocked.

## Usage

```ts
import { impersonateFetch } from "@webcrawl/curl-impersonate";

const res = await impersonateFetch("https://www.stubhub.com/concert-tickets/", {
  profile: "chrome150", // default
  timeoutMs: 12_000,
});
// { status: 200, headers, contentType: "text/html", body: Uint8Array }
```

Redirects are **manual** (not followed): one call = one hop, so you keep SSRF-guarding every redirect the way the webcrawl engine does.

### Profiles

| Profile | Notes |
|---|---|
| `chrome150` | default — newest profile verified to pass both stubhub + expedia AWS WAF |
| `chrome142` | older fallback |
| `chrome151_macos`, `chrome152` | newer presets from the binary |

Headers (`User-Agent`, `sec-ch-ua`, `Sec-Fetch-*`, `Accept-Language`, `Priority`) are generated per-profile so they stay fingerprint-coherent — a Chrome 150 handshake never carries Chrome 136 client hints.

## Binary acquisition (zero deps)

The binary is downloaded on first use into `~/.cache/webcrawl-impersonate/v2.3.2/<platform>/` (or `os.tmpdir()` when HOME isn't writable — serverless):

1. `WEBCRAWL_IMPERSONATE_BIN=/path/to/curl-impersonate` env override — checked first, skips download.
2. Cached binary — no network.
3. Pinned GitHub release asset (`lexiforest/curl-impersonate` v2.3.2), sha256-verified per asset before extraction. Downloads fail soft: the tier reports unavailable and callers fall back.

macOS (arm64/x64), Linux (glibc/musl, arm64/x64). `ensureImpersonate()` pre-warms for CLI/MCP startup; `isImpersonateAvailable()` probes without network.

## License

MIT. The vendored binary is [curl-impersonate](https://github.com/lexiforest/curl-impersonate) (curl + BoringSSL under their own licenses).
