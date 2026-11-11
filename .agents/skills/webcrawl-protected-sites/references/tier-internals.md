# Anti-bot tier internals

## The ladder (in order)

1. **`impit-tls`** — default. `impit` native TLS-impersonated fetch: real-browser TLS handshake + HTTP/2, zero keys. Handles most non-protected sites and light fingerprinting.
2. **`impersonate`** — curl-impersonate with a pinned Chrome fingerprint (JA3/JA4 TLS + HTTP/2 SETTINGS/frame ordering + header order). Wins most Cloudflare and AWS WAF interstitials without a proxy.
3. **`proxy-impersonate`** — same fingerprint, through your residential proxy. Required when the block is **IP-reputation based** (datacenter egress denied). Enabled by env vars; skipped entirely when unset.
4. **Stealth browser** — real Chrome/Chromium via Playwright/sandbox: full JS challenge solving (DataDome, Cloudflare Turnstile, AWS WAF JS challenges). Warm sessions (solved cookies) are cached per domain and reused by lower tiers — the browser pays the cost once, lightweight tiers ride its cookies afterwards.
5. **Render provider / local Chrome (`tier: "render"` or `tier: "browser"`)** — not part of the anti-bot ladder: it handles pages the ladder *passes* but cannot render (JS SPA shells where listings only appear client-side). Local mode dumps the hydrated DOM through installed Chrome. `WEBCRAWL_RENDER_URL` (+ optional `WEBCRAWL_RENDER_KEY`) enables a hosted provider (the cloud tier sets it server-side). Any provider speaking the reader text format (`Title:` / `URL Source:` / `Markdown Content:`) works. The engine detects the shell (`needsBrowserEscalation`), memoizes the domain render-needed (1h TTL), and routes later scrapes provider- or Chrome-first.

## Proxy configuration (any vendor)

```bash
# Full URL form
export WEBCRAWL_PROXY_URL="http://user:pass@gateway.example.com:8080"

# Split form (credentials + gateway)
export WEBCRAWL_PROXY_USER="user"
export WEBCRAWL_PROXY_PWD="pass"
export WEBCRAWL_PROXY_HOST="residential.example.com"   # default gate.decodo.com
export WEBCRAWL_PROXY_PORT="7000"
```

- Works with any HTTP(S) residential proxy: Decodo, Bright Data, Oxylabs, IPRoyal, self-hosted gateways.
- `DECODO_*` env vars are honored as a legacy fallback.
- Proxy cost visibility: the result reports `proxyBytes` — the billable traffic through the gateway.

## Domain memoization

- When a domain is found proxy-needed (challenge at direct tiers), it's marked in the session store with a **1h TTL**.
- Later requests to that domain **skip straight to the proxy tier** — first hit pays the ladder cost, subsequent hits are fast.
- Session stores are in-memory by default; the engine also supports an external store (e.g. Postgres) for multi-process deployments via `registerExternalSessionStore`.

## Reading challenge responses

- **AWS WAF**: HTTP 202 with a JS-challenge shell; the `impersonate` tier usually clears it.
- **DataDome**: 200 with an interstitial or a ~40-char challenge stub; typically IP-blocked → needs proxy tier, hardest cases need the stealth browser.
- **Cloudflare**: 403/503 "Just a moment" → `impersonate` usually wins; Turnstile challenges need the browser tier.
- **Status 200 + no content ≠ success.** Always validate the body looks like real content (title matches, substantive text) before reporting success.

## Diagnosis workflow

1. Scrape → check `tier` and body quality.
2. Challenge shell → set proxy env vars → scrape → check `tier: "proxy-impersonate"` and `proxyBytes > 0`.
3. Still challenged → `npx webcrawl doctor` (Chrome/stealth readiness) → stealth browser tier.
4. Bot check passes but page is a JS shell (real title, no listings) → local Chrome dump-dom (`webcrawl doctor`), then a render provider (`WEBCRAWL_RENDER_URL`) or `--mode cloud`. Empty/blocked pages return `success: false`.
5. All tiers exhausted → accept the block.
