# Real-estate listing parsers

## Built-in extractor (zero-key)

```bash
npx webcrawl search "3 bedroom house in marrickville" -c real-estate --sub buy
```

The built-in real-estate target returns normalized rows: price, address, bedrooms, bathrooms, parking, property type, suburb, portal, image, link — no selectors to maintain. `--sub buy|rent|sold` selects the listing class.

## Price-string parsing

Portals use messy price strings. Parse defensively:

| Portal string | Meaning | Store as |
|---|---|---|
| `$1,250,000 - $1,395,000` | guide range | `priceMin=1250000, priceMax=1395000, priceType=guide` |
| `Contact agent` / `Contact` | no advertised price | `price=null, priceType=contact-agent` — never guess |
| `Auction` | auction listing (no fixed price) | `priceType=auction` |
| `$650 / wk` | rental | `price=650, period=week` |
| `Offers over $1.2m` | threshold | `priceMin=1200000, priceType=offers-over` |
| `Sold $1,450,000` (sold class) | final sale | `price=1450000, priceType=sold` |

Never coerce "Contact agent" to a number; keep `priceType` so filters don't silently drop those rows.

## Portal pagination patterns

- **realestate.com.au**: list pages at `/buy|rent|sold/in-<suburb>+<state>-<postcode>/`; pagination via `?page=N` (cap ~list page 50). Map first to discover.
- **Domain**: similar path scheme; `/<state>/<suburb>/` style URLs; JS-heavy — the stealth tier may be needed.
- **Zillow (US)**: search pages are JS-rendered and bot-protected; use the anti-bot ladder and expect the proxy tier; prefer state JSON endpoints embedded in the page over DOM scraping.

## State-file schema (suburb watch)

```json
{
  "marrickville-buy": {
    "seen": {
      "4 Smith St": { "price": { "min": 1350000, "type": "guide" }, "beds": 3, "firstSeen": "2026-11-01", "lastSeen": "2026-11-01", "url": "…", "reduced": 0 }
    },
    "lastChecked": "2026-11-01T09:00:00Z"
  }
}
```

Key = `address + portal` (same property across portals is two rows until deduped by address). On each run: new address = **new listing**; lower price on same address = **price reduction**; address gone = **withdrawn/sold**.

## Dedupe across portals

Normalize the address (lowercase, strip unit formatting, strip suburb) and match on normalized address + beds/baths proximity; identical property on two portals merges into one logical listing with both links kept.

## Alerting

Reuse the deal-watch alerting pattern (`references/alerting.md` in `webcrawl-deal-watch`): ntfy.sh push with the listing link in the `Click` header. New matching listings and price reductions are the alert-worthy events.
