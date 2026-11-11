# Mobile alerting: ntfy.sh and Telegram

(Shared pattern with the deal-watch skill — the same setup works for ticket alerts.)

## ntfy.sh (default — free, no signup)

ntfy.sh is an open-source push-notification relay. A "topic" is a pub/sub channel; publishing is one HTTP POST, subscribing is opening the topic in the app.

**One-time setup for the user:**

1. Install the ntfy app ([iOS](https://apps.apple.com/us/app/ntfy/id1625396344) / [Android](https://play.google.com/store/apps/details?id=io.heckel.ntfy)) or use the web UI at <https://ntfy.sh>.
2. Pick a **long random topic name** — e.g. `alex-ticket-watch-k4m9wqz2` (the topic name is the only access control on the public server; a guessable name means anyone can send/read your alerts). Use ≥20 chars of randomness.
3. Subscribe to that topic in the app.

**Sending a ticket alert (from your monitor script):**

```bash
curl -d "Cubs tickets just hit $85 all-in (was $120) — 2 seats in Section 209" \
     -H "Title: Ticket price drop" \
     -H "Tags: ticket" \
     -H "Priority: high" \
     -H "Click: https://www.stubhub.com/chicago-cubs-tickets/venue/8660/" \
     ntfy.sh/my-long-random-topic
```

Useful headers: `Title`, `Priority` (min/low/default/high/urgent), `Tags` (emoji shortcuts), `Click` (URL opened when the notification is tapped — always set it to the event page so the user can act immediately).

Self-hosting: `docker run -p 80:80 binwiederhier/ntfy serve` if the user prefers not to use the public server; the app works the same.

## Telegram bot (alternative)

```bash
# one-time: message @BotFather → /newbot → get <BOT_TOKEN>; message the bot once, then:
curl "https://api.telegram.org/bot<BOT_TOKEN>/getUpdates"   # find chat_id
curl "https://api.telegram.org/bot<BOT_TOKEN>/sendMessage" \
     -d chat_id=<CHAT_ID> \
     -d text="Cubs tickets hit $85 all-in — https://www.stubhub.com/..."
```

Store `BOT_TOKEN`/`CHAT_ID` in env vars, never in the repo.

## Scheduling the re-check loop

Cron (every 30 min during on-sales and the hours before an event):

```cron
*/30 * * * * cd /path/to/monitor && ./check.sh >> watch.log 2>&1
```

Keep poll intervals ≥15 min per event page — ticketing sites are aggressively protected and faster polling risks blocks (and is unnecessary; prices move on minute-scales, not second-scales).

## Alert deduping (avoid notification spam)

- Alert only when a trigger condition **first** becomes true (price crosses target, sold-out → available), or on a further ≥5% price drop.
- Record `lastAlertedPrice` in state; suppress repeats until the price moves meaningfully again.
- A price that stays under target is NOT a new alert every cycle — one alert, then silence unless it drops further.
