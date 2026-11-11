# Mobile alerting: ntfy.sh and Telegram

## ntfy.sh (default — free, no signup)

ntfy.sh is an open-source push-notification relay. A "topic" is a pub/sub channel; publishing is one HTTP POST, subscribing is opening the topic in the app.

**One-time setup for the user:**

1. Install the ntfy app ([iOS](https://apps.apple.com/us/app/ntfy/id1625396344) / [Android](https://play.google.com/store/apps/details?id=io.heckel.ntfy)) or use the web UI at <https://ntfy.sh>.
2. Pick a **long random topic name** — e.g. `ajain-webcrawl-deals-x7k2mqp9` (the topic name is the only access control on the public server; a guessable name means anyone can send/read your alerts). Use ≥20 chars of randomness.
3. Subscribe to that topic in the app.

**Sending an alert (from your monitor script):**

```bash
curl -d "Sony WH-1000XM5 hit $229 (target $248) — https://www.amazon.com/dp/XXXX" \
     -H "Title: Deal alert" \
     -H "Tags: money" \
     -H "Priority: high" \
     -H "Click: https://www.amazon.com/dp/XXXX" \
     ntfy.sh/my-long-random-topic
```

Useful headers: `Title`, `Priority` (min/low/default/high/urgent), `Tags` (emoji shortcuts: money, package, bell), `Click` (URL opened when the notification is tapped — always set it to the product/event page).

Self-hosting: `docker run -p 80:80 binwiederhier/ntfy serve` if the user prefers not to use the public server; the app works the same.

## Telegram bot (alternative)

```bash
# one-time: message @BotFather → /newbot → get <BOT_TOKEN>; message the bot once, then:
curl "https://api.telegram.org/bot<BOT_TOKEN>/getUpdates"   # find chat_id
curl "https://api.telegram.org/bot<BOT_TOKEN>/sendMessage" \
     -d chat_id=<CHAT_ID> \
     -d text="Deal alert: Sony WH-1000XM5 hit $229 — https://www.amazon.com/dp/XXXX"
```

Store `BOT_TOKEN`/`CHAT_ID` in env vars, never in the repo.

## Scheduling the re-check loop

Cron (every 30 min during Black Friday week):

```cron
*/30 * * * * cd /path/to/monitor && ./check.sh >> watch.log 2>&1
```

Or launchd (macOS) / systemd timer (Linux) / an agent-session scheduler if the monitor runs inside a coding agent. Keep state in `state.json` next to the script.

## Alert deduping (avoid notification spam)

- Alert only when a trigger condition **first** becomes true, or on a further ≥5% price drop while already under target.
- Record `lastAlertedPrice` in state; suppress repeats until the price moves meaningfully again.
- One notification per item per check-cycle; batch multiple simultaneous hits into one ntfy message when >3 fire at once.
