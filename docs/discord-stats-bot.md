# Discord Stats Bot

This is just a tiny example bot so we can hit `/api/stats` and dump something useful into Discord without dragging the whole admin panel into it.

The bot code is here:

- `examples/discord_stats_bot.py`

It supports either:

- `WON_STATS_TOKEN` using `Authorization: Bearer ...`
- Cloudflare Access service-token headers using:
  - `CF_ACCESS_CLIENT_ID`
  - `CF_ACCESS_CLIENT_SECRET`

## What it does

Right now it gives a simple slash command:

```text
/wonstatus
```

That returns:

- how many players are online
- how many live games there are
- who is in-game vs still in lobby
- what rooms are open
- a quick live games list
- rough peer/game traffic totals

So basically, enough to answer "is anyone on?" and "are they actually playing or just sitting in lobby?"

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-discord-bot.txt
```

## Env vars

```bash
export DISCORD_BOT_TOKEN="your-discord-bot-token"
export WON_STATS_URL="https://stats.homeworld.kerrbell.dev/api/stats"

# optional if your stats endpoint still expects the app token
export WON_STATS_TOKEN="your-stats-token"

# optional if the hostname is protected by Cloudflare Access
export CF_ACCESS_CLIENT_ID="your-access-client-id"
export CF_ACCESS_CLIENT_SECRET="your-access-client-secret"

# optional, but handy while testing slash commands in one server
export WON_STATUS_GUILD_ID="123456789012345678"
```

## Run it

```bash
python examples/discord_stats_bot.py
```

## Notes

- The `game` vs `lobby` state comes from the server's `/api/stats` inference, not from some magic perfect in-game flag. In practice it is still useful.
- If your Cloudflare side is already injecting the backend auth header, you can leave `WON_STATS_TOKEN` unset.
- This is meant to be a dead simple example, not a giant bot framework.

## Example output

Something like this:

```text
Homeworld Server Status
2 players online, 1 live game

Counts
Rooms: 2
Games: 1
Reconnects: 1
IPs: 2

Traffic
Peer msgs: 9
Peer bytes: 665
Game objs: 1
Obj bytes: 185

Players
In game: Bravo
In lobby: Alpha

Rooms
Default :15100 | 1 players | 0 games
Fleet Battle :15102 | 1 players | 1 games

Live Games
Bravo in Fleet Battle | 185 bytes
```
