# Widened Live-Feed Match Hints Design

Date: 2026-05-01

## Summary

This design widens the `won_oss_server` live-feed contract with two new event
types that sit between raw routed packets and authoritative client-final
uploads:

- `match_checkpoint_hint`
- `match_resolution_hint`

The goal is to make `homeworld_stats` materially better at:

- locking real wins and losses from routed archives
- classifying drops, resigns, and incomplete endings more honestly
- explaining why an inferred result was chosen

The gateway remains a hint publisher, not a second stats engine. The replay
reducer in `homeworld_stats` continues to own winner inference unless a higher
authority source exists.

## Problem

Today the stats pipeline has two extremes:

1. raw `peer_packet` traffic, which is rich but noisy and incomplete for end
   state reconstruction
2. authoritative client-final uploads, which are excellent when present but do
   not exist for many real matches

That leaves a middle gap. The reducer can reconstruct a lot, but it still has
to guess too much during quiet stretches, disconnect-heavy endings, and matches
where the room collapses before a clean final upload arrives.

`won_oss_server` already knows useful room-lifecycle and roster information at
the time the match is happening. We should capture that information as durable
live-feed hints so replays have more anchors than raw packets alone.

## Goals

- Reduce archive matches that end as `No winner locked`.
- Improve classification of drop, resign, and incomplete endings.
- Improve replay/debug visibility for why a result was inferred.
- Keep AI and PvE classification intact.
- Preserve client-final uploads as the top authority.

## Non-Goals

- Do not turn `won_oss_server` into a full gameplay simulator.
- Do not let gateway hints silently override authoritative client-final state.
- Do not remove or replace raw `peer_packet` archiving.
- Do not require synchronized deployment of both repos to keep the live feed
  working. New event types must be forward-compatible.

## Recommended Approach

Keep the current live-feed event contract intact and add two new event types on
top of it:

- `match_checkpoint_hint`: advisory state anchors emitted on change and on a
  heartbeat
- `match_resolution_hint`: terminal-state clues emitted near match collapse

This approach keeps the gateway small, keeps `homeworld_stats` as the single
outcome brain, and still captures the room/runtime knowledge the reducer cannot
reconstruct later from packets alone.

## Current Contract

The live feed already emits:

- `match_started`
- `match_updated`
- `match_finished`
- `match_slot_manifest`
- `match_launch_config`
- `peer_packet`
- `routing_object_upsert`
- `routing_object_delete`
- `player_joined`
- `player_left`

This design extends that contract rather than changing the meaning of existing
events.

## Authority Model

The widened pipeline uses a tiered authority model:

1. client-final uploads and authoritative final stats
2. replay reducer plus gateway terminal hints
3. replay reducer alone
4. legacy routed inference fallback

`match_checkpoint_hint` is advisory only.

`match_resolution_hint` can promote or downgrade replay confidence, but it does
not outrank client-final uploads and does not directly declare official winners
on its own.

## New Event: `match_checkpoint_hint`

### Purpose

Provide periodic and change-driven anchors that capture what the gateway knows
about the live room, player presence, and a narrow set of high-value packet
clues.

### Emission Model

Emit on both:

- meaningful state changes
- heartbeat every 10 to 15 seconds while a match is live

### Triggers

- player joined
- player left
- routing object upsert/delete
- room refresh
- buffered packet-derived hint activity
- heartbeat interval elapsed

### Payload Shape

```json
{
  "event": "match_checkpoint_hint",
  "match_id": "homeworld:15102:1777004990169",
  "room_port": 15102,
  "room_name": "Homeworld Chat",
  "room_path": "/Homeworld",
  "transport_mode": "routed",
  "capture_source": "routed_live_feed",
  "reason": "peer_decode",
  "hint_authority": "advisory",
  "emitted_at": 1777005001.123,
  "started_at": 1777004206.649,
  "participant_count": 6,
  "room_state": {
    "published": false,
    "is_game_room": true,
    "active_game_count": 1,
    "data_object_count": 1,
    "pending_reconnect_count": 0
  },
  "presence": {
    "connected": [
      {
        "client_id": 1,
        "player_name": "&Z&e&r&o|&S&F",
        "player_id": "zero",
        "gameplay_index": 0,
        "player_type": "human"
      }
    ],
    "reconnecting": [],
    "departed_recently": []
  },
  "slot_manifest": {
    "players": []
  },
  "launch_config": {
    "lobby_title": "2v2 no rush",
    "map_name": "Clan Wars (2-6)",
    "map_code": "pkwar6",
    "players": []
  },
  "packet_hints": {
    "alliance_changes": [],
    "player_dropped_masks": [],
    "sync_anchors": [],
    "godsync_anchors": [],
    "scuttle_candidates": [],
    "command_ship_signals": []
  },
  "evidence": [
    "room_refresh",
    "peer_decode:alliance_info",
    "peer_decode:sync"
  ]
}
```

### Semantics

- `reason` is a single coarse trigger for why this checkpoint was emitted.
- `presence` is the gateway's best current room presence picture, not a claim
  about simulated survival.
- `slot_manifest` and `launch_config` are snapshots of the latest known metadata
  for replay convenience.
- `packet_hints` contains only lightweight, stable, cheap-to-decode clues.
- `evidence` is human-readable support text for later replay/debug inspection.

### Lightweight Packet Hints

The gateway should only derive a narrow packet hint set:

- alliance messages
- player dropped masks
- sync frame and checksum anchors
- godsync frame anchors
- limited tactical or self-destruct markers that are stable enough to help
  classify scuttle/command-ship risk

If decoding fails, the gateway still emits the original `peer_packet` event and
simply omits the derived hint.

## New Event: `match_resolution_hint`

### Purpose

Provide terminal-state clues when the gateway observes room collapse patterns
that the replay reducer alone may not classify correctly.

### Emission Model

Emit when the gateway observes one of the following:

- clean `match_finished` transition
- abrupt room collapse
- final disconnect pattern with reconnect holds
- last-known connected roster shrinking to a single surviving side
- packet-derived terminal patterns near the end of the room lifecycle

### Payload Shape

```json
{
  "event": "match_resolution_hint",
  "match_id": "homeworld:15102:1777004990169",
  "room_port": 15102,
  "room_name": "Homeworld Chat",
  "room_path": "/Homeworld",
  "hint_authority": "terminal_support",
  "emitted_at": 1777008923.551,
  "basis": "abrupt_room_collapse",
  "classification": "likely_incomplete",
  "room_state": {
    "published": false,
    "is_game_room": false,
    "pending_reconnect_count": 2
  },
  "presence": {
    "connected_final": [],
    "reconnecting_final": [
      {
        "client_id": 4,
        "player_name": "Volans|SF"
      }
    ]
  },
  "survivor_hint": {
    "surviving_gameplay_indices": [0, 1],
    "surviving_player_names": ["&Z&e&r&o|&S&F", "&Chainster"]
  },
  "packet_hints": {
    "player_dropped_masks": [2],
    "alliance_changes": [],
    "sync_anchors": [],
    "godsync_anchors": []
  },
  "evidence": [
    "match_finished_missing",
    "room_unpublished_with_reconnect_holds",
    "single_connected_team_remained"
  ]
}
```

### Semantics

- `basis` is the primary gateway-observed terminal reason.
- `classification` is a gateway-level terminal suggestion, not an official
  match result.
- `survivor_hint` is optional and only present when the gateway has enough room
  context to suggest a remaining side.
- `evidence` must always explain why the hint exists.

### Allowed `basis` Values

- `clean_finish`
- `abrupt_room_collapse`
- `reconnect_heavy_collapse`
- `final_connected_roster`
- `packet_terminal_pattern`

### Allowed `classification` Values

- `clean_terminal_support`
- `likely_incomplete`
- `likely_disconnect_heavy`
- `survivor_group_remaining`
- `ambiguous_terminal_support`

## Gateway Architecture Changes (`won_oss_server`)

### New Per-Match Hint State

Add a small per-live-match accumulator keyed by room port and tied to the
current `match_id`. This is not a simulator. It stores only:

- `last_checkpoint_emitted_at`
- latest room snapshot summary
- latest launch config snapshot
- latest slot manifest snapshot
- last-known connected and reconnecting roster picture
- buffered lightweight packet hints since the previous checkpoint
- terminal room-collapse context for the next resolution hint

### Emission Strategy

- Change-driven emission happens inline with existing live room events.
- Heartbeat emission runs from existing maintenance or refresh paths, not from a
  dedicated per-match task.
- Checkpoints should be coalesced. If nothing changed, emit a compact heartbeat
  rather than a giant duplicate payload.
- Resolution hints should be emitted once per match collapse edge, with enough
  evidence to be useful later.

### Ownership Boundary

The gateway does **not** compute official winners.

It only publishes:

- room and presence anchors
- buffered packet-derived hints
- terminal room-collapse evidence

This keeps `homeworld_stats` as the single outcome decision-maker for routed
replay.

## Stats Consumption Changes (`homeworld_stats`)

### Ingest

Teach `ingest_live_event` to accept:

- `match_checkpoint_hint`
- `match_resolution_hint`

Unknown fields must be ignored safely. The new events should be archived like
other live-feed events so replays stay reproducible.

### Replay Consumption

`match_checkpoint_hint` should:

- enrich replay snapshots with gateway-seen presence state
- contribute sync and godsync anchors to replay/debug views
- preserve launch/slot context as durable snapshots
- give the reducer better timeline support for who was still present and when

`match_resolution_hint` should:

- promote replay confidence when it agrees with the reducer
- bias disconnect-heavy endings toward incomplete instead of forcing a fake
  clean result
- support better defeat/resign/drop labeling when the room lifecycle provides
  terminal evidence the packet stream lacks

### Outcome Confidence

Add or promote replay confidence labels that make the new support explicit:

- `latched_replay`
- `latched_replay_with_drop_noise`
- `latched_replay_with_gateway_terminal_support`
- `incomplete_with_gateway_terminal_support`
- `unresolved_replay`

These are replay confidence labels, not hard authority replacements.

### Storage Strategy

Do not create a separate hidden state store for gateway hints.

Instead:

- archive the new events in the match event archive
- optionally mirror high-value normalized fields into replay snapshots or
  outcome evidence rows during ingest/replay

This keeps rebuilds deterministic and minimizes drift between raw archives and
derived views.

## Safety And Error Handling

### `won_oss_server`

- Lightweight hint decoding must be best-effort.
- Failure to decode a hint must not block routing or drop the original packet
  event.
- Heartbeat checkpoint emission must be cheap and bounded.
- Hint emission must not stall the routing path.

### `homeworld_stats`

- Gateway hints can never silently overwrite authoritative client-final state.
- Gateway terminal hints may promote or downgrade confidence, not bypass the
  authority stack.
- Unknown hint fields must be ignored for forward compatibility.

## Testing Strategy

### `won_oss_server`

Add tests that verify:

- checkpoint hints emit on change
- checkpoint hints emit on heartbeat
- AI and human slot metadata survives inside checkpoint snapshots
- roster presence appears in checkpoint hints
- packet-derived alliance, drop, and sync clues are included when present
- resolution hints emit on clean finish
- resolution hints emit on abrupt collapse
- resolution hints include evidence and classification

### `homeworld_stats`

Add tests that verify:

- the new hint events ingest and archive cleanly
- replay snapshots include gateway presence and checkpoint anchors
- gateway resolution hints can improve replay confidence
- disconnect-heavy endings are classified more honestly when terminal hints are
  present
- authoritative client-final state still wins over gateway hints

## Rollout Plan

1. Extend `won_oss_server` to emit the new event types.
2. Verify the live feed still works with older `homeworld_stats` consumers that
   simply ignore unknown events.
3. Extend `homeworld_stats` to ingest and use the new hints.
4. Replay real archives to compare:
   - `No winner locked` counts
   - incomplete/drop classification rates
   - replay explanation quality

## Success Criteria

- Fewer archive matches end as `No winner locked`.
- Fewer false clean results are reported for disconnect-heavy endings.
- Replay/detail surfaces can explain more clearly why a result was inferred.
- AI/PvE classification does not regress.
- Client-final uploads remain the top authority.

## Open Decisions Resolved By This Design

- Use both periodic checkpoints and terminal resolution hints.
- Use change-driven plus heartbeat emission.
- Keep gateway hints tiered, not fully authoritative.
- Keep packet intelligence hybrid and lightweight in the gateway.
- Optimize for all three outcomes: fewer unresolved matches, better terminal
  classification, and better replay/debug visibility, with win/loss accuracy as
  the tie-breaker.
