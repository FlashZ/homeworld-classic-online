# Live Feed Hints Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add gateway-side checkpoint and terminal resolution hints, then teach `homeworld_stats` replay/outcome code to use them for stronger win/loss and incomplete-match inference.

**Architecture:** Extend `won_oss_server` with two additive live-feed events, `match_checkpoint_hint` and `match_resolution_hint`, backed by a small per-match hint accumulator. Extend `homeworld_stats` ingest and replay code to archive the new events, fold checkpoint hints into replay snapshots, and let terminal hints promote or downgrade replay confidence without outranking client-final uploads.

**Tech Stack:** Python 3.12, asyncio gateway live feed, pytest, sqlite-backed stats service, existing replay reducer in `hwstats.sim`.

---

## File Map

- Modify: `H:/Code_Projects/won_oss_server/gateway/titan_service.py`
  - Add per-match hint state, heartbeat/change-driven checkpoint emission, lightweight packet hint extraction, and resolution hint emission.
- Modify: `H:/Code_Projects/won_oss_server/tests/test_stats_api.py`
  - Add gateway tests for checkpoint and resolution hint events.
- Modify: `H:/Code_Projects/homeworld_stats/hwstats/service.py`
  - Ingest new hint events, include them in replay preparation, and expose stronger confidence/evidence handling.
- Modify: `H:/Code_Projects/homeworld_stats/hwstats/sim/models.py`
  - Add replay structures for gateway checkpoint and terminal hint support.
- Modify: `H:/Code_Projects/homeworld_stats/hwstats/sim/reducer.py`
  - Feed checkpoint and terminal hints into state/replay flow.
- Modify: `H:/Code_Projects/homeworld_stats/hwstats/sim/evidence.py`
  - Add confidence labels and payload fields for gateway-supported replay outcomes.
- Modify: `H:/Code_Projects/homeworld_stats/tests/test_hwstats_service.py`
  - Add ingest/replay tests for new hint events.
- Modify: `H:/Code_Projects/homeworld_stats/tests/test_sim_service_replay.py`
  - Add replay surface tests for checkpoint snapshots and terminal hint confidence promotion.

---

### Task 1: Add Gateway Checkpoint Hint Events

**Files:**
- Modify: `H:/Code_Projects/won_oss_server/tests/test_stats_api.py`
- Modify: `H:/Code_Projects/won_oss_server/gateway/titan_service.py`

- [ ] **Step 1: Write the failing gateway checkpoint tests**

Add tests near the existing live-feed contract tests in `H:/Code_Projects/won_oss_server/tests/test_stats_api.py`:

```python
def test_gateway_emits_checkpoint_hint_with_presence_and_launch_context() -> None:
    gateway = titan_binary_gateway.BinaryGatewayServer(
        "127.0.0.1",
        9100,
        public_host="homeworld.kerrbell.dev",
        public_port=15101,
        routing_port=15100,
        valid_versions=["0110"],
    )
    routing_server = _LiveFeedRoutingServer()
    gateway.routing_manager = _LiveFeedRoutingManager(routing_server)
    gateway.queue_match_launch_config(
        room_port=15102,
        lobby_title="2v2 no rush",
        map_name="Clan Wars (2-6)",
        map_code="pkwar6",
        settings={"room_flags": 7, "allied_victory": True},
        captain_identity={"player_id": "zero", "player_name": "&Z&e&r&o|&S&F"},
        players=[
            {"player_id": "zero", "player_name": "&Z&e&r&o|&S&F", "gameplay_index": 0, "player_type": "human"},
            {"player_id": "cpu-1", "player_name": "CPU Alpha", "gameplay_index": 3, "player_type": "ai", "is_ai": True, "difficulty": "Hard"},
        ],
        transport_mode="routed",
    )
    queue = gateway.subscribe_live_feed()
    gateway.record_live_player_event(
        "player_joined",
        room_port=15102,
        player_id=1,
        player_name="&Z&e&r&o|&S&F",
        player_ip="1.1.1.1",
    )

    events: list[dict[str, object]] = []
    while True:
        try:
            events.append(queue.get_nowait())
        except asyncio.QueueEmpty:
            break

    checkpoint = next(event for event in events if event["event"] == "match_checkpoint_hint")
    assert checkpoint["hint_authority"] == "advisory"
    assert checkpoint["reason"] in {"player_joined", "room_refresh", "heartbeat"}
    assert checkpoint["launch_config"]["lobby_title"] == "2v2 no rush"
    assert checkpoint["launch_config"]["players"][1]["ai_difficulty"] == "Hard"
    assert checkpoint["presence"]["connected"][0]["player_name"] == "&Z&e&r&o|&S&F"


def test_gateway_emits_checkpoint_hint_with_packet_hints_for_alliance_drop_and_sync() -> None:
    gateway = titan_binary_gateway.BinaryGatewayServer(
        "127.0.0.1",
        9100,
        public_host="homeworld.kerrbell.dev",
        public_port=15101,
        routing_port=15100,
        valid_versions=["0110"],
    )
    routing_server = _LiveFeedRoutingServer()
    gateway.routing_manager = _LiveFeedRoutingManager(routing_server)
    queue = gateway.subscribe_live_feed()
    gateway.record_live_player_event("player_joined", room_port=15102, player_id=1, player_name="&Z&e&r&o|&S&F", player_ip="1.1.1.1")
    gateway.record_live_player_event("player_joined", room_port=15102, player_id=2, player_name="Volans|SF", player_ip="2.2.2.2")
    alliance_body = struct.pack("<IHH", 1, 0, 1)
    dropped_mask = 1 << 1
    dropped_verify = dropped_mask ^ 0xFE389BCA
    sync_body = struct.pack("<IH14x", 3104, 77)
    payload = b"\x03\xe2\x60" + _build_hw_packet(0xCCCC, 2103, [(13, alliance_body), (17, struct.pack("<II", dropped_mask, dropped_verify))], sender=0)
    sync_payload = b"\x03\xe2\x60" + _build_hw_packet(0x5555, 2104, [(16, sync_body)], sender=0)
    gateway.record_live_peer_packet("peer_packet", room_port=15102, sender_client_id=1, sender_name="&Z&e&r&o|&S&F", recipient_client_ids=[2], recipient_count=1, payload=payload, packet_kind="SendDataBroadcast")
    gateway.record_live_peer_packet("peer_packet", room_port=15102, sender_client_id=1, sender_name="&Z&e&r&o|&S&F", recipient_client_ids=[2], recipient_count=1, payload=sync_payload, packet_kind="SendDataBroadcast")

    events: list[dict[str, object]] = []
    while True:
        try:
            events.append(queue.get_nowait())
        except asyncio.QueueEmpty:
            break

    checkpoint = next(event for event in reversed(events) if event["event"] == "match_checkpoint_hint")
    assert checkpoint["packet_hints"]["alliance_changes"]
    assert checkpoint["packet_hints"]["player_dropped_masks"] == [2]
    assert checkpoint["packet_hints"]["sync_anchors"][0]["randcheck"] == 77
```

- [ ] **Step 2: Run the gateway checkpoint tests to verify they fail**

Run:

```powershell
& 'C:\Users\twist\AppData\Local\Programs\Python\Python312\python.exe' -m pytest -q tests\test_stats_api.py -k "checkpoint_hint"
```

Expected: FAIL because `match_checkpoint_hint` is not emitted yet.

- [ ] **Step 3: Implement minimal checkpoint hint support in the gateway**

Add small helper structures and emission calls in `H:/Code_Projects/won_oss_server/gateway/titan_service.py`:

```python
def _ensure_match_hint_state(self, room_port: int, match_id: str) -> dict[str, object]:
    state = self._match_hint_state.setdefault(
        int(room_port),
        {
            "match_id": str(match_id),
            "last_checkpoint_emitted_at": 0.0,
            "slot_manifest": {},
            "launch_config": {},
            "presence": {"connected": [], "reconnecting": [], "departed_recently": []},
            "packet_hints": {
                "alliance_changes": [],
                "player_dropped_masks": [],
                "sync_anchors": [],
                "godsync_anchors": [],
                "scuttle_candidates": [],
                "command_ship_signals": [],
            },
        },
    )
    state["match_id"] = str(match_id)
    return state


def _emit_match_checkpoint_hint(self, room_port: int, *, reason: str, snapshot: Optional[Dict[str, object]] = None) -> Dict[str, object] | None:
    state = self._live_matches.get(int(room_port))
    if state is None:
        return None
    match_id = str(state["match_id"])
    hint_state = self._ensure_match_hint_state(int(room_port), match_id)
    room_snapshot = dict(snapshot or self._routing_room_snapshot(int(room_port)))
    payload = {
        "match_id": match_id,
        "room_port": int(room_port),
        "room_name": self._preferred_room_title(room_snapshot, fallback=state.get("room_name")),
        "room_path": str(room_snapshot.get("room_path") or state.get("room_path") or ""),
        "transport_mode": "routed",
        "capture_source": "routed_live_feed",
        "reason": str(reason or "heartbeat"),
        "hint_authority": "advisory",
        "started_at": float(state.get("started_at") or 0.0),
        "participant_count": self._room_participant_count(room_snapshot),
        "room_state": {
            "published": bool(room_snapshot.get("published", False)),
            "is_game_room": bool(room_snapshot.get("is_game_room", False)),
            "active_game_count": int(room_snapshot.get("active_game_count") or 0),
            "data_object_count": int(room_snapshot.get("data_object_count") or 0),
            "pending_reconnect_count": int(room_snapshot.get("pending_reconnect_count") or 0),
        },
        "presence": dict(hint_state.get("presence") or {}),
        "slot_manifest": dict(hint_state.get("slot_manifest") or {}),
        "launch_config": dict(hint_state.get("launch_config") or {}),
        "packet_hints": self._drain_match_packet_hints(int(room_port)),
        "evidence": [str(reason or "heartbeat")],
    }
    hint_state["last_checkpoint_emitted_at"] = time.time()
    return self._publish_live_feed_event("match_checkpoint_hint", payload)
```

Also update:

- `__init__` to add `self._match_hint_state: Dict[int, Dict[str, object]] = {}`
- `_emit_pending_match_slot_manifest` and `_emit_pending_match_launch_config` to mirror latest snapshots into hint state
- `record_live_player_event` to update `presence.connected` and emit a checkpoint hint
- `record_live_peer_packet` to buffer lightweight packet hints and emit a checkpoint hint when non-empty

- [ ] **Step 4: Run the checkpoint tests again**

Run:

```powershell
& 'C:\Users\twist\AppData\Local\Programs\Python\Python312\python.exe' -m pytest -q tests\test_stats_api.py -k "checkpoint_hint"
```

Expected: PASS.

- [ ] **Step 5: Commit the gateway checkpoint slice**

```powershell
git -c safe.directory=H:/Code_Projects/won_oss_server -C 'H:\Code_Projects\won_oss_server' add gateway/titan_service.py tests/test_stats_api.py
git -c safe.directory=H:/Code_Projects/won_oss_server -C 'H:\Code_Projects\won_oss_server' commit -m "feat: add live feed checkpoint hints"
```

### Task 2: Add Gateway Resolution Hint Events

**Files:**
- Modify: `H:/Code_Projects/won_oss_server/tests/test_stats_api.py`
- Modify: `H:/Code_Projects/won_oss_server/gateway/titan_service.py`

- [ ] **Step 1: Write the failing resolution hint tests**

Add tests in `H:/Code_Projects/won_oss_server/tests/test_stats_api.py`:

```python
def test_gateway_emits_resolution_hint_for_clean_finish() -> None:
    gateway = titan_binary_gateway.BinaryGatewayServer(
        "127.0.0.1",
        9100,
        public_host="homeworld.kerrbell.dev",
        public_port=15101,
        routing_port=15100,
        valid_versions=["0110"],
    )
    routing_server = _LiveFeedRoutingServer()
    gateway.routing_manager = _LiveFeedRoutingManager(routing_server)
    queue = gateway.subscribe_live_feed()
    gateway.record_live_player_event("player_joined", room_port=15102, player_id=1, player_name="Alpha", player_ip="1.1.1.1")
    gateway.record_live_player_event("player_joined", room_port=15102, player_id=2, player_name="Bravo", player_ip="2.2.2.2")
    routing_server.snapshot["is_game_room"] = False
    routing_server.snapshot["published"] = False
    gateway.record_live_room_refresh(15102)

    events: list[dict[str, object]] = []
    while True:
        try:
            events.append(queue.get_nowait())
        except asyncio.QueueEmpty:
            break

    resolution = next(event for event in events if event["event"] == "match_resolution_hint")
    assert resolution["hint_authority"] == "terminal_support"
    assert resolution["basis"] in {"clean_finish", "final_connected_roster"}
    assert resolution["classification"] in {"clean_terminal_support", "survivor_group_remaining"}
    assert resolution["evidence"]


def test_gateway_emits_resolution_hint_for_reconnect_heavy_collapse() -> None:
    gateway = titan_binary_gateway.BinaryGatewayServer(
        "127.0.0.1",
        9100,
        public_host="homeworld.kerrbell.dev",
        public_port=15101,
        routing_port=15100,
        valid_versions=["0110"],
    )
    routing_server = _LiveFeedRoutingServer()
    gateway.routing_manager = _LiveFeedRoutingManager(routing_server)
    queue = gateway.subscribe_live_feed()
    gateway.record_live_player_event("player_joined", room_port=15102, player_id=1, player_name="Alpha", player_ip="1.1.1.1")
    routing_server.snapshot["pending_reconnect_count"] = 2
    routing_server.snapshot["pending_reconnects"] = [{"client_id": 9, "client_name": "Ghost", "seconds_remaining": 42}]
    routing_server.snapshot["is_game_room"] = False
    routing_server.snapshot["published"] = False
    gateway.record_live_room_refresh(15102)

    events: list[dict[str, object]] = []
    while True:
        try:
            events.append(queue.get_nowait())
        except asyncio.QueueEmpty:
            break

    resolution = next(event for event in events if event["event"] == "match_resolution_hint")
    assert resolution["basis"] in {"abrupt_room_collapse", "reconnect_heavy_collapse"}
    assert resolution["classification"] in {"likely_incomplete", "likely_disconnect_heavy"}
    assert resolution["room_state"]["pending_reconnect_count"] == 2
```

- [ ] **Step 2: Run the resolution tests to verify they fail**

Run:

```powershell
& 'C:\Users\twist\AppData\Local\Programs\Python\Python312\python.exe' -m pytest -q tests\test_stats_api.py -k "resolution_hint"
```

Expected: FAIL because `match_resolution_hint` does not exist yet.

- [ ] **Step 3: Implement minimal resolution hint support**

Add helpers in `H:/Code_Projects/won_oss_server/gateway/titan_service.py`:

```python
def _emit_match_resolution_hint(
    self,
    room_port: int,
    *,
    basis: str,
    classification: str,
    snapshot: Optional[Dict[str, object]] = None,
    survivor_hint: Optional[Dict[str, object]] = None,
    evidence: Optional[list[str]] = None,
) -> Dict[str, object] | None:
    state = self._live_matches.get(int(room_port))
    if state is None:
        return None
    hint_state = self._ensure_match_hint_state(int(room_port), str(state["match_id"]))
    room_snapshot = dict(snapshot or self._routing_room_snapshot(int(room_port)))
    payload = {
        "match_id": str(state["match_id"]),
        "room_port": int(room_port),
        "room_name": self._preferred_room_title(room_snapshot, fallback=state.get("room_name")),
        "room_path": str(room_snapshot.get("room_path") or state.get("room_path") or ""),
        "hint_authority": "terminal_support",
        "basis": str(basis),
        "classification": str(classification),
        "room_state": {
            "published": bool(room_snapshot.get("published", False)),
            "is_game_room": bool(room_snapshot.get("is_game_room", False)),
            "pending_reconnect_count": int(room_snapshot.get("pending_reconnect_count") or 0),
        },
        "presence": {
            "connected_final": list(dict(hint_state.get("presence") or {}).get("connected") or []),
            "reconnecting_final": list(dict(hint_state.get("presence") or {}).get("reconnecting") or []),
        },
        "survivor_hint": dict(survivor_hint or {}),
        "packet_hints": self._drain_match_packet_hints(int(room_port), clear=False),
        "evidence": list(evidence or []),
    }
    return self._publish_live_feed_event("match_resolution_hint", payload)
```

Call it from `_sync_live_match_state` before removing the live match state when a room transitions out of game mode.

- [ ] **Step 4: Run the resolution tests again**

Run:

```powershell
& 'C:\Users\twist\AppData\Local\Programs\Python\Python312\python.exe' -m pytest -q tests\test_stats_api.py -k "resolution_hint"
```

Expected: PASS.

- [ ] **Step 5: Commit the gateway resolution slice**

```powershell
git -c safe.directory=H:/Code_Projects/won_oss_server -C 'H:\Code_Projects\won_oss_server' add gateway/titan_service.py tests/test_stats_api.py
git -c safe.directory=H:/Code_Projects/won_oss_server -C 'H:\Code_Projects\won_oss_server' commit -m "feat: add live feed resolution hints"
```

### Task 3: Ingest And Archive New Hint Events In `homeworld_stats`

**Files:**
- Modify: `H:/Code_Projects/homeworld_stats/tests/test_hwstats_service.py`
- Modify: `H:/Code_Projects/homeworld_stats/hwstats/service.py`

- [ ] **Step 1: Write the failing ingest test**

Add a service test in `H:/Code_Projects/homeworld_stats/tests/test_hwstats_service.py`:

```python
def test_service_ingests_checkpoint_and_resolution_hint_events(tmp_path: Path) -> None:
    service = HomeworldStatsService(
        db_path=tmp_path / "homeworld_stats.db",
        data_root=tmp_path / "data",
    )
    match_id = "homeworld:15102:hint-ingest"

    service.ingest_live_event(
        {
            "event": "match_started",
            "product": "homeworld",
            "match_id": match_id,
            "room_port": 15102,
            "room_name": "Hint Test",
            "room_path": "/Homeworld",
            "started_at": 1710000000.0,
            "participant_count": 2,
        }
    )
    service.ingest_live_event(
        {
            "event": "match_checkpoint_hint",
            "product": "homeworld",
            "match_id": match_id,
            "room_port": 15102,
            "room_name": "Hint Test",
            "room_path": "/Homeworld",
            "hint_authority": "advisory",
            "reason": "peer_decode",
            "presence": {"connected": [{"player_name": "Alpha", "gameplay_index": 0}], "reconnecting": [], "departed_recently": []},
            "packet_hints": {"sync_anchors": [{"frame": 2104, "randcheck": 77}], "alliance_changes": [], "player_dropped_masks": []},
        }
    )
    service.ingest_live_event(
        {
            "event": "match_resolution_hint",
            "product": "homeworld",
            "match_id": match_id,
            "room_port": 15102,
            "room_name": "Hint Test",
            "room_path": "/Homeworld",
            "hint_authority": "terminal_support",
            "basis": "reconnect_heavy_collapse",
            "classification": "likely_incomplete",
            "evidence": ["room_unpublished_with_reconnect_holds"],
        }
    )

    events = service.get_match_events(match_id)
    assert any(event["event"] == "match_checkpoint_hint" for event in events)
    assert any(event["event"] == "match_resolution_hint" for event in events)
```

- [ ] **Step 2: Run the ingest test to verify it fails**

Run:

```powershell
& 'C:\Users\twist\AppData\Local\Programs\Python\Python312\python.exe' -m pytest -q tests\test_hwstats_service.py -k "hint_events"
```

Expected: FAIL because the service currently ignores the new event types for snapshots/replay.

- [ ] **Step 3: Implement minimal ingest support**

Extend `ingest_live_event` in `H:/Code_Projects/homeworld_stats/hwstats/service.py`:

```python
if event_type in {"match_checkpoint_hint", "match_resolution_hint"}:
    self._ensure_match_row(event)
    if self.persist_match_snapshots:
        self.store.append_match_snapshot(match_id, event_type, event)
    return
```

Keep the event archive behavior unchanged so the hints replay from archive automatically.

- [ ] **Step 4: Run the ingest test again**

Run:

```powershell
& 'C:\Users\twist\AppData\Local\Programs\Python\Python312\python.exe' -m pytest -q tests\test_hwstats_service.py -k "hint_events"
```

Expected: PASS.

- [ ] **Step 5: Commit the stats ingest slice**

```powershell
git -c safe.directory=H:/Code_Projects/homeworld_stats -C 'H:\Code_Projects\homeworld_stats' add hwstats/service.py tests/test_hwstats_service.py
git -c safe.directory=H:/Code_Projects/homeworld_stats -C 'H:\Code_Projects\homeworld_stats' commit -m "feat: ingest live feed hint events"
```

### Task 4: Feed Gateway Hints Into Replay Confidence And Snapshots

**Files:**
- Modify: `H:/Code_Projects/homeworld_stats/tests/test_sim_service_replay.py`
- Modify: `H:/Code_Projects/homeworld_stats/hwstats/sim/models.py`
- Modify: `H:/Code_Projects/homeworld_stats/hwstats/sim/reducer.py`
- Modify: `H:/Code_Projects/homeworld_stats/hwstats/sim/evidence.py`
- Modify: `H:/Code_Projects/homeworld_stats/hwstats/service.py`

- [ ] **Step 1: Write the failing replay tests**

Add tests in `H:/Code_Projects/homeworld_stats/tests/test_sim_service_replay.py`:

```python
def test_service_replay_includes_gateway_checkpoint_presence_and_sync_anchors(tmp_path: Path) -> None:
    service = _seed_service_with_phase2_match(tmp_path)
    service.ingest_live_event(
        {
            "event": "match_checkpoint_hint",
            "product": "homeworld",
            "match_id": MATCH_ID,
            "room_port": 15102,
            "room_name": "Replay Test",
            "room_path": "/Homeworld",
            "hint_authority": "advisory",
            "reason": "peer_decode",
            "presence": {"connected": [{"player_name": "&Chainster", "gameplay_index": 0}], "reconnecting": [], "departed_recently": []},
            "packet_hints": {"sync_anchors": [{"frame": 2104, "randcheck": 77}], "alliance_changes": [], "player_dropped_masks": []},
        }
    )

    replay = service.get_match_replay(MATCH_ID)

    assert replay["available"] is True
    assert replay["gateway_hints"]["checkpoint_count"] >= 1
    assert replay["gateway_hints"]["sync_anchor_count"] >= 1
    assert replay["snapshots"][-1]["gateway_presence"]["connected"][0]["player_name"] == "&Chainster"


def test_service_replay_promotes_confidence_when_gateway_resolution_hint_supports_terminal_state(tmp_path: Path) -> None:
    service = _seed_service_with_phase2_match(tmp_path)
    service.ingest_live_event(
        {
            "event": "match_resolution_hint",
            "product": "homeworld",
            "match_id": MATCH_ID,
            "room_port": 15102,
            "room_name": "Replay Test",
            "room_path": "/Homeworld",
            "hint_authority": "terminal_support",
            "basis": "final_connected_roster",
            "classification": "survivor_group_remaining",
            "survivor_hint": {"surviving_player_names": ["&Chainster", "&Z&e&r&o|&S&F"]},
            "evidence": ["single_connected_team_remained"],
        }
    )

    replay = service.get_match_replay(MATCH_ID)

    assert replay["confidence"] in {"latched_replay_with_gateway_terminal_support", "authoritative"}
    assert "gateway_terminal_support" in replay["evidence"]
```

- [ ] **Step 2: Run the replay tests to verify they fail**

Run:

```powershell
& 'C:\Users\twist\AppData\Local\Programs\Python\Python312\python.exe' -m pytest -q tests\test_sim_service_replay.py -k "gateway"
```

Expected: FAIL because replay payloads do not yet expose gateway hint state or upgraded confidence.

- [ ] **Step 3: Implement minimal replay support**

Add replay model fields in `H:/Code_Projects/homeworld_stats/hwstats/sim/models.py`:

```python
@dataclass
class ReplaySnapshot:
    frame: int
    ts: float
    reason: str
    winner_latched: bool = False
    desync_detected: bool = False
    players: list[PlayerReplaySnapshot] = field(default_factory=list)
    gateway_presence: dict[str, Any] = field(default_factory=dict)
    gateway_packet_hints: dict[str, Any] = field(default_factory=dict)


@dataclass
class SimState:
    ...
    gateway_checkpoint_hints: list[dict[str, Any]] = field(default_factory=list)
    gateway_resolution_hints: list[dict[str, Any]] = field(default_factory=list)
```

Then fold the new events into replay preparation in `H:/Code_Projects/homeworld_stats/hwstats/service.py` and `H:/Code_Projects/homeworld_stats/hwstats/sim/reducer.py`:

```python
if event_name == "match_checkpoint_hint":
    state.gateway_checkpoint_hints.append(dict(event))
    if state.snapshots:
        state.snapshots[-1].gateway_presence = dict(event.get("presence") or {})
        state.snapshots[-1].gateway_packet_hints = dict(event.get("packet_hints") or {})

if event_name == "match_resolution_hint":
    state.gateway_resolution_hints.append(dict(event))
```

Promote confidence in `H:/Code_Projects/homeworld_stats/hwstats/sim/evidence.py`:

```python
has_gateway_terminal_support = bool(state.gateway_resolution_hints)
if state.winner_latched and has_gateway_terminal_support:
    confidence = "latched_replay_with_gateway_terminal_support"
    evidence = _append_unique(evidence, "gateway_terminal_support")
```

Expose summary fields from `replay_result_payload`:

```python
"gateway_hints": {
    "checkpoint_count": len(state.gateway_checkpoint_hints),
    "resolution_count": len(state.gateway_resolution_hints),
    "sync_anchor_count": sum(len(dict(hint.get("packet_hints") or {}).get("sync_anchors") or []) for hint in state.gateway_checkpoint_hints),
},
```

- [ ] **Step 4: Run the replay tests again**

Run:

```powershell
& 'C:\Users\twist\AppData\Local\Programs\Python\Python312\python.exe' -m pytest -q tests\test_sim_service_replay.py -k "gateway"
```

Expected: PASS.

- [ ] **Step 5: Run cross-repo verification**

Run:

```powershell
& 'C:\Users\twist\AppData\Local\Programs\Python\Python312\python.exe' -m pytest -q tests\test_stats_api.py
& 'C:\Users\twist\AppData\Local\Programs\Python\Python312\python.exe' -m pytest -q tests\test_hwstats_service.py tests\test_sim_service_replay.py
& 'C:\Users\twist\AppData\Local\Programs\Python\Python312\python.exe' -m pytest -q
```

Expected:

- `won_oss_server` targeted stats API suite passes
- `homeworld_stats` targeted replay/service suites pass
- full suites pass in both repos or any failure is investigated before claiming completion

- [ ] **Step 6: Commit the replay support slice**

```powershell
git -c safe.directory=H:/Code_Projects/homeworld_stats -C 'H:\Code_Projects\homeworld_stats' add hwstats/service.py hwstats/sim/models.py hwstats/sim/reducer.py hwstats/sim/evidence.py tests/test_hwstats_service.py tests/test_sim_service_replay.py
git -c safe.directory=H:/Code_Projects/homeworld_stats -C 'H:\Code_Projects\homeworld_stats' commit -m "feat: use live feed hints in replay confidence"
```
