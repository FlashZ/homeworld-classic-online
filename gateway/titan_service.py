from __future__ import annotations

import argparse
import asyncio
import base64
from collections import deque
import contextlib
import hashlib
import logging
import os
from pathlib import Path
import re
import struct
import time
from typing import Any, Deque, Dict, Optional, Tuple

from .protocol import *
from . import protocol as _protocol
from .routing import RoutingServerManager
from .admin import AdminDashboardServer, DASHBOARD_LOG_HANDLER
from .firewall import _handle_firewall_probe
from .product_profile import (
    CATACLYSM_PRODUCT_PROFILE,
    HOMEWORLD_PRODUCT_PROFILE,
    PRODUCT_PROFILES,
    ProductProfile,
    product_profile_from_name,
)

globals().update({name: getattr(_protocol, name) for name in dir(_protocol) if name.startswith('_')})
LOGGER = logging.getLogger(__name__)
LEAVE_FOR_GAME_WINDOW_SECONDS = 3.0
_MULTIPLAYER_LEVEL_PATH_RE = re.compile(
    rb"(?i)multiplayer\\(?P<folder>[^\\\x00\r\n]+)\\(?P<file>[^\\\x00\r\n]+)\.level"
)

class BinaryGatewayServer:
    def __init__(self, backend_host: str, backend_port: int,
                 event_bus: Optional[GatewayEventBus] = None,
                 public_host: str = "127.0.0.1",
                 public_port: int = 15101,
                 routing_port: int = 15100,
                 routing_max_port: Optional[int] = None,
                 version_str: str = "",
                 valid_versions: Optional[list[str]] = None,
                 keys_dir: Optional[str] = None,
                 backend_shared_secret: str = "",
                 backend_timeout_s: float = BACKEND_RPC_TIMEOUT_SECONDS,
                 product_profile: ProductProfile = HOMEWORLD_PRODUCT_PROFILE,
                 user_id_start: int = 1000,
                 peer_session_id_min: int = 1,
                 peer_session_id_max: int = MAX_PEER_SESSION_ID):
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.backend_shared_secret = backend_shared_secret.strip()
        self.backend_timeout_s = max(1.0, float(backend_timeout_s))
        self.event_bus = event_bus or GatewayEventBus()
        self.live_feed_bus = GatewayLiveFeedBus()
        self.product_profile = product_profile
        self.public_host = public_host
        self.public_port = public_port
        self.routing_port = routing_port
        self.routing_max_port = (
            int(routing_max_port)
            if routing_max_port is not None
            else int(routing_port)
        )
        resolved_valid_versions = list(valid_versions or [])
        if not resolved_valid_versions:
            if str(version_str or "").strip():
                resolved_valid_versions = [str(version_str).strip()]
            else:
                resolved_valid_versions = list(self.product_profile.backend_valid_versions)
        self.version_str = str(version_str or resolved_valid_versions[0]).strip()
        self.valid_versions = tuple(resolved_valid_versions)
        # Auth1 crypto state (loaded from keys_dir if provided)
        self._auth_keys_loaded = False
        self._key_block: bytes = b""
        self._auth_p = self._auth_q = self._auth_g = self._auth_y = self._auth_x = 0
        self._ver_p = self._ver_q = self._ver_g = 0
        self._next_user_id = int(user_id_start)
        self._issued_user_ids: set[int] = set()
        self._peer_session_id_min = max(1, int(peer_session_id_min))
        self._peer_session_id_max = max(
            self._peer_session_id_min,
            min(MAX_PEER_SESSION_ID, int(peer_session_id_max)),
        )
        self._next_peer_session_id = self._peer_session_id_min
        self._peer_sessions: Dict[int, PeerSession] = {}
        self._activity: Deque[Dict[str, object]] = deque(maxlen=500)
        self._activity_counts: Dict[str, int] = {}
        self._ip_activity: Dict[str, Dict[str, object]] = {}
        self._banned_ips: Dict[str, str] = {}
        self.routing_manager: Optional[RoutingServerManager] = None
        self._maintenance_task: Optional[asyncio.Task] = None
        self._live_feed_event_id = 0
        self._live_matches: Dict[int, Dict[str, object]] = {}
        self._inferred_room_metadata: Dict[int, Dict[str, object]] = {}
        self._pending_match_slot_manifests: Dict[int, Dict[str, object]] = {}
        self._pending_match_launch_configs: Dict[int, Dict[str, object]] = {}
        self.started_at = time.time()
        if keys_dir:
            self._load_keys(keys_dir)

    async def _call_backend(self, payload: Dict[str, object]) -> Dict[str, object]:
        return await call_backend(
            self.backend_host,
            self.backend_port,
            payload,
            shared_secret=self.backend_shared_secret,
            timeout_s=self.backend_timeout_s,
        )

    def start_background_tasks(self) -> None:
        if self._maintenance_task is None:
            self._maintenance_task = asyncio.create_task(self._peer_session_maintenance_loop())

    async def stop_background_tasks(self) -> None:
        task = self._maintenance_task
        self._maintenance_task = None
        if task is None:
            return
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    def _touch_peer_session(self, session: PeerSession) -> None:
        session.last_used_at = time.time()

    def _alloc_user_id(self) -> int:
        user_id = int(self._next_user_id)
        self._next_user_id = user_id + 1
        self._issued_user_ids.add(user_id)
        return user_id

    def _expire_peer_sessions(self) -> int:
        now = time.time()
        expired_ids = [
            session_id
            for session_id, session in list(self._peer_sessions.items())
            if now - session.last_used_at >= PEER_SESSION_TTL_SECONDS
        ]
        for session_id in expired_ids:
            session = self._peer_sessions.pop(session_id, None)
            if session is None:
                continue
            LOGGER.info(
                "Peer(session): expired session_id=%d role=%s idle_for=%.1fs",
                session.session_id,
                session.role,
                max(0.0, now - session.last_used_at),
            )
        return len(expired_ids)

    async def _peer_session_maintenance_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(PEER_SESSION_SWEEP_INTERVAL_SECONDS)
                self._expire_peer_sessions()
                self._prune_ip_activity()
        except asyncio.CancelledError:
            raise

    def _prune_ip_activity(self) -> int:
        now = time.time()
        removed = 0
        stale_ips = [
            ip
            for ip, raw in list(self._ip_activity.items())
            if now - float(raw.get("last_seen", 0.0)) >= IP_ACTIVITY_TTL_SECONDS
        ]
        for ip in stale_ips:
            self._ip_activity.pop(ip, None)
            removed += 1

        overflow = len(self._ip_activity) - MAX_IP_ACTIVITY_ROWS
        if overflow > 0:
            oldest = sorted(
                self._ip_activity.items(),
                key=lambda item: (float(item[1].get("last_seen", 0.0)), item[0]),
            )[:overflow]
            for ip, _raw in oldest:
                if ip in self._ip_activity:
                    self._ip_activity.pop(ip, None)
                    removed += 1
        return removed

    def record_activity(
        self,
        kind: str,
        *,
        product: str = "",
        room_port: Optional[int] = None,
        room_name: str = "",
        room_path: str = "",
        player_id: Optional[int] = None,
        player_name: str = "",
        player_ip: str = "",
        text: str = "",
        details: Optional[Dict[str, object]] = None,
    ) -> None:
        now = time.time()
        product_key = str(product or self.product_profile.key).strip() or self.product_profile.key
        event = {
            "ts": now,
            "kind": kind,
            "product": product_key,
            "room_port": room_port,
            "room_name": room_name,
            "room_path": room_path,
            "player_id": player_id,
            "player_name": player_name,
            "player_ip": player_ip,
            "text": text,
        }
        if details:
            event["details"] = dict(details)
        self._activity.append(event)
        self._activity_counts[kind] = self._activity_counts.get(kind, 0) + 1

        if player_ip:
            stats = self._ip_activity.setdefault(
                player_ip,
                {
                    "ip": player_ip,
                    "join_count": 0,
                    "leave_count": 0,
                    "chat_count": 0,
                    "last_seen": 0.0,
                    "player_names": set(),
                    "rooms": set(),
                    "products": set(),
                },
            )
            stats["last_seen"] = now
            if player_name:
                cast_names = stats["player_names"]
                if isinstance(cast_names, set):
                    cast_names.add(player_name)
            if room_name:
                cast_rooms = stats["rooms"]
                if isinstance(cast_rooms, set):
                    cast_rooms.add(room_name)
            cast_products = stats["products"]
            if isinstance(cast_products, set) and product_key:
                cast_products.add(product_key)
            count_key = f"{kind}_count"
            if count_key in stats:
                stats[count_key] = int(stats[count_key]) + 1

    @staticmethod
    def _mark_activity_left_for_game(event: Dict[str, object]) -> None:
        details = event.get("details")
        if isinstance(details, dict):
            copied = dict(details)
        else:
            copied = {}
        copied["left_for_game"] = True
        event["details"] = copied

    def _activity_base_ports(self) -> Dict[str, int]:
        return {self.product_profile.key: int(self.routing_port)}

    def _annotate_activity_transitions(
        self,
        events: list[Dict[str, object]],
        *,
        base_ports_by_product: Dict[str, int],
    ) -> None:
        leave_events_by_player: Dict[tuple[str, str, str], list[Dict[str, object]]] = {}
        for event in events:
            if str(event.get("kind") or "") != "leave":
                continue
            product = str(event.get("product") or self.product_profile.key)
            base_port = int(base_ports_by_product.get(product) or 0)
            port = int(event.get("room_port") or 0)
            if not base_port or not port:
                continue
            player_name = str(event.get("player_name") or "")
            player_ip = str(event.get("player_ip") or "")
            if not player_name and not player_ip:
                continue
            key = (product, player_name, player_ip)
            event_ts = float(event.get("ts") or 0.0)
            bucket = leave_events_by_player.setdefault(key, [])
            bucket[:] = [
                previous
                for previous in bucket
                if abs(event_ts - float(previous.get("ts") or 0.0)) <= LEAVE_FOR_GAME_WINDOW_SECONDS
            ]
            for previous in bucket:
                previous_port = int(previous.get("room_port") or 0)
                if previous_port == port:
                    continue
                if (previous_port == base_port) == (port == base_port):
                    continue
                self._mark_activity_left_for_game(previous)
                self._mark_activity_left_for_game(event)
            bucket.append(event)

    def _activity_snapshot(
        self,
        limit: int = 150,
        *,
        base_ports_by_product: Optional[Dict[str, int]] = None,
    ) -> list[Dict[str, object]]:
        if limit <= 0:
            return []
        join_leave_chat = [
            entry for entry in self._activity
            if entry.get("kind") in {"join", "rejoin", "leave", "chat", "broadcast"}
        ]
        events: list[Dict[str, object]] = []
        for entry in list(join_leave_chat)[-limit:]:
            copied = dict(entry)
            if isinstance(copied.get("details"), dict):
                copied["details"] = dict(copied["details"])
            events.append(copied)
        self._annotate_activity_transitions(
            events,
            base_ports_by_product=base_ports_by_product or self._activity_base_ports(),
        )
        return events[::-1]

    def _ip_activity_snapshot(self, limit: int = 50) -> list[Dict[str, object]]:
        rows = []
        for ip, raw in self._ip_activity.items():
            player_names = raw.get("player_names", set())
            rooms = raw.get("rooms", set())
            products = raw.get("products", set())
            rows.append(
                {
                    "ip": ip,
                    "join_count": int(raw.get("join_count", 0)),
                    "leave_count": int(raw.get("leave_count", 0)),
                    "chat_count": int(raw.get("chat_count", 0)),
                    "last_seen": float(raw.get("last_seen", 0.0)),
                    "player_names": sorted(player_names) if isinstance(player_names, set) else [],
                    "rooms": sorted(rooms) if isinstance(rooms, set) else [],
                    "products": sorted(products) if isinstance(products, set) else [],
                }
            )
        rows.sort(key=lambda item: (-item["join_count"], -item["chat_count"], item["ip"]))
        return rows[:max(1, limit)]

    def ban_ip(self, ip: str, reason: str = "") -> None:
        self._banned_ips[ip.strip()] = reason

    def unban_ip(self, ip: str) -> bool:
        return self._banned_ips.pop(ip.strip(), None) is not None

    def clear_activity(self) -> None:
        self._activity.clear()
        self._activity_counts.clear()
        self._ip_activity.clear()

    def subscribe_live_feed(self, maxsize: int = 1024) -> asyncio.Queue:
        return self.live_feed_bus.subscribe(maxsize=maxsize)

    def unsubscribe_live_feed(self, queue: asyncio.Queue) -> None:
        self.live_feed_bus.unsubscribe(queue)

    def _next_live_feed_event_id(self) -> str:
        self._live_feed_event_id += 1
        return str(self._live_feed_event_id)

    @staticmethod
    def _live_payload_preview_hex(payload: bytes, limit: int = 32) -> str:
        return bytes(payload or b"")[:limit].hex()

    @staticmethod
    def _live_payload_fingerprint(payload: bytes) -> str:
        raw = bytes(payload or b"")
        if not raw:
            return "empty"
        digest = hashlib.blake2s(raw, digest_size=6).hexdigest()
        return f"{len(raw)}b:{digest}:{raw[:8].hex()}"

    def _publish_live_feed_event(
        self,
        event_name: str,
        payload: Dict[str, object],
    ) -> Dict[str, object]:
        event = {
            "id": self._next_live_feed_event_id(),
            "event": event_name,
            "ts": time.time(),
            "product": self.product_profile.key,
        }
        event.update(payload)
        self.live_feed_bus.publish(event)
        return event

    @staticmethod
    def _infer_room_metadata_from_payload(payload: bytes) -> Dict[str, object] | None:
        if not payload:
            return None
        match = _MULTIPLAYER_LEVEL_PATH_RE.search(bytes(payload))
        if match is None:
            return None
        display_name = match.group("file").decode("latin-1", errors="ignore").strip()
        level_path = match.group(0).decode("latin-1", errors="ignore").strip()
        if not display_name or not level_path:
            return None
        return {
            "display_name": display_name,
            "game_name": display_name,
            "map_name": display_name,
            "level_path": level_path,
            "metadata_source": "peer_packet",
        }

    def _remember_inferred_room_metadata(self, room_port: int, payload: bytes) -> None:
        inferred = self._infer_room_metadata_from_payload(payload)
        if inferred is None:
            return
        self._inferred_room_metadata[int(room_port)] = inferred

    def _is_generic_room_label(self, value: object) -> bool:
        normalized = str(value or "").strip().lower()
        generic_labels = {
            "",
            "unknown",
            str(self.product_profile.lobby_room_name or "").strip().lower(),
            str(self.product_profile.lobby_room_description or "").strip().lower(),
        }
        return normalized in generic_labels

    def _preferred_room_title(
        self,
        snapshot: Dict[str, object],
        *,
        fallback: object = "",
    ) -> str:
        room_name = str(
            snapshot.get("room_display_name")
            or snapshot.get("room_name")
            or fallback
            or ""
        ).strip()
        if not self._is_generic_room_label(room_name):
            return room_name

        room_description = str(snapshot.get("room_description") or "").strip()
        if not self._is_generic_room_label(room_description):
            return room_description

        fallback_label = str(fallback or "").strip()
        if not self._is_generic_room_label(fallback_label):
            return fallback_label

        return room_name or room_description or fallback_label

    def _apply_room_title_fallback(
        self,
        snapshot: Dict[str, object],
        *,
        fallback: object = "",
    ) -> Dict[str, object]:
        hydrated = dict(snapshot)
        preferred_title = self._preferred_room_title(hydrated, fallback=fallback)
        if not preferred_title:
            return hydrated

        current_display = str(hydrated.get("room_display_name") or "").strip()
        current_name = str(hydrated.get("room_name") or "").strip()
        if not current_display or self._is_generic_room_label(current_display):
            hydrated["room_display_name"] = preferred_title
        if not current_name or self._is_generic_room_label(current_name):
            hydrated["room_name"] = preferred_title
        return hydrated

    def _apply_inferred_room_snapshot(
        self,
        room_port: int,
        snapshot: Dict[str, object],
    ) -> Dict[str, object]:
        hydrated = self._apply_room_title_fallback(snapshot)
        inferred = self._inferred_room_metadata.get(int(room_port))
        if not inferred:
            return hydrated
        display_name = str(inferred.get("display_name") or "")
        if display_name:
            current_name = self._preferred_room_title(hydrated)
            if self._is_generic_room_label(current_name):
                hydrated["room_display_name"] = display_name
                hydrated["room_name"] = display_name
        games = [
            dict(game)
            for game in (hydrated.get("games", []) or [])
            if isinstance(game, dict)
        ]
        if not games and str(inferred.get("game_name") or ""):
            games = [
                {
                    "link_id": 0,
                    "owner_id": 0,
                    "owner_name": "",
                    "name": str(inferred["game_name"]),
                    "data_len": 0,
                    "lifespan": 0,
                    "data_preview_hex": "",
                    "synthetic": True,
                    "level_path": str(inferred.get("level_path") or ""),
                }
            ]
        hydrated["games"] = games
        if games:
            hydrated["game_count"] = max(int(hydrated.get("game_count") or 0), len(games))
        hydrated["map_name"] = str(inferred.get("map_name") or hydrated.get("map_name") or "")
        hydrated["level_path"] = str(inferred.get("level_path") or hydrated.get("level_path") or "")
        hydrated["metadata_source"] = str(inferred.get("metadata_source") or hydrated.get("metadata_source") or "")
        return hydrated

    def _apply_inferred_dashboard_snapshot(
        self,
        raw_snapshot: Dict[str, object],
    ) -> Dict[str, object]:
        snapshot = dict(raw_snapshot)
        rooms = []
        room_lookup: Dict[int, Dict[str, object]] = {}
        for room in snapshot.get("rooms", []) or []:
            if not isinstance(room, dict):
                continue
            port = int(room.get("listen_port") or room.get("port") or 0)
            hydrated = self._apply_inferred_room_snapshot(port, dict(room))
            rooms.append(hydrated)
            if port > 0:
                room_lookup[port] = hydrated
        snapshot["rooms"] = rooms

        players = []
        for player in snapshot.get("players", []) or []:
            if not isinstance(player, dict):
                continue
            hydrated = dict(player)
            port = int(hydrated.get("room_port") or 0)
            room = room_lookup.get(port)
            if room is not None:
                hydrated["room_name"] = str(
                    room.get("room_display_name")
                    or room.get("room_name")
                    or hydrated.get("room_name")
                    or ""
                )
            else:
                preferred_title = self._preferred_room_title({"room_name": hydrated.get("room_name")})
                if preferred_title:
                    hydrated["room_name"] = preferred_title
            players.append(hydrated)
        snapshot["players"] = players

        servers = []
        for server in snapshot.get("servers", []) or []:
            if not isinstance(server, dict):
                continue
            hydrated = dict(server)
            port = int(hydrated.get("listen_port") or hydrated.get("port") or 0)
            room = room_lookup.get(port)
            if room is not None:
                hydrated["room_name"] = str(
                    room.get("room_display_name")
                    or room.get("room_name")
                    or hydrated.get("room_name")
                    or ""
                )
                hydrated["room_description"] = str(
                    room.get("room_description")
                    or hydrated.get("room_description")
                    or ""
                )
                hydrated["game_count"] = max(
                    int(hydrated.get("game_count") or 0),
                    int(room.get("game_count") or 0),
                )
            else:
                preferred_title = self._preferred_room_title(hydrated)
                if preferred_title:
                    hydrated["room_name"] = preferred_title
            servers.append(hydrated)
        snapshot["servers"] = servers

        games = []
        game_ports: set[int] = set()
        for game in snapshot.get("games", []) or []:
            if not isinstance(game, dict):
                continue
            hydrated = dict(game)
            room_port = int(hydrated.get("room_port") or 0)
            inferred = self._inferred_room_metadata.get(room_port)
            if inferred and str(inferred.get("display_name") or ""):
                hydrated["room_name"] = str(inferred["display_name"])
                if not hydrated.get("name"):
                    hydrated["name"] = str(inferred.get("game_name") or "")
            games.append(hydrated)
            if room_port > 0:
                game_ports.add(room_port)
        for port, inferred in self._inferred_room_metadata.items():
            room = room_lookup.get(int(port))
            if room is None or int(port) in game_ports:
                continue
            if not bool(room.get("is_game_room", False)):
                continue
            games.append(
                {
                    "room_port": int(port),
                    "room_name": str(inferred.get("display_name") or ""),
                    "name": str(inferred.get("game_name") or ""),
                    "owner_name": "",
                    "link_id": 0,
                    "lifespan": 0,
                    "data_len": 0,
                    "data_preview_hex": "",
                    "synthetic": True,
                    "level_path": str(inferred.get("level_path") or ""),
                }
            )
        snapshot["games"] = games
        snapshot["current_game_count"] = len(games)
        return snapshot

    def _routing_room_snapshot(self, room_port: int) -> Dict[str, object]:
        if self.routing_manager is None:
            return {}
        get_server = getattr(self.routing_manager, "get_server", None)
        if callable(get_server):
            room_server = get_server(int(room_port))
            snapshot_fn = getattr(room_server, "dashboard_snapshot", None)
            if callable(snapshot_fn):
                snapshot = snapshot_fn()
                if isinstance(snapshot, dict):
                    return self._apply_inferred_room_snapshot(int(room_port), dict(snapshot))
        routing_snapshot = self._routing_dashboard_snapshot()
        for room in routing_snapshot.get("rooms", []) or []:
            if not isinstance(room, dict):
                continue
            port = int(room.get("listen_port") or room.get("port") or 0)
            if port == int(room_port):
                return dict(room)
        return {}

    @staticmethod
    def _room_participant_count(snapshot: Dict[str, object]) -> int:
        clients = snapshot.get("clients", []) or []
        pending = snapshot.get("pending_reconnects", []) or []
        return len(clients) + len(pending)

    @staticmethod
    def _room_is_live_match(snapshot: Dict[str, object]) -> bool:
        if not bool(snapshot.get("is_game_room", False)):
            return False
        if BinaryGatewayServer._room_participant_count(snapshot) < 2:
            return False
        return any(
            int(snapshot.get(key) or 0) > 0
            for key in ("peer_data_messages", "peer_data_bytes", "data_object_count", "game_count", "active_game_count")
        )

    def _live_match_payload(
        self,
        room_port: int,
        snapshot: Dict[str, object],
        state: Dict[str, object],
        *,
        now: Optional[float] = None,
    ) -> Dict[str, object]:
        current = float(now if now is not None else time.time())
        games = snapshot.get("games", []) or []
        first_game = games[0] if games and isinstance(games[0], dict) else {}
        room_title = self._preferred_room_title(snapshot, fallback=state.get("room_name"))
        return {
            "match_id": state["match_id"],
            "room_port": int(room_port),
            "room_name": room_title,
            "room_path": str(snapshot.get("room_path") or state.get("room_path") or ""),
            "display_name": room_title,
            "map_name": str(first_game.get("name") or snapshot.get("map_name") or room_title or ""),
            "level_path": str(snapshot.get("level_path") or ""),
            "participant_count": self._room_participant_count(snapshot),
            "started_at": float(state["started_at"]),
            "duration_seconds": int(max(0.0, current - float(state["started_at"]))),
            "peer_data_messages": int(snapshot.get("peer_data_messages") or 0),
            "peer_data_bytes": int(snapshot.get("peer_data_bytes") or 0),
            "data_object_count": int(snapshot.get("data_object_count") or 0),
            "game_count": int(snapshot.get("game_count") or len(games)),
            "game_name": str(first_game.get("name") or ""),
            "owner_name": str(first_game.get("owner_name") or ""),
        }

    @staticmethod
    def _normalize_match_slot_manifest_players(players: Any) -> list[Dict[str, object]]:
        normalized: list[Dict[str, object]] = []
        if not isinstance(players, list):
            return normalized
        for fallback_index, player in enumerate(players):
            if not isinstance(player, dict):
                continue
            player_id = str(player.get("player_id") or "").strip()
            player_name = str(
                player.get("player_name")
                or player.get("nickname")
                or player.get("username")
                or player_id
            ).strip()
            gameplay_index = player.get("gameplay_index", player.get("slot_index", fallback_index))
            try:
                gameplay_index = int(gameplay_index)
            except (TypeError, ValueError):
                gameplay_index = int(fallback_index)
            if not player_name:
                continue
            normalized.append(
                {
                    "player_id": player_id,
                    "player_name": player_name,
                    "gameplay_index": gameplay_index,
                }
            )
        normalized.sort(key=lambda item: (int(item.get("gameplay_index") or 0), str(item.get("player_name") or "")))
        return normalized

    def queue_match_slot_manifest(self, *, room_port: int, players: list[dict[str, object]]) -> None:
        normalized_players = self._normalize_match_slot_manifest_players(players)
        if not normalized_players:
            return
        port = int(room_port)
        self._pending_match_slot_manifests[port] = {"players": normalized_players}
        if port in self._live_matches:
            self._emit_pending_match_slot_manifest(port)

    def queue_match_launch_config(
        self,
        *,
        room_port: int,
        lobby_title: str,
        map_name: str,
        map_code: str,
        settings: dict[str, object] | None,
        captain_identity: dict[str, object] | None,
        players: list[dict[str, object]],
        transport_mode: str = "routed",
    ) -> None:
        port = int(room_port)
        self._pending_match_launch_configs[port] = {
            "transport_mode": str(transport_mode or "routed"),
            "lobby_title": str(lobby_title or "").strip(),
            "map_name": str(map_name or "").strip(),
            "map_code": str(map_code or "").strip(),
            "settings": dict(settings or {}),
            "captain_identity": dict(captain_identity or {}),
            "players": self._normalize_match_slot_manifest_players(players),
        }
        if port in self._live_matches:
            self._emit_pending_match_launch_config(port)

    def _emit_pending_match_slot_manifest(
        self,
        room_port: int,
        *,
        snapshot: Optional[Dict[str, object]] = None,
    ) -> None:
        port = int(room_port)
        pending = self._pending_match_slot_manifests.get(port)
        state = self._live_matches.get(port)
        if pending is None or state is None:
            return
        room_snapshot = dict(snapshot or self._routing_room_snapshot(port))
        room_title = self._preferred_room_title(room_snapshot, fallback=state.get("room_name"))
        payload: Dict[str, object] = {
            "match_id": str(state["match_id"]),
            "room_port": port,
            "room_name": room_title,
            "room_path": str(room_snapshot.get("room_path") or state.get("room_path") or ""),
            "players": list(pending.get("players") or []),
        }
        self._publish_live_feed_event("match_slot_manifest", payload)
        self._pending_match_slot_manifests.pop(port, None)

    def _emit_pending_match_launch_config(
        self,
        room_port: int,
        *,
        snapshot: Optional[Dict[str, object]] = None,
    ) -> None:
        port = int(room_port)
        pending = self._pending_match_launch_configs.get(port)
        state = self._live_matches.get(port)
        if pending is None or state is None:
            return
        room_snapshot = dict(snapshot or self._routing_room_snapshot(port))
        room_title = self._preferred_room_title(room_snapshot, fallback=state.get("room_name"))
        payload: Dict[str, object] = {
            "match_id": str(state["match_id"]),
            "room_port": port,
            "room_name": room_title,
            "room_path": str(room_snapshot.get("room_path") or state.get("room_path") or ""),
            "transport_mode": str(pending.get("transport_mode") or "routed"),
            "capture_source": "routed_live_feed",
            "lobby_title": str(pending.get("lobby_title") or room_title or ""),
            "map_name": str(pending.get("map_name") or ""),
            "map_code": str(pending.get("map_code") or ""),
            "settings": dict(pending.get("settings") or {}),
            "captain_identity": dict(pending.get("captain_identity") or {}),
            "players": list(pending.get("players") or []),
        }
        self._publish_live_feed_event("match_launch_config", payload)
        self._pending_match_launch_configs.pop(port, None)

    def _sync_live_match_state(
        self,
        room_port: int,
        *,
        snapshot: Optional[Dict[str, object]] = None,
        emit_update: bool = False,
    ) -> Optional[str]:
        room_port = int(room_port)
        room_snapshot = dict(snapshot or self._routing_room_snapshot(room_port))
        now = time.time()
        state = self._live_matches.get(room_port)
        is_live = self._room_is_live_match(room_snapshot)

        if is_live and state is None:
            state = {
                "match_id": f"{self.product_profile.key}:{room_port}:{int(now * 1000)}",
                "started_at": now,
                "room_name": self._preferred_room_title(room_snapshot),
                "room_path": str(room_snapshot.get("room_path") or ""),
            }
            self._live_matches[room_port] = state
            self._publish_live_feed_event(
                "match_started",
                self._live_match_payload(room_port, room_snapshot, state, now=now),
            )
            self._emit_pending_match_launch_config(room_port, snapshot=room_snapshot)
            self._emit_pending_match_slot_manifest(room_port, snapshot=room_snapshot)
            return str(state["match_id"])

        if is_live and state is not None:
            state["room_name"] = self._preferred_room_title(room_snapshot, fallback=state.get("room_name"))
            state["room_path"] = str(room_snapshot.get("room_path") or state.get("room_path") or "")
            if emit_update:
                self._emit_pending_match_launch_config(room_port, snapshot=room_snapshot)
                self._publish_live_feed_event(
                    "match_updated",
                    self._live_match_payload(room_port, room_snapshot, state, now=now),
                )
            return str(state["match_id"])

        if state is not None:
            participants = self._room_participant_count(room_snapshot)
            if participants <= 0:
                self._inferred_room_metadata.pop(room_port, None)
                self._pending_match_slot_manifests.pop(room_port, None)
                self._pending_match_launch_configs.pop(room_port, None)
                self._publish_live_feed_event(
                    "match_finished",
                    self._live_match_payload(room_port, room_snapshot, state, now=now),
                )
                self._live_matches.pop(room_port, None)
                return None
            if emit_update:
                self._publish_live_feed_event(
                    "match_updated",
                    self._live_match_payload(room_port, room_snapshot, state, now=now),
                )
            return str(state["match_id"])

        return None

    def record_live_player_event(
        self,
        event_name: str,
        *,
        room_port: int,
        player_id: int,
        player_name: str,
        player_ip: str = "",
        details: Optional[Dict[str, object]] = None,
    ) -> None:
        room_snapshot = self._routing_room_snapshot(room_port)
        existing = self._live_matches.get(int(room_port))
        room_title = self._preferred_room_title(room_snapshot)
        payload: Dict[str, object] = {
            "room_port": int(room_port),
            "room_name": room_title,
            "room_path": str(room_snapshot.get("room_path") or ""),
            "player_id": int(player_id),
            "player_name": str(player_name),
            "player_ip": str(player_ip or ""),
            "participant_count": self._room_participant_count(room_snapshot),
        }
        if existing is not None:
            payload["match_id"] = str(existing["match_id"])
        if details:
            payload["details"] = dict(details)
        self._publish_live_feed_event(event_name, payload)
        self._sync_live_match_state(int(room_port), snapshot=room_snapshot, emit_update=True)

    def record_live_routing_object_event(
        self,
        event_name: str,
        *,
        room_port: int,
        link_id: int,
        owner_id: int,
        owner_name: str,
        data_type_text: str,
        payload: bytes,
        lifespan: int = 0,
    ) -> None:
        room_snapshot = self._routing_room_snapshot(room_port)
        match_id = self._sync_live_match_state(int(room_port), snapshot=room_snapshot, emit_update=False)
        raw_payload = bytes(payload or b"")
        room_title = self._preferred_room_title(room_snapshot)
        event_payload: Dict[str, object] = {
            "room_port": int(room_port),
            "room_name": room_title,
            "room_path": str(room_snapshot.get("room_path") or ""),
            "link_id": int(link_id),
            "owner_id": int(owner_id),
            "owner_name": str(owner_name or ""),
            "data_type_text": str(data_type_text or ""),
            "lifespan": int(lifespan),
            "payload_len": len(raw_payload),
            "payload_preview_hex": self._live_payload_preview_hex(raw_payload),
            "payload_base64": base64.b64encode(raw_payload).decode("ascii"),
            "fingerprint": self._live_payload_fingerprint(raw_payload),
        }
        if match_id:
            event_payload["match_id"] = match_id
        self._publish_live_feed_event(event_name, event_payload)
        self._sync_live_match_state(int(room_port), snapshot=room_snapshot, emit_update=True)

    def record_live_peer_packet(
        self,
        event_name: str,
        *,
        room_port: int,
        sender_client_id: int,
        sender_name: str,
        recipient_client_ids: list[int],
        recipient_count: int,
        payload: bytes,
        packet_kind: str,
    ) -> None:
        self._remember_inferred_room_metadata(int(room_port), bytes(payload or b""))
        room_snapshot = self._routing_room_snapshot(room_port)
        match_id = self._sync_live_match_state(int(room_port), snapshot=room_snapshot, emit_update=False)
        raw_payload = bytes(payload or b"")
        games = room_snapshot.get("games", []) or []
        first_game = games[0] if games and isinstance(games[0], dict) else {}
        room_title = self._preferred_room_title(room_snapshot)
        event_payload: Dict[str, object] = {
            "room_port": int(room_port),
            "room_name": room_title,
            "room_path": str(room_snapshot.get("room_path") or ""),
            "game_name": str(first_game.get("name") or room_snapshot.get("map_name") or ""),
            "map_name": str(first_game.get("name") or room_snapshot.get("map_name") or room_title or ""),
            "sender_client_id": int(sender_client_id),
            "sender_name": str(sender_name or ""),
            "recipient_client_ids": [int(client_id) for client_id in recipient_client_ids],
            "recipient_count": int(recipient_count),
            "packet_kind": str(packet_kind or ""),
            "payload_len": len(raw_payload),
            "payload_preview_hex": self._live_payload_preview_hex(raw_payload),
            "payload_base64": base64.b64encode(raw_payload).decode("ascii"),
            "fingerprint": self._live_payload_fingerprint(raw_payload),
        }
        if room_snapshot.get("level_path"):
            event_payload["level_path"] = str(room_snapshot.get("level_path") or "")
        if match_id:
            event_payload["match_id"] = match_id
        self._publish_live_feed_event(event_name, event_payload)
        self._sync_live_match_state(int(room_port), snapshot=room_snapshot, emit_update=True)

    def _routing_dashboard_snapshot(self) -> Dict[str, object]:
        raw_snapshot = (
            self.routing_manager.dashboard_snapshot()
            if self.routing_manager is not None
            else {}
        )
        if not isinstance(raw_snapshot, dict):
            return {}
        raw_snapshot = self._apply_inferred_dashboard_snapshot(raw_snapshot)

        product_key = self.product_profile.key
        snapshot = dict(raw_snapshot)

        players: list[Dict[str, object]] = []
        for player in raw_snapshot.get("players", []) or []:
            if not isinstance(player, dict):
                continue
            row = dict(player)
            row["product"] = str(row.get("product") or product_key)
            players.append(row)

        servers: list[Dict[str, object]] = []
        for server in raw_snapshot.get("servers", []) or []:
            if not isinstance(server, dict):
                continue
            row = dict(server)
            row["product"] = str(row.get("product") or product_key)
            row["players"] = [
                {
                    **dict(player),
                    "product": str(dict(player).get("product") or row["product"]),
                }
                for player in row.get("players", []) or []
                if isinstance(player, dict)
            ]
            row["games"] = [
                {
                    **dict(game),
                    "product": str(dict(game).get("product") or row["product"]),
                }
                for game in row.get("games", []) or []
                if isinstance(game, dict)
            ]
            servers.append(row)

        games: list[Dict[str, object]] = []
        for game in raw_snapshot.get("games", []) or []:
            if not isinstance(game, dict):
                continue
            row = dict(game)
            row["product"] = str(row.get("product") or product_key)
            games.append(row)

        rooms: list[Dict[str, object]] = []
        for room in raw_snapshot.get("rooms", []) or []:
            if not isinstance(room, dict):
                continue
            row = dict(room)
            row["product"] = str(row.get("product") or product_key)
            rooms.append(row)

        snapshot["players"] = players
        snapshot["servers"] = servers
        snapshot["games"] = games
        snapshot["rooms"] = rooms
        snapshot["products"] = [product_key]
        return snapshot

    def stats_snapshot(self) -> Dict[str, object]:
        routing_snapshot = self._routing_dashboard_snapshot()

        rooms_raw = routing_snapshot.get("rooms", [])
        servers_raw = routing_snapshot.get("servers", [])
        players_raw = routing_snapshot.get("players", [])
        games_raw = routing_snapshot.get("games", [])

        room_is_game: Dict[int, bool] = {}
        room_reconnect_counts: Dict[int, int] = {}
        room_data_object_counts: Dict[int, int] = {}
        room_peer_data_messages: Dict[int, int] = {}
        room_peer_data_bytes: Dict[int, int] = {}
        room_game_data_bytes: Dict[int, int] = {}
        reconnecting_players: list[Dict[str, object]] = []

        for room in rooms_raw:
            if not isinstance(room, dict):
                continue
            port = int(room.get("listen_port") or 0)
            room_is_game[port] = bool(room.get("is_game_room", False))
            room_data_object_counts[port] = int(
                room.get("data_object_count")
                or len(room.get("data_objects", []) or [])
            )
            pending_reconnects = room.get("pending_reconnects", []) or []
            room_reconnect_counts[port] = len(pending_reconnects)
            room_name = str(room.get("room_display_name") or room.get("room_name") or "")
            for reservation in pending_reconnects:
                if not isinstance(reservation, dict):
                    continue
                reconnecting_players.append(
                    {
                        "product": str(reservation.get("product") or room.get("product") or self.product_profile.key),
                        "name": str(reservation.get("client_name") or ""),
                        "client_id": int(reservation.get("client_id") or 0),
                        "room_name": room_name,
                        "room_port": port,
                        "seconds_remaining": int(reservation.get("seconds_remaining") or 0),
                        "last_activity_kind": str(reservation.get("last_activity_kind") or ""),
                    }
                )

        players: list[Dict[str, object]] = []
        for player in players_raw:
            if not isinstance(player, dict):
                continue
            room_port = int(player.get("room_port") or 0)
            peer_data_messages = int(player.get("peer_data_messages") or 0)
            peer_data_bytes = int(player.get("peer_data_bytes") or 0)
            room_peer_data_messages[room_port] = room_peer_data_messages.get(room_port, 0) + peer_data_messages
            room_peer_data_bytes[room_port] = room_peer_data_bytes.get(room_port, 0) + peer_data_bytes
            players.append(
                {
                    "product": str(player.get("product") or self.product_profile.key),
                    "name": str(player.get("client_name") or ""),
                    "client_id": int(player.get("client_id") or 0),
                    "room_name": str(player.get("room_name") or ""),
                    "room_port": room_port,
                    # Retail routing does not expose a dedicated per-player presence
                    # flag, so we infer "game" from whether the player is in an
                    # active unpublished routing room.
                    "state": "game" if room_is_game.get(room_port, False) else "lobby",
                    "connected_seconds": int(player.get("connected_seconds") or 0),
                    "idle_seconds": int(player.get("idle_seconds") or 0),
                    "last_activity_kind": str(player.get("last_activity_kind") or ""),
                    "peer_data_messages": peer_data_messages,
                    "peer_data_bytes": peer_data_bytes,
                }
            )

        rooms: list[Dict[str, object]] = []
        for room in servers_raw:
            if not isinstance(room, dict):
                continue
            port = int(room.get("listen_port") or 0)
            rooms.append(
                {
                    "product": str(room.get("product") or self.product_profile.key),
                    "name": str(room.get("room_name") or ""),
                    "port": port,
                    "description": str(room.get("room_description") or ""),
                    "path": str(room.get("room_path") or ""),
                    "published": bool(room.get("published", False)),
                    "password_protected": bool(room.get("room_password_set", False)),
                    "player_count": int(room.get("player_count") or 0),
                    "game_count": int(room.get("game_count") or 0),
                    "active_game_count": 1 if room_is_game.get(port, False) else 0,
                    "is_game_room": bool(room_is_game.get(port, False)),
                    "reconnecting_count": int(room_reconnect_counts.get(port, 0)),
                    "peer_data_messages": int(room_peer_data_messages.get(port, 0)),
                    "peer_data_bytes": int(room_peer_data_bytes.get(port, 0)),
                    "game_data_bytes": int(room_game_data_bytes.get(port, 0)),
                    "data_object_count": int(room_data_object_counts.get(port, 0)),
                }
            )

        games: list[Dict[str, object]] = []
        for game in games_raw:
            if not isinstance(game, dict):
                continue
            room_port = int(game.get("room_port") or 0)
            data_len = int(game.get("data_len") or 0)
            room_game_data_bytes[room_port] = room_game_data_bytes.get(room_port, 0) + data_len
            games.append(
                {
                    "product": str(game.get("product") or self.product_profile.key),
                    "name": str(game.get("name") or ""),
                    "owner_name": str(game.get("owner_name") or ""),
                    "room_name": str(game.get("room_name") or ""),
                    "room_port": room_port,
                    "link_id": int(game.get("link_id") or 0),
                    "lifespan": int(game.get("lifespan") or 0),
                    "data_len": data_len,
                    "data_preview_hex": str(game.get("data_preview_hex") or ""),
                }
            )

        for room in rooms:
            port = int(room["port"])
            room["game_data_bytes"] = int(room_game_data_bytes.get(port, 0))

        traffic = {
            "peer_data_messages_total": sum(room_peer_data_messages.values()),
            "peer_data_bytes_total": sum(room_peer_data_bytes.values()),
            "game_object_count": len(games),
            "game_object_bytes_total": sum(int(game["data_len"]) for game in games),
        }

        return {
            "generated_at": time.time(),
            "server": {
                "product": self.product_profile.key,
                "community_name": self.product_profile.community_name,
                "directory_root": self.product_profile.directory_root,
                "valid_versions_service": self.product_profile.valid_versions_service,
                "public_host": self.public_host,
                "public_port": self.public_port,
                "routing_port": self.routing_port,
                "routing_max_port": self.routing_max_port,
                "version": self.version_str,
                "valid_versions": list(self.valid_versions),
                "products": [
                    {
                        "product": self.product_profile.key,
                        "community_name": self.product_profile.community_name,
                        "directory_root": self.product_profile.directory_root,
                        "valid_versions_service": self.product_profile.valid_versions_service,
                        "routing_port": self.routing_port,
                        "routing_max_port": self.routing_max_port,
                        "version": self.version_str,
                        "valid_versions": list(self.valid_versions),
                        "backend_host": self.backend_host,
                        "backend_port": self.backend_port,
                    }
                ],
            },
            "counts": {
                "players_online": len(players),
                "rooms_open": len(rooms),
                "rooms_published": sum(1 for room in rooms if room["published"]),
                "games_live": sum(1 for room in rooms if room["is_game_room"]),
                "unique_ips": int(routing_snapshot.get("current_unique_ip_count") or 0),
                "players_reconnecting": len(reconnecting_players),
            },
            "traffic": traffic,
            "players": players,
            "reconnecting_players": reconnecting_players,
            "rooms": rooms,
            "games": games,
        }

    def dashboard_snapshot(self, activity_limit: int = 150) -> Dict[str, object]:
        self._prune_ip_activity()
        routing_snapshot = self._routing_dashboard_snapshot()
        return {
            "product": self.product_profile.key,
            "community_name": self.product_profile.community_name,
            "directory_root": self.product_profile.directory_root,
            "valid_versions_service": self.product_profile.valid_versions_service,
            "public_host": self.public_host,
            "public_port": self.public_port,
            "routing_port": self.routing_port,
            "routing_max_port": self.routing_max_port,
            "backend_host": self.backend_host,
            "backend_port": self.backend_port,
            "version_str": self.version_str,
            "valid_versions": list(self.valid_versions),
            "auth_keys_loaded": self._auth_keys_loaded,
            "next_user_id": self._next_user_id,
            "peer_session_count": len(self._peer_sessions),
            "activity_metrics": {
                "join_count": self._activity_counts.get("join", 0),
                "leave_count": self._activity_counts.get("leave", 0),
                "chat_count": self._activity_counts.get("chat", 0),
                "room_open_count": self._activity_counts.get("room_open", 0),
                "unique_ip_count": len(self._ip_activity),
            },
            "activity": self._activity_snapshot(limit=activity_limit),
            "ip_metrics": self._ip_activity_snapshot(limit=50),
            "peer_sessions": {
                str(session_id): {
                    "role": session.role,
                    "session_id": session.session_id,
                    "sequenced": session.sequenced,
                    "in_seq": session.in_seq,
                    "out_seq": session.out_seq,
                    "created_at": session.created_at,
                    "last_used_at": session.last_used_at,
                    "session_key_len": len(session.session_key),
                }
                for session_id, session in sorted(self._peer_sessions.items())
            },
            "routing_manager": routing_snapshot,
            "products": {
                self.product_profile.key: {
                    "community_name": self.product_profile.community_name,
                    "directory_root": self.product_profile.directory_root,
                    "valid_versions_service": self.product_profile.valid_versions_service,
                    "routing_port": self.routing_port,
                    "routing_max_port": self.routing_max_port,
                    "backend_host": self.backend_host,
                    "backend_port": self.backend_port,
                    "version_str": self.version_str,
                    "valid_versions": list(self.valid_versions),
                }
            },
            "banned_ips": [
                {"ip": ip, "reason": reason}
                for ip, reason in sorted(self._banned_ips.items())
            ],
        }

    def health_snapshot(self) -> Dict[str, object]:
        return {
            "ok": True,
            "status": "ok",
            "shared_edge": False,
            "product": self.product_profile.key,
            "community_name": self.product_profile.community_name,
            "public_host": self.public_host,
            "public_port": self.public_port,
            "routing_port": self.routing_port,
            "uptime_seconds": int(max(0.0, time.time() - self.started_at)),
        }

    def readiness_snapshot(self) -> Dict[str, object]:
        checks = {
            "auth_keys_loaded": self._auth_keys_loaded,
            "routing_manager_attached": self.routing_manager is not None,
        }
        payload = self.health_snapshot()
        payload.update(
            {
                "ready": all(checks.values()),
                "status": "ready" if all(checks.values()) else "not_ready",
                "checks": checks,
                "backend": {
                    "host": self.backend_host,
                    "port": self.backend_port,
                },
            }
        )
        return payload

    def _load_keys(self, keys_dir: str) -> None:
        """Load verifier and auth server keypairs; build the signed key block."""
        from pathlib import Path
        kdir = Path(keys_dir)
        ver_priv_der = (kdir / "verifier_private.der").read_bytes()
        auth_priv_der = (kdir / "authserver_private.der").read_bytes()

        vp, vq, vg, vy, vx = won_crypto.decode_private_key(ver_priv_der)
        ap, aq, ag, ay, ax = won_crypto.decode_private_key(auth_priv_der)

        self._ver_p, self._ver_q, self._ver_g = vp, vq, vg
        self._auth_p, self._auth_q, self._auth_g = ap, aq, ag
        self._auth_y, self._auth_x = ay, ax

        self._key_block = won_crypto.build_auth1_pubkey_block(
            auth_p=ap, auth_q=aq, auth_g=ag, auth_y=ay,
            block_id=1,
            ver_p=vp, ver_q=vq, ver_g=vg, ver_x=vx,
        )
        self._auth_keys_loaded = True
        LOGGER.info("Auth1 keys loaded from %s (key_block=%d bytes)", keys_dir, len(self._key_block))

    def _build_user_cert(self, user_id: int) -> Tuple[bytes, int, int]:
        """Generate an ephemeral user keypair and build a signed Auth1Certificate.

        Returns (certificate_bytes, user_y, user_x).
        """
        p, q, g = self._auth_p, self._auth_q, self._auth_g
        # Generate ephemeral user private key
        q_bytes = (q.bit_length() + 7) // 8
        while True:
            ux = int.from_bytes(os.urandom(q_bytes + 4), 'big') % (q - 1) + 1
            uy = pow(g, ux, p)
            if uy > 1:
                break
        cert = won_crypto.build_auth1_certificate(
            user_id=user_id,
            community_id=1,
            trust_level=2,
            user_p=p, user_q=q, user_g=g, user_y=uy,
            auth_p=p, auth_q=q, auth_g=g, auth_x=self._auth_x,
        )
        return cert, uy, ux

    async def _handle_auth1_connection(self, reader: asyncio.StreamReader,
                                        writer: asyncio.StreamWriter,
                                        first_body: bytes) -> None:
        """Handle a stateful Auth1 handshake on a single connection.

        The client may start with either:
          - Auth1GetPubKeys (msg_type=1) — full 4-message flow
          - Auth1LoginRequestHW (msg_type=30) — client already has a cached key block

        Full flow:
          1. Client -> Auth1GetPubKeys       (msg_type=1)
          2. Server -> Auth1GetPubKeysReply   (msg_type=2)
          3. Client -> Auth1LoginRequestHW    (msg_type=30)
          4. Server -> Auth1LoginChallengeHW  (msg_type=32)
          5. Client -> Auth1LoginConfirmHW    (msg_type=33)
          6. Server -> Auth1LoginReply        (msg_type=4)

        Short flow (skips steps 1-2):
          1. Client -> Auth1LoginRequestHW    (msg_type=30)
          2. Server -> Auth1LoginChallengeHW  (msg_type=32)
          3. Client -> Auth1LoginConfirmHW    (msg_type=33)
          4. Server -> Auth1LoginReply        (msg_type=4)
        """
        peer = writer.get_extra_info("peername", ("?", 0))

        # Parse the first message to determine which step we're at
        svc, msg, first_msg_body = won_crypto.parse_tmessage(first_body)
        LOGGER.info("Auth1: first message from %s:%s (svc=%d msg=%d, %d bytes)",
                     *peer, svc, msg, len(first_msg_body))

        if msg == won_crypto.AUTH1_GET_PUB_KEYS:
            # Full flow: send GetPubKeysReply, then wait for LoginRequestHW
            reply = won_crypto.build_auth1_pubkeys_reply(self._key_block)
            writer.write(reply)
            await writer.drain()
            LOGGER.info("Auth1: GetPubKeysReply sent to %s:%s (%d bytes)", *peer, len(reply))

            # Read the next message (should be LoginRequestHW)
            body = await _titan_recv(reader)
            svc, msg, req_body = won_crypto.parse_tmessage(body)
            LOGGER.info("Auth1: next message from %s:%s (svc=%d msg=%d, %d bytes)",
                         *peer, svc, msg, len(req_body))
        elif msg == won_crypto.AUTH1_LOGIN_REQUEST_HW:
            # Short flow: client already has key block, jumped straight to login
            req_body = first_msg_body
            LOGGER.info("Auth1: client skipped GetPubKeys, starting at LoginRequestHW")
        else:
            LOGGER.warning("Auth1: unexpected msg_type=%d from %s:%s, closing", msg, *peer)
            return

        # --- LoginRequestHW processing ---
        login_req = won_crypto.parse_auth1_login_request(req_body)
        LOGGER.info("Auth1: LoginRequestHW block_id=%d eg_len=%d bf_len=%d",
                      login_req['block_id'], len(login_req['eg_ciphertext']), len(login_req['bf_data']))

        # Decrypt the session key from the ElGamal ciphertext
        try:
            session_key = won_crypto.eg_decrypt(
                login_req['eg_ciphertext'],
                self._auth_p, self._auth_g, self._auth_x,
            )
            LOGGER.info("Auth1: Session key decrypted (%d bytes)", len(session_key))
        except Exception as exc:
            LOGGER.error("Auth1: ElGamal decrypt failed: %s", exc)
            return

        client_ip = None
        if isinstance(peer, (tuple, list)) and peer:
            client_ip = str(peer[0])

        native_login = None
        try:
            native_login = won_crypto.parse_auth1_login_payload(login_req["bf_data"], session_key)
            LOGGER.info(
                "Auth1: native login user=%r community=%r create=%s need_key=%s cd_key=%s login_key=%s variant=%s",
                native_login["username"],
                native_login["community_name"],
                native_login["create_account"],
                native_login["need_key"],
                _mask_account_key(str(native_login["cd_key"])),
                _mask_account_key(str(native_login["login_key"])),
                native_login.get("ciphertext_variant", "direct"),
            )
        except Exception as exc:
            LOGGER.warning("Auth1: failed to parse native login payload from %s:%s: %s", *peer, exc)
            return

        backend = await self._call_backend(
            {
                "action": "AUTH_LOGIN_NATIVE",
                "username": str(native_login["username"]),
                "password": str(native_login["password"]),
                "new_password": str(native_login["new_password"]),
                "cd_key": str(native_login["cd_key"]),
                "login_key": str(native_login["login_key"]),
                "create_account": bool(native_login["create_account"]),
                "client_ip": client_ip,
            }
        )
        if not backend.get("ok"):
            error_code = str(backend.get("error", "native_auth_failed"))
            status = _native_auth_error_to_status(error_code)
            LOGGER.warning(
                "Auth1: native login rejected for user=%r from %s:%s error=%s status=%d",
                native_login["username"],
                *peer,
                error_code,
                status,
            )
            try:
                writer.write(won_crypto.build_auth1_login_failure_reply(status))
                await writer.drain()
            except Exception as exc:
                LOGGER.debug("Auth1: failed to send login failure reply to %s:%s: %s", *peer, exc)
            return
        native_result = backend.get("result", {})
        if isinstance(native_result, dict):
            LOGGER.info(
                "Auth1: native account accepted user=%r created=%s cd_key_bound=%s binding_changed=%s",
                native_result.get("username", native_login["username"]),
                bool(native_result.get("created", False)),
                bool(native_result.get("cd_key_bound", False)),
                bool(native_result.get("binding_changed", False)),
            )

        # --- Send LoginChallengeHW ---
        challenge_seed = os.urandom(16)
        challenge_reply = won_crypto.build_auth1_challenge(challenge_seed, session_key)
        writer.write(challenge_reply)
        await writer.drain()
        LOGGER.info("Auth1: ChallengeHW sent to %s:%s", *peer)

        # --- Receive LoginConfirmHW ---
        body = await _titan_recv(reader)
        svc, msg, confirm_body = won_crypto.parse_tmessage(body)
        LOGGER.info("Auth1: ConfirmHW received from %s:%s (svc=%d msg=%d, %d bytes)",
                     *peer, svc, msg, len(confirm_body))
        # We accept any confirm — we're not doing real file hash verification

        # --- Send LoginReply with certificate + client private key ---
        user_id = self._alloc_user_id()
        cert, user_y, user_x = self._build_user_cert(user_id)

        login_reply = self._build_auth1_login_reply_with_key(cert, user_x, session_key)
        writer.write(login_reply)
        await writer.drain()
        LOGGER.info("Auth1: LoginReply sent to %s:%s (user_id=%d, cert=%d bytes)",
                     *peer, user_id, len(cert))

    def _build_auth1_login_reply_with_key(self, cert: bytes, user_x: int,
                                           session_key: bytes) -> bytes:
        """Build Auth1LoginReply containing certificate + encrypted private key.

        Wire layout (TMsgAuth1LoginReply::Pack + EncryptAndPack):
          [u16 LE status=0]
          [u8  error_count=0]
          [u8  num_clear_entries=1]
          [u8  type=1 (ALCertificate)]
          [u16 LE cert_len]
          [cert bytes]
          [BF_encrypt(session_key, [u8 num_crypt=1][u8 type=2][u16 LE key_len][key_der])]

        Clear entries: Certificate (type=1)
        Encrypted entries: ClientPrivateKey (type=2) — encrypted with session key
        """
        p, q, g = self._auth_p, self._auth_q, self._auth_g
        # Encode client private key as DER
        user_y = pow(g, user_x, p)
        priv_key_der = won_crypto.encode_private_key(p, q, g, user_y, user_x)

        body = struct.pack('<H', 0)   # status = Success
        body += bytes([0])            # error_count = 0

        # --- Clear section ---
        body += bytes([1])            # num_clear_entries = 1
        # Clear Entry: Certificate (type=1)
        body += bytes([1])
        body += struct.pack('<H', len(cert))
        body += cert

        # --- Encrypted section ---
        # Build plaintext buffer: [u8 num_crypt_entries][entries...]
        crypt_buf = bytes([1])        # num_crypt_entries = 1
        # Entry: ClientPrivateKey (type=2)
        crypt_buf += bytes([2])
        crypt_buf += struct.pack('<H', len(priv_key_der))
        crypt_buf += priv_key_der
        # Encrypt with session key (Blowfish CBC)
        encrypted = won_crypto.bf_encrypt(crypt_buf, session_key)
        body += encrypted

        return won_crypto.build_tmessage(
            won_crypto.AUTH1_SERVICE_TYPE,
            won_crypto.AUTH1_LOGIN_REPLY,
            body,
        )

    def _alloc_peer_session_id(self) -> int:
        range_size = (self._peer_session_id_max - self._peer_session_id_min) + 1
        for _ in range(range_size):
            session_id = self._next_peer_session_id
            self._next_peer_session_id = (
                self._peer_session_id_min
                if session_id >= self._peer_session_id_max
                else session_id + 1
            )
            if session_id not in self._peer_sessions:
                return session_id
        raise RuntimeError("peer_session_id_exhausted")

    async def _handle_auth1_peer_connection(self, reader: asyncio.StreamReader,
                                             writer: asyncio.StreamWriter,
                                             first_body: bytes) -> None:
        """Handle Auth1PeerToPeer for directory/factory server flows on port 15101."""
        peer = writer.get_extra_info("peername", ("?", 0))
        svc, msg, req_body = won_crypto.parse_tmessage(first_body)
        LOGGER.info(
            "Auth1Peer: first message from %s:%s (svc=%d msg=%d, %d bytes)",
            *peer, svc, msg, len(req_body),
        )
        if svc != AUTH1_PEER_SERVICE_TYPE or msg != AUTH1_PEER_REQUEST:
            LOGGER.warning("Auth1Peer: unexpected first message svc=%d msg=%d", svc, msg)
            return

        req = _parse_auth1_peer_request(req_body)
        client_cert = _parse_auth1_certificate(bytes(req["certificate"]))
        if client_cert["sig"] and not won_crypto.nr_md5_verify(
            bytes(client_cert["unsigned"]),
            bytes(client_cert["sig"]),
            self._auth_p,
            self._auth_q,
            self._auth_g,
            self._auth_y,
        ):
            LOGGER.warning("Auth1Peer: client certificate failed auth-key verification")
            return

        LOGGER.info(
            "Auth1Peer: request auth_mode=%d encrypt_mode=%d flags=0x%04x user_id=%d",
            req["auth_mode"], req["encrypt_mode"], req["encrypt_flags"], client_cert["user_id"],
        )

        server_user_id = self._next_user_id
        self._next_user_id += 1
        server_cert, _server_y, server_x = self._build_user_cert(server_user_id)
        secret_b = os.urandom(8)
        secret_b_plain = struct.pack("<H", len(secret_b)) + secret_b
        secret_b_cipher = won_crypto.eg_encrypt(
            secret_b_plain,
            int(client_cert["p"]),
            int(client_cert["g"]),
            int(client_cert["y"]),
        )

        challenge1 = _build_auth1_peer_challenge1(secret_b_cipher, server_cert)
        writer.write(challenge1)
        await writer.drain()
        LOGGER.info("Auth1Peer: Challenge1 sent to %s:%s", *peer)

        body = await _titan_recv(reader)
        svc, msg, challenge2_body = won_crypto.parse_tmessage(body)
        LOGGER.info(
            "Auth1Peer: next message from %s:%s (svc=%d msg=%d, %d bytes)",
            *peer, svc, msg, len(challenge2_body),
        )
        if svc != AUTH1_PEER_SERVICE_TYPE or msg != AUTH1_PEER_CHALLENGE2:
            LOGGER.warning("Auth1Peer: expected Challenge2, got svc=%d msg=%d", svc, msg)
            return

        challenge2_cipher = _parse_auth1_peer_challenge2(challenge2_body)
        challenge2_plain = won_crypto.eg_decrypt(
            challenge2_cipher,
            self._auth_p,
            self._auth_g,
            server_x,
        )
        if len(challenge2_plain) < 2:
            LOGGER.warning("Auth1Peer: Challenge2 plaintext too short")
            return
        secret_b_len, = struct.unpack("<H", challenge2_plain[:2])
        secret_b_echo = challenge2_plain[2:2 + secret_b_len]
        secret_a = challenge2_plain[2 + secret_b_len:]
        if secret_b_echo != secret_b:
            LOGGER.warning("Auth1Peer: SecretB mismatch from %s:%s", *peer)
            return
        if not secret_a:
            LOGGER.warning("Auth1Peer: empty SecretA from %s:%s", *peer)
            return

        self._expire_peer_sessions()
        session_id = self._alloc_peer_session_id() if req["auth_mode"] == 2 else 0
        secret_a_cipher = won_crypto.eg_encrypt(
            struct.pack("<H", len(secret_a)) + secret_a,
            int(client_cert["p"]),
            int(client_cert["g"]),
            int(client_cert["y"]),
        )
        complete = _build_auth1_peer_complete(secret_a_cipher, session_id)
        writer.write(complete)
        await writer.drain()
        LOGGER.info(
            "Auth1Peer: Complete sent to %s:%s (session_id=%d)",
            *peer, session_id,
        )

        if req["auth_mode"] == 2 and req["encrypt_mode"] == 1 and session_id != 0:
            role = PEER_ROLE_FACTORY if (int(req["encrypt_flags"]) & 0x0001) else PEER_ROLE_DIRECTORY
            sequenced = role == PEER_ROLE_DIRECTORY
            session = PeerSession(secret_b, session_id, role=role, sequenced=sequenced)
            self._peer_sessions[session_id] = session
            self._touch_peer_session(session)
            if role == PEER_ROLE_DIRECTORY:
                await self._handle_directory_session(reader, writer, session)
            elif role == PEER_ROLE_FACTORY:
                await self._handle_factory_session(reader, writer, session)

    async def _handle_directory_session(self, reader: asyncio.StreamReader,
                                         writer: asyncio.StreamWriter,
                                         session: PeerSession,
                                         first_body: Optional[bytes] = None) -> None:
        """Handle post-peer-auth encrypted directory traffic on the same socket."""
        peer = writer.get_extra_info("peername", ("?", 0))
        self._touch_peer_session(session)
        while True:
            if first_body is not None:
                body = first_body
                first_body = None
            else:
                try:
                    body = await _titan_recv(reader)
                except asyncio.IncompleteReadError:
                    return
            if not body:
                return

            if body[0] == 0x06:
                clear = _decrypt_small_session(
                    body,
                    session.session_key,
                    session.session_id,
                    session.in_seq if session.sequenced else None,
                )
                if session.sequenced:
                    session.in_seq += 1
            else:
                LOGGER.warning(
                    "Dir(session): unexpected header 0x%02x from %s:%s",
                    body[0], *peer,
                )
                return

            if len(clear) < 5:
                LOGGER.warning("Dir(session): clear message too short from %s:%s", *peer)
                return

            req = _decode_dir_get(clear)
            self._touch_peer_session(session)
            LOGGER.info(
                "Dir(session): path=%r svc_filter=%r",
                req["path"], req["service_name"],
            )
            reply_clear = await self._titan_dir_get_reply_body(req)
            reply_enc = _encrypt_small_session(
                reply_clear,
                session.session_key,
                session.session_id,
                session.out_seq if session.sequenced else None,
            )
            if session.sequenced:
                session.out_seq += 1
            writer.write(_titan_wrap(reply_enc))
            await writer.drain()
            # Homeworld tears down the dir pipe after handling the reply.
            return

    async def _handle_factory_session(self, reader: asyncio.StreamReader,
                                       writer: asyncio.StreamWriter,
                                       session: PeerSession,
                                       first_body: Optional[bytes] = None) -> None:
        """Handle post-peer-auth encrypted factory traffic on the same socket."""
        peer = writer.get_extra_info("peername", ("?", 0))
        self._touch_peer_session(session)
        if first_body is not None:
            body = first_body
        else:
            try:
                body = await _titan_recv(reader)
            except asyncio.IncompleteReadError:
                return
        if not body:
            return
        if body[0] != 0x06:
            LOGGER.warning(
                "Factory(session): unexpected header 0x%02x from %s:%s",
                body[0], *peer,
            )
            return

        clear = _decrypt_small_session(
            body,
            session.session_key,
            session.session_id,
            None,
        )
        req = _parse_fact_start_process(clear)
        self._touch_peer_session(session)
        LOGGER.info(
            "Factory(session): StartProcess process=%r display=%r register_dir=%r total_ports=%d",
            req["process_name"],
            req["display_name"],
            req["register_dir"],
            req["total_ports"],
        )

        selected_port = self.routing_port
        factory_id = "gateway_factory"
        process_name = str(req["process_name"])
        game_name = self.product_profile.key if process_name == self.product_profile.routing_game_process_name else "chat"
        room_password = _extract_factory_password(str(req["cmd_line"]))
        managed_locally = False

        if self.routing_manager is not None and process_name in {
            self.product_profile.routing_chat_process_name,
            self.product_profile.routing_game_process_name,
        }:
            try:
                selected_port = await self.routing_manager.allocate_server(
                    publish_in_directory=(process_name == self.product_profile.routing_chat_process_name)
                )
                managed_locally = True
                routing_server = self.routing_manager._servers.get(selected_port)
                if routing_server is not None and process_name == self.product_profile.routing_chat_process_name:
                    routing_server._room_password = room_password
            except Exception as exc:
                LOGGER.warning("Factory(session): routing allocation failed: %s", exc)

        if room_password:
            LOGGER.info(
                "Factory(session): extracted room password for %r (len=%d)",
                process_name,
                len(room_password),
            )

        try:
            await self._call_backend(
                {
                    "action": "REGISTER_FACTORY",
                    "factory_id": factory_id,
                    "host": self.public_host,
                    "region": "global",
                    "max_processes": 4,
                }
            )
            if managed_locally:
                LOGGER.info(
                    "Factory(session): using local routing manager for %r on port=%d; "
                    "skipping backend FACTORY_START_PROCESS",
                    process_name,
                    selected_port,
                )
            else:
                backend = await self._call_backend(
                    {
                        "action": "FACTORY_START_PROCESS",
                        "factory_id": factory_id,
                        "process_name": process_name,
                        "game_name": game_name,
                        "port": selected_port,
                    }
                )
                if backend.get("ok"):
                    server = backend.get("server", {})
                    if isinstance(server, dict):
                        selected_port = int(server.get("port", selected_port))
                else:
                    LOGGER.warning(
                        "Factory(session): backend FACTORY_START_PROCESS failed: %s",
                        backend.get("error", "unknown_error"),
                    )
        except Exception as exc:
            LOGGER.warning("Factory(session): backend start-process bridge failed: %s", exc)

        reply_clear = _build_small_fact_status_reply(0, [selected_port])
        reply_enc = _encrypt_small_session(
            reply_clear,
            session.session_key,
            session.session_id,
            None,
        )
        writer.write(_titan_wrap(reply_enc))
        await writer.drain()
        LOGGER.info(
            "Factory(session): StatusReply sent to %s:%s (port=%d)",
            *peer, selected_port,
        )

    async def _handle_titan_packet(
        self,
        packet_hex: str,
        client_ip: Optional[str] = None,
    ) -> Dict[str, object]:
        try:
            packet = binascii.unhexlify(packet_hex.encode("ascii"))
        except Exception:
            return {"ok": False, "error": "invalid_packet_hex"}

        req = decode_request(packet)
        kind = req.get("kind")
        if kind == "auth_login":
            backend = await self._call_backend(
                {
                    "action": "AUTH_LOGIN",
                    "username": req["username"],
                    "password": req["password"],
                    "client_ip": client_ip,
                }
            )
            if backend.get("ok"):
                reply = AuthLoginReply(STATUS_OK, str(backend.get("token", ""))).encode()
            else:
                reply = AuthLoginReply(STATUS_FAIL, str(backend.get("error", "auth_failed"))).encode()
            return {"ok": True, "packet_hex": binascii.hexlify(reply).decode("ascii")}

        if kind == "dir_get":
            backend = await self._call_backend({"action": "TITAN_DIR_GET", "path": req["path"]})
            if backend.get("ok"):
                reply = DirGetReply(STATUS_OK, json.dumps(backend.get("entities", {}))).encode()
            else:
                reply = DirGetReply(STATUS_FAIL, json.dumps({"error": backend.get("error", "dir_failed")})).encode()
            return {"ok": True, "packet_hex": binascii.hexlify(reply).decode("ascii")}

        if kind == "route_register":
            backend = await self._call_backend({"action": "TITAN_ROUTE_REGISTER", "lobby_id": req["lobby_id"], "player_id": req["player_id"]})
            if backend.get("ok"):
                reply = RoutingStatusReply(STATUS_OK, "registered").encode()
            else:
                reply = RoutingStatusReply(STATUS_FAIL, str(backend.get("error", "route_register_failed"))).encode()
            return {"ok": True, "packet_hex": binascii.hexlify(reply).decode("ascii")}

        if kind == "route_join":
            backend = await self._call_backend({"action": "TITAN_ROUTE_JOIN", "lobby_id": req["lobby_id"], "player_id": req["player_id"]})
            if backend.get("ok"):
                reply = RoutingStatusReply(STATUS_OK, "joined").encode()
            else:
                reply = RoutingStatusReply(STATUS_FAIL, str(backend.get("error", "route_join_failed"))).encode()
            return {"ok": True, "packet_hex": binascii.hexlify(reply).decode("ascii")}

        if kind == "route_chat":
            backend = await self._call_backend({"action": "TITAN_ROUTE_CHAT", "lobby_id": req["lobby_id"], "from_player": req["player_id"], "message": req["message"]})
            if backend.get("ok"):
                reply = RoutingChatEvent(STATUS_OK, req["lobby_id"], req["player_id"], req["message"]).encode()
            else:
                reply = RoutingStatusReply(STATUS_FAIL, str(backend.get("error", "route_chat_failed"))).encode()
            return {"ok": True, "packet_hex": binascii.hexlify(reply).decode("ascii")}

        if kind == "route_data_set":
            backend = await self._call_backend({"action": "TITAN_ROUTE_SET_DATA_OBJECT", "lobby_id": req["lobby_id"], "key": req["key"], "value": req["value"]})
            if backend.get("ok"):
                backend2 = await self._call_backend({"action": "TITAN_ROUTE_GET_DATA_OBJECT", "lobby_id": req["lobby_id"], "key": req["key"]})
                if backend2.get("ok"):
                    reply = RoutingDataObjectReply(STATUS_OK, req["key"], str(backend2.get("value", ""))).encode()
                else:
                    reply = RoutingStatusReply(STATUS_FAIL, "data_object_read_failed").encode()
            else:
                reply = RoutingStatusReply(STATUS_FAIL, str(backend.get("error", "route_data_set_failed"))).encode()
            return {"ok": True, "packet_hex": binascii.hexlify(reply).decode("ascii")}

        reply = RoutingStatusReply(STATUS_FAIL, "unknown_message").encode()
        return {"ok": True, "packet_hex": binascii.hexlify(reply).decode("ascii")}

    async def _push_events_loop(self, queue: asyncio.Queue, writer: asyncio.StreamWriter) -> None:
        """Background task: read events from queue, encode as OP_SERVER_EVENT frames, push to client."""
        try:
            while True:
                event = await queue.get()
                try:
                    frame = encode_frame(OP_SERVER_EVENT, event)
                    writer.write(frame)
                    await writer.drain()
                except (ConnectionError, OSError):
                    break
        except asyncio.CancelledError:
            pass

    async def _publish_post_action_events(self, opcode: int, action: Dict[str, object], response: Dict[str, object]) -> None:
        """After event-generating actions, publish to all lobby members via the bus."""
        if not response.get("ok"):
            return

        lobby_id = str(action.get("lobby_id", ""))
        if not lobby_id:
            return

        event: Optional[Dict[str, object]] = None

        if opcode == OP_ROUTE_CHAT:
            event = {
                "type": "chat",
                "lobby_id": lobby_id,
                "from": str(action.get("from_player", "")),
                "message": str(action.get("message", "")),
            }
        elif opcode == OP_JOIN_LOBBY:
            event = {
                "type": "lobby_join",
                "lobby_id": lobby_id,
                "player_id": str(action.get("player_id", "")),
            }
        elif opcode == OP_START_GAME:
            launch = response.get("launch", {})
            if isinstance(launch, dict):
                event = {
                    "type": "game_launch",
                    "lobby_id": lobby_id,
                    "server": launch.get("server", {}),
                    "players": launch.get("players", []),
                    "map_name": launch.get("map_name", ""),
                }
                server = launch.get("server", {})
                if isinstance(server, dict):
                    room_port = server.get("port")
                    try:
                        room_port = int(room_port)
                    except (TypeError, ValueError):
                        room_port = 0
                    if room_port > 0:
                        launch_config = launch.get("launch_config", {})
                        if isinstance(launch_config, dict):
                            self.queue_match_launch_config(
                                room_port=room_port,
                                lobby_title=str(launch_config.get("lobby_title") or ""),
                                map_name=str(launch_config.get("map_name") or launch.get("map_name") or ""),
                                map_code=str(launch_config.get("map_code") or launch.get("map_name") or ""),
                                settings=dict(launch_config.get("settings") or {}),
                                captain_identity=dict(launch_config.get("captain_identity") or {}),
                                players=list(launch_config.get("players") or launch.get("players", [])),
                                transport_mode=str(launch_config.get("transport_mode") or "routed"),
                            )
                        self.queue_match_slot_manifest(
                            room_port=room_port,
                            players=list(launch.get("players", []) or []),
                        )

        if event is None:
            return

        # Fetch lobby members from backend to know who to push to
        try:
            backend_resp = await self._call_backend({"action": "TITAN_DIR_GET", "path": self.product_profile.directory_root})
            entities = backend_resp.get("entities", {})
            lobby_ent = entities.get(lobby_id)
            if isinstance(lobby_ent, dict):
                # Fall back to querying the lobby directly
                pass
        except Exception:
            pass

        # Simpler: query lobby player list directly
        try:
            lobby_resp = await self._call_backend({"action": "LIST_LOBBIES"})
            lobbies = lobby_resp.get("lobbies", [])
            for lob in lobbies:
                if isinstance(lob, dict) and lob.get("lobby_id") == lobby_id:
                    player_ids = lob.get("players", [])
                    if isinstance(player_ids, list):
                        self.event_bus.publish(player_ids, event)
                    return
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Titan native protocol path
    # ------------------------------------------------------------------

    async def _handle_titan_native(self, reader: asyncio.StreamReader,
                                    writer: asyncio.StreamWriter,
                                    first4: bytes) -> None:
        """Handle a connection that speaks the real Titan LE-framed protocol.

        Auth1 connections (ServiceType 0xC9 = 201) are stateful 4-message
        exchanges and are delegated to _handle_auth1_connection.

        Other connections (DirGet etc.) are ONE-SHOT: read one frame, send
        one reply, close.  This mirrors Silencer's ProcessClient15101.
        """
        peer = writer.get_extra_info("peername", ("?", 0))
        LOGGER.info("Titan native connection from %s:%s", *peer)
        try:
            body = await _titan_recv(reader, first4)
            if not body:
                return

            self._expire_peer_sessions()

            if len(body) >= 8:
                try:
                    service_type, message_type, _ = won_crypto.parse_tmessage(body)
                except Exception:
                    service_type = 0
                    message_type = 0
                if service_type == won_crypto.AUTH1_SERVICE_TYPE:
                    if not self._auth_keys_loaded:
                        LOGGER.error("Auth1 request received but no keys loaded (use --keys-dir)")
                        return
                    await self._handle_auth1_connection(reader, writer, body)
                    return
                if service_type == AUTH1_PEER_SERVICE_TYPE:
                    if not self._auth_keys_loaded:
                        LOGGER.error("Auth1Peer request received but no keys loaded (use --keys-dir)")
                        return
                    await self._handle_auth1_peer_connection(reader, writer, body)
                    return

            if len(body) >= 3 and body[0] == 0x06:
                session_id, = struct.unpack("<H", body[1:3])
                session = self._peer_sessions.get(session_id)
                if session is not None:
                    self._touch_peer_session(session)
                    LOGGER.info(
                        "Peer(session): resumed encrypted request from %s:%s (session_id=%d role=%s)",
                        *peer, session_id, session.role,
                    )
                    if session.role == PEER_ROLE_DIRECTORY:
                        await self._handle_directory_session(reader, writer, session, first_body=body)
                    elif session.role == PEER_ROLE_FACTORY:
                        await self._handle_factory_session(reader, writer, session, first_body=body)
                    return
                LOGGER.info(
                    "Peer(session): unknown or expired session_id=%d from %s:%s",
                    session_id,
                    *peer,
                )
                return

            # Non-Auth1: one-shot dispatch (DirGet, etc.)
            version = body[0] if body else 0
            msg_type = body[1] if len(body) > 1 else 0
            LOGGER.debug(
                "Titan msg from %s:%s  ver=0x%02x type=0x%02x len=%d",
                peer[0], peer[1], version, msg_type, len(body),
            )
            reply_bytes = await self._dispatch_titan(version, msg_type, body)
            if reply_bytes:
                writer.write(reply_bytes)
                await writer.drain()
            await asyncio.sleep(1.0)   # mirror Silencer's sleep(1) before close
        except asyncio.IncompleteReadError:
            pass
        except Exception as exc:
            LOGGER.error("Titan native error from %s:%s: %s", *peer, exc)
        finally:
            writer.close()
            await writer.wait_closed()

    async def _dispatch_titan(self, version: int, msg_type: int,
                               body: bytes) -> Optional[bytes]:
        """Route an incoming Titan native message to the appropriate handler.

        Auth1 messages (ServiceType 0xC9) are handled by _handle_auth1_connection
        before reaching this method.  This only handles non-Auth1 one-shot messages.
        """
        if msg_type == 0x02:  # Dir Get Request (SmallMessage)
            try:
                req = _decode_dir_get(body)
                LOGGER.info(
                    "DirGet path=%r svc_filter=%r",
                    req["path"], req["service_name"],
                )
                return await self._titan_dir_get_reply(req)
            except Exception as exc:
                LOGGER.error("DirGet parse error: %s", exc)
                return None
        if (
            len(body) >= 8
            and body[0] == MINI_HEADER_TYPE
            and body[1] == MINI_COMMON_SERVICE
            and body[2] == MINI_COMM_PING
        ):
            try:
                ping = _parse_mini_ping(body)
                LOGGER.info(
                    "MiniPing: request start_tick=%d extended=%s",
                    ping["start_tick"], ping["extended"],
                )
                return _titan_wrap(_build_mini_ping_reply(int(ping["start_tick"])))
            except Exception as exc:
                LOGGER.error("MiniPing parse error: %s", exc)
                return None
        LOGGER.warning(
            "Unhandled Titan msg_type=0x%02x len=%d body=%s",
            msg_type, len(body), body[:64].hex(),
        )
        return None

    async def _titan_dir_get_reply_body(self, req: Dict[str, object]) -> bytes:
        """Build a clear SmallMessage Dir Get reply body.

        Discriminator (service_name / DataObject-type-filter substring matching):
          * "ValidVersions"     → COMBINED WON DirG2MultiEntityReply: service
                                  entries (AuthServer, TitanRoutingServer,
                                  TitanFactoryServer) with net_addr AND DataObjects.
          * "Auth"              → WON DirG2MultiEntityReply with AuthServer entry
          * "Routing"|"Factory" → WON DirG2MultiEntityReply with routing entries
          * anything else       → minimal DirG2MultiEntityReply (fallback)
        """
        path = str(req.get("path", self.product_profile.titan_servers_path))
        svc = str(req.get("service_name", ""))

        try:
            ip_raw = _socket.inet_aton(self.public_host)
        except Exception:
            ip_raw = b"\x7f\x00\x00\x01"
        auth_addr = struct.pack(">H", self.public_port) + ip_raw
        routing_addr = struct.pack(">H", self.routing_port) + ip_raw

        if path == self.product_profile.directory_root:
            LOGGER.info("DirGet: native %s query", self.product_profile.directory_root)
            flags = (
                DIR_GF_DECOMPSERVICES
                | DIR_GF_ADDTYPE
                | DIR_GF_DIRADDNAME
                | DIR_GF_ADDDISPLAYNAME
                | DIR_GF_SERVADDNAME
                | DIR_GF_SERVADDNETADDR
                | DIR_GF_ADDDATAOBJECTS
                | DIR_GF_ADDDOTYPE
                | DIR_GF_ADDDODATA
            )
            entries = []
            factory_entries = []
            if self.routing_manager is not None:
                entries.extend(self.routing_manager.directory_entries())
            if not entries:
                backend = await self._call_backend({"action": "TITAN_DIR_GET", "path": self.product_profile.directory_root})
                if backend.get("ok"):
                    for entity_name, ent in dict(backend.get("entities", {})).items():
                        if not isinstance(ent, dict):
                            continue
                        payload = ent.get("payload", {})
                        if not isinstance(payload, dict):
                            payload = {}
                        if ent.get("entity_type") == "routing_room":
                            display_name = str(payload.get("Description", entity_name))
                            data_objects = []
                            for obj_name in ("Description", "RoomFlags", "__RSClientCount"):
                                if obj_name in payload:
                                    data_objects.append(_pack_directory_data_object(obj_name, payload[obj_name]))
                            entries.append({
                                "type": "S",
                                "name": self.product_profile.routing_service_name,
                                "display_name": display_name,
                                "net_addr": routing_addr,
                                "data_objects": data_objects,
                            })

            titan_backend = await self._call_backend({"action": "TITAN_DIR_GET", "path": self.product_profile.titan_servers_path})
            if titan_backend.get("ok"):
                for entity_name, ent in dict(titan_backend.get("entities", {})).items():
                    if not isinstance(ent, dict):
                        continue
                    entity_name_s = str(entity_name)
                    is_factory = (
                        ent.get("entity_type") == "factory"
                        or entity_name_s.startswith("Factory:")
                        or entity_name_s == self.product_profile.factory_service_name
                    )
                    if not is_factory:
                        continue
                    payload = ent.get("payload", {})
                    if not isinstance(payload, dict):
                        payload = {}
                    display_name = str(payload.get("Description", entity_name_s.split(":", 1)[-1]))
                    data_objects = [
                        _pack_directory_data_object(
                            "Description",
                            payload.get("Description", display_name),
                        )
                    ]
                    for obj_name, default_value in (
                        (self.product_profile.factory_current_object_name, 0),
                        (self.product_profile.factory_total_object_name, 0),
                        ("__ServerUptime", 0),
                    ):
                        data_objects.append(
                            _pack_directory_data_object(obj_name, payload.get(obj_name, default_value))
                        )
                    factory_entries.append({
                        "type": "S",
                        "name": self.product_profile.factory_service_name,
                        "display_name": display_name,
                        "net_addr": auth_addr,
                        "data_objects": data_objects,
                    })

            if not factory_entries:
                factory_entries.append({
                    "type": "S",
                    "name": self.product_profile.factory_service_name,
                    "display_name": self.product_profile.default_factory_display_name,
                    "net_addr": auth_addr,
                    "data_objects": [
                        _pack_directory_data_object("Description", self.product_profile.default_factory_display_name),
                        _pack_directory_data_object(self.product_profile.factory_current_object_name, 0),
                        _pack_directory_data_object(self.product_profile.factory_total_object_name, 0),
                        _pack_directory_data_object("__ServerUptime", 0),
                    ],
                })

            # Homeworld uses factory servers in two different passes:
            # 1. Before HWDS, it records FACTSERVER_ADDRESSES for actual
            #    StartRoutingServer requests.
            # 2. After an HWDS directory marker, it treats factory services as
            #    entries for the "Choose Server" picker UI.
            # So we intentionally publish the same factory set in both places.
            entries.extend(factory_entries)
            entries.append({
                "type": "D",
                "name": self.product_profile.factory_directory_marker,
                "display_name": self.product_profile.factory_directory_marker,
                "data_objects": [],
            })
            entries.extend(factory_entries)
            return _encode_dir_reply_body(flags, entries)

        if self.product_profile.matches_valid_versions_filter(svc):
            version_blob = "\r\n".join(self.valid_versions).encode("ascii")
            LOGGER.info(
                "DirGet: version check (combined)  svc_filter=%r  versions=%r",
                svc, list(self.valid_versions),
            )
            # Homeworld never makes separate Auth/Routing DirGet queries after
            # the version check — it discovers all server addresses from THIS
            # single /TitanServers reply.  GetServiceOp::Init() confirms the
            # standard WON flags are:
            #   DIR_GF_DECOMPSERVICES | DIR_GF_ADDDATAOBJECTS |
            #   DIR_GF_SERVADDNAME    | DIR_GF_SERVADDNETADDR
            # so service entries WITH addresses AND DataObjects come back
            # together in one packet.
            #
            # We return three service entries (AuthServer, TitanRoutingServer,
            # TitanFactoryServer), each carrying the version DataObject so the
            # existing GetVersionOp / GetServiceOp logic is satisfied.
            flags = (
                DIR_GF_DECOMPSERVICES
                | DIR_GF_ADDTYPE
                | DIR_GF_SERVADDNAME
                | DIR_GF_SERVADDNETADDR
                | DIR_GF_ADDDATAOBJECTS
                | DIR_GF_ADDDOTYPE
                | DIR_GF_ADDDODATA
            )
            version_service_name = (svc or self.product_profile.valid_versions_service).encode("ascii")
            ver_do = (version_service_name, version_blob)
            entries = [
                {"type": "S", "name": self.product_profile.auth_service_name, "net_addr": auth_addr, "data_objects": [ver_do]},
                {"type": "S", "name": self.product_profile.routing_service_name, "net_addr": routing_addr, "data_objects": [ver_do]},
                {"type": "S", "name": self.product_profile.factory_service_name, "net_addr": routing_addr, "data_objects": [ver_do]},
            ]
            return _encode_dir_reply_body(flags, entries)

        if self.product_profile.matches_auth_filter(svc):
            # Auth server lives on our Titan port (15101).  Homeworld opens a
            # fresh TCP connection there for the auth exchange.
            LOGGER.info(
                "DirGet: auth server query (svc=%r) → WON reply %s:%s",
                svc, self.public_host, self.public_port,
            )
            flags = (
                DIR_GF_DECOMPSERVICES
                | DIR_GF_ADDTYPE
                | DIR_GF_SERVADDNAME
                | DIR_GF_SERVADDNETADDR
            )
            entries = [{"type": "S", "name": self.product_profile.auth_service_name, "net_addr": auth_addr}]
            return _encode_dir_reply_body(flags, entries)

        if self.product_profile.matches_routing_or_factory_filter(svc):
            # Routing/lobby server lives on port 15100 (SilencerRoutingServer).
            LOGGER.info(
                "DirGet: routing server query (svc=%r) → WON reply %s:%s",
                svc, self.public_host, self.routing_port,
            )
            flags = (
                DIR_GF_DECOMPSERVICES
                | DIR_GF_ADDTYPE
                | DIR_GF_SERVADDNAME
                | DIR_GF_SERVADDNETADDR
            )
            entries = [
                {"type": "S", "name": self.product_profile.routing_service_name, "net_addr": routing_addr},
                {"type": "S", "name": self.product_profile.factory_service_name, "net_addr": routing_addr},
            ]
            return _encode_dir_reply_body(flags, entries)

        # Fallback: minimal DirG2MultiEntityReply with a single service entry.
        name = svc or path.split("/")[-1] or "WONServer"
        # net_addr wire format: [u16 BE port][u32 BE IP]
        # IPAddr::SetSixByte memcpy's into &sin_port, so port comes first.
        net_addr = struct.pack(">H", self.public_port) + ip_raw
        fallback_flags = (
            DIR_GF_DECOMPROOT
            | DIR_GF_DECOMPSERVICES
            | DIR_GF_ADDTYPE
            | DIR_GF_SERVADDPATH
            | DIR_GF_SERVADDNAME
            | DIR_GF_SERVADDNETADDR
            | DIR_GF_ADDDISPLAYNAME
        )
        entries = [{
            "type": "S",
            "name": name,
            "path": path,
            "display_name": name,
            "net_addr": net_addr,
        }]
        LOGGER.info(
            "DirGet reply (fallback): path=%r filter=%r entries=%d addr=%s:%s",
            path, svc, len(entries), self.public_host, self.public_port,
        )
        return _encode_dir_reply_body(fallback_flags, entries)

    async def _titan_dir_get_reply(self, req: Dict[str, object]) -> bytes:
        return _titan_wrap(await self._titan_dir_get_reply_body(req))

    # ------------------------------------------------------------------
    # Custom binary protocol path  (our own framing, big-endian)
    # ------------------------------------------------------------------

    async def _handle_custom_protocol(self, reader: asyncio.StreamReader,
                                       writer: asyncio.StreamWriter,
                                       first4: bytes) -> None:
        ctx = ConnectionContext()
        push_task: Optional[asyncio.Task] = None
        event_queue: Optional[asyncio.Queue] = None
        try:
            hdr = first4
            peer = writer.get_extra_info("peername", ("?", 0))
            while True:
                length = struct.unpack(">I", hdr)[0]
                if length <= 0 or length > 10_000_000:
                    raise ValueError("invalid_frame_length")
                body = await reader.readexactly(length)
                opcode, payload = decode_frame(body)
                action = opcode_to_action(opcode, payload, ctx)
                if action.get("action") == "AUTH_LOGIN":
                    action["client_ip"] = str(peer[0])

                if action.get("action") == "INVALID":
                    response = {"ok": False, "error": action.get("error", "invalid")}
                elif action.get("action") == "UNKNOWN_BINARY_OPCODE":
                    response = {"ok": False, "error": "unknown_binary_opcode", "opcode": opcode}
                else:
                    try:
                        if action.get("action") == "TITAN_MESSAGE":
                            response = await self._handle_titan_packet(
                                str(action.get("packet_hex", "")),
                                client_ip=str(peer[0]),
                            )
                        else:
                            response = await self._call_backend(action)
                    except Exception as exc:
                        response = {"ok": False, "error": str(exc)}

                # State transitions
                if opcode == OP_AUTH_LOGIN and response.get("ok") and isinstance(response.get("token"), str):
                    ctx.token = str(response["token"])
                    ctx.state = ConnState.AUTHED
                if opcode == OP_REGISTER_PLAYER and response.get("ok"):
                    p = response.get("player", {})
                    if isinstance(p, dict) and isinstance(p.get("player_id"), str):
                        ctx.player_id = str(p["player_id"])
                        ctx.state = ConnState.PLAYER_READY
                        # Subscribe to push events once player is ready
                        if event_queue is None and ctx.player_id:
                            event_queue = self.event_bus.subscribe(ctx.player_id)
                            push_task = asyncio.create_task(
                                self._push_events_loop(event_queue, writer)
                            )
                if opcode == OP_ROUTE_REGISTER and response.get("ok"):
                    lid = str(action.get("lobby_id", ""))
                    if lid:
                        ctx.registered_lobbies.add(lid)

                # Send response frame
                writer.write(encode_frame(action_to_response_opcode(opcode), response))
                await writer.drain()

                # Publish events to other connected clients
                await self._publish_post_action_events(opcode, action, response)

                hdr = await reader.readexactly(4)

        except asyncio.IncompleteReadError:
            pass
        except Exception as exc:
            try:
                writer.write(encode_frame(0xFF, {"ok": False, "error": str(exc)}))
                await writer.drain()
            except Exception:
                pass
        finally:
            # Clean up push subscription
            if push_task is not None:
                push_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await push_task
            if event_queue is not None and ctx.player_id:
                self.event_bus.unsubscribe(ctx.player_id, event_queue)
            writer.close()
            await writer.wait_closed()

    # ------------------------------------------------------------------
    # Connection entry point — auto-detects protocol from first 4 bytes
    # ------------------------------------------------------------------

    async def handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter) -> None:
        """Dispatch incoming connections to Titan-native or custom handler."""
        try:
            first4 = await reader.readexactly(4)
        except asyncio.IncompleteReadError:
            return
        is_titan, _ = _is_titan_native(first4)
        if is_titan:
            await self._handle_titan_native(reader, writer, first4)
        else:
            await self._handle_custom_protocol(reader, writer, first4)


class SharedRoutingServerManager:
    def __init__(self, managers: Dict[str, RoutingServerManager]) -> None:
        self._managers = {
            str(product): manager
            for product, manager in managers.items()
            if manager is not None
        }
        first = next(iter(self._managers.values()), None)
        self.host = first.host if first is not None else ""
        self.public_host = first.public_host if first is not None else ""
        self.base_port = first.base_port if first is not None else 0
        self.max_port = max(
            (
                int(manager.max_port or manager.base_port)
                for manager in self._managers.values()
            ),
            default=0,
        )

    def dashboard_snapshot(self) -> Dict[str, object]:
        listener_ports: set[int] = set()
        players: list[Dict[str, object]] = []
        servers: list[Dict[str, object]] = []
        games: list[Dict[str, object]] = []
        rooms: list[Dict[str, object]] = []
        current_ips: set[str] = set()
        current_game_room_count = 0
        next_port_by_product: Dict[str, int] = {}

        for product, manager in self._managers.items():
            snapshot = manager.dashboard_snapshot()
            listener_ports.update(
                int(port) for port in snapshot.get("listener_ports", []) or []
            )
            next_port_by_product[product] = int(snapshot.get("next_port") or 0)
            current_game_room_count += int(
                snapshot.get("current_game_room_count") or 0
            )

            for player in snapshot.get("players", []) or []:
                if not isinstance(player, dict):
                    continue
                row = dict(player)
                row["product"] = product
                players.append(row)
                client_ip = str(row.get("client_ip") or "")
                if client_ip:
                    current_ips.add(client_ip)

            for server in snapshot.get("servers", []) or []:
                if not isinstance(server, dict):
                    continue
                row = dict(server)
                row["product"] = product
                servers.append(row)

            for game in snapshot.get("games", []) or []:
                if not isinstance(game, dict):
                    continue
                row = dict(game)
                row["product"] = product
                games.append(row)

            for room in snapshot.get("rooms", []) or []:
                if not isinstance(room, dict):
                    continue
                row = dict(room)
                row["product"] = product
                rooms.append(row)

        players.sort(
            key=lambda item: (
                str(item.get("product") or ""),
                str(item.get("room_name") or ""),
                str(item.get("client_name") or ""),
                int(item.get("client_id") or 0),
            )
        )
        servers.sort(
            key=lambda item: (
                str(item.get("product") or ""),
                str(item.get("room_name") or ""),
                int(item.get("listen_port") or 0),
            )
        )
        games.sort(
            key=lambda item: (
                str(item.get("product") or ""),
                str(item.get("room_name") or ""),
                str(item.get("name") or ""),
                int(item.get("link_id") or 0),
            )
        )
        rooms.sort(
            key=lambda item: (
                str(item.get("product") or ""),
                int(item.get("listen_port") or 0),
            )
        )

        return {
            "mode": "shared_edge",
            "products": sorted(self._managers),
            "host": self.host,
            "public_host": self.public_host,
            "base_port": self.base_port,
            "max_port": self.max_port,
            "next_port_by_product": next_port_by_product,
            "listener_ports": sorted(listener_ports),
            "room_count": len(rooms),
            "published_room_count": sum(
                1 for room in rooms if room.get("published")
            ),
            "current_player_count": len(players),
            "current_unique_ip_count": len(current_ips),
            "current_game_room_count": current_game_room_count,
            "current_game_count": len(games),
            "players": players,
            "servers": servers,
            "games": games,
            "rooms": rooms,
        }

    def get_server(self, port: int) -> Optional[SilencerRoutingServer]:
        for manager in self._managers.values():
            server = manager.get_server(port)
            if server is not None:
                return server
        return None

    async def admin_kick_player(self, port: int, client_id: int) -> bool:
        for manager in self._managers.values():
            if manager.get_server(port) is not None:
                return await manager.admin_kick_player(port, client_id)
        return False

    async def admin_broadcast(
        self,
        message: str,
        room_port: Optional[int] = None,
    ) -> int:
        if room_port is not None:
            for manager in self._managers.values():
                if manager.get_server(room_port) is not None:
                    return await manager.admin_broadcast(message, room_port)
            return 0
        total = 0
        for manager in self._managers.values():
            total += await manager.admin_broadcast(message)
        return total

    async def close_all(self) -> None:
        for manager in self._managers.values():
            await manager.close_all()


class SharedBinaryGatewayServer:
    def __init__(
        self,
        runtimes: Dict[str, BinaryGatewayServer],
        *,
        default_product_key: str = HOMEWORLD_PRODUCT_PROFILE.key,
    ) -> None:
        if not runtimes:
            raise ValueError("shared_edge_requires_runtimes")
        self.runtimes = dict(runtimes)
        self.default_product_key = (
            default_product_key
            if default_product_key in self.runtimes
            else next(iter(self.runtimes))
        )
        self.default_runtime = self.runtimes[self.default_product_key]
        self.event_bus = self.default_runtime.event_bus
        shared_live_feed_bus = GatewayLiveFeedBus()
        for runtime in self.runtimes.values():
            runtime.live_feed_bus = shared_live_feed_bus
        self.live_feed_bus = shared_live_feed_bus
        self.public_host = self.default_runtime.public_host
        self.public_port = self.default_runtime.public_port
        self.backend_shared_secret = self.default_runtime.backend_shared_secret
        self.backend_timeout_s = self.default_runtime.backend_timeout_s
        shared_activity: Deque[Dict[str, object]] = deque(maxlen=500)
        shared_activity_counts: Dict[str, int] = {}
        shared_ip_activity: Dict[str, Dict[str, object]] = {}
        shared_banned_ips: Dict[str, str] = {}
        for runtime in self.runtimes.values():
            runtime._activity = shared_activity
            runtime._activity_counts = shared_activity_counts
            runtime._ip_activity = shared_ip_activity
            runtime._banned_ips = shared_banned_ips
        self._activity = shared_activity
        self._activity_counts = shared_activity_counts
        self._ip_activity = shared_ip_activity
        self._banned_ips = shared_banned_ips
        self.started_at = time.time()
        self.routing_manager = SharedRoutingServerManager(
            {
                product: runtime.routing_manager
                for product, runtime in self.runtimes.items()
                if runtime.routing_manager is not None
            }
        )

    def _expire_peer_sessions(self) -> int:
        expired = 0
        for runtime in self.runtimes.values():
            expired += runtime._expire_peer_sessions()
        return expired

    def _runtime_for_native_login(
        self,
        native_login: Dict[str, object],
    ) -> BinaryGatewayServer:
        community_name = str(native_login.get("community_name") or "").strip().lower()
        for runtime in self.runtimes.values():
            if runtime.product_profile.community_name.strip().lower() == community_name:
                return runtime
        return self.default_runtime

    def _runtime_for_dir_request(
        self,
        req: Dict[str, object],
    ) -> BinaryGatewayServer:
        path = str(req.get("path") or "")
        service_name = str(req.get("service_name") or "")
        if service_name:
            for runtime in self.runtimes.values():
                profile = runtime.product_profile
                if service_name == profile.valid_versions_service:
                    return runtime
        for runtime in self.runtimes.values():
            profile = runtime.product_profile
            if path == profile.directory_root or path.startswith(profile.directory_root + "/"):
                return runtime
            if profile.matches_valid_versions_filter(service_name):
                return runtime
            if path == profile.titan_servers_path and (
                profile.matches_auth_filter(service_name)
                or profile.matches_routing_or_factory_filter(service_name)
            ):
                return runtime
        return self.default_runtime

    def _runtime_for_user_id(self, user_id: int) -> Optional[BinaryGatewayServer]:
        for runtime in self.runtimes.values():
            if int(user_id) in runtime._issued_user_ids:
                return runtime
        return None

    def _runtime_for_peer_session(
        self,
        session_id: int,
    ) -> Optional[BinaryGatewayServer]:
        for runtime in self.runtimes.values():
            if int(session_id) in runtime._peer_sessions:
                return runtime
        return None

    def start_background_tasks(self) -> None:
        for runtime in self.runtimes.values():
            runtime.start_background_tasks()

    async def stop_background_tasks(self) -> None:
        for runtime in self.runtimes.values():
            await runtime.stop_background_tasks()

    def record_activity(self, *args: object, **kwargs: object) -> None:
        self.default_runtime.record_activity(*args, **kwargs)

    def ban_ip(self, ip: str, reason: str = "") -> None:
        self.default_runtime.ban_ip(ip, reason)

    def unban_ip(self, ip: str) -> bool:
        return self.default_runtime.unban_ip(ip)

    def clear_activity(self) -> None:
        self.default_runtime.clear_activity()

    def subscribe_live_feed(self, maxsize: int = 1024) -> asyncio.Queue:
        return self.live_feed_bus.subscribe(maxsize=maxsize)

    def unsubscribe_live_feed(self, queue: asyncio.Queue) -> None:
        self.live_feed_bus.unsubscribe(queue)

    async def _handle_auth1_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        first_body: bytes,
    ) -> None:
        auth_runtime = self.default_runtime
        peer = writer.get_extra_info("peername", ("?", 0))
        svc, msg, first_msg_body = won_crypto.parse_tmessage(first_body)
        LOGGER.info(
            "Auth1(shared): first message from %s:%s (svc=%d msg=%d, %d bytes)",
            *peer,
            svc,
            msg,
            len(first_msg_body),
        )

        if msg == won_crypto.AUTH1_GET_PUB_KEYS:
            reply = won_crypto.build_auth1_pubkeys_reply(auth_runtime._key_block)
            writer.write(reply)
            await writer.drain()
            LOGGER.info(
                "Auth1(shared): GetPubKeysReply sent to %s:%s (%d bytes)",
                *peer,
                len(reply),
            )

            body = await _titan_recv(reader)
            svc, msg, req_body = won_crypto.parse_tmessage(body)
            LOGGER.info(
                "Auth1(shared): next message from %s:%s (svc=%d msg=%d, %d bytes)",
                *peer,
                svc,
                msg,
                len(req_body),
            )
        elif msg == won_crypto.AUTH1_LOGIN_REQUEST_HW:
            req_body = first_msg_body
            LOGGER.info("Auth1(shared): client skipped GetPubKeys, starting at LoginRequestHW")
        else:
            LOGGER.warning(
                "Auth1(shared): unexpected msg_type=%d from %s:%s, closing",
                msg,
                *peer,
            )
            return

        login_req = won_crypto.parse_auth1_login_request(req_body)
        LOGGER.info(
            "Auth1(shared): LoginRequestHW block_id=%d eg_len=%d bf_len=%d",
            login_req["block_id"],
            len(login_req["eg_ciphertext"]),
            len(login_req["bf_data"]),
        )

        try:
            session_key = won_crypto.eg_decrypt(
                login_req["eg_ciphertext"],
                auth_runtime._auth_p,
                auth_runtime._auth_g,
                auth_runtime._auth_x,
            )
            LOGGER.info(
                "Auth1(shared): Session key decrypted (%d bytes)",
                len(session_key),
            )
        except Exception as exc:
            LOGGER.error("Auth1(shared): ElGamal decrypt failed: %s", exc)
            return

        client_ip = None
        if isinstance(peer, (tuple, list)) and peer:
            client_ip = str(peer[0])

        try:
            native_login = won_crypto.parse_auth1_login_payload(
                login_req["bf_data"],
                session_key,
            )
        except Exception as exc:
            LOGGER.warning(
                "Auth1(shared): failed to parse native login payload from %s:%s: %s",
                *peer,
                exc,
            )
            return

        runtime = self._runtime_for_native_login(native_login)
        LOGGER.info(
            "Auth1(shared): classified user=%r community=%r -> product=%s",
            native_login["username"],
            native_login["community_name"],
            runtime.product_profile.key,
        )

        backend = await runtime._call_backend(
            {
                "action": "AUTH_LOGIN_NATIVE",
                "username": str(native_login["username"]),
                "password": str(native_login["password"]),
                "new_password": str(native_login["new_password"]),
                "cd_key": str(native_login["cd_key"]),
                "login_key": str(native_login["login_key"]),
                "create_account": bool(native_login["create_account"]),
                "client_ip": client_ip,
            }
        )
        if not backend.get("ok"):
            error_code = str(backend.get("error", "native_auth_failed"))
            status = _native_auth_error_to_status(error_code)
            LOGGER.warning(
                "Auth1(shared): native login rejected for user=%r from %s:%s error=%s status=%d product=%s",
                native_login["username"],
                *peer,
                error_code,
                status,
                runtime.product_profile.key,
            )
            with contextlib.suppress(Exception):
                writer.write(won_crypto.build_auth1_login_failure_reply(status))
                await writer.drain()
            return

        challenge_seed = os.urandom(16)
        challenge_reply = won_crypto.build_auth1_challenge(challenge_seed, session_key)
        writer.write(challenge_reply)
        await writer.drain()
        LOGGER.info("Auth1(shared): ChallengeHW sent to %s:%s", *peer)

        body = await _titan_recv(reader)
        svc, msg, confirm_body = won_crypto.parse_tmessage(body)
        LOGGER.info(
            "Auth1(shared): ConfirmHW received from %s:%s (svc=%d msg=%d, %d bytes)",
            *peer,
            svc,
            msg,
            len(confirm_body),
        )

        user_id = runtime._alloc_user_id()
        cert, _user_y, user_x = runtime._build_user_cert(user_id)
        login_reply = runtime._build_auth1_login_reply_with_key(cert, user_x, session_key)
        writer.write(login_reply)
        await writer.drain()
        LOGGER.info(
            "Auth1(shared): LoginReply sent to %s:%s (product=%s user_id=%d cert=%d bytes)",
            *peer,
            runtime.product_profile.key,
            user_id,
            len(cert),
        )

    async def _handle_titan_native(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        first4: bytes,
    ) -> None:
        peer = writer.get_extra_info("peername", ("?", 0))
        LOGGER.info("Titan native connection from %s:%s", *peer)
        try:
            body = await _titan_recv(reader, first4)
            if not body:
                return

            self._expire_peer_sessions()

            if len(body) >= 8:
                try:
                    service_type, message_type, req_body = won_crypto.parse_tmessage(body)
                except Exception:
                    service_type = 0
                    message_type = 0
                    req_body = b""
                if service_type == won_crypto.AUTH1_SERVICE_TYPE:
                    if not self.default_runtime._auth_keys_loaded:
                        LOGGER.error("Auth1 request received but no keys loaded (use --keys-dir)")
                        return
                    await self._handle_auth1_connection(reader, writer, body)
                    return
                if service_type == AUTH1_PEER_SERVICE_TYPE:
                    if not self.default_runtime._auth_keys_loaded:
                        LOGGER.error("Auth1Peer request received but no keys loaded (use --keys-dir)")
                        return
                    runtime = self.default_runtime
                    with contextlib.suppress(Exception):
                        req = _parse_auth1_peer_request(req_body)
                        client_cert = _parse_auth1_certificate(bytes(req["certificate"]))
                        runtime = (
                            self._runtime_for_user_id(int(client_cert["user_id"]))
                            or self.default_runtime
                        )
                    LOGGER.info(
                        "Auth1Peer(shared): dispatching %s:%s to product=%s",
                        *peer,
                        runtime.product_profile.key,
                    )
                    await runtime._handle_auth1_peer_connection(reader, writer, body)
                    return

            if len(body) >= 3 and body[0] == 0x06:
                session_id, = struct.unpack("<H", body[1:3])
                runtime = self._runtime_for_peer_session(session_id)
                if runtime is not None:
                    session = runtime._peer_sessions.get(session_id)
                    if session is not None:
                        runtime._touch_peer_session(session)
                        LOGGER.info(
                            "Peer(session/shared): resumed encrypted request from %s:%s (product=%s session_id=%d role=%s)",
                            *peer,
                            runtime.product_profile.key,
                            session_id,
                            session.role,
                        )
                        if session.role == PEER_ROLE_DIRECTORY:
                            await runtime._handle_directory_session(
                                reader,
                                writer,
                                session,
                                first_body=body,
                            )
                        elif session.role == PEER_ROLE_FACTORY:
                            await runtime._handle_factory_session(
                                reader,
                                writer,
                                session,
                                first_body=body,
                            )
                        return
                LOGGER.info(
                    "Peer(session/shared): unknown or expired session_id=%d from %s:%s",
                    session_id,
                    *peer,
                )
                return

            if len(body) >= 2 and body[1] == 0x02:
                try:
                    req = _decode_dir_get(body)
                    runtime = self._runtime_for_dir_request(req)
                    LOGGER.info(
                        "DirGet(shared): path=%r svc_filter=%r -> product=%s",
                        req["path"],
                        req["service_name"],
                        runtime.product_profile.key,
                    )
                    reply_bytes = await runtime._titan_dir_get_reply(req)
                    if reply_bytes:
                        writer.write(reply_bytes)
                        await writer.drain()
                    await asyncio.sleep(1.0)
                    return
                except Exception as exc:
                    LOGGER.error("DirGet(shared) parse error: %s", exc)
                    return

            reply_bytes = await self.default_runtime._dispatch_titan(
                body[0] if body else 0,
                body[1] if len(body) > 1 else 0,
                body,
            )
            if reply_bytes:
                writer.write(reply_bytes)
                await writer.drain()
            await asyncio.sleep(1.0)
        except asyncio.IncompleteReadError:
            pass
        except Exception as exc:
            LOGGER.error("Titan native error from %s:%s: %s", *peer, exc)
        finally:
            writer.close()
            with contextlib.suppress(ConnectionResetError, BrokenPipeError, ConnectionAbortedError, OSError):
                await writer.wait_closed()

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            first4 = await reader.readexactly(4)
        except asyncio.IncompleteReadError:
            return
        is_titan, _ = _is_titan_native(first4)
        if is_titan:
            await self._handle_titan_native(reader, writer, first4)
        else:
            await self.default_runtime._handle_custom_protocol(reader, writer, first4)

    def stats_snapshot(self) -> Dict[str, object]:
        routing_snapshot = self.routing_manager.dashboard_snapshot()
        rooms_raw = routing_snapshot.get("rooms", [])
        servers_raw = routing_snapshot.get("servers", [])
        players_raw = routing_snapshot.get("players", [])
        games_raw = routing_snapshot.get("games", [])

        room_is_game: Dict[int, bool] = {}
        room_reconnect_counts: Dict[int, int] = {}
        room_data_object_counts: Dict[int, int] = {}
        room_peer_data_messages: Dict[int, int] = {}
        room_peer_data_bytes: Dict[int, int] = {}
        room_game_data_bytes: Dict[int, int] = {}
        reconnecting_players: list[Dict[str, object]] = []

        for room in rooms_raw:
            if not isinstance(room, dict):
                continue
            port = int(room.get("listen_port") or 0)
            room_is_game[port] = bool(room.get("is_game_room", False))
            room_data_object_counts[port] = int(
                room.get("data_object_count")
                or len(room.get("data_objects", []) or [])
            )
            pending_reconnects = room.get("pending_reconnects", []) or []
            room_reconnect_counts[port] = len(pending_reconnects)
            room_name = str(room.get("room_display_name") or room.get("room_name") or "")
            room_product = str(room.get("product") or "")
            for reservation in pending_reconnects:
                if not isinstance(reservation, dict):
                    continue
                reconnecting_players.append(
                    {
                        "product": room_product,
                        "name": str(reservation.get("client_name") or ""),
                        "client_id": int(reservation.get("client_id") or 0),
                        "room_name": room_name,
                        "room_port": port,
                        "seconds_remaining": int(reservation.get("seconds_remaining") or 0),
                        "last_activity_kind": str(reservation.get("last_activity_kind") or ""),
                    }
                )

        players: list[Dict[str, object]] = []
        for player in players_raw:
            if not isinstance(player, dict):
                continue
            room_port = int(player.get("room_port") or 0)
            peer_data_messages = int(player.get("peer_data_messages") or 0)
            peer_data_bytes = int(player.get("peer_data_bytes") or 0)
            room_peer_data_messages[room_port] = room_peer_data_messages.get(room_port, 0) + peer_data_messages
            room_peer_data_bytes[room_port] = room_peer_data_bytes.get(room_port, 0) + peer_data_bytes
            players.append(
                {
                    "product": str(player.get("product") or ""),
                    "name": str(player.get("client_name") or ""),
                    "client_id": int(player.get("client_id") or 0),
                    "room_name": str(player.get("room_name") or ""),
                    "room_port": room_port,
                    "state": "game" if room_is_game.get(room_port, False) else "lobby",
                    "connected_seconds": int(player.get("connected_seconds") or 0),
                    "idle_seconds": int(player.get("idle_seconds") or 0),
                    "last_activity_kind": str(player.get("last_activity_kind") or ""),
                    "peer_data_messages": peer_data_messages,
                    "peer_data_bytes": peer_data_bytes,
                }
            )

        rooms: list[Dict[str, object]] = []
        for room in servers_raw:
            if not isinstance(room, dict):
                continue
            port = int(room.get("listen_port") or 0)
            rooms.append(
                {
                    "product": str(room.get("product") or ""),
                    "name": str(room.get("room_name") or ""),
                    "port": port,
                    "description": str(room.get("room_description") or ""),
                    "path": str(room.get("room_path") or ""),
                    "published": bool(room.get("published", False)),
                    "password_protected": bool(room.get("room_password_set", False)),
                    "player_count": int(room.get("player_count") or 0),
                    "game_count": int(room.get("game_count") or 0),
                    "active_game_count": 1 if room_is_game.get(port, False) else 0,
                    "is_game_room": bool(room_is_game.get(port, False)),
                    "reconnecting_count": int(room_reconnect_counts.get(port, 0)),
                    "peer_data_messages": int(room_peer_data_messages.get(port, 0)),
                    "peer_data_bytes": int(room_peer_data_bytes.get(port, 0)),
                    "game_data_bytes": int(room_game_data_bytes.get(port, 0)),
                    "data_object_count": int(room_data_object_counts.get(port, 0)),
                }
            )

        games: list[Dict[str, object]] = []
        for game in games_raw:
            if not isinstance(game, dict):
                continue
            room_port = int(game.get("room_port") or 0)
            data_len = int(game.get("data_len") or 0)
            room_game_data_bytes[room_port] = room_game_data_bytes.get(room_port, 0) + data_len
            games.append(
                {
                    "product": str(game.get("product") or ""),
                    "name": str(game.get("name") or ""),
                    "owner_name": str(game.get("owner_name") or ""),
                    "room_name": str(game.get("room_name") or ""),
                    "room_port": room_port,
                    "link_id": int(game.get("link_id") or 0),
                    "lifespan": int(game.get("lifespan") or 0),
                    "data_len": data_len,
                    "data_preview_hex": str(game.get("data_preview_hex") or ""),
                }
            )

        for room in rooms:
            port = int(room["port"])
            room["game_data_bytes"] = int(room_game_data_bytes.get(port, 0))

        traffic = {
            "peer_data_messages_total": sum(room_peer_data_messages.values()),
            "peer_data_bytes_total": sum(room_peer_data_bytes.values()),
            "game_object_count": len(games),
            "game_object_bytes_total": sum(int(game["data_len"]) for game in games),
        }

        return {
            "generated_at": time.time(),
            "server": {
                "product": "shared-edge",
                "community_name": " / ".join(
                    runtime.product_profile.community_name
                    for runtime in self.runtimes.values()
                ),
                "directory_root": "multiple",
                "valid_versions_service": "multiple",
                "public_host": self.public_host,
                "public_port": self.default_runtime.public_port,
                "routing_port": 0,
                "routing_max_port": 0,
                "version": "multi",
                "valid_versions": sorted(
                    {
                        version
                        for runtime in self.runtimes.values()
                        for version in runtime.valid_versions
                    }
                ),
                "products": [
                    {
                        "product": runtime.product_profile.key,
                        "community_name": runtime.product_profile.community_name,
                        "directory_root": runtime.product_profile.directory_root,
                        "valid_versions_service": runtime.product_profile.valid_versions_service,
                        "routing_port": runtime.routing_port,
                        "routing_max_port": runtime.routing_max_port,
                        "version": runtime.version_str,
                        "valid_versions": list(runtime.valid_versions),
                        "backend_host": runtime.backend_host,
                        "backend_port": runtime.backend_port,
                    }
                    for runtime in self.runtimes.values()
                ],
            },
            "counts": {
                "players_online": len(players),
                "rooms_open": len(rooms),
                "rooms_published": sum(1 for room in rooms if room["published"]),
                "games_live": sum(1 for room in rooms if room["is_game_room"]),
                "unique_ips": int(routing_snapshot.get("current_unique_ip_count") or 0),
                "players_reconnecting": len(reconnecting_players),
            },
            "traffic": traffic,
            "players": players,
            "reconnecting_players": reconnecting_players,
            "rooms": rooms,
            "games": games,
        }

    def dashboard_snapshot(self, activity_limit: int = 150) -> Dict[str, object]:
        self.default_runtime._prune_ip_activity()
        routing_snapshot = self.routing_manager.dashboard_snapshot()
        peer_sessions: Dict[str, Dict[str, object]] = {}
        for product, runtime in self.runtimes.items():
            for session_id, session in sorted(runtime._peer_sessions.items()):
                peer_sessions[f"{product}:{session_id}"] = {
                    "product": product,
                    "role": session.role,
                    "session_id": session.session_id,
                    "sequenced": session.sequenced,
                    "in_seq": session.in_seq,
                    "out_seq": session.out_seq,
                    "created_at": session.created_at,
                    "last_used_at": session.last_used_at,
                    "session_key_len": len(session.session_key),
                }

        return {
            "product": "shared-edge",
            "community_name": " / ".join(
                runtime.product_profile.community_name
                for runtime in self.runtimes.values()
            ),
            "directory_root": "multiple",
            "valid_versions_service": "multiple",
            "public_host": self.public_host,
            "public_port": self.default_runtime.public_port,
            "routing_port": 0,
            "backend_host": "",
            "backend_port": 0,
            "version_str": "multi",
            "valid_versions": sorted(
                {
                    version
                    for runtime in self.runtimes.values()
                    for version in runtime.valid_versions
                }
            ),
            "auth_keys_loaded": all(
                runtime._auth_keys_loaded for runtime in self.runtimes.values()
            ),
            "next_user_id": {
                product: runtime._next_user_id
                for product, runtime in self.runtimes.items()
            },
            "peer_session_count": len(peer_sessions),
            "activity_metrics": {
                "join_count": self._activity_counts.get("join", 0),
                "leave_count": self._activity_counts.get("leave", 0),
                "chat_count": self._activity_counts.get("chat", 0),
                "room_open_count": self._activity_counts.get("room_open", 0),
                "unique_ip_count": len(self._ip_activity),
            },
            "activity": self.default_runtime._activity_snapshot(
                limit=activity_limit,
                base_ports_by_product={
                    product: int(runtime.routing_port)
                    for product, runtime in self.runtimes.items()
                },
            ),
            "ip_metrics": self.default_runtime._ip_activity_snapshot(limit=50),
            "peer_sessions": peer_sessions,
            "routing_manager": routing_snapshot,
            "products": {
                product: {
                    "community_name": runtime.product_profile.community_name,
                    "directory_root": runtime.product_profile.directory_root,
                    "valid_versions_service": runtime.product_profile.valid_versions_service,
                    "routing_port": runtime.routing_port,
                    "routing_max_port": runtime.routing_max_port,
                    "backend_host": runtime.backend_host,
                    "backend_port": runtime.backend_port,
                    "version_str": runtime.version_str,
                    "valid_versions": list(runtime.valid_versions),
                }
                for product, runtime in self.runtimes.items()
            },
            "banned_ips": [
                {"ip": ip, "reason": reason}
                for ip, reason in sorted(self._banned_ips.items())
            ],
        }

    def health_snapshot(self) -> Dict[str, object]:
        return {
            "ok": True,
            "status": "ok",
            "shared_edge": True,
            "product": "shared-edge",
            "community_name": " / ".join(
                runtime.product_profile.community_name
                for runtime in self.runtimes.values()
            ),
            "public_host": self.public_host,
            "public_port": self.default_runtime.public_port,
            "routing_port": 0,
            "uptime_seconds": int(max(0.0, time.time() - self.started_at)),
            "products": sorted(self.runtimes),
        }

    def readiness_snapshot(self) -> Dict[str, object]:
        product_checks = {
            product: {
                "auth_keys_loaded": runtime._auth_keys_loaded,
                "routing_manager_attached": runtime.routing_manager is not None,
                "backend_host": runtime.backend_host,
                "backend_port": runtime.backend_port,
                "routing_port": runtime.routing_port,
            }
            for product, runtime in self.runtimes.items()
        }
        ready = bool(product_checks) and all(
            checks["auth_keys_loaded"] and checks["routing_manager_attached"]
            for checks in product_checks.values()
        )
        payload = self.health_snapshot()
        payload.update(
            {
                "ready": ready,
                "status": "ready" if ready else "not_ready",
                "checks": {
                    "routing_manager_attached": self.routing_manager is not None,
                    "runtime_count": len(product_checks),
                },
                "products": product_checks,
            }
        )
        return payload


def _default_gateway_db_path(product_profile: ProductProfile) -> Path:
    return (
        Path(__file__).resolve().parent.parent
        / "data"
        / product_profile.key
        / "won_server.db"
    )


def _default_gateway_keys_dir(product_profile: ProductProfile) -> Path:
    repo_root = Path(__file__).resolve().parent.parent
    product_keys = repo_root / "data" / product_profile.key / "keys"
    if product_keys.exists():
        return product_keys
    return repo_root / "keys"


def _resolve_gateway_runtime_config(
    args: argparse.Namespace,
) -> tuple[ProductProfile, str, list[str], str, Optional[str]]:
    product_profile = product_profile_from_name(
        getattr(args, "product", HOMEWORLD_PRODUCT_PROFILE.key)
    )
    return _resolve_gateway_runtime_config_for_profile(
        product_profile,
        version_str=getattr(args, "version_str", ""),
        valid_version_values=list(getattr(args, "valid_version", []) or []),
        valid_versions_file=getattr(args, "valid_versions_file", None),
        db_path=getattr(args, "db_path", ""),
        keys_dir=getattr(args, "keys_dir", ""),
    )


def _resolve_gateway_runtime_config_for_profile(
    product_profile: ProductProfile,
    *,
    version_str: str = "",
    valid_version_values: list[str] | None = None,
    valid_versions_file: Optional[str] = None,
    db_path: str = "",
    keys_dir: Optional[str] = None,
) -> tuple[ProductProfile, str, list[str], str, Optional[str]]:
    valid_versions: list[str] = []
    if valid_versions_file:
        raw = Path(valid_versions_file).read_text(encoding="utf-8")
        valid_versions.extend(_parse_valid_versions_text(raw))
    if valid_version_values:
        for value in valid_version_values:
            valid_versions.extend(_parse_valid_versions_text(value))
    if not valid_versions and str(version_str or "").strip():
        valid_versions.extend(_parse_valid_versions_text(version_str))
    if not valid_versions:
        valid_versions.extend(product_profile.backend_valid_versions)

    version_str = str(valid_versions[0] if valid_versions else "").strip()
    db_path = str(db_path or "").strip()
    if not db_path:
        db_path = str(_default_gateway_db_path(product_profile))
    keys_dir = str(keys_dir or "").strip() or None
    if not keys_dir:
        keys_dir = str(_default_gateway_keys_dir(product_profile))
    return product_profile, version_str, valid_versions, db_path, keys_dir


def _resolve_shared_routing_ranges(
    args: argparse.Namespace,
) -> Dict[str, tuple[int, int]]:
    overall_start = int(args.routing_port)
    overall_end = int(args.routing_max_port)
    if overall_end <= overall_start:
        raise ValueError("shared_edge_requires_routing_max_port_greater_than_routing_port")

    total_ports = (overall_end - overall_start) + 1
    if total_ports < 4:
        raise ValueError("shared_edge_requires_at_least_4_routing_ports")

    cat_start = int(getattr(args, "cataclysm_routing_port", 0) or 0)
    if cat_start <= 0:
        cat_start = overall_start + max(1, total_ports // 2)

    home_max = int(getattr(args, "homeworld_routing_max_port", 0) or 0)
    if home_max <= 0:
        home_max = cat_start - 1

    cat_max = int(getattr(args, "cataclysm_routing_max_port", 0) or 0)
    if cat_max <= 0:
        cat_max = overall_end

    if home_max < overall_start:
        raise ValueError("shared_edge_homeworld_range_invalid")
    if cat_start <= home_max:
        raise ValueError("shared_edge_requires_non_overlapping_routing_ranges")
    if cat_max < cat_start or cat_max > overall_end:
        raise ValueError("shared_edge_cataclysm_range_invalid")

    excluded = {int(args.port), int(args.firewall_port)}
    if overall_start in excluded or cat_start in excluded:
        raise ValueError("shared_edge_routing_port_conflicts_with_public_or_firewall_port")

    return {
        HOMEWORLD_PRODUCT_PROFILE.key: (overall_start, home_max),
        CATACLYSM_PRODUCT_PROFILE.key: (cat_start, cat_max),
    }


def _resolve_shared_gateway_config(
    args: argparse.Namespace,
) -> Dict[str, object]:
    ranges = _resolve_shared_routing_ranges(args)
    home_profile, home_version, home_versions, home_db_path, home_keys_dir = (
        _resolve_gateway_runtime_config_for_profile(
            HOMEWORLD_PRODUCT_PROFILE,
            version_str=getattr(args, "version_str", ""),
            valid_version_values=list(getattr(args, "valid_version", []) or []),
            valid_versions_file=getattr(args, "valid_versions_file", None),
            db_path=getattr(args, "db_path", ""),
            keys_dir=getattr(args, "keys_dir", ""),
        )
    )
    cat_profile, cat_version, cat_versions, cat_db_path, cat_keys_dir = (
        _resolve_gateway_runtime_config_for_profile(
            CATACLYSM_PRODUCT_PROFILE,
            version_str=str(getattr(args, "cataclysm_version_str", "") or ""),
            valid_version_values=list(getattr(args, "cataclysm_valid_version", []) or []),
            valid_versions_file=getattr(args, "cataclysm_valid_versions_file", None),
            db_path=str(getattr(args, "cataclysm_db_path", "") or ""),
            keys_dir=str(getattr(args, "cataclysm_keys_dir", "") or home_keys_dir or ""),
        )
    )

    default_product_key = str(getattr(args, "product", HOMEWORLD_PRODUCT_PROFILE.key) or "").strip().lower()
    if default_product_key not in {HOMEWORLD_PRODUCT_PROFILE.key, CATACLYSM_PRODUCT_PROFILE.key}:
        default_product_key = HOMEWORLD_PRODUCT_PROFILE.key

    return {
        "default_product_key": default_product_key,
        "admin_db_path": home_db_path if default_product_key == HOMEWORLD_PRODUCT_PROFILE.key else cat_db_path,
        "runtimes": {
            HOMEWORLD_PRODUCT_PROFILE.key: {
                "product_profile": home_profile,
                "backend_host": str(args.backend_host),
                "backend_port": int(args.backend_port),
                "version_str": home_version,
                "valid_versions": home_versions,
                "db_path": home_db_path,
                "keys_dir": home_keys_dir,
                "routing_port": ranges[HOMEWORLD_PRODUCT_PROFILE.key][0],
                "routing_max_port": ranges[HOMEWORLD_PRODUCT_PROFILE.key][1],
                "user_id_start": 1000,
                "peer_session_id_min": 1,
                "peer_session_id_max": 32767,
            },
            CATACLYSM_PRODUCT_PROFILE.key: {
                "product_profile": cat_profile,
                "backend_host": str(getattr(args, "cataclysm_backend_host", "") or args.backend_host),
                "backend_port": int(getattr(args, "cataclysm_backend_port", 0) or (int(args.backend_port) + 1)),
                "version_str": cat_version,
                "valid_versions": cat_versions,
                "db_path": cat_db_path,
                "keys_dir": cat_keys_dir,
                "routing_port": ranges[CATACLYSM_PRODUCT_PROFILE.key][0],
                "routing_max_port": ranges[CATACLYSM_PRODUCT_PROFILE.key][1],
                "user_id_start": 1_000_000,
                "peer_session_id_min": 32768,
                "peer_session_id_max": MAX_PEER_SESSION_ID,
            },
        },
    }


async def main_async(args: argparse.Namespace) -> None:
    event_bus = GatewayEventBus()
    if args.admin_port > 0 and not _is_loopback_host(args.admin_host) and not str(args.admin_token or "").strip():
        raise ValueError("Refusing to expose the admin dashboard on a non-loopback host without --admin-token.")
    db_path = ""
    db_paths: Dict[str, str] = {}
    default_db_product = ""
    routing_managers: list[RoutingServerManager] = []
    routing_servers: list[asyncio.base_events.Server] = []

    if getattr(args, "shared_edge", False):
        shared_config = _resolve_shared_gateway_config(args)
        runtimes: Dict[str, BinaryGatewayServer] = {}
        for product_key, runtime_config in dict(shared_config["runtimes"]).items():
            product_profile = runtime_config["product_profile"]
            runtime = BinaryGatewayServer(
                str(runtime_config["backend_host"]),
                int(runtime_config["backend_port"]),
                event_bus,
                public_host=args.public_host,
                public_port=args.port,
                routing_port=int(runtime_config["routing_port"]),
                routing_max_port=int(runtime_config["routing_max_port"]),
                version_str=str(runtime_config["version_str"]),
                valid_versions=list(runtime_config["valid_versions"]),
                keys_dir=runtime_config["keys_dir"],
                backend_shared_secret=args.backend_shared_secret,
                backend_timeout_s=args.backend_timeout,
                product_profile=product_profile,
                user_id_start=int(runtime_config["user_id_start"]),
                peer_session_id_min=int(runtime_config["peer_session_id_min"]),
                peer_session_id_max=int(runtime_config["peer_session_id_max"]),
            )
            LOGGER.info(
                "Shared-edge runtime: %s root=%s versions=%r backend=%s:%s routing=%d-%d",
                product_profile.key,
                product_profile.directory_root,
                list(runtime.valid_versions),
                runtime.backend_host,
                runtime.backend_port,
                int(runtime_config["routing_port"]),
                int(runtime_config["routing_max_port"]),
            )
            routing_manager = RoutingServerManager(
                args.host,
                args.public_host,
                int(runtime_config["routing_port"]),
                max_port=int(runtime_config["routing_max_port"]),
                excluded_ports={args.port, args.firewall_port},
                gateway=runtime,
                product_profile=product_profile,
            )
            runtime.routing_manager = routing_manager
            runtimes[product_key] = runtime
            routing_managers.append(routing_manager)
            _routing_srv, routing_server = await routing_manager.start_listener(
                int(runtime_config["routing_port"]),
                publish_in_directory=True,
            )
            routing_servers.append(routing_server)

        srv = SharedBinaryGatewayServer(
            runtimes,
            default_product_key=str(shared_config["default_product_key"]),
        )
        db_path = str(shared_config["admin_db_path"])
        db_paths = {
            product_key: str(runtime_config["db_path"])
            for product_key, runtime_config in dict(shared_config["runtimes"]).items()
        }
        default_db_product = str(shared_config["default_product_key"])
    else:
        product_profile, version_str, valid_versions, db_path, keys_dir = (
            _resolve_gateway_runtime_config(args)
        )
        srv = BinaryGatewayServer(
            args.backend_host, args.backend_port, event_bus,
            public_host=args.public_host,
            public_port=args.port,
            routing_port=args.routing_port,
            routing_max_port=args.routing_max_port,
            version_str=version_str,
            valid_versions=valid_versions,
            keys_dir=keys_dir,
            backend_shared_secret=args.backend_shared_secret,
            backend_timeout_s=args.backend_timeout,
            product_profile=product_profile,
        )
        LOGGER.info(
            "Gateway product profile: %s (root=%s versions=%s)",
            product_profile.key,
            product_profile.directory_root,
            product_profile.valid_versions_service,
        )
        LOGGER.info("ValidVersions configured: %r", list(srv.valid_versions))
        routing_manager = RoutingServerManager(
            args.host,
            args.public_host,
            args.routing_port,
            max_port=args.routing_max_port,
            excluded_ports={args.port, args.firewall_port},
            gateway=srv,
            product_profile=product_profile,
        )
        srv.routing_manager = routing_manager
        routing_managers.append(routing_manager)
        _routing_srv, routing_server = await routing_manager.start_listener(
            args.routing_port,
            publish_in_directory=True,
        )
        routing_servers.append(routing_server)
        db_paths = {product_profile.key: str(db_path)}
        default_db_product = product_profile.key

    server = await asyncio.start_server(srv.handle_client, args.host, args.port)
    firewall_server = await asyncio.start_server(
        _handle_firewall_probe, args.host, args.firewall_port
    )
    admin_dashboard = AdminDashboardServer(
        srv,
        db_path,
        DASHBOARD_LOG_HANDLER,
        db_paths=db_paths,
        default_db_product=default_db_product,
        admin_token=args.admin_token,
        stats_token=args.stats_token,
    )
    admin_server = None
    if args.admin_port > 0:
        admin_server = await asyncio.start_server(
            admin_dashboard.handle_client,
            args.admin_host,
            args.admin_port,
        )
        admin_dashboard.start_background_tasks()
    srv.start_background_tasks()

    addrs = ", ".join(str(s.getsockname()) for s in (server.sockets or []))
    r_addrs = ", ".join(
        str(sockname)
        for routing_server in routing_servers
        for sockname in (routing_server.sockets or [])
    )
    fw_addrs = ", ".join(str(s.getsockname()) for s in (firewall_server.sockets or []))
    admin_addrs = ", ".join(str(s.getsockname()) for s in (admin_server.sockets or [])) if admin_server else ""
    if getattr(args, "shared_edge", False):
        print(f"Titan binary gateway  listening on {addrs} -> shared edge")
    else:
        print(f"Titan binary gateway  listening on {addrs} -> {args.backend_host}:{args.backend_port}")
    print(f"Routing server        listening on {r_addrs}")
    print(f"Firewall probe        listening on {fw_addrs}")
    if admin_server:
        print(f"Admin dashboard       listening on {admin_addrs}")
    print(f"Public address reported to clients: {args.public_host}  gateway:{args.port}")

    try:
        async with contextlib.AsyncExitStack() as stack:
            await stack.enter_async_context(server)
            await stack.enter_async_context(firewall_server)
            for routing_server in routing_servers:
                await stack.enter_async_context(routing_server)
            if admin_server is not None:
                await stack.enter_async_context(admin_server)

            tasks = [
                server.serve_forever(),
                firewall_server.serve_forever(),
                *[routing_server.serve_forever() for routing_server in routing_servers],
            ]
            if admin_server is not None:
                tasks.append(admin_server.serve_forever())
            await asyncio.gather(*tasks)
    finally:
        await admin_dashboard.stop_background_tasks()
        await srv.stop_background_tasks()
        for routing_manager in routing_managers:
            await routing_manager.close_all()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Binary Titan gateway with connection state machine")
    p.add_argument(
        "--product",
        default=HOMEWORLD_PRODUCT_PROFILE.key,
        choices=sorted(PRODUCT_PROFILES),
        help="Product profile to advertise on the Titan side.",
    )
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=15101,
        help="Port for Titan directory/version-check queries (retail clients hardcode 15101)")
    p.add_argument("--backend-host", default="127.0.0.1")
    p.add_argument("--backend-port", type=int, default=9100,
                   help="Port of the internal WON backend (won_server.py)")
    p.add_argument(
        "--backend-shared-secret",
        default=os.environ.get("BACKEND_SHARED_SECRET", ""),
        help="Optional shared secret sent to the internal backend JSON-RPC service.",
    )
    p.add_argument(
        "--backend-timeout",
        type=float,
        default=float(os.environ.get("BACKEND_RPC_TIMEOUT", BACKEND_RPC_TIMEOUT_SECONDS)),
        help="Timeout in seconds for backend JSON-RPC calls.",
    )
    p.add_argument(
        "--shared-edge",
        action="store_true",
        help="Serve Homeworld and Cataclysm from one public Titan edge using separate internal runtimes.",
    )
    p.add_argument("--public-host", default="127.0.0.1",
        help="Public IP reported to retail clients in directory replies")
    p.add_argument("--routing-port", type=int, default=15100,
        help="Port for the retail routing/lobby server (clients connect here for chat and lobbies)")
    p.add_argument("--routing-max-port", type=int, default=15120,
                   help="Highest TCP port the gateway may allocate for extra room/game routing listeners")
    p.add_argument(
        "--homeworld-routing-max-port",
        type=int,
        default=0,
        help="Optional upper bound for Homeworld routing ports when --shared-edge is enabled.",
    )
    p.add_argument(
        "--cataclysm-backend-host",
        default="",
        help="Override backend host for the Cataclysm runtime when --shared-edge is enabled.",
    )
    p.add_argument(
        "--cataclysm-backend-port",
        type=int,
        default=0,
        help="Override backend port for the Cataclysm runtime when --shared-edge is enabled. Defaults to --backend-port + 1.",
    )
    p.add_argument(
        "--cataclysm-routing-port",
        type=int,
        default=0,
        help="Base routing port for Cataclysm when --shared-edge is enabled. Defaults to the upper half of the configured routing range.",
    )
    p.add_argument(
        "--cataclysm-routing-max-port",
        type=int,
        default=0,
        help="Highest Cataclysm routing port when --shared-edge is enabled. Defaults to --routing-max-port.",
    )
    p.add_argument("--firewall-port", type=int, default=2021,
        help="Port for WON firewall probe listener (retail clients probe this to detect NAT)")
    p.add_argument("--admin-host", default="127.0.0.1",
                   help="Bind host for the local admin dashboard (127.0.0.1 keeps it local-only)")
    p.add_argument("--admin-port", type=int, default=8080,
                   help="Port for the local admin dashboard (set to 0 to disable)")
    p.add_argument(
        "--admin-token",
        default=os.environ.get("ADMIN_TOKEN", ""),
        help="Optional token for the admin dashboard. Required if --admin-host is not loopback.",
    )
    p.add_argument(
        "--stats-token",
        default=os.environ.get("STATS_TOKEN", ""),
        help="Optional token for the bot-friendly /api/stats endpoint. Falls back to --admin-token when unset.",
    )
    p.add_argument("--db-path", default="",
                   help="Path to the SQLite backend DB shown in the admin dashboard. Defaults to data/<product>/won_server.db when omitted.")
    p.add_argument("--version-str", default="",
                   help="Legacy single ValidVersions override. When omitted, defaults to the selected product profile's version set.")
    p.add_argument("--valid-version", action="append", default=[],
                   help="Exact versionString accepted by the selected product's ValidVersions service. Repeat for multiple allowed builds.")
    p.add_argument("--valid-versions-file", default=None,
                   help="Text file containing one exact allowed versionString per line for the selected product.")
    p.add_argument("--cataclysm-db-path", default="",
                   help="SQLite backend DB path for Cataclysm when --shared-edge is enabled.")
    p.add_argument("--cataclysm-version-str", default="",
                   help="Legacy Cataclysm ValidVersions override when --shared-edge is enabled.")
    p.add_argument("--cataclysm-valid-version", action="append", default=[],
                   help="Exact versionString accepted by Cataclysm when --shared-edge is enabled.")
    p.add_argument("--cataclysm-valid-versions-file", default=None,
                   help="Text file containing one exact Cataclysm allowed versionString per line when --shared-edge is enabled.")
    p.add_argument("--keys-dir", default=None,
                   help="Directory containing Auth1 keypairs (verifier_private.der, "
                        "authserver_private.der). Defaults to data/<product>/keys when present, "
                        "otherwise keys/.")
    p.add_argument("--cataclysm-keys-dir", default=None,
                   help="Optional Cataclysm key directory when --shared-edge is enabled. Defaults to --keys-dir.")
    p.add_argument("--log", "--log-level", dest="log_level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                   help="Logging verbosity (DEBUG shows every raw packet event)")
    return p

async def start_gateway_async(args: argparse.Namespace) -> None:
    await main_async(args)


def start_gateway(argv: Optional[list[str]] = None) -> None:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )
    DASHBOARD_LOG_HANDLER.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")
    )
    logging.getLogger().addHandler(DASHBOARD_LOG_HANDLER)
    asyncio.run(main_async(args))
