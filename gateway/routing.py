from __future__ import annotations

import asyncio
import binascii
import contextlib
from dataclasses import dataclass, field
import hashlib
import logging
import re
import struct
import time
from typing import Dict, Optional, Tuple

from .protocol import *
from . import protocol as _protocol
from .product_profile import (
    CATACLYSM_PRODUCT_PROFILE,
    HOMEWORLD_PRODUCT_PROFILE,
    ProductProfile,
)

globals().update({name: getattr(_protocol, name) for name in dir(_protocol) if name.startswith('_')})
LOGGER = logging.getLogger(__name__)

PUBLISHED_GAME_ACTIVITY_WINDOW_SECONDS = 15.0
_MULTIPLAYER_LEVEL_PATH_RE = re.compile(
    rb"(?i)multiplayer\\(?P<folder>[^\\\x00\r\n]+)\\(?P<file>[^\\\x00\r\n]+)\.level"
)


async def _routing_recv_with_idle_timeout(reader: asyncio.StreamReader) -> bytes:
    timeout = ROUTING_IDLE_TIMEOUT_SECONDS
    if timeout is None:
        return await _routing_recv(reader)
    timeout_value = float(timeout)
    if timeout_value <= 0.0:
        return await _routing_recv(reader)
    return await asyncio.wait_for(_routing_recv(reader), timeout=timeout_value)

@dataclass
class NativeRouteSubscription:
    link_id: int
    data_type: bytes
    exact_or_recursive: bool
    group_or_members: bool


@dataclass
class NativeRouteDataObject:
    link_id: int
    owner_id: int
    lifespan: int
    data_type: bytes
    data: bytes


@dataclass
class NativeRouteClientState:
    client_id: int
    client_name_raw: bytes
    client_name: str
    client_ip: str
    client_ip_u32: int
    writer: asyncio.StreamWriter
    session_key: bytes
    out_seq: Optional[int]
    auth_user_id: int = 0
    account_username: str = ""
    connected_at: float = field(default_factory=time.time)
    last_activity_at: float = field(default_factory=time.time)
    last_activity_kind: str = "register"
    last_server_keepalive_at: float = 0.0
    chat_count: int = 0
    peer_data_messages: int = 0
    peer_data_bytes: int = 0
    admin_sender_announced: bool = False
    subscriptions: list[NativeRouteSubscription] = field(default_factory=list)
    write_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


@dataclass
class PendingNativeReconnect:
    client_id: int
    client_name_raw: bytes
    client_name: str
    client_ip: str
    client_ip_u32: int
    connected_at: float
    last_activity_at: float
    last_activity_kind: str
    chat_count: int
    peer_data_messages: int
    peer_data_bytes: int
    auth_user_id: int = 0
    account_username: str = ""
    subscriptions: list[NativeRouteSubscription] = field(default_factory=list)
    reserved_at: float = field(default_factory=time.time)
    expires_at: float = field(
        default_factory=lambda: time.time() + ROUTING_RECONNECT_GRACE_SECONDS
    )


class SilencerRoutingServer:
    """Replication of the Silencer Routing Server's port-15100 logic.

    Protocol framing (client → server):
        [LE u16 total_len][payload]
        where payload_size = total_len - 2

    Payload layout:
        [0x03][0x02][type_byte][data...]

    Server responses are raw (no length prefix).
    """

    # Packet type IDs (from connectedclientclass.cc)
    _NEW_CONFLICT_ID  = 0x09
    _ABORT_CONFLICT   = 0x0b
    _CLIENTQUERY_ID   = 0x0f
    _USER_TERMINATION = 0x1d
    _INIT_ID          = 0x1f
    _CONFLICTQUERY_ID = 0x29
    _CHATMESSAGE_ID   = 0x35

    def __init__(
        self,
        gateway: Optional["BinaryGatewayServer"] = None,
        listen_port: Optional[int] = None,
        publish_in_directory: bool = True,
        product_profile: ProductProfile = HOMEWORLD_PRODUCT_PROFILE,
    ) -> None:
        # Shared across all concurrent connections (mirrors StaticConflict global).
        self.gateway = gateway
        self.listen_port = listen_port
        self._publish_in_directory = publish_in_directory
        self.product_profile = product_profile
        self._published = False
        self._room_allocated = False
        self._room_allocated_at = 0.0
        self._conflict_data: bytes = _SILENCER_EMPTY_CONFLICT
        self._next_native_client_id = 1
        self._native_clients: Dict[int, NativeRouteClientState] = {}
        self._data_objects: Dict[Tuple[int, bytes], NativeRouteDataObject] = {}
        self._room_display_name = self.product_profile.lobby_room_name
        self._room_description = self.product_profile.lobby_room_description
        self._room_password = ""
        self._room_flags = 0
        self._room_path = self.product_profile.directory_root
        self._inferred_game_name = ""
        self._inferred_level_path = ""
        self._pending_reconnects: Dict[int, PendingNativeReconnect] = {}
        self._maintenance_task: Optional[asyncio.Task] = None
        self._solo_peer_data_log_state: Dict[Tuple[str, int], Dict[str, object]] = {}
        self._last_peer_data_at = 0.0

    def start_background_tasks(self) -> None:
        if self._maintenance_task is None:
            self._maintenance_task = asyncio.create_task(self._maintenance_loop())

    async def stop_background_tasks(self) -> None:
        task = self._maintenance_task
        self._maintenance_task = None
        if task is None:
            return
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    def _room_has_state(self) -> bool:
        return any(
            (
                self._room_allocated,
                self._room_allocated_at > 0.0,
                self._published,
                self._native_clients,
                self._pending_reconnects,
                self._data_objects,
                self._room_password,
                self._room_flags,
                self._room_path != self.product_profile.directory_root,
                self._room_display_name != self.product_profile.lobby_room_name,
                self._room_description != self.product_profile.lobby_room_description,
                self._inferred_game_name,
                self._inferred_level_path,
                self._conflict_data != _SILENCER_EMPTY_CONFLICT,
            )
        )

    def _reset_room_state(self, reason: str) -> None:
        if self._native_clients or self._pending_reconnects:
            return
        if not self._room_has_state():
            return
        LOGGER.info(
            "Routing(native): ResetRoom port=%s reason=%s published=%s data_objects=%d",
            self.listen_port,
            reason,
            self._published,
            len(self._data_objects),
        )
        if self.gateway is not None and (
            self._published
            or self._room_allocated
            or self._data_objects
            or self._room_password
        ):
            self.gateway.record_activity(
                "room_close",
                room_port=self.listen_port,
                room_name=self._room_display_name,
                room_path=self._room_path,
            )
        self._published = False
        self._room_allocated = False
        self._room_allocated_at = 0.0
        self._conflict_data = _SILENCER_EMPTY_CONFLICT
        self._next_native_client_id = 1
        self._data_objects.clear()
        self._room_display_name = self.product_profile.lobby_room_name
        self._room_description = self.product_profile.lobby_room_description
        self._room_password = ""
        self._room_flags = 0
        self._room_path = self.product_profile.directory_root
        self._inferred_game_name = ""
        self._inferred_level_path = ""
        self._solo_peer_data_log_state.clear()
        self._last_peer_data_at = 0.0

    def _effective_room_display_name(self) -> str:
        if (
            self._inferred_game_name
            and not self._publish_in_directory
            and self._room_display_name == self.product_profile.lobby_room_name
        ):
            return self._inferred_game_name
        return self._room_display_name

    def _maybe_infer_game_metadata(self, payload: bytes) -> None:
        if not payload or self._publish_in_directory:
            return
        if self._data_objects:
            return
        match = _MULTIPLAYER_LEVEL_PATH_RE.search(bytes(payload))
        if match is None:
            return
        level_name = match.group("file").decode("latin-1", errors="ignore").strip()
        level_path = match.group(0).decode("latin-1", errors="ignore").strip()
        if not level_name or not level_path:
            return
        changed = level_name != self._inferred_game_name or level_path != self._inferred_level_path
        self._inferred_game_name = level_name
        self._inferred_level_path = level_path
        if changed:
            LOGGER.info(
                "Routing(native): inferred game metadata port=%s name=%r level_path=%r",
                self.listen_port,
                self._inferred_game_name,
                self._inferred_level_path,
            )

    def mark_room_allocated(self) -> None:
        self._room_allocated = True
        self._room_allocated_at = time.time()

    def _reap_unused_room_allocation(self) -> None:
        if not self._room_allocated:
            return
        if self._published or self._native_clients or self._pending_reconnects:
            return
        if self._room_allocated_at <= 0.0:
            return
        if time.time() - self._room_allocated_at < ROOM_ALLOCATION_GRACE_SECONDS:
            return
        self._reset_room_state("allocation_timeout")

    def _should_offer_reconnect(
        self,
        client: NativeRouteClientState,
        disconnect_reason: str,
    ) -> bool:
        if disconnect_reason not in {"transport_lost", "connection_reset", "eof"}:
            return False
        # Homeworld uses unpublished game routes, so published lobby/chat rooms
        # should still broadcast the leave immediately to avoid stale names.
        if not self._publish_in_directory:
            return True

        # Cataclysm can keep gameplay on the published room. When the room was
        # just carrying active peer-data traffic, preserve a reconnect window so
        # the client can transition back cleanly after the match ends or the
        # connection blips.
        now = time.time()
        if self.product_profile.key == CATACLYSM_PRODUCT_PROFILE.key:
            active_participant_count = len(self._native_clients) + len(self._pending_reconnects)
            room_peer_data_messages = sum(
                int(active.peer_data_messages)
                for active in self._native_clients.values()
            ) + int(client.peer_data_messages)
            room_peer_data_bytes = sum(
                int(active.peer_data_bytes)
                for active in self._native_clients.values()
            ) + int(client.peer_data_bytes)
            return self._recent_published_game_activity(
                now,
                active_participant_count,
                room_peer_data_messages,
                room_peer_data_bytes,
            )
        return False

    def _park_disconnected_client(
        self,
        client: NativeRouteClientState,
        disconnect_reason: str,
    ) -> None:
        reservation = PendingNativeReconnect(
            client_id=client.client_id,
            client_name_raw=bytes(client.client_name_raw),
            client_name=str(client.client_name),
            client_ip=str(client.client_ip),
            client_ip_u32=int(client.client_ip_u32),
            connected_at=float(client.connected_at),
            last_activity_at=float(client.last_activity_at),
            last_activity_kind=str(client.last_activity_kind),
            chat_count=int(client.chat_count),
            peer_data_messages=int(client.peer_data_messages),
            peer_data_bytes=int(client.peer_data_bytes),
            auth_user_id=int(client.auth_user_id),
            account_username=str(client.account_username),
            subscriptions=[
                NativeRouteSubscription(
                    link_id=sub.link_id,
                    data_type=bytes(sub.data_type),
                    exact_or_recursive=bool(sub.exact_or_recursive),
                    group_or_members=bool(sub.group_or_members),
                )
                for sub in client.subscriptions
            ],
        )
        self._pending_reconnects[reservation.client_id] = reservation
        LOGGER.info(
            "Routing(native): ReconnectReservation id=%d name=%r ip=%s grace=%.1fs reason=%s",
            reservation.client_id,
            reservation.client_name,
            reservation.client_ip,
            max(0.0, reservation.expires_at - reservation.reserved_at),
            disconnect_reason,
        )

    async def _claim_pending_reconnect(
        self,
        client_name_raw: bytes,
        client_ip: str,
    ) -> Optional[PendingNativeReconnect]:
        await self._expire_pending_reconnects()
        for client_id, reservation in list(self._pending_reconnects.items()):
            if reservation.client_ip != client_ip:
                continue
            if reservation.client_name_raw != bytes(client_name_raw):
                continue
            self._pending_reconnects.pop(client_id, None)
            LOGGER.info(
                "Routing(native): ReconnectClaim id=%d name=%r ip=%s",
                reservation.client_id,
                reservation.client_name,
                reservation.client_ip,
            )
            return reservation
        return None

    async def _claim_pending_reconnect_by_id(
        self,
        client_id: int,
        client_ip: str,
    ) -> Optional[PendingNativeReconnect]:
        await self._expire_pending_reconnects()
        reservation = self._pending_reconnects.get(int(client_id))
        if reservation is None:
            return None
        if reservation.client_ip != client_ip:
            return None
        self._pending_reconnects.pop(int(client_id), None)
        LOGGER.info(
            "Routing(native): ReconnectClaim id=%d name=%r ip=%s (client-id path)",
            reservation.client_id,
            reservation.client_name,
            reservation.client_ip,
        )
        return reservation

    async def _finalize_client_departure(
        self,
        client_id: int,
        client_name: str,
        client_ip: str,
        *,
        auth_user_id: int = 0,
        account_username: str = "",
        disconnect_reason: str,
        remove_owned_objects: bool = True,
        broadcast_leave: bool = True,
    ) -> None:
        if self.gateway is not None:
            self.gateway.record_activity(
                "leave",
                room_port=self.listen_port,
                room_name=self._room_display_name,
                room_path=self._room_path,
                player_id=client_id,
                player_name=client_name,
                player_ip=client_ip,
                details={"reason": disconnect_reason},
            )
            self.gateway.record_live_player_event(
                "player_left",
                room_port=int(self.listen_port or 0),
                player_id=int(client_id),
                player_name=str(client_name),
                player_ip=str(client_ip),
                details={"reason": disconnect_reason},
            )
            self.gateway._release_native_login_claim(
                user_id=int(auth_user_id),
                username=str(account_username),
                reason=f"routing_{disconnect_reason}",
            )
        LOGGER.info(
            "Routing(native): Client disconnected id=%d name=%r reason=%s",
            client_id,
            client_name,
            disconnect_reason,
        )
        if remove_owned_objects:
            removed_objects = await self._remove_owned_data_objects(client_id)
            if removed_objects:
                LOGGER.info(
                    "Routing(native): removed %d owned data objects for disconnected client_id=%d",
                    removed_objects,
                    client_id,
                )
        if broadcast_leave:
            delivered = await self._broadcast_native_route_group_change(
                _build_mini_routing_group_change(
                    CHAT_GROUP_ID,
                    client_id,
                    ROUTING_REASON_VOLUNTARY_DISCONNECT,
                ),
                exclude_client_id=client_id,
            )
            if delivered:
                LOGGER.info(
                    "Routing(native): GroupChange leave broadcast sent to %d clients",
                    delivered,
                )
        if not self._native_clients and not self._pending_reconnects:
            self._reset_room_state(f"empty_after_{disconnect_reason}")

    async def admin_kick_client(self, client_id: int) -> bool:
        """Admin action: forcibly disconnect a client by id."""
        client = self._native_clients.get(client_id)
        if client is None:
            return False
        LOGGER.info(
            "Routing(admin): kicking client_id=%d name=%r ip=%s",
            client.client_id, client.client_name, client.client_ip,
        )
        try:
            client.writer.close()
            await client.writer.wait_closed()
        except Exception:
            pass
        return True

    async def admin_broadcast_chat(self, text: str) -> int:
        """Admin action: send a chat message from [ADMIN] to all clients."""
        text = _sanitize_routing_chat_text(text)
        if not text:
            LOGGER.info("Routing(admin): broadcast suppressed empty message")
            return 0
        data = _encode_routing_chat_text(CHAT_GROUP_ID, text, b"")
        join_msg = _build_mini_routing_group_change_ex(
            CHAT_GROUP_ID,
            ADMIN_BROADCAST_CLIENT_ID,
            ROUTING_REASON_NEW_CLIENT,
            ADMIN_BROADCAST_CLIENT_NAME_RAW,
            ADMIN_BROADCAST_CLIENT_IP_U32,
        )
        peer_chat = _build_mini_routing_peer_chat(
            client_id=ADMIN_BROADCAST_CLIENT_ID,
            chat_type=CHAT_GROUP_ID,
            data=data,
            addressees=[],
            include_exclude_flag=False,
        )
        delivered = 0
        for client in list(self._native_clients.values()):
            try:
                if not client.admin_sender_announced:
                    await self._send_native_route_client_reply(client, join_msg)
                    client.admin_sender_announced = True
                await self._send_native_route_client_reply(client, peer_chat)
                delivered += 1
            except Exception as exc:
                LOGGER.warning(
                    "Routing(admin): failed broadcast to client_id=%d: %s",
                    client.client_id, exc,
                )
        LOGGER.info("Routing(admin): broadcast delivered to %d clients", delivered)
        return delivered

    async def _expire_pending_reconnects(self) -> None:
        now = time.time()
        expired_ids = [
            client_id
            for client_id, reservation in list(self._pending_reconnects.items())
            if reservation.expires_at <= now
        ]
        for client_id in expired_ids:
            reservation = self._pending_reconnects.pop(client_id, None)
            if reservation is None:
                continue
            LOGGER.info(
                "Routing(native): ReconnectReservation expired id=%d name=%r idle_for=%.1fs",
                reservation.client_id,
                reservation.client_name,
                max(0.0, now - reservation.reserved_at),
            )
            await self._finalize_client_departure(
                reservation.client_id,
                reservation.client_name,
                reservation.client_ip,
                auth_user_id=reservation.auth_user_id,
                account_username=reservation.account_username,
                disconnect_reason="reconnect_expired",
            )

    async def _send_server_keepalives(self) -> None:
        now = time.time()
        keepalive = _build_mini_routing_keep_alive()
        for client in list(self._native_clients.values()):
            if now - client.last_activity_at < ROUTING_HEARTBEAT_IDLE_SECONDS:
                continue
            if (
                client.last_server_keepalive_at > 0.0
                and now - client.last_server_keepalive_at < ROUTING_HEARTBEAT_INTERVAL_SECONDS
            ):
                continue
            try:
                await self._send_native_route_client_reply(client, keepalive)
                client.last_server_keepalive_at = now
                LOGGER.debug(
                    "Routing(native): ServerKeepAlive sent to client_id=%d name=%r",
                    client.client_id,
                    client.client_name,
                )
            except Exception as exc:
                LOGGER.warning(
                    "Routing(native): ServerKeepAlive failed for client_id=%d name=%r: %s",
                    client.client_id,
                    client.client_name,
                    exc,
                )
                with contextlib.suppress(Exception):
                    client.writer.close()

    async def _maintenance_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(ROUTING_MAINTENANCE_INTERVAL_SECONDS)
                self._reap_unused_room_allocation()
                await self._expire_pending_reconnects()
                await self._send_server_keepalives()
        except asyncio.CancelledError:
            raise

    def _touch_native_client(
        self,
        client_id: Optional[int],
        activity_kind: str,
        payload_len: int = 0,
    ) -> Optional[NativeRouteClientState]:
        if not client_id:
            return None
        client = self._native_clients.get(int(client_id))
        if client is None:
            return None
        client.last_activity_at = time.time()
        client.last_activity_kind = activity_kind
        if activity_kind == "chat":
            client.chat_count += 1
        elif activity_kind == "peer_data":
            client.peer_data_messages += 1
            client.peer_data_bytes += max(0, int(payload_len))
        return client

    def _recent_published_game_activity(
        self,
        now: float,
        active_participant_count: int,
        room_peer_data_messages: int,
        room_peer_data_bytes: int,
    ) -> bool:
        if not self._publish_in_directory:
            return False
        if self.product_profile.key != CATACLYSM_PRODUCT_PROFILE.key:
            return False
        if self._last_peer_data_at <= 0.0:
            return False
        if now - self._last_peer_data_at > PUBLISHED_GAME_ACTIVITY_WINDOW_SECONDS:
            return False
        if active_participant_count >= 2:
            return True
        return room_peer_data_messages >= 8 or room_peer_data_bytes >= 1024

    def _recent_unpublished_game_activity(self, now: float) -> bool:
        if self._publish_in_directory:
            return False
        if self._last_peer_data_at <= 0.0:
            return False
        return (now - self._last_peer_data_at) <= PUBLISHED_GAME_ACTIVITY_WINDOW_SECONDS

    def _alloc_native_client_id(self) -> int:
        reserved_ids = set(self._native_clients) | set(self._pending_reconnects)
        for _ in range(MAX_NATIVE_CLIENT_ID):
            client_id = self._next_native_client_id
            self._next_native_client_id = 1 if client_id >= MAX_NATIVE_CLIENT_ID else client_id + 1
            if client_id not in reserved_ids:
                return client_id
        raise RuntimeError("native_client_id_exhausted")

    def _flush_solo_peer_data_logs(self, client_id: Optional[int] = None) -> None:
        keys = [
            key
            for key in list(self._solo_peer_data_log_state)
            if client_id is None or key[1] == int(client_id)
        ]
        now = time.monotonic()
        for key in keys:
            state = self._solo_peer_data_log_state.pop(key, None)
            if not state:
                continue
            suppressed = int(state.get("suppressed", 0))
            if suppressed <= 0:
                continue
            kind, tracked_client_id = key
            window_started = float(state.get("window_started_monotonic", now))
            LOGGER.info(
                "Routing(native): %s from client_id=%d suppressed %d additional no-recipient packets over %.1fs (latest_len=%d reply=%s%s)",
                kind,
                tracked_client_id,
                suppressed,
                max(0.0, now - window_started),
                int(state.get("latest_len", 0)),
                bool(state.get("latest_reply", False)),
                self._peer_data_fingerprint_suffix(state.get("latest_fingerprint", "")),
            )

    @staticmethod
    def _peer_data_fingerprint(data: bytes) -> str:
        payload = bytes(data or b"")
        if not payload:
            return "empty"
        digest = hashlib.blake2s(payload, digest_size=6).hexdigest()
        head = payload[:8].hex()
        return f"{len(payload)}b:{digest}:{head}"

    def _peer_data_fingerprint_suffix(self, fingerprint: object) -> str:
        if self._publish_in_directory:
            return ""
        value = str(fingerprint or "").strip()
        if not value:
            return ""
        return f" fingerprint={value}"

    def _log_native_peer_data_event(
        self,
        kind: str,
        client_id: int,
        payload: bytes,
        recipients: int,
        should_send_reply: bool,
    ) -> None:
        data_len = len(bytes(payload or b""))
        fingerprint = self._peer_data_fingerprint(payload)
        if recipients > 0 or client_id <= 0:
            self._flush_solo_peer_data_logs(client_id if client_id > 0 else None)
            LOGGER.info(
                "Routing(native): %s from client_id=%d data_len=%d recipients=%d reply=%s%s",
                kind,
                client_id,
                data_len,
                recipients,
                should_send_reply,
                self._peer_data_fingerprint_suffix(fingerprint),
            )
            return

        now = time.monotonic()
        key = (kind, int(client_id))
        state = self._solo_peer_data_log_state.get(key)
        if state is None:
            self._solo_peer_data_log_state[key] = {
                "window_started_monotonic": now,
                "last_emit_monotonic": now,
                "suppressed": 0,
                "latest_len": int(data_len),
                "latest_reply": bool(should_send_reply),
                "latest_fingerprint": fingerprint,
            }
            LOGGER.info(
                "Routing(native): %s from client_id=%d data_len=%d recipients=0 reply=%s%s (no peers connected; suppressing repeats)",
                kind,
                client_id,
                data_len,
                should_send_reply,
                self._peer_data_fingerprint_suffix(fingerprint),
            )
            return

        state["latest_len"] = int(data_len)
        state["latest_reply"] = bool(should_send_reply)
        state["latest_fingerprint"] = fingerprint
        last_emit = float(state.get("last_emit_monotonic", now))
        if now - last_emit < 5.0:
            state["suppressed"] = int(state.get("suppressed", 0)) + 1
            return

        suppressed = int(state.get("suppressed", 0))
        window_started = float(state.get("window_started_monotonic", now))
        if suppressed > 0:
            LOGGER.info(
                "Routing(native): %s from client_id=%d suppressed %d additional no-recipient packets over %.1fs (latest_len=%d reply=%s%s)",
                kind,
                client_id,
                suppressed,
                max(0.0, now - window_started),
                int(state.get("latest_len", 0)),
                bool(state.get("latest_reply", False)),
                self._peer_data_fingerprint_suffix(state.get("latest_fingerprint", "")),
            )

        state["window_started_monotonic"] = now
        state["last_emit_monotonic"] = now
        state["suppressed"] = 0
        LOGGER.info(
            "Routing(native): %s from client_id=%d data_len=%d recipients=0 reply=%s%s (still no peers connected; suppressing repeats)",
            kind,
            client_id,
            data_len,
            should_send_reply,
            self._peer_data_fingerprint_suffix(fingerprint),
        )

    def can_host_room(self) -> bool:
        return (
            not self._room_allocated
            and not self._published
            and not self._native_clients
            and not self._pending_reconnects
        )

    def is_directory_visible(self) -> bool:
        return self._publish_in_directory and self._published

    def native_directory_entry(self, public_host: str) -> Optional[Dict[str, object]]:
        if not self.is_directory_visible() or self.listen_port is None:
            return None
        try:
            ip_raw = _socket.inet_aton(public_host)
        except Exception:
            ip_raw = b"\x7f\x00\x00\x01"
        return {
            "type": "S",
            "name": self.product_profile.routing_service_name,
            "display_name": self._effective_room_display_name() or self.product_profile.routing_service_name,
            "net_addr": struct.pack(">H", int(self.listen_port)) + ip_raw,
            "data_objects": [
                _pack_directory_data_object(
                    "Description",
                    self._room_description or self._effective_room_display_name(),
                ),
                _pack_directory_data_object("RoomFlags", self._room_flags),
                _pack_directory_data_object("__RSClientCount", len(self._native_clients)),
            ],
        }

    def dashboard_snapshot(self) -> Dict[str, object]:
        now = time.time()
        data_objects = []
        for key in sorted(self._data_objects):
            obj = self._data_objects[key]
            data_objects.append(
                {
                    "link_id": obj.link_id,
                    "owner_id": obj.owner_id,
                    "lifespan": obj.lifespan,
                    "data_type_hex": obj.data_type.hex(),
                    "data_type_text": _decode_routing_data_type(obj.data_type),
                    "data_len": len(obj.data),
                    "data_preview_hex": obj.data[:32].hex(),
                }
            )

        clients = []
        client_lookup: Dict[int, NativeRouteClientState] = {}
        for client_id in sorted(self._native_clients):
            client = self._native_clients[client_id]
            client_lookup[client.client_id] = client
            clients.append(
                {
                    "client_id": client.client_id,
                    "client_name": client.client_name,
                    "client_name_hex": client.client_name_raw.hex(),
                    "client_ip": client.client_ip,
                    "client_ip_u32": client.client_ip_u32,
                    "out_seq": client.out_seq,
                    "connected_at": client.connected_at,
                    "connected_seconds": int(max(0.0, now - client.connected_at)),
                    "last_activity_at": client.last_activity_at,
                    "idle_seconds": int(max(0.0, now - client.last_activity_at)),
                    "last_activity_kind": client.last_activity_kind,
                    "chat_count": client.chat_count,
                    "peer_data_messages": client.peer_data_messages,
                    "peer_data_bytes": client.peer_data_bytes,
                    "subscription_count": len(client.subscriptions),
                    "subscriptions": [
                        {
                            "link_id": sub.link_id,
                            "data_type_hex": sub.data_type.hex(),
                            "data_type_text": _decode_routing_data_type(sub.data_type),
                            "exact_or_recursive": sub.exact_or_recursive,
                            "group_or_members": sub.group_or_members,
                        }
                        for sub in client.subscriptions
                    ],
                }
            )

        room_peer_data_messages = sum(
            int(client["peer_data_messages"]) for client in clients
        )
        room_peer_data_bytes = sum(
            int(client["peer_data_bytes"]) for client in clients
        )

        games = []
        for data_object in self._data_objects.values():
            owner = client_lookup.get(data_object.owner_id)
            games.append(
                {
                    "link_id": data_object.link_id,
                    "owner_id": data_object.owner_id,
                    "owner_name": owner.client_name if owner is not None else "",
                    "name": _decode_routing_data_type(data_object.data_type),
                    "data_len": len(data_object.data),
                    "lifespan": data_object.lifespan,
                    "data_preview_hex": data_object.data[:32].hex(),
                }
            )
        if not games and self._inferred_game_name and not self._publish_in_directory:
            games.append(
                {
                    "link_id": 0,
                    "owner_id": 0,
                    "owner_name": "",
                    "name": self._inferred_game_name,
                    "data_len": 0,
                    "lifespan": 0,
                    "data_preview_hex": "",
                    "synthetic": True,
                    "level_path": self._inferred_level_path,
                }
            )
        games.sort(key=lambda item: (item["owner_name"], item["name"], item["link_id"]))

        pending_reconnects = []
        for client_id in sorted(self._pending_reconnects):
            reservation = self._pending_reconnects[client_id]
            pending_reconnects.append(
                {
                    "client_id": reservation.client_id,
                    "client_name": reservation.client_name,
                    "client_ip": reservation.client_ip,
                    "reserved_at": reservation.reserved_at,
                    "seconds_remaining": max(0, int(reservation.expires_at - now)),
                    "last_activity_kind": reservation.last_activity_kind,
                    "peer_data_messages": reservation.peer_data_messages,
                    "peer_data_bytes": reservation.peer_data_bytes,
                }
            )

        active_participant_count = len(clients) + len(pending_reconnects)
        is_game_room = bool(
            (
                not self._publish_in_directory
                and (
                    clients
                    or data_objects
                    or room_peer_data_messages
                    or room_peer_data_bytes
                    or (pending_reconnects and self._recent_unpublished_game_activity(now))
                )
            )
            or self._recent_published_game_activity(
                now,
                active_participant_count,
                room_peer_data_messages,
                room_peer_data_bytes,
            )
        )

        return {
            "listen_port": self.listen_port,
            "publish_in_directory": self._publish_in_directory,
            "published": self._published,
            "room_allocated": self._room_allocated,
            "room_display_name": self._effective_room_display_name(),
            "room_description": self._room_description,
            "room_password_set": bool(self._room_password),
            "room_flags": self._room_flags,
            "room_path": self._room_path,
            "is_game_room": is_game_room,
            "active_game_count": 1 if is_game_room else 0,
            "native_client_count": len(clients),
            "pending_reconnect_count": len(pending_reconnects),
            "pending_reconnects": pending_reconnects,
            "client_names": [client["client_name"] for client in clients],
            "clients": clients,
            "game_count": len(games),
            "games": games,
            "peer_data_messages": room_peer_data_messages,
            "peer_data_bytes": room_peer_data_bytes,
            "seconds_since_last_peer_data": (
                max(0, int(now - self._last_peer_data_at))
                if self._last_peer_data_at > 0.0
                else None
            ),
            "data_object_count": len(data_objects),
            "data_objects": data_objects,
            "inferred_game_name": self._inferred_game_name,
            "inferred_level_path": self._inferred_level_path,
            "conflict_data_len": len(self._conflict_data),
        }

    def _is_native_auth_request(self, payload: bytes) -> bool:
        try:
            svc, msg, _body = won_crypto.parse_tmessage(payload)
        except Exception:
            return False
        return svc == AUTH1_PEER_SERVICE_TYPE and msg == AUTH1_PEER_REQUEST

    def _routing_client_list_entries(self) -> list[Tuple[int, bytes, int]]:
        clients = [
            (client.client_id, client.client_name_raw, client.client_ip_u32)
            for client in self._native_clients.values()
        ]
        if clients:
            clients.append(
                (
                    ADMIN_BROADCAST_CLIENT_ID,
                    ADMIN_BROADCAST_CLIENT_NAME_RAW,
                    ADMIN_BROADCAST_CLIENT_IP_U32,
                )
            )
        return clients

    async def _send_native_route_reply(
        self,
        writer: asyncio.StreamWriter,
        clear_msg: bytes,
        session_key: bytes,
        seq_num: Optional[int],
    ) -> Optional[int]:
        reply_enc = _encrypt_persistent_non_t(clear_msg, session_key, seq_num)
        writer.write(_routing_wrap(reply_enc))
        await writer.drain()
        return None if seq_num is None else seq_num + 1

    async def _send_native_route_client_reply(
        self,
        client: NativeRouteClientState,
        clear_msg: bytes,
    ) -> None:
        async with client.write_lock:
            client.out_seq = await self._send_native_route_reply(
                client.writer,
                clear_msg,
                client.session_key,
                client.out_seq,
            )

    async def _broadcast_native_route_chat(
        self,
        sender_client_id: int,
        chat_type: int,
        data: bytes,
        addressees: list[int],
        include_exclude_flag: bool,
    ) -> int:
        addressee_set = set(addressees)
        peer_chat = _build_mini_routing_peer_chat(
            sender_client_id,
            chat_type,
            data,
            addressees,
            include_exclude_flag,
        )

        targets: list[NativeRouteClientState] = []
        for client_id, client in list(self._native_clients.items()):
            if client_id == sender_client_id:
                continue
            listed = client_id in addressee_set
            if addressees:
                if include_exclude_flag and not listed:
                    continue
                if not include_exclude_flag and listed:
                    continue
            elif include_exclude_flag:
                continue
            targets.append(client)

        delivered = 0
        for client in targets:
            try:
                await self._send_native_route_client_reply(client, peer_chat)
                delivered += 1
            except Exception as exc:
                LOGGER.warning(
                    "Routing(native): failed chat delivery to client_id=%d name=%r: %s",
                    client.client_id,
                    client.client_name,
                    exc,
                )
        return delivered

    async def _broadcast_native_route_peer_data(
        self,
        sender_client_id: int,
        data: bytes,
        addressees: list[int],
        include_exclude_flag: bool,
    ) -> int:
        addressee_set = set(addressees)
        peer_data = _build_mini_routing_peer_data(sender_client_id, data)

        targets: list[NativeRouteClientState] = []
        for client_id, client in list(self._native_clients.items()):
            if client_id == sender_client_id:
                continue
            listed = client_id in addressee_set
            if addressees:
                if include_exclude_flag and not listed:
                    continue
                if not include_exclude_flag and listed:
                    continue
            elif include_exclude_flag:
                continue
            targets.append(client)

        delivered = 0
        for client in targets:
            try:
                await self._send_native_route_client_reply(client, peer_data)
                delivered += 1
            except Exception as exc:
                LOGGER.warning(
                    "Routing(native): failed peer-data delivery to client_id=%d name=%r: %s",
                    client.client_id,
                    client.client_name,
                    exc,
                )
        return delivered

    async def _broadcast_native_route_group_change(
        self,
        clear_msg: bytes,
        exclude_client_id: int = 0,
    ) -> int:
        delivered = 0
        for client_id, client in list(self._native_clients.items()):
            if exclude_client_id and client_id == exclude_client_id:
                continue
            try:
                await self._send_native_route_client_reply(client, clear_msg)
                delivered += 1
            except Exception as exc:
                LOGGER.warning(
                    "Routing(native): failed group-change delivery to client_id=%d name=%r: %s",
                    client.client_id,
                    client.client_name,
                    exc,
                )
        return delivered

    @staticmethod
    def _route_data_key(link_id: int, data_type: bytes) -> Tuple[int, bytes]:
        return int(link_id), bytes(data_type)

    @staticmethod
    def _route_data_matches_subscription(
        data_object: NativeRouteDataObject,
        subscription: NativeRouteSubscription,
    ) -> bool:
        if subscription.link_id not in {0, int(data_object.link_id)}:
            return False
        if not subscription.data_type:
            return True
        if subscription.exact_or_recursive:
            return data_object.data_type == subscription.data_type
        return data_object.data_type.startswith(subscription.data_type)

    def _route_reply_tuple(self, data_object: NativeRouteDataObject) -> Tuple[int, int, bytes, bytes]:
        return (
            data_object.link_id,
            data_object.owner_id,
            bytes(data_object.data_type),
            bytes(data_object.data),
        )

    def _route_data_objects_for_subscription(
        self,
        subscription: NativeRouteSubscription,
    ) -> list[Tuple[int, int, bytes, bytes]]:
        matches = [
            self._route_reply_tuple(data_object)
            for data_object in self._data_objects.values()
            if self._route_data_matches_subscription(data_object, subscription)
        ]
        matches.sort(key=lambda item: (item[0], item[2]))
        return matches

    async def _broadcast_native_route_data_object(
        self,
        clear_msg: bytes,
        data_object: NativeRouteDataObject,
    ) -> int:
        delivered = 0
        for client in list(self._native_clients.values()):
            if not any(
                self._route_data_matches_subscription(data_object, subscription)
                for subscription in client.subscriptions
            ):
                continue
            try:
                await self._send_native_route_client_reply(client, clear_msg)
                delivered += 1
            except Exception as exc:
                LOGGER.warning(
                    "Routing(native): failed data-object delivery to client_id=%d name=%r: %s",
                    client.client_id,
                    client.client_name,
                    exc,
                )
        return delivered

    async def _remove_owned_data_objects(self, owner_id: int) -> int:
        removed = 0
        for key, data_object in list(self._data_objects.items()):
            if data_object.owner_id != owner_id:
                continue
            self._data_objects.pop(key, None)
            removed += 1
            LOGGER.info(
                "Routing(native): AutoDeleteDataObject owner_id=%d link_id=%d type=%r name=%r on disconnect",
                owner_id,
                data_object.link_id,
                data_object.data_type,
                _decode_routing_data_type(data_object.data_type),
            )
            delivered = await self._broadcast_native_route_data_object(
                _build_mini_routing_delete_data_object(
                    data_object.link_id,
                    data_object.data_type,
                ),
                data_object,
            )
            LOGGER.info(
                "Routing(native): AutoDeleteDataObject broadcast sent to %d subscribed clients",
                delivered,
            )
            if self.gateway is not None:
                self.gateway.record_live_routing_object_event(
                    "routing_object_delete",
                    room_port=int(self.listen_port or 0),
                    link_id=int(data_object.link_id),
                    owner_id=int(data_object.owner_id),
                    owner_name="",
                    data_type_text=_decode_routing_data_type(data_object.data_type),
                    payload=bytes(data_object.data),
                    lifespan=int(data_object.lifespan),
                )
        return removed

    async def _handle_native_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        first_payload: bytes,
    ) -> None:
        peer = writer.get_extra_info("peername", ("?", 0))
        if self.gateway is None or not self.gateway._auth_keys_loaded:
            LOGGER.warning(
                "Routing(native): rejecting %s:%s because Auth1 keys are not available",
                *peer,
            )
            return

        registered_client_id = 0
        session_key = b""
        in_seq: Optional[int] = None
        out_seq: Optional[int] = None
        disconnect_reason = "transport_lost"
        auth_user_id = 0
        account_username = ""

        try:
            svc, msg, req_body = won_crypto.parse_tmessage(first_payload)
            LOGGER.info(
                "Routing(native): Auth1Peer first message from %s:%s (svc=%d msg=%d, %d bytes)",
                *peer, svc, msg, len(req_body),
            )
            if svc != AUTH1_PEER_SERVICE_TYPE or msg != AUTH1_PEER_REQUEST:
                LOGGER.warning(
                    "Routing(native): unexpected first message svc=%d msg=%d from %s:%s",
                    svc, msg, *peer,
                )
                return

            req = _parse_auth1_peer_request(req_body)
            client_cert = _parse_auth1_certificate(bytes(req["certificate"]))
            auth_user_id = int(client_cert["user_id"])
            if client_cert["sig"] and not won_crypto.nr_md5_verify(
                bytes(client_cert["unsigned"]),
                bytes(client_cert["sig"]),
                self.gateway._auth_p,
                self.gateway._auth_q,
                self.gateway._auth_g,
                self.gateway._auth_y,
            ):
                LOGGER.warning("Routing(native): client certificate failed auth-key verification")
                return

            LOGGER.info(
                "Routing(native): Auth1Peer request auth_mode=%d encrypt_mode=%d flags=0x%04x user_id=%d",
                req["auth_mode"], req["encrypt_mode"], req["encrypt_flags"], client_cert["user_id"],
            )
            account_username = self.gateway._username_for_active_native_login(auth_user_id)

            server_user_id = self.gateway._next_user_id
            self.gateway._next_user_id += 1
            server_cert, _server_y, server_x = self.gateway._build_user_cert(server_user_id)
            secret_b = os.urandom(8)
            secret_b_plain = struct.pack("<H", len(secret_b)) + secret_b
            secret_b_cipher = won_crypto.eg_encrypt(
                secret_b_plain,
                int(client_cert["p"]),
                int(client_cert["g"]),
                int(client_cert["y"]),
            )

            challenge1 = _routing_tmessage_payload(
                _build_auth1_peer_challenge1(secret_b_cipher, server_cert)
            )
            writer.write(_routing_wrap(challenge1))
            await writer.drain()
            LOGGER.info("Routing(native): Auth1Peer Challenge1 sent to %s:%s", *peer)

            payload = await _routing_recv(reader)
            svc, msg, challenge2_body = won_crypto.parse_tmessage(payload)
            LOGGER.info(
                "Routing(native): Auth1Peer next message from %s:%s (svc=%d msg=%d, %d bytes)",
                *peer, svc, msg, len(challenge2_body),
            )
            if svc != AUTH1_PEER_SERVICE_TYPE or msg != AUTH1_PEER_CHALLENGE2:
                LOGGER.warning(
                    "Routing(native): expected Challenge2, got svc=%d msg=%d from %s:%s",
                    svc, msg, *peer,
                )
                return

            challenge2_cipher = _parse_auth1_peer_challenge2(challenge2_body)
            challenge2_plain = won_crypto.eg_decrypt(
                challenge2_cipher,
                self.gateway._auth_p,
                self.gateway._auth_g,
                server_x,
            )
            if len(challenge2_plain) < 2:
                LOGGER.warning("Routing(native): Challenge2 plaintext too short from %s:%s", *peer)
                return
            secret_b_len, = struct.unpack("<H", challenge2_plain[:2])
            secret_b_echo = challenge2_plain[2:2 + secret_b_len]
            secret_a = challenge2_plain[2 + secret_b_len:]
            if secret_b_echo != secret_b:
                LOGGER.warning("Routing(native): SecretB mismatch from %s:%s", *peer)
                return
            if not secret_a:
                LOGGER.warning("Routing(native): empty SecretA from %s:%s", *peer)
                return

            secret_a_cipher = won_crypto.eg_encrypt(
                struct.pack("<H", len(secret_a)) + secret_a,
                int(client_cert["p"]),
                int(client_cert["g"]),
                int(client_cert["y"]),
            )
            complete = _routing_tmessage_payload(_build_auth1_peer_complete(secret_a_cipher))
            writer.write(_routing_wrap(complete))
            await writer.drain()
            LOGGER.info("Routing(native): Auth1Peer Complete sent to %s:%s", *peer)

            session_key = secret_b
            if (int(req["encrypt_flags"]) & 0x0001) == 0:
                in_seq = 1
                out_seq = 1

            while True:
                try:
                    payload = await _routing_recv_with_idle_timeout(reader)
                except asyncio.TimeoutError:
                    disconnect_reason = "idle_timeout"
                    if registered_client_id and registered_client_id in self._native_clients:
                        idle_client = self._native_clients[registered_client_id]
                        LOGGER.info(
                            "Routing(native): idle timeout from %s:%s (id=%d name=%r idle_for=%.1fs)",
                            *peer,
                            idle_client.client_id,
                            idle_client.client_name,
                            max(0.0, time.time() - idle_client.last_activity_at),
                        )
                    else:
                        LOGGER.info(
                            "Routing(native): idle timeout from %s:%s before RegisterClient",
                            *peer,
                        )
                    return
                if payload[0] not in {0x04, 0x06}:
                    disconnect_reason = "protocol_error"
                    LOGGER.warning(
                        "Routing(native): unexpected post-auth header 0x%02x from %s:%s",
                        payload[0], *peer,
                    )
                    return

                clear = _decrypt_persistent_non_t(payload, session_key, in_seq)
                if in_seq is not None:
                    in_seq += 1

                if clear[0] == SMALL_HEADER_TYPE:
                    service_type, message_type, _msg_body = _parse_small_message(clear)
                    if service_type == SMALL_COMMON_SERVICE and message_type in {
                        SMALL_COMM_REGISTER_REQUEST,
                        SMALL_COMM_REGISTER_REQUEST_EX,
                    }:
                        req = _parse_small_common_register_request(clear)
                        for obj_type, obj_data in req["data_objects"]:
                            if obj_type == b"Description":
                                with contextlib.suppress(UnicodeDecodeError):
                                    self._room_description = obj_data.decode("utf-16-le")
                            elif obj_type == b"RoomFlags" and len(obj_data) >= 4:
                                self._room_flags, = struct.unpack("<I", obj_data[:4])
                        if req["display_name"]:
                            self._room_display_name = str(req["display_name"])
                        if req["path"]:
                            self._room_path = str(req["path"])
                        self._published = True
                        if self.gateway is not None:
                            self.gateway.record_activity(
                                "room_open",
                                room_port=self.listen_port,
                                room_name=self._room_display_name,
                                room_path=self._room_path,
                                details={
                                    "description": self._room_description,
                                    "room_flags": self._room_flags,
                                    "protected": bool(self._room_password),
                                },
                            )
                        LOGGER.info(
                            "Routing(native): RegisterRequest port=%s display=%r desc=%r path=%r room_flags=0x%08x dirs=%d",
                            self.listen_port,
                            self._room_display_name,
                            self._room_description,
                            self._room_path,
                            self._room_flags,
                            len(req["dir_addresses"]),
                        )
                        out_seq = await self._send_native_route_reply(
                            writer,
                            _build_small_common_status_reply(0),
                            session_key,
                            out_seq,
                        )
                        LOGGER.info("Routing(native): RegisterRequest success sent to %s:%s", *peer)
                        continue

                if clear[0] == MINI_HEADER_TYPE:
                    service_type, message_type, _msg_body = _parse_mini_message(clear)
                    if service_type == MINI_COMMON_SERVICE and message_type == MINI_COMM_PING:
                        ping = _parse_mini_ping(clear)
                        self._touch_native_client(registered_client_id, "ping")
                        LOGGER.info(
                            "Routing(native): MiniPing start_tick=%d extended=%s",
                            ping["start_tick"], ping["extended"],
                        )
                        out_seq = await self._send_native_route_reply(
                            writer,
                            _build_mini_ping_reply(int(ping["start_tick"])),
                            session_key,
                            out_seq,
                        )
                        if registered_client_id and registered_client_id in self._native_clients:
                            self._native_clients[registered_client_id].out_seq = out_seq
                        continue

                    if service_type == MINI_ROUTING_SERVICE and message_type == ROUTING_REGISTER_CLIENT:
                        req = _parse_mini_routing_register_client(clear)
                        if self._room_password and str(req["password"]) != self._room_password:
                            LOGGER.info(
                                "Routing(native): RegisterClient rejected name=%r supplied_password=%s protected=%s",
                                req["client_name"],
                                bool(req["password"]),
                                True,
                            )
                            out_seq = await self._send_native_route_reply(
                                writer,
                                _build_mini_routing_register_client_reply(
                                    STATUS_ROUTING_INVALID_PASSWORD,
                                    0,
                                    b"",
                                    self._room_description,
                                ),
                                session_key,
                                out_seq,
                            )
                            LOGGER.info(
                                "Routing(native): RegisterClientReply sent to %s:%s (status=%d)",
                                *peer,
                                STATUS_ROUTING_INVALID_PASSWORD,
                            )
                            continue
                        client_ip = str(peer[0]) if peer and len(peer) > 0 and isinstance(peer[0], str) else "127.0.0.1"
                        client_ip_u32 = int.from_bytes(_host_to_ip4(client_ip), "little")
                        reconnect = await self._claim_pending_reconnect(
                            bytes(req["client_name_raw"]),
                            client_ip,
                        )
                        registered_client_id = (
                            reconnect.client_id
                            if reconnect is not None
                            else self._alloc_native_client_id()
                        )
                        login_auth_user_id = (
                            int(reconnect.auth_user_id)
                            if reconnect is not None and int(reconnect.auth_user_id)
                            else int(auth_user_id)
                        )
                        login_account_username = (
                            str(reconnect.account_username)
                            if reconnect is not None and str(reconnect.account_username)
                            else str(account_username)
                        )
                        self._native_clients[registered_client_id] = NativeRouteClientState(
                            client_id=registered_client_id,
                            client_name_raw=bytes(req["client_name_raw"]),
                            client_name=str(req["client_name"]),
                            client_ip=client_ip,
                            client_ip_u32=client_ip_u32,
                            writer=writer,
                            session_key=session_key,
                            out_seq=out_seq,
                            auth_user_id=login_auth_user_id,
                            account_username=login_account_username,
                            connected_at=(
                                reconnect.connected_at
                                if reconnect is not None
                                else time.time()
                            ),
                            last_activity_at=time.time(),
                            last_activity_kind=(
                                "reconnect" if reconnect is not None else "register"
                            ),
                            chat_count=(
                                reconnect.chat_count
                                if reconnect is not None
                                else 0
                            ),
                            peer_data_messages=(
                                reconnect.peer_data_messages
                                if reconnect is not None
                                else 0
                            ),
                            peer_data_bytes=(
                                reconnect.peer_data_bytes
                                if reconnect is not None
                                else 0
                            ),
                            subscriptions=(
                                [
                                    NativeRouteSubscription(
                                        link_id=sub.link_id,
                                        data_type=bytes(sub.data_type),
                                        exact_or_recursive=bool(sub.exact_or_recursive),
                                        group_or_members=bool(sub.group_or_members),
                                    )
                                    for sub in reconnect.subscriptions
                                ]
                                if reconnect is not None
                                else []
                            ),
                        )
                        if self.gateway is not None and login_auth_user_id:
                            self.gateway._attach_native_login_claim(
                                login_auth_user_id,
                                registered_client_id,
                            )
                            attached_username = self.gateway._username_for_active_native_login(
                                login_auth_user_id
                            )
                            if attached_username:
                                self._native_clients[registered_client_id].account_username = attached_username
                        LOGGER.info(
                            "Routing(native): RegisterClient %s id=%d name=%r setup_chat=%s host=%s spectator=%s",
                            "resume" if reconnect is not None else "new",
                            registered_client_id,
                            req["client_name"],
                            req["setup_chat"],
                            req["trying_to_become_host"],
                            req["become_spectator"],
                        )
                        out_seq = await self._send_native_route_reply(
                            writer,
                            _build_mini_routing_register_client_reply(
                                0,
                                registered_client_id,
                                bytes(req["client_name_raw"]),
                                self._room_description,
                            ),
                            session_key,
                            out_seq,
                        )
                        self._native_clients[registered_client_id].out_seq = out_seq
                        LOGGER.info(
                            "Routing(native): RegisterClientReply sent to %s:%s (client_id=%d)",
                            *peer, registered_client_id,
                        )
                        self._touch_native_client(
                            registered_client_id,
                            "reconnect" if reconnect is not None else "join",
                        )
                        if self.gateway is not None:
                            self.gateway.record_activity(
                                "rejoin" if reconnect is not None else "join",
                                room_port=self.listen_port,
                                room_name=self._room_display_name,
                                room_path=self._room_path,
                                player_id=registered_client_id,
                                player_name=str(req["client_name"]),
                                player_ip=client_ip,
                            )
                            self.gateway.record_live_player_event(
                                "player_joined",
                                room_port=int(self.listen_port or 0),
                                player_id=int(registered_client_id),
                                player_name=str(req["client_name"]),
                                player_ip=str(client_ip),
                                details={"mode": "reconnect" if reconnect is not None else "register"},
                            )
                        if reconnect is None:
                            delivered = await self._broadcast_native_route_group_change(
                                _build_mini_routing_group_change_ex(
                                    CHAT_GROUP_ID,
                                    registered_client_id,
                                    ROUTING_REASON_NEW_CLIENT,
                                    bytes(req["client_name_raw"]),
                                    client_ip_u32,
                                ),
                                exclude_client_id=registered_client_id,
                            )
                            if delivered:
                                LOGGER.info(
                                    "Routing(native): GroupChangeEx join broadcast sent to %d clients",
                                    delivered,
                                )
                        continue

                    if service_type == MINI_ROUTING_SERVICE and message_type == ROUTING_GET_CLIENT_LIST:
                        clients = self._routing_client_list_entries()
                        LOGGER.info(
                            "Routing(native): GetClientList from %s:%s (%d clients)",
                            *peer, len(clients),
                        )
                        out_seq = await self._send_native_route_reply(
                            writer,
                            _build_mini_routing_get_client_list_reply(clients),
                            session_key,
                            out_seq,
                        )
                        if registered_client_id and registered_client_id in self._native_clients:
                            self._native_clients[registered_client_id].out_seq = out_seq
                            self._native_clients[registered_client_id].admin_sender_announced = True
                        continue

                    if service_type == MINI_ROUTING_SERVICE and message_type == ROUTING_SUBSCRIBE_DATA_OBJECT:
                        req = _parse_mini_routing_subscribe_data_object(clear)
                        subscription = NativeRouteSubscription(
                            link_id=int(req["link_id"]),
                            data_type=bytes(req["data_type"]),
                            exact_or_recursive=bool(req["exact_or_recursive"]),
                            group_or_members=bool(req["group_or_members"]),
                        )
                        if registered_client_id and registered_client_id in self._native_clients:
                            self._native_clients[registered_client_id].subscriptions.append(subscription)
                        matches = self._route_data_objects_for_subscription(subscription)
                        LOGGER.info(
                            "Routing(native): SubscribeDataObject link_id=%d type=%r recursive=%s members=%s",
                            req["link_id"],
                            bytes(req["data_type"]),
                            not req["exact_or_recursive"],
                            req["group_or_members"],
                        )
                        out_seq = await self._send_native_route_reply(
                            writer,
                            _build_mini_routing_read_data_object_reply(matches),
                            session_key,
                            out_seq,
                        )
                        if registered_client_id and registered_client_id in self._native_clients:
                            self._native_clients[registered_client_id].out_seq = out_seq
                        LOGGER.info(
                            "Routing(native): ReadDataObjectReply sent to %s:%s (%d objects)",
                            *peer,
                            len(matches),
                        )
                        continue

                    if service_type == MINI_ROUTING_SERVICE and message_type == ROUTING_CREATE_DATA_OBJECT:
                        req = _parse_mini_routing_create_data_object(clear)
                        key = self._route_data_key(int(req["link_id"]), bytes(req["data_type"]))
                        data_object = NativeRouteDataObject(
                            link_id=int(req["link_id"]),
                            owner_id=int(req["owner_id"]),
                            lifespan=int(req["lifespan"]),
                            data_type=bytes(req["data_type"]),
                            data=bytes(req["data"]),
                        )
                        self._touch_native_client(registered_client_id, "game_object")
                        existed = key in self._data_objects
                        self._data_objects[key] = data_object
                        LOGGER.info(
                            "Routing(native): CreateDataObject link_id=%d owner_id=%d lifespan=%d type=%r name=%r data_len=%d",
                            data_object.link_id,
                            data_object.owner_id,
                            data_object.lifespan,
                            data_object.data_type,
                            _decode_routing_data_type(data_object.data_type),
                            len(data_object.data),
                        )
                        out_seq = await self._send_native_route_reply(
                            writer,
                            _build_mini_routing_status_reply(0),
                            session_key,
                            out_seq,
                        )
                        if registered_client_id and registered_client_id in self._native_clients:
                            self._native_clients[registered_client_id].out_seq = out_seq
                        if existed:
                            delivered = await self._broadcast_native_route_data_object(
                                _build_mini_routing_replace_data_object(
                                    data_object.link_id,
                                    data_object.data_type,
                                    data_object.data,
                                ),
                                data_object,
                            )
                            LOGGER.info(
                                "Routing(native): ReplaceDataObject broadcast sent to %d subscribed clients",
                                delivered,
                            )
                        else:
                            delivered = await self._broadcast_native_route_data_object(
                                _build_mini_routing_create_data_object(
                                    data_object.link_id,
                                    data_object.owner_id,
                                    data_object.lifespan,
                                    data_object.data_type,
                                    data_object.data,
                                ),
                                data_object,
                            )
                            LOGGER.info(
                                "Routing(native): CreateDataObject broadcast sent to %d subscribed clients",
                                delivered,
                            )
                        if self.gateway is not None:
                            self.gateway.record_live_routing_object_event(
                                "routing_object_upsert",
                                room_port=int(self.listen_port or 0),
                                link_id=int(data_object.link_id),
                                owner_id=int(data_object.owner_id),
                                owner_name=(
                                    self._native_clients[data_object.owner_id].client_name
                                    if data_object.owner_id in self._native_clients
                                    else ""
                                ),
                                data_type_text=_decode_routing_data_type(data_object.data_type),
                                payload=bytes(data_object.data),
                                lifespan=int(data_object.lifespan),
                            )
                        continue

                    if service_type == MINI_ROUTING_SERVICE and message_type == ROUTING_REPLACE_DATA_OBJECT:
                        req = _parse_mini_routing_replace_data_object(clear)
                        key = self._route_data_key(int(req["link_id"]), bytes(req["data_type"]))
                        existing = self._data_objects.get(key)
                        owner_id = existing.owner_id if existing is not None else int(registered_client_id or 0)
                        lifespan = existing.lifespan if existing is not None else 0
                        data_object = NativeRouteDataObject(
                            link_id=int(req["link_id"]),
                            owner_id=owner_id,
                            lifespan=lifespan,
                            data_type=bytes(req["data_type"]),
                            data=bytes(req["data"]),
                        )
                        self._touch_native_client(registered_client_id, "game_object")
                        self._data_objects[key] = data_object
                        LOGGER.info(
                            "Routing(native): ReplaceDataObject link_id=%d owner_id=%d type=%r name=%r data_len=%d",
                            data_object.link_id,
                            data_object.owner_id,
                            data_object.data_type,
                            _decode_routing_data_type(data_object.data_type),
                            len(data_object.data),
                        )
                        out_seq = await self._send_native_route_reply(
                            writer,
                            _build_mini_routing_status_reply(0),
                            session_key,
                            out_seq,
                        )
                        if registered_client_id and registered_client_id in self._native_clients:
                            self._native_clients[registered_client_id].out_seq = out_seq
                        delivered = await self._broadcast_native_route_data_object(
                            _build_mini_routing_replace_data_object(
                                data_object.link_id,
                                data_object.data_type,
                                data_object.data,
                            ),
                            data_object,
                        )
                        LOGGER.info(
                            "Routing(native): ReplaceDataObject broadcast sent to %d subscribed clients",
                            delivered,
                        )
                        if self.gateway is not None:
                            self.gateway.record_live_routing_object_event(
                                "routing_object_upsert",
                                room_port=int(self.listen_port or 0),
                                link_id=int(data_object.link_id),
                                owner_id=int(data_object.owner_id),
                                owner_name=(
                                    self._native_clients[data_object.owner_id].client_name
                                    if data_object.owner_id in self._native_clients
                                    else ""
                                ),
                                data_type_text=_decode_routing_data_type(data_object.data_type),
                                payload=bytes(data_object.data),
                                lifespan=int(data_object.lifespan),
                            )
                        continue

                    if service_type == MINI_ROUTING_SERVICE and message_type == ROUTING_DELETE_DATA_OBJECT:
                        req = _parse_mini_routing_delete_data_object(clear)
                        key = self._route_data_key(int(req["link_id"]), bytes(req["data_type"]))
                        existing = self._data_objects.pop(key, None)
                        self._touch_native_client(registered_client_id, "game_object")
                        LOGGER.info(
                            "Routing(native): DeleteDataObject link_id=%d type=%r name=%r existed=%s",
                            req["link_id"],
                            bytes(req["data_type"]),
                            _decode_routing_data_type(bytes(req["data_type"])),
                            existing is not None,
                        )
                        out_seq = await self._send_native_route_reply(
                            writer,
                            _build_mini_routing_status_reply(0),
                            session_key,
                            out_seq,
                        )
                        if registered_client_id and registered_client_id in self._native_clients:
                            self._native_clients[registered_client_id].out_seq = out_seq
                        if existing is not None:
                            delivered = await self._broadcast_native_route_data_object(
                                _build_mini_routing_delete_data_object(
                                    existing.link_id,
                                    existing.data_type,
                                ),
                                existing,
                            )
                            LOGGER.info(
                                "Routing(native): DeleteDataObject broadcast sent to %d subscribed clients",
                                delivered,
                            )
                            if self.gateway is not None:
                                self.gateway.record_live_routing_object_event(
                                    "routing_object_delete",
                                    room_port=int(self.listen_port or 0),
                                    link_id=int(existing.link_id),
                                    owner_id=int(existing.owner_id),
                                    owner_name=(
                                        self._native_clients[existing.owner_id].client_name
                                        if existing.owner_id in self._native_clients
                                        else ""
                                    ),
                                    data_type_text=_decode_routing_data_type(existing.data_type),
                                    payload=bytes(existing.data),
                                    lifespan=int(existing.lifespan),
                                )
                        continue

                    if service_type == MINI_ROUTING_SERVICE and message_type == ROUTING_RENEW_DATA_OBJECT:
                        req = _parse_mini_routing_renew_data_object(clear)
                        key = self._route_data_key(int(req["link_id"]), bytes(req["data_type"]))
                        existing = self._data_objects.get(key)
                        self._touch_native_client(registered_client_id, "game_object")
                        if existing is not None:
                            existing.lifespan = int(req["new_lifespan"])
                        LOGGER.info(
                            "Routing(native): RenewDataObject link_id=%d type=%r name=%r new_lifespan=%d existed=%s",
                            req["link_id"],
                            bytes(req["data_type"]),
                            _decode_routing_data_type(bytes(req["data_type"])),
                            req["new_lifespan"],
                            existing is not None,
                        )
                        out_seq = await self._send_native_route_reply(
                            writer,
                            _build_mini_routing_status_reply(0),
                            session_key,
                            out_seq,
                        )
                        if registered_client_id and registered_client_id in self._native_clients:
                            self._native_clients[registered_client_id].out_seq = out_seq
                        continue

                    if service_type == MINI_ROUTING_SERVICE and message_type == ROUTING_SEND_CHAT:
                        req = _parse_mini_routing_send_chat(clear)
                        sender_name = "unknown"
                        if registered_client_id and registered_client_id in self._native_clients:
                            sender_name = self._native_clients[registered_client_id].client_name
                        delivered = 0
                        if registered_client_id:
                            delivered = await self._broadcast_native_route_chat(
                                registered_client_id,
                                int(req["chat_type"]),
                                bytes(req["data"]),
                                list(req["addressees"]),
                                bool(req["include_exclude_flag"]),
                            )
                        client = self._touch_native_client(registered_client_id, "chat")
                        LOGGER.info(
                            "Routing(native): Chat from client_id=%d name=%r type=%d recipients=%d reply=%s sanitized=%s text=%r",
                            registered_client_id,
                            sender_name,
                            req["chat_type"],
                            delivered,
                            req["should_send_reply"],
                            req["raw_text"] != req["text"],
                            req["text"],
                        )
                        if self.gateway is not None and client is not None:
                            self.gateway.record_activity(
                                "chat",
                                room_port=self.listen_port,
                                room_name=self._room_display_name,
                                room_path=self._room_path,
                                player_id=client.client_id,
                                player_name=client.client_name,
                                player_ip=client.client_ip,
                                text=str(req["text"]),
                            )
                        if req["should_send_reply"]:
                            out_seq = await self._send_native_route_reply(
                                writer,
                                _build_mini_routing_status_reply(0),
                                session_key,
                                out_seq,
                            )
                            if registered_client_id and registered_client_id in self._native_clients:
                                self._native_clients[registered_client_id].out_seq = out_seq
                        continue

                    if service_type == MINI_ROUTING_SERVICE and message_type == ROUTING_SEND_DATA:
                        req = _parse_mini_routing_send_data(clear)
                        delivered = 0
                        self._last_peer_data_at = time.time()
                        self._touch_native_client(registered_client_id, "peer_data", len(bytes(req["data"])))
                        if registered_client_id:
                            delivered = await self._broadcast_native_route_peer_data(
                                registered_client_id,
                                bytes(req["data"]),
                                list(req["addressees"]),
                                bool(req["include_exclude_flag"]),
                            )
                        self._log_native_peer_data_event(
                            "SendData",
                            int(registered_client_id),
                            bytes(req["data"]),
                            delivered,
                            bool(req["should_send_reply"]),
                        )
                        self._maybe_infer_game_metadata(bytes(req["data"]))
                        if self.gateway is not None:
                            sender_name = (
                                self._native_clients[registered_client_id].client_name
                                if registered_client_id in self._native_clients
                                else ""
                            )
                            self.gateway.record_live_peer_packet(
                                "peer_packet",
                                room_port=int(self.listen_port or 0),
                                sender_client_id=int(registered_client_id or 0),
                                sender_name=sender_name,
                                recipient_client_ids=[int(client_id) for client_id in req["addressees"]],
                                recipient_count=int(delivered),
                                payload=bytes(req["data"]),
                                packet_kind="SendData",
                            )
                        if req["should_send_reply"]:
                            out_seq = await self._send_native_route_reply(
                                writer,
                                _build_mini_routing_status_reply(0),
                                session_key,
                                out_seq,
                            )
                            if registered_client_id and registered_client_id in self._native_clients:
                                self._native_clients[registered_client_id].out_seq = out_seq
                        continue

                    if service_type == MINI_ROUTING_SERVICE and message_type == ROUTING_SEND_DATA_BROADCAST:
                        req = _parse_mini_routing_send_data_broadcast(clear)
                        delivered = 0
                        self._last_peer_data_at = time.time()
                        self._touch_native_client(registered_client_id, "peer_data", len(bytes(req["data"])))
                        if registered_client_id:
                            delivered = await self._broadcast_native_route_peer_data(
                                registered_client_id,
                                bytes(req["data"]),
                                [],
                                False,
                            )
                        self._log_native_peer_data_event(
                            "SendDataBroadcast",
                            int(registered_client_id),
                            bytes(req["data"]),
                            delivered,
                            bool(req["should_send_reply"]),
                        )
                        self._maybe_infer_game_metadata(bytes(req["data"]))
                        if self.gateway is not None:
                            sender_name = (
                                self._native_clients[registered_client_id].client_name
                                if registered_client_id in self._native_clients
                                else ""
                            )
                            recipient_ids = [
                                int(client_id)
                                for client_id in self._native_clients
                                if int(client_id) != int(registered_client_id or 0)
                            ]
                            self.gateway.record_live_peer_packet(
                                "peer_packet",
                                room_port=int(self.listen_port or 0),
                                sender_client_id=int(registered_client_id or 0),
                                sender_name=sender_name,
                                recipient_client_ids=recipient_ids,
                                recipient_count=int(delivered),
                                payload=bytes(req["data"]),
                                packet_kind="SendDataBroadcast",
                            )
                        if req["should_send_reply"]:
                            out_seq = await self._send_native_route_reply(
                                writer,
                                _build_mini_routing_status_reply(0),
                                session_key,
                                out_seq,
                            )
                            if registered_client_id and registered_client_id in self._native_clients:
                                self._native_clients[registered_client_id].out_seq = out_seq
                        continue

                    if service_type == MINI_ROUTING_SERVICE and message_type == ROUTING_KEEP_ALIVE:
                        self._touch_native_client(registered_client_id, "keepalive")
                        LOGGER.debug("Routing(native): KeepAlive from %s:%s", *peer)
                        continue

                    if service_type == MINI_ROUTING_SERVICE and message_type == ROUTING_RECONNECT_CLIENT:
                        req = _parse_mini_routing_reconnect_client(clear)
                        reconnect = await self._claim_pending_reconnect_by_id(
                            int(req["client_id"]),
                            client_ip,
                        )
                        if reconnect is None:
                            LOGGER.info(
                                "Routing(native): ReconnectClient failed from %s:%s for client_id=%d",
                                *peer,
                                int(req["client_id"]),
                            )
                            out_seq = await self._send_native_route_reply(
                                writer,
                                _build_mini_routing_status_reply(-1),
                                session_key,
                                out_seq,
                            )
                            continue

                        registered_client_id = reconnect.client_id
                        self._native_clients[registered_client_id] = NativeRouteClientState(
                            client_id=reconnect.client_id,
                            client_name_raw=bytes(reconnect.client_name_raw),
                            client_name=str(reconnect.client_name),
                            client_ip=str(reconnect.client_ip),
                            client_ip_u32=int(reconnect.client_ip_u32),
                            writer=writer,
                            session_key=session_key,
                            out_seq=out_seq,
                            auth_user_id=int(reconnect.auth_user_id),
                            account_username=str(reconnect.account_username),
                            connected_at=float(reconnect.connected_at),
                            last_activity_at=float(reconnect.last_activity_at),
                            last_activity_kind=str(reconnect.last_activity_kind),
                            chat_count=int(reconnect.chat_count),
                            peer_data_messages=int(reconnect.peer_data_messages),
                            peer_data_bytes=int(reconnect.peer_data_bytes),
                            subscriptions=[
                                NativeRouteSubscription(
                                    link_id=sub.link_id,
                                    data_type=bytes(sub.data_type),
                                    exact_or_recursive=bool(sub.exact_or_recursive),
                                    group_or_members=bool(sub.group_or_members),
                                )
                                for sub in reconnect.subscriptions
                            ],
                        )
                        if self.gateway is not None and int(reconnect.auth_user_id):
                            self.gateway._attach_native_login_claim(
                                int(reconnect.auth_user_id),
                                registered_client_id,
                            )
                            attached_username = self.gateway._username_for_active_native_login(
                                int(reconnect.auth_user_id)
                            )
                            if attached_username:
                                self._native_clients[registered_client_id].account_username = attached_username
                        self._touch_native_client(registered_client_id, "reconnect")
                        LOGGER.info(
                            "Routing(native): ReconnectClient success from %s:%s id=%d name=%r want_missed=%s",
                            *peer,
                            registered_client_id,
                            reconnect.client_name,
                            bool(req["want_missed_messages"]),
                        )
                        if self.gateway is not None:
                            self.gateway.record_activity(
                                "rejoin",
                                room_port=self.listen_port,
                                room_name=self._room_display_name,
                                room_path=self._room_path,
                                player_id=registered_client_id,
                                player_name=reconnect.client_name,
                                player_ip=client_ip,
                                details={"mode": "routing_reconnect"},
                            )
                            self.gateway.record_live_player_event(
                                "player_joined",
                                room_port=int(self.listen_port or 0),
                                player_id=int(registered_client_id),
                                player_name=str(reconnect.client_name),
                                player_ip=str(client_ip),
                                details={"mode": "routing_reconnect"},
                            )
                        out_seq = await self._send_native_route_reply(
                            writer,
                            _build_mini_routing_status_reply(0),
                            session_key,
                            out_seq,
                        )
                        if registered_client_id in self._native_clients:
                            self._native_clients[registered_client_id].out_seq = out_seq
                        continue

                    if service_type == MINI_ROUTING_SERVICE and message_type == ROUTING_DISCONNECT_CLIENT:
                        disconnect_reason = "voluntary_disconnect"
                        if registered_client_id and registered_client_id in self._native_clients:
                            client = self._native_clients[registered_client_id]
                            LOGGER.info(
                                "Routing(native): DisconnectClient from %s:%s (id=%d name=%r)",
                                *peer, client.client_id, client.client_name,
                            )
                        else:
                            LOGGER.info("Routing(native): DisconnectClient from %s:%s", *peer)
                        return

                LOGGER.warning(
                    "Routing(native): unhandled clear msg header=0x%02x from %s:%s body=%s",
                    clear[0], *peer, clear[:64].hex(),
                )
                disconnect_reason = "protocol_error"
                return
        except asyncio.IncompleteReadError:
            disconnect_reason = "eof"
        except ConnectionResetError:
            disconnect_reason = "connection_reset"
        except (BrokenPipeError, ConnectionAbortedError):
            disconnect_reason = "transport_lost"
        except Exception:
            disconnect_reason = "handler_error"
            raise
        finally:
            if registered_client_id:
                self._flush_solo_peer_data_logs(registered_client_id)
                client = self._native_clients.pop(registered_client_id, None)
                if client is not None:
                    if self._should_offer_reconnect(client, disconnect_reason):
                        self._park_disconnected_client(client, disconnect_reason)
                        if self.gateway is not None:
                            self.gateway.record_live_room_refresh(int(self.listen_port or 0))
                    else:
                        await self._finalize_client_departure(
                            client.client_id,
                            client.client_name,
                            client.client_ip,
                            auth_user_id=client.auth_user_id,
                            account_username=client.account_username,
                            disconnect_reason=disconnect_reason,
                        )

    async def _handle_silencer_session(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        first_payload: bytes,
    ) -> None:
        peer = writer.get_extra_info("peername", ("?", 0))
        payload = first_payload
        while True:
            if payload[:2] != b"\x03\x02":
                LOGGER.warning(
                    "Routing: missing \\x03\\x02 header from %s:%s payload=%s",
                    *peer, payload[:32].hex(),
                )
                return

            msg_type = payload[2]
            data = payload[3:]

            if msg_type == self._INIT_ID:
                LOGGER.info("Routing: INIT from %s:%s", *peer)
                writer.write(_SILENCER_ROUTING_ACK)
                await writer.drain()
                await asyncio.sleep(0.05)
                writer.write(_SILENCER_ROUTING_USAGE)
                await writer.drain()

            elif msg_type == self._NEW_CONFLICT_ID:
                if len(data) == _SILENCER_CONFLICT_DATA_LEN:
                    LOGGER.info(
                        "Routing: NEW_CONFLICT from %s:%s (%d bytes)",
                        *peer, len(data),
                    )
                    tail = bytes(
                        _SILENCER_CONFLICT_TOTAL
                        - len(_SILENCER_CONFLICT_HDR)
                        - _SILENCER_CONFLICT_DATA_LEN
                    )
                    self._conflict_data = (
                        _SILENCER_CONFLICT_HDR + data[:_SILENCER_CONFLICT_DATA_LEN] + tail
                    )
                else:
                    LOGGER.warning(
                        "Routing: NEW_CONFLICT bad size %d (want %d) from %s:%s",
                        len(data), _SILENCER_CONFLICT_DATA_LEN, *peer,
                    )
                writer.write(self._conflict_data)
                await writer.drain()
                LOGGER.info("Routing: conflict listing sent to %s:%s", *peer)

            elif msg_type == self._CONFLICTQUERY_ID:
                LOGGER.info("Routing: CONFLICTQUERY from %s:%s", *peer)
                writer.write(self._conflict_data)
                await writer.drain()

            elif msg_type == self._CHATMESSAGE_ID:
                LOGGER.info(
                    "Routing: CHATMESSAGE (-> conflict listing) from %s:%s", *peer
                )
                writer.write(self._conflict_data)
                await writer.drain()

            elif msg_type == self._ABORT_CONFLICT:
                LOGGER.info("Routing: ABORT_CONFLICT from %s:%s", *peer)

            elif msg_type == self._USER_TERMINATION:
                LOGGER.info("Routing: USER_TERMINATION from %s:%s (keeping conn)", *peer)

            elif msg_type == self._CLIENTQUERY_ID:
                LOGGER.info("Routing: CLIENTQUERY (ignored) from %s:%s", *peer)

            else:
                LOGGER.warning(
                    "Routing: unknown msg_type=0x%02x len=%d from %s:%s",
                    msg_type, len(data), *peer,
                )

            payload = await _routing_recv(reader)

    async def handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername", ("?", 0))
        LOGGER.info("Routing-%s connection from %s:%s", self.listen_port, *peer)
        try:
            payload = await _routing_recv(reader)
            if self._is_native_auth_request(payload):
                await self._handle_native_client(reader, writer, payload)
            else:
                await self._handle_silencer_session(reader, writer, payload)
            return

        except asyncio.IncompleteReadError:
            LOGGER.debug("Routing: EOF from %s:%s", *peer)
        except Exception as exc:
            LOGGER.error("Routing: error from %s:%s: %s", *peer, exc)
        finally:
            writer.close()
            with contextlib.suppress(ConnectionResetError, BrokenPipeError, ConnectionAbortedError, OSError):
                await writer.wait_closed()


class RoutingServerManager:
    def __init__(
        self,
        host: str,
        public_host: str,
        base_port: int,
        max_port: Optional[int] = None,
        excluded_ports: Optional[set[int]] = None,
        gateway: Optional["BinaryGatewayServer"] = None,
        product_profile: ProductProfile = HOMEWORLD_PRODUCT_PROFILE,
    ) -> None:
        self.host = host
        self.public_host = public_host
        self.base_port = base_port
        self.max_port = max_port
        self.gateway = gateway
        self.product_profile = product_profile
        self._excluded_ports = set(excluded_ports or set())
        self._listeners: Dict[int, asyncio.base_events.Server] = {}
        self._servers: Dict[int, SilencerRoutingServer] = {}
        self._next_port = base_port
        self._lock = asyncio.Lock()

    async def _start_listener_locked(
        self,
        port: int,
        publish_in_directory: bool,
    ) -> Tuple[SilencerRoutingServer, asyncio.base_events.Server]:
        existing = self._listeners.get(port)
        if existing is not None:
            return self._servers[port], existing

        routing_srv = SilencerRoutingServer(
            self.gateway,
            listen_port=port,
            publish_in_directory=publish_in_directory,
            product_profile=self.product_profile,
        )
        listener = await asyncio.start_server(routing_srv.handle_client, self.host, port)
        routing_srv.start_background_tasks()
        self._listeners[port] = listener
        self._servers[port] = routing_srv
        LOGGER.info(
            "Routing(manager): listener started on %s:%d (publish=%s)",
            self.host,
            port,
            publish_in_directory,
        )
        return routing_srv, listener

    async def start_listener(
        self,
        port: int,
        publish_in_directory: bool = True,
    ) -> Tuple[SilencerRoutingServer, asyncio.base_events.Server]:
        async with self._lock:
            return await self._start_listener_locked(port, publish_in_directory)

    async def allocate_server(self, publish_in_directory: bool = True) -> int:
        async with self._lock:
            for port in sorted(self._servers):
                server = self._servers[port]
                if server.can_host_room() and server._publish_in_directory == publish_in_directory:
                    server.mark_room_allocated()
                    return port

            port = self._next_port
            while port in self._listeners or port in self._excluded_ports:
                port += 1
            if self.max_port is not None and port > self.max_port:
                raise RuntimeError(
                    f"routing_port_range_exhausted:{self.base_port}-{self.max_port}"
                )
            self._next_port = port + 1
            server, _listener = await self._start_listener_locked(port, publish_in_directory)
            server.mark_room_allocated()
            return port

    def directory_entries(self) -> list[Dict[str, object]]:
        entries: list[Dict[str, object]] = []
        for port in sorted(self._servers):
            entry = self._servers[port].native_directory_entry(self.public_host)
            if entry is not None:
                entries.append(entry)
        return entries

    def dashboard_snapshot(self) -> Dict[str, object]:
        room_snapshots = [
            self._servers[port].dashboard_snapshot()
            for port in sorted(self._servers)
        ]
        players: list[Dict[str, object]] = []
        servers: list[Dict[str, object]] = []
        live_games: list[Dict[str, object]] = []
        current_ips: set[str] = set()
        current_game_room_count = 0

        for room in room_snapshots:
            room_players = []
            room_is_game = bool(room.get("is_game_room"))
            if room_is_game:
                current_game_room_count += 1
            for client in room.get("clients", []):
                player_entry = {
                    "client_id": client.get("client_id"),
                    "client_name": client.get("client_name"),
                    "client_ip": client.get("client_ip"),
                    "chat_count": client.get("chat_count", 0),
                    "connected_seconds": client.get("connected_seconds", 0),
                    "idle_seconds": client.get("idle_seconds", 0),
                    "last_activity_kind": client.get("last_activity_kind", ""),
                    "subscription_count": client.get("subscription_count", 0),
                    "peer_data_messages": client.get("peer_data_messages", 0),
                    "peer_data_bytes": client.get("peer_data_bytes", 0),
                    "room_port": room.get("listen_port"),
                    "room_name": room.get("room_display_name"),
                    "room_is_game": room_is_game,
                    "room_path": room.get("room_path"),
                    "room_password_set": room.get("room_password_set", False),
                }
                room_players.append(player_entry)
                players.append(player_entry)
                if player_entry["client_ip"]:
                    current_ips.add(str(player_entry["client_ip"]))

            room_games = [
                {
                    **game,
                    "room_port": room.get("listen_port"),
                    "room_name": room.get("room_display_name"),
                }
                for game in room.get("games", [])
            ]
            live_games.extend(room_games)
            servers.append(
                {
                    "listen_port": room.get("listen_port"),
                    "room_name": room.get("room_display_name"),
                    "room_description": room.get("room_description"),
                    "room_path": room.get("room_path"),
                    "published": room.get("published", False),
                    "room_password_set": room.get("room_password_set", False),
                    "room_flags": room.get("room_flags", 0),
                    "player_count": len(room_players),
                    "is_game_room": room_is_game,
                    "active_game_count": room.get("active_game_count", 1 if room_is_game else 0),
                    "peer_data_messages": room.get("peer_data_messages", 0),
                    "peer_data_bytes": room.get("peer_data_bytes", 0),
                    "players": room_players,
                    "game_count": len(room_games),
                    "games": room_games,
                }
            )

        players.sort(key=lambda item: (str(item["room_name"]), str(item["client_name"]), int(item["client_id"] or 0)))
        servers.sort(key=lambda item: (str(item["room_name"]), int(item["listen_port"] or 0)))
        live_games.sort(key=lambda item: (str(item["room_name"]), str(item["name"]), int(item["link_id"] or 0)))

        return {
            "host": self.host,
            "public_host": self.public_host,
            "base_port": self.base_port,
            "max_port": self.max_port,
            "next_port": self._next_port,
            "listener_ports": sorted(self._listeners),
            "room_count": len(room_snapshots),
            "published_room_count": sum(1 for room in room_snapshots if room.get("published")),
            "current_player_count": len(players),
            "current_unique_ip_count": len(current_ips),
            "current_game_room_count": current_game_room_count,
            "current_game_count": len(live_games),
            "players": players,
            "servers": servers,
            "games": live_games,
            "rooms": room_snapshots,
        }

    def get_server(self, port: int) -> Optional[SilencerRoutingServer]:
        return self._servers.get(port)

    async def admin_kick_player(self, port: int, client_id: int) -> bool:
        server = self._servers.get(port)
        if server is None:
            return False
        return await server.admin_kick_client(client_id)

    async def admin_broadcast(self, message: str, room_port: Optional[int] = None) -> int:
        total = 0
        if room_port is not None:
            server = self._servers.get(room_port)
            if server is not None:
                total += await server.admin_broadcast_chat(message)
        else:
            for server in self._servers.values():
                total += await server.admin_broadcast_chat(message)
        return total

    async def close_all(self) -> None:
        listeners = list(self._listeners.values())
        for server in list(self._servers.values()):
            with contextlib.suppress(Exception):
                await server.stop_background_tasks()
        for listener in listeners:
            listener.close()
        for listener in listeners:
            with contextlib.suppress(Exception):
                await listener.wait_closed()


