from __future__ import annotations

import asyncio
import importlib
import logging
import struct
import time

import titan_binary_gateway

routing_module = importlib.import_module("gateway.routing")


def test_native_route_subscription_is_constructible() -> None:
    subscription = titan_binary_gateway.NativeRouteSubscription(
        link_id=7,
        data_type=b"HW",
        exact_or_recursive=True,
        group_or_members=False,
    )

    assert subscription.link_id == 7
    assert subscription.data_type == b"HW"
    assert subscription.exact_or_recursive is True
    assert subscription.group_or_members is False


def test_parse_mini_routing_reconnect_client() -> None:
    clear = bytes(
        [
            titan_binary_gateway.MINI_HEADER_TYPE,
            titan_binary_gateway.MINI_ROUTING_SERVICE,
            titan_binary_gateway.ROUTING_RECONNECT_CLIENT,
            0x34,
            0x12,
            0x01,
        ]
    )

    parsed = titan_binary_gateway._parse_mini_routing_reconnect_client(clear)

    assert parsed == {
        "client_id": 0x1234,
        "want_missed_messages": True,
    }


def test_claim_pending_reconnect_by_id_requires_matching_ip() -> None:
    server = titan_binary_gateway.SilencerRoutingServer()
    server._pending_reconnects[7] = titan_binary_gateway.PendingNativeReconnect(
        client_id=7,
        client_name_raw=b"Alpha",
        client_name="Alpha",
        client_ip="1.2.3.4",
        client_ip_u32=0,
        connected_at=100.0,
        last_activity_at=101.0,
        last_activity_kind="peer_data",
        chat_count=1,
        peer_data_messages=2,
        peer_data_bytes=64,
    )

    missing = asyncio.run(server._claim_pending_reconnect_by_id(7, "9.9.9.9"))
    found = asyncio.run(server._claim_pending_reconnect_by_id(7, "1.2.3.4"))

    assert missing is None
    assert found is not None
    assert found.client_id == 7
    assert 7 not in server._pending_reconnects


def test_evict_native_login_removes_active_client_and_pending_reconnect() -> None:
    class FakeGateway:
        def __init__(self) -> None:
            self.releases: list[dict[str, object]] = []

        def record_activity(self, *_args: object, **_kwargs: object) -> None:
            pass

        def record_live_player_event(self, *_args: object, **_kwargs: object) -> None:
            pass

        def _release_native_login_claim(self, **kwargs: object) -> bool:
            self.releases.append(dict(kwargs))
            return True

    class FakeWriter:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    gateway = FakeGateway()
    writer = FakeWriter()
    server = titan_binary_gateway.SilencerRoutingServer(
        gateway,
        listen_port=15102,
        publish_in_directory=True,
    )
    server._native_clients[5] = titan_binary_gateway.NativeRouteClientState(
        client_id=5,
        client_name_raw=b"DaMaG",
        client_name="DaMaG",
        client_ip="1.2.3.4",
        client_ip_u32=0,
        writer=writer,  # type: ignore[arg-type]
        session_key=b"",
        out_seq=None,
        auth_user_id=1000,
        account_username="DaMaG",
    )
    server._pending_reconnects[7] = titan_binary_gateway.PendingNativeReconnect(
        client_id=7,
        client_name_raw=b"DaMaG",
        client_name="DaMaG",
        client_ip="1.2.3.4",
        client_ip_u32=0,
        connected_at=100.0,
        last_activity_at=101.0,
        last_activity_kind="peer_data",
        chat_count=1,
        peer_data_messages=2,
        peer_data_bytes=64,
        auth_user_id=1000,
        account_username="DaMaG",
    )

    evicted = asyncio.run(
        server.evict_native_login(
            user_id=1000,
            username="DaMaG",
            reason="native_login_replaced",
        )
    )

    assert evicted == 2
    assert writer.closed is True
    assert server._native_clients == {}
    assert server._pending_reconnects == {}
    assert [release["user_id"] for release in gateway.releases] == [1000, 1000]
    assert all(
        release["reason"] == "routing_native_login_replaced"
        for release in gateway.releases
    )


def test_replace_active_native_login_evicts_old_routing_session() -> None:
    class FakeRoutingManager:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        async def evict_native_login(self, **kwargs: object) -> int:
            self.calls.append(dict(kwargs))
            return 1

    runtime = titan_binary_gateway.BinaryGatewayServer("127.0.0.1", 0)
    routing_manager = FakeRoutingManager()
    runtime.routing_manager = routing_manager  # type: ignore[assignment]
    runtime._register_native_login_claim("DaMaG", 1000)
    runtime._attach_native_login_claim(1000, 5)

    replaced = asyncio.run(runtime._replace_active_native_login("DaMaG"))

    assert replaced is True
    assert runtime._username_for_active_native_login(1000) == ""
    assert routing_manager.calls == [
        {
            "user_id": 1000,
            "username": "DaMaG",
            "reason": "native_login_replaced",
        }
    ]


def test_reconnect_client_before_register_uses_peer_ip(monkeypatch) -> None:
    class FakeGateway:
        _auth_keys_loaded = True
        _auth_p = 23
        _auth_q = 11
        _auth_g = 5
        _auth_y = 8
        _next_user_id = 2000

        def __init__(self) -> None:
            self.attached: list[tuple[int, int]] = []
            self.events: list[tuple[str, dict[str, object]]] = []

        def _build_user_cert(self, user_id: int) -> tuple[bytes, int, int]:
            return b"server-cert", 0, 3

        def _username_for_active_native_login(self, user_id: int) -> str:
            return "DaMaG" if int(user_id) == 1040 else ""

        def _attach_native_login_claim(self, user_id: int, client_id: int) -> None:
            self.attached.append((int(user_id), int(client_id)))

        def _release_native_login_claim(self, **_kwargs: object) -> bool:
            return True

        def record_activity(self, kind: str, **kwargs: object) -> None:
            self.events.append((kind, dict(kwargs)))

        def record_live_player_event(self, kind: str, **kwargs: object) -> None:
            self.events.append((kind, dict(kwargs)))

    class FakeReader:
        pass

    class FakeWriter:
        def __init__(self) -> None:
            self.writes: list[bytes] = []
            self.closed = False

        def get_extra_info(self, name: str, default: object = None) -> object:
            if name == "peername":
                return ("213.217.0.31", 49476)
            return default

        def write(self, data: bytes) -> None:
            self.writes.append(bytes(data))

        async def drain(self) -> None:
            pass

        def close(self) -> None:
            self.closed = True

    secret_b = b"12345678"
    clear_reconnect = bytes(
        [
            titan_binary_gateway.MINI_HEADER_TYPE,
            titan_binary_gateway.MINI_ROUTING_SERVICE,
            titan_binary_gateway.ROUTING_RECONNECT_CLIENT,
            0x07,
            0x00,
            0x00,
        ]
    )
    clear_disconnect = bytes(
        [
            titan_binary_gateway.MINI_HEADER_TYPE,
            titan_binary_gateway.MINI_ROUTING_SERVICE,
            titan_binary_gateway.ROUTING_DISCONNECT_CLIENT,
        ]
    )
    routing_payloads = iter([b"challenge2", b"\x04reconnect", b"\x04disconnect"])

    async def fake_recv(_reader: object) -> bytes:
        try:
            return next(routing_payloads)
        except StopIteration:
            raise asyncio.IncompleteReadError(partial=b"", expected=1)

    def fake_parse_tmessage(body: bytes) -> tuple[int, int, bytes]:
        if body == b"first":
            return (
                titan_binary_gateway.AUTH1_PEER_SERVICE_TYPE,
                titan_binary_gateway.AUTH1_PEER_REQUEST,
                b"request",
            )
        return (
            titan_binary_gateway.AUTH1_PEER_SERVICE_TYPE,
            titan_binary_gateway.AUTH1_PEER_CHALLENGE2,
            b"challenge2",
        )

    def fake_decrypt(payload: bytes, _session_key: bytes, _seq: object) -> bytes:
        if payload == b"\x04reconnect":
            return clear_reconnect
        return clear_disconnect

    async def fake_send_reply(
        _writer: object,
        clear_msg: bytes,
        _session_key: bytes,
        out_seq: object,
    ) -> object:
        assert clear_msg
        return out_seq

    monkeypatch.setattr(routing_module.won_crypto, "parse_tmessage", fake_parse_tmessage)
    monkeypatch.setattr(
        routing_module,
        "_parse_auth1_peer_request",
        lambda _body: {
            "certificate": b"cert",
            "auth_mode": 1,
            "encrypt_mode": 1,
            "encrypt_flags": 0x0001,
        },
    )
    monkeypatch.setattr(
        routing_module,
        "_parse_auth1_certificate",
        lambda _cert: {
            "sig": b"",
            "unsigned": b"",
            "user_id": 1040,
            "p": 23,
            "g": 5,
            "y": 8,
        },
    )
    monkeypatch.setattr(routing_module.os, "urandom", lambda _size: secret_b)
    monkeypatch.setattr(routing_module.won_crypto, "eg_encrypt", lambda *args: b"cipher")
    monkeypatch.setattr(
        routing_module.won_crypto,
        "eg_decrypt",
        lambda *args: struct.pack("<H", len(secret_b)) + secret_b + b"secret-a",
    )
    monkeypatch.setattr(
        routing_module,
        "_parse_auth1_peer_challenge2",
        lambda _body: b"challenge2-cipher",
    )
    monkeypatch.setattr(routing_module, "_routing_recv_with_idle_timeout", fake_recv)
    monkeypatch.setattr(routing_module, "_decrypt_persistent_non_t", fake_decrypt)

    gateway = FakeGateway()
    server = titan_binary_gateway.SilencerRoutingServer(
        gateway,  # type: ignore[arg-type]
        listen_port=15103,
        publish_in_directory=False,
    )
    server._send_native_route_reply = fake_send_reply  # type: ignore[method-assign]
    server._pending_reconnects[7] = titan_binary_gateway.PendingNativeReconnect(
        client_id=7,
        client_name_raw=b"DaMaG",
        client_name="DaMaG",
        client_ip="213.217.0.31",
        client_ip_u32=0,
        connected_at=100.0,
        last_activity_at=101.0,
        last_activity_kind="peer_data",
        chat_count=1,
        peer_data_messages=2,
        peer_data_bytes=64,
        auth_user_id=1040,
        account_username="DaMaG",
    )

    asyncio.run(server._handle_native_client(FakeReader(), FakeWriter(), b"first"))  # type: ignore[arg-type]

    assert gateway.attached == [(1040, 7)]
    assert 7 not in server._pending_reconnects
    assert any(kind == "rejoin" for kind, _event in gateway.events)


def test_dashboard_snapshot_marks_unpublished_active_room_as_game_room() -> None:
    manager = titan_binary_gateway.RoutingServerManager(
        host="127.0.0.1",
        public_host="127.0.0.1",
        base_port=15100,
    )
    server = titan_binary_gateway.SilencerRoutingServer(
        listen_port=15102,
        publish_in_directory=False,
    )
    server._native_clients[1] = titan_binary_gateway.NativeRouteClientState(
        client_id=1,
        client_name_raw=b"Alpha",
        client_name="Alpha",
        client_ip="1.2.3.4",
        client_ip_u32=0,
        writer=None,  # type: ignore[arg-type]
        session_key=b"",
        out_seq=None,
    )
    manager._servers[15102] = server

    snapshot = manager.dashboard_snapshot()

    assert snapshot["current_game_room_count"] == 1
    assert snapshot["current_game_count"] == 0
    assert snapshot["players"][0]["room_is_game"] is True
    assert snapshot["servers"][0]["is_game_room"] is True
    assert snapshot["servers"][0]["active_game_count"] == 1
    assert snapshot["rooms"][0]["is_game_room"] is True
    assert snapshot["rooms"][0]["active_game_count"] == 1


def test_dashboard_snapshot_keeps_unpublished_pending_reconnect_room_live_when_activity_is_recent() -> None:
    server = titan_binary_gateway.SilencerRoutingServer(
        listen_port=15102,
        publish_in_directory=False,
    )
    for client_id, name in ((1, "Alpha"), (2, "Bravo")):
        server._pending_reconnects[client_id] = titan_binary_gateway.PendingNativeReconnect(
            client_id=client_id,
            client_name_raw=name.encode("ascii"),
            client_name=name,
            client_ip=f"1.2.3.{client_id}",
            client_ip_u32=0,
            connected_at=100.0,
            last_activity_at=101.0,
            last_activity_kind="peer_data",
            chat_count=0,
            peer_data_messages=12,
            peer_data_bytes=4096,
        )
    server._last_peer_data_at = time.time()

    snapshot = server.dashboard_snapshot()

    assert snapshot["pending_reconnect_count"] == 2
    assert snapshot["is_game_room"] is True
    assert snapshot["active_game_count"] == 1


def test_dashboard_snapshot_does_not_leave_unpublished_pending_reconnect_room_stuck_as_game() -> None:
    server = titan_binary_gateway.SilencerRoutingServer(
        listen_port=15102,
        publish_in_directory=False,
    )
    for client_id, name in ((1, "Alpha"), (2, "Bravo")):
        server._pending_reconnects[client_id] = titan_binary_gateway.PendingNativeReconnect(
            client_id=client_id,
            client_name_raw=name.encode("ascii"),
            client_name=name,
            client_ip=f"1.2.3.{client_id}",
            client_ip_u32=0,
            connected_at=100.0,
            last_activity_at=101.0,
            last_activity_kind="peer_data",
            chat_count=0,
            peer_data_messages=12,
            peer_data_bytes=4096,
        )
    server._last_peer_data_at = (
        time.time() - titan_binary_gateway.PUBLISHED_GAME_ACTIVITY_WINDOW_SECONDS - 1.0
    )

    snapshot = server.dashboard_snapshot()

    assert snapshot["pending_reconnect_count"] == 2
    assert snapshot["is_game_room"] is False
    assert snapshot["active_game_count"] == 0


def test_dashboard_snapshot_marks_cataclysm_published_room_as_game_when_peer_data_is_recent() -> None:
    manager = titan_binary_gateway.RoutingServerManager(
        host="127.0.0.1",
        public_host="127.0.0.1",
        base_port=15110,
        product_profile=titan_binary_gateway.CATACLYSM_PRODUCT_PROFILE,
    )
    server = titan_binary_gateway.SilencerRoutingServer(
        listen_port=15110,
        publish_in_directory=True,
        product_profile=titan_binary_gateway.CATACLYSM_PRODUCT_PROFILE,
    )
    for client_id, name in ((1, "Alpha"), (2, "Bravo")):
        server._native_clients[client_id] = titan_binary_gateway.NativeRouteClientState(
            client_id=client_id,
            client_name_raw=name.encode("ascii"),
            client_name=name,
            client_ip=f"1.2.3.{client_id}",
            client_ip_u32=0,
            writer=None,  # type: ignore[arg-type]
            session_key=b"",
            out_seq=None,
            peer_data_messages=12,
            peer_data_bytes=4096,
        )
    server._last_peer_data_at = time.time()
    manager._servers[15110] = server

    snapshot = manager.dashboard_snapshot()

    assert snapshot["current_game_room_count"] == 1
    assert snapshot["servers"][0]["is_game_room"] is True
    assert snapshot["rooms"][0]["is_game_room"] is True


def test_dashboard_snapshot_does_not_leave_cataclysm_published_room_stuck_as_game() -> None:
    server = titan_binary_gateway.SilencerRoutingServer(
        listen_port=15110,
        publish_in_directory=True,
        product_profile=titan_binary_gateway.CATACLYSM_PRODUCT_PROFILE,
    )
    server._native_clients[1] = titan_binary_gateway.NativeRouteClientState(
        client_id=1,
        client_name_raw=b"Alpha",
        client_name="Alpha",
        client_ip="1.2.3.4",
        client_ip_u32=0,
        writer=None,  # type: ignore[arg-type]
        session_key=b"",
        out_seq=None,
        peer_data_messages=20,
        peer_data_bytes=8192,
    )
    server._last_peer_data_at = (
        time.time() - titan_binary_gateway.PUBLISHED_GAME_ACTIVITY_WINDOW_SECONDS - 1.0
    )

    snapshot = server.dashboard_snapshot()

    assert snapshot["is_game_room"] is False
    assert snapshot["active_game_count"] == 0


def test_reconnect_reservations_are_not_offered_for_published_lobbies() -> None:
    lobby_server = titan_binary_gateway.SilencerRoutingServer(
        listen_port=15100,
        publish_in_directory=True,
    )
    game_server = titan_binary_gateway.SilencerRoutingServer(
        listen_port=15110,
        publish_in_directory=False,
    )
    client = titan_binary_gateway.NativeRouteClientState(
        client_id=1,
        client_name_raw=b"Alpha",
        client_name="Alpha",
        client_ip="1.2.3.4",
        client_ip_u32=0,
        writer=None,  # type: ignore[arg-type]
        session_key=b"",
        out_seq=None,
    )

    assert lobby_server._should_offer_reconnect(client, "eof") is False
    assert game_server._should_offer_reconnect(client, "eof") is True


def test_cataclysm_published_room_offers_reconnect_when_recent_gameplay_is_active() -> None:
    server = titan_binary_gateway.SilencerRoutingServer(
        listen_port=15110,
        publish_in_directory=True,
        product_profile=titan_binary_gateway.CATACLYSM_PRODUCT_PROFILE,
    )
    client = titan_binary_gateway.NativeRouteClientState(
        client_id=1,
        client_name_raw=b"Alpha",
        client_name="Alpha",
        client_ip="1.2.3.4",
        client_ip_u32=0,
        writer=None,  # type: ignore[arg-type]
        session_key=b"",
        out_seq=None,
        peer_data_messages=20,
        peer_data_bytes=8192,
    )
    server._last_peer_data_at = time.time()

    assert server._should_offer_reconnect(client, "connection_reset") is True


def test_cataclysm_published_room_does_not_offer_reconnect_after_gameplay_goes_stale() -> None:
    server = titan_binary_gateway.SilencerRoutingServer(
        listen_port=15110,
        publish_in_directory=True,
        product_profile=titan_binary_gateway.CATACLYSM_PRODUCT_PROFILE,
    )
    client = titan_binary_gateway.NativeRouteClientState(
        client_id=1,
        client_name_raw=b"Alpha",
        client_name="Alpha",
        client_ip="1.2.3.4",
        client_ip_u32=0,
        writer=None,  # type: ignore[arg-type]
        session_key=b"",
        out_seq=None,
        peer_data_messages=20,
        peer_data_bytes=8192,
    )
    server._last_peer_data_at = (
        time.time() - titan_binary_gateway.PUBLISHED_GAME_ACTIVITY_WINDOW_SECONDS - 1.0
    )

    assert server._should_offer_reconnect(client, "connection_reset") is False


def test_game_room_peer_data_logs_include_packet_fingerprint(caplog) -> None:
    server = titan_binary_gateway.SilencerRoutingServer(
        listen_port=15102,
        publish_in_directory=False,
    )

    with caplog.at_level(logging.INFO):
        server._log_native_peer_data_event(
            "SendDataBroadcast",
            7,
            b"\x01\x02\x03\x04",
            1,
            False,
        )

    assert "fingerprint=4b:" in caplog.text


def test_published_lobby_peer_data_logs_omit_packet_fingerprint(caplog) -> None:
    server = titan_binary_gateway.SilencerRoutingServer(
        listen_port=15100,
        publish_in_directory=True,
    )

    with caplog.at_level(logging.INFO):
        server._log_native_peer_data_event(
            "SendDataBroadcast",
            7,
            b"\x01\x02\x03\x04",
            1,
            False,
        )

    assert "fingerprint=" not in caplog.text


def test_routing_recv_skips_wait_for_when_idle_timeout_is_disabled(monkeypatch) -> None:
    async def fake_recv(_reader: object) -> bytes:
        return b"payload"

    def fail_wait_for(*args: object, **kwargs: object) -> object:
        raise AssertionError("wait_for should not be used when idle timeout is disabled")

    monkeypatch.setattr(routing_module, "ROUTING_IDLE_TIMEOUT_SECONDS", None)
    monkeypatch.setattr(routing_module, "_routing_recv", fake_recv)
    monkeypatch.setattr(routing_module.asyncio, "wait_for", fail_wait_for)

    payload = asyncio.run(routing_module._routing_recv_with_idle_timeout(object()))

    assert payload == b"payload"


def test_broadcast_native_route_peer_data_records_slow_recipient_diagnostics(
    monkeypatch,
    caplog,
) -> None:
    server = titan_binary_gateway.SilencerRoutingServer(
        listen_port=15102,
        publish_in_directory=False,
    )
    sender = titan_binary_gateway.NativeRouteClientState(
        client_id=1,
        client_name_raw=b"Alpha",
        client_name="Alpha",
        client_ip="1.2.3.4",
        client_ip_u32=0,
        writer=None,  # type: ignore[arg-type]
        session_key=b"",
        out_seq=None,
    )
    recipient = titan_binary_gateway.NativeRouteClientState(
        client_id=2,
        client_name_raw=b"Bravo",
        client_name="Bravo",
        client_ip="1.2.3.5",
        client_ip_u32=0,
        writer=None,  # type: ignore[arg-type]
        session_key=b"",
        out_seq=None,
    )
    recipient.slow_peer_data_events = 0
    recipient.slowest_peer_data_send_ms = 0
    recipient.last_slow_peer_data_send_ms = 0
    recipient.last_slow_peer_data_at = 0.0
    server._native_clients = {1: sender, 2: recipient}

    async def fake_send(
        client: titan_binary_gateway.NativeRouteClientState,
        clear_msg: bytes,
    ) -> None:
        assert client.client_id == 2
        assert clear_msg
        await asyncio.sleep(0.2)

    monkeypatch.setattr(server, "_send_native_route_client_reply", fake_send)

    with caplog.at_level(logging.WARNING):
        delivered = asyncio.run(
            server._broadcast_native_route_peer_data(
                1,
                b"\x01\x02\x03\x04",
                [],
                False,
            )
        )

    assert delivered == 1
    assert recipient.slow_peer_data_events == 1
    assert recipient.slowest_peer_data_send_ms >= 1
    assert recipient.last_slow_peer_data_send_ms >= 1
    assert recipient.last_slow_peer_data_at > 0.0
    assert "slow peer-data delivery" in caplog.text
    assert "recipient_id=2" in caplog.text


def test_broadcast_native_route_peer_data_does_not_wait_for_slow_recipient(
    monkeypatch,
) -> None:
    server = titan_binary_gateway.SilencerRoutingServer(
        listen_port=15102,
        publish_in_directory=False,
    )
    for client_id, name in ((1, "Alpha"), (2, "Bravo"), (3, "Charlie")):
        server._native_clients[client_id] = titan_binary_gateway.NativeRouteClientState(
            client_id=client_id,
            client_name_raw=name.encode("ascii"),
            client_name=name,
            client_ip=f"1.2.3.{client_id}",
            client_ip_u32=0,
            writer=None,  # type: ignore[arg-type]
            session_key=b"",
            out_seq=None,
        )

    events: list[tuple[int, str, float]] = []

    async def fake_send(
        client: titan_binary_gateway.NativeRouteClientState,
        clear_msg: bytes,
    ) -> None:
        assert clear_msg
        events.append((client.client_id, "start", time.perf_counter()))
        if client.client_id == 2:
            await asyncio.sleep(0.2)
        events.append((client.client_id, "end", time.perf_counter()))

    monkeypatch.setattr(server, "_send_native_route_client_reply", fake_send)

    delivered = asyncio.run(
        server._broadcast_native_route_peer_data(
            1,
            b"\x01\x02\x03\x04",
            [],
            False,
        )
    )

    assert delivered == 2
    starts = {
        client_id: timestamp
        for client_id, phase, timestamp in events
        if phase == "start"
    }
    ends = {
        client_id: timestamp
        for client_id, phase, timestamp in events
        if phase == "end"
    }
    assert starts[3] - starts[2] < 0.05
    assert ends[3] < ends[2]


def test_broadcast_native_route_peer_data_times_out_stalled_recipient(
    monkeypatch,
    caplog,
) -> None:
    class FakeWriter:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    server = titan_binary_gateway.SilencerRoutingServer(
        listen_port=15102,
        publish_in_directory=False,
    )
    sender = titan_binary_gateway.NativeRouteClientState(
        client_id=1,
        client_name_raw=b"Alpha",
        client_name="Alpha",
        client_ip="1.2.3.4",
        client_ip_u32=0,
        writer=None,  # type: ignore[arg-type]
        session_key=b"",
        out_seq=None,
    )
    slow_writer = FakeWriter()
    slow = titan_binary_gateway.NativeRouteClientState(
        client_id=2,
        client_name_raw=b"Bravo",
        client_name="Bravo",
        client_ip="1.2.3.5",
        client_ip_u32=0,
        writer=slow_writer,  # type: ignore[arg-type]
        session_key=b"",
        out_seq=None,
    )
    fast = titan_binary_gateway.NativeRouteClientState(
        client_id=3,
        client_name_raw=b"Charlie",
        client_name="Charlie",
        client_ip="1.2.3.6",
        client_ip_u32=0,
        writer=None,  # type: ignore[arg-type]
        session_key=b"",
        out_seq=None,
    )
    server._native_clients = {1: sender, 2: slow, 3: fast}

    async def fake_send(
        client: titan_binary_gateway.NativeRouteClientState,
        clear_msg: bytes,
    ) -> None:
        assert clear_msg
        if client.client_id == 2:
            await asyncio.sleep(0.2)

    monkeypatch.setattr(server, "_send_native_route_client_reply", fake_send)
    monkeypatch.setattr(routing_module, "PEER_DATA_SEND_TIMEOUT_SECONDS", 0.05, raising=False)

    with caplog.at_level(logging.WARNING):
        delivered = asyncio.run(
            server._broadcast_native_route_peer_data(
                1,
                b"\x01\x02\x03\x04",
                [],
                False,
            )
        )

    assert delivered == 1
    assert slow_writer.closed is True
    assert "peer-data delivery timed out" in caplog.text
    assert "recipient_id=2" in caplog.text


def test_dashboard_snapshot_reports_slow_peer_data_delivery_diagnostics() -> None:
    server = titan_binary_gateway.SilencerRoutingServer(
        listen_port=15102,
        publish_in_directory=False,
    )
    client = titan_binary_gateway.NativeRouteClientState(
        client_id=1,
        client_name_raw=b"Alpha",
        client_name="Alpha",
        client_ip="1.2.3.4",
        client_ip_u32=0,
        writer=None,  # type: ignore[arg-type]
        session_key=b"",
        out_seq=None,
    )
    client.slow_peer_data_events = 3
    client.slowest_peer_data_send_ms = 187
    client.last_slow_peer_data_send_ms = 133
    client.last_slow_peer_data_at = time.time() - 5.0
    server._native_clients[1] = client

    snapshot = server.dashboard_snapshot()

    assert snapshot["slow_peer_data_events"] == 3
    assert snapshot["slowest_peer_data_send_ms"] == 187
    assert snapshot["clients"][0]["slow_peer_data_events"] == 3
    assert snapshot["clients"][0]["slowest_peer_data_send_ms"] == 187
    assert snapshot["clients"][0]["last_slow_peer_data_send_ms"] == 133
    assert snapshot["clients"][0]["seconds_since_last_slow_peer_data"] >= 0


def test_dashboard_snapshot_reports_peer_write_buffer_diagnostics() -> None:
    class FakeTransport:
        def get_write_buffer_size(self) -> int:
            return 4096

        def get_write_buffer_limits(self) -> tuple[int, int]:
            return (1024, 2048)

    class FakeWriter:
        def __init__(self) -> None:
            self.transport = FakeTransport()

        def get_extra_info(self, name: str, default: object = None) -> object:
            if name == "transport":
                return self.transport
            return default

    server = titan_binary_gateway.SilencerRoutingServer(
        listen_port=15102,
        publish_in_directory=False,
    )
    client = titan_binary_gateway.NativeRouteClientState(
        client_id=1,
        client_name_raw=b"Alpha",
        client_name="Alpha",
        client_ip="1.2.3.4",
        client_ip_u32=0,
        writer=FakeWriter(),  # type: ignore[arg-type]
        session_key=b"",
        out_seq=None,
    )
    server._native_clients[1] = client

    snapshot = server.dashboard_snapshot()

    assert snapshot["largest_write_buffer_size"] == 4096
    assert snapshot["clients"][0]["write_buffer_size"] == 4096
    assert snapshot["clients"][0]["write_buffer_high_water"] == 2048
