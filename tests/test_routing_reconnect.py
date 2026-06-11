from __future__ import annotations

import asyncio
import importlib
import logging
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
