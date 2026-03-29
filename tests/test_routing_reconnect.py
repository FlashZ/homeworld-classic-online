from __future__ import annotations

import asyncio

import titan_binary_gateway


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
