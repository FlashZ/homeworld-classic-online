from __future__ import annotations

import titan_binary_gateway


class _FakeRoutingManager:
    def dashboard_snapshot(self) -> dict[str, object]:
        return {
            "current_unique_ip_count": 2,
            "players": [
                {
                    "client_id": 1,
                    "client_name": "Alpha",
                    "room_name": "Default",
                    "room_port": 15100,
                    "connected_seconds": 120,
                    "idle_seconds": 3,
                    "last_activity_kind": "chat",
                    "peer_data_messages": 2,
                    "peer_data_bytes": 54,
                },
                {
                    "client_id": 2,
                    "client_name": "Bravo",
                    "room_name": "Fleet Battle",
                    "room_port": 15102,
                    "connected_seconds": 240,
                    "idle_seconds": 9,
                    "last_activity_kind": "peer_data",
                    "peer_data_messages": 7,
                    "peer_data_bytes": 611,
                },
            ],
            "servers": [
                {
                    "listen_port": 15100,
                    "room_name": "Default",
                    "room_description": "Lobby",
                    "room_path": "/Homeworld",
                    "published": True,
                    "room_password_set": False,
                    "player_count": 1,
                    "game_count": 0,
                },
                {
                    "listen_port": 15102,
                    "room_name": "Fleet Battle",
                    "room_description": "1v1",
                    "room_path": "/Homeworld",
                    "published": True,
                    "room_password_set": True,
                    "player_count": 1,
                    "game_count": 1,
                },
            ],
            "games": [
                {
                    "name": "hw_game",
                    "owner_name": "Bravo",
                    "room_name": "Fleet Battle",
                    "room_port": 15102,
                    "link_id": 44,
                    "lifespan": 90,
                    "data_len": 185,
                    "data_preview_hex": "aabbccddeeff00112233",
                }
            ],
            "rooms": [
                {
                    "listen_port": 15100,
                    "room_display_name": "Default",
                    "is_game_room": False,
                    "game_count": 0,
                    "data_object_count": 0,
                    "pending_reconnects": [
                        {
                            "client_id": 9,
                            "client_name": "Ghost",
                            "seconds_remaining": 42,
                            "last_activity_kind": "eof",
                        }
                    ],
                },
                {
                    "listen_port": 15102,
                    "room_display_name": "Fleet Battle",
                    "is_game_room": True,
                    "game_count": 1,
                    "data_object_count": 1,
                    "pending_reconnects": [],
                },
            ],
        }


def test_gateway_stats_snapshot_returns_bot_safe_presence_summary() -> None:
    gateway = titan_binary_gateway.BinaryGatewayServer(
        "127.0.0.1",
        9100,
        public_host="homeworld.kerrbell.dev",
        public_port=15101,
        routing_port=15100,
        valid_versions=["0110"],
    )
    gateway.routing_manager = _FakeRoutingManager()

    snapshot = gateway.stats_snapshot()

    assert snapshot["server"] == {
        "public_host": "homeworld.kerrbell.dev",
        "public_port": 15101,
        "routing_port": 15100,
        "version": "0110",
        "valid_versions": ["0110"],
    }
    assert snapshot["counts"] == {
        "players_online": 2,
        "rooms_open": 2,
        "rooms_published": 2,
        "games_live": 1,
        "unique_ips": 2,
        "players_reconnecting": 1,
    }
    assert snapshot["players"] == [
        {
            "name": "Alpha",
            "client_id": 1,
            "room_name": "Default",
            "room_port": 15100,
            "state": "lobby",
            "connected_seconds": 120,
            "idle_seconds": 3,
            "last_activity_kind": "chat",
            "peer_data_messages": 2,
            "peer_data_bytes": 54,
        },
        {
            "name": "Bravo",
            "client_id": 2,
            "room_name": "Fleet Battle",
            "room_port": 15102,
            "state": "game",
            "connected_seconds": 240,
            "idle_seconds": 9,
            "last_activity_kind": "peer_data",
            "peer_data_messages": 7,
            "peer_data_bytes": 611,
        },
    ]
    assert snapshot["traffic"] == {
        "peer_data_messages_total": 9,
        "peer_data_bytes_total": 665,
        "game_object_count": 1,
        "game_object_bytes_total": 185,
    }
    assert snapshot["rooms"] == [
        {
            "name": "Default",
            "port": 15100,
            "description": "Lobby",
            "path": "/Homeworld",
            "published": True,
            "password_protected": False,
            "player_count": 1,
            "game_count": 0,
            "active_game_count": 0,
            "is_game_room": False,
            "reconnecting_count": 1,
            "peer_data_messages": 2,
            "peer_data_bytes": 54,
            "game_data_bytes": 0,
            "data_object_count": 0,
        },
        {
            "name": "Fleet Battle",
            "port": 15102,
            "description": "1v1",
            "path": "/Homeworld",
            "published": True,
            "password_protected": True,
            "player_count": 1,
            "game_count": 1,
            "active_game_count": 1,
            "is_game_room": True,
            "reconnecting_count": 0,
            "peer_data_messages": 7,
            "peer_data_bytes": 611,
            "game_data_bytes": 185,
            "data_object_count": 1,
        },
    ]
    assert snapshot["games"] == [
        {
            "name": "hw_game",
            "owner_name": "Bravo",
            "room_name": "Fleet Battle",
            "room_port": 15102,
            "link_id": 44,
            "lifespan": 90,
            "data_len": 185,
            "data_preview_hex": "aabbccddeeff00112233",
        }
    ]
    assert snapshot["reconnecting_players"] == [
        {
            "name": "Ghost",
            "client_id": 9,
            "room_name": "Default",
            "room_port": 15100,
            "seconds_remaining": 42,
            "last_activity_kind": "eof",
        }
    ]


def test_gateway_stats_snapshot_infers_live_game_from_active_unpublished_room() -> None:
    class _InferredGameRoutingManager:
        def dashboard_snapshot(self) -> dict[str, object]:
            return {
                "current_unique_ip_count": 1,
                "current_game_room_count": 1,
                "players": [
                    {
                        "client_id": 1,
                        "client_name": "Alpha",
                        "room_name": "Homeworld Chat",
                        "room_port": 15102,
                        "connected_seconds": 45,
                        "idle_seconds": 0,
                        "last_activity_kind": "peer_data",
                        "peer_data_messages": 12,
                        "peer_data_bytes": 4096,
                    },
                    {
                        "client_id": 2,
                        "client_name": "Bravo",
                        "room_name": "Homeworld Chat",
                        "room_port": 15102,
                        "connected_seconds": 44,
                        "idle_seconds": 0,
                        "last_activity_kind": "peer_data",
                        "peer_data_messages": 10,
                        "peer_data_bytes": 3072,
                    },
                ],
                "servers": [
                    {
                        "listen_port": 15102,
                        "room_name": "Homeworld Chat",
                        "room_description": "Homeworld Chat",
                        "room_path": "/Homeworld",
                        "published": False,
                        "room_password_set": False,
                        "player_count": 2,
                        "game_count": 0,
                        "active_game_count": 1,
                        "is_game_room": True,
                    }
                ],
                "games": [],
                "rooms": [
                    {
                        "listen_port": 15102,
                        "room_display_name": "Homeworld Chat",
                        "is_game_room": True,
                        "active_game_count": 1,
                        "game_count": 0,
                        "data_object_count": 0,
                        "pending_reconnects": [],
                    }
                ],
            }

    gateway = titan_binary_gateway.BinaryGatewayServer(
        "127.0.0.1",
        9100,
        public_host="homeworld.kerrbell.dev",
        public_port=15101,
        routing_port=15100,
        valid_versions=["0110"],
    )
    gateway.routing_manager = _InferredGameRoutingManager()

    snapshot = gateway.stats_snapshot()

    assert snapshot["counts"]["games_live"] == 1
    assert [player["state"] for player in snapshot["players"]] == ["game", "game"]
    assert snapshot["rooms"] == [
        {
            "name": "Homeworld Chat",
            "port": 15102,
            "description": "Homeworld Chat",
            "path": "/Homeworld",
            "published": False,
            "password_protected": False,
            "player_count": 2,
            "game_count": 0,
            "active_game_count": 1,
            "is_game_room": True,
            "reconnecting_count": 0,
            "peer_data_messages": 22,
            "peer_data_bytes": 7168,
            "game_data_bytes": 0,
            "data_object_count": 0,
        }
    ]
    assert snapshot["traffic"] == {
        "peer_data_messages_total": 22,
        "peer_data_bytes_total": 7168,
        "game_object_count": 0,
        "game_object_bytes_total": 0,
    }


def test_stats_token_is_scoped_to_stats_endpoint() -> None:
    dashboard = titan_binary_gateway.AdminDashboardServer(
        gateway=object(),
        db_path="won_server.db",
        log_handler=titan_binary_gateway.DashboardLogHandler(),
        admin_token="admin-secret",
        stats_token="stats-secret",
    )

    assert dashboard._is_authorized("/api/stats", {"token": ["stats-secret"]}, {})
    assert not dashboard._is_authorized("/api/snapshot", {"token": ["stats-secret"]}, {})
    assert dashboard._is_authorized("/api/stats", {"token": ["admin-secret"]}, {})
    assert dashboard._is_authorized("/api/snapshot", {"token": ["admin-secret"]}, {})
