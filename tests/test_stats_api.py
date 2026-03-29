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
                },
                {
                    "client_id": 2,
                    "client_name": "Bravo",
                    "room_name": "Fleet Battle",
                    "room_port": 15102,
                    "connected_seconds": 240,
                    "idle_seconds": 9,
                    "last_activity_kind": "peer_data",
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
                    "data_len": 185,
                }
            ],
            "rooms": [
                {
                    "listen_port": 15100,
                    "room_display_name": "Default",
                    "game_count": 0,
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
                    "game_count": 1,
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
        },
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
