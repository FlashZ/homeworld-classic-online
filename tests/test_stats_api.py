from __future__ import annotations

import argparse
import asyncio
import time

from product_profile import CATACLYSM_PRODUCT_PROFILE, HOMEWORLD_PRODUCT_PROFILE
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
        "product": "homeworld",
        "community_name": "Homeworld",
        "directory_root": "/Homeworld",
        "valid_versions_service": "HomeworldValidVersions",
        "public_host": "homeworld.kerrbell.dev",
        "public_port": 15101,
        "routing_port": 15100,
        "routing_max_port": 15100,
        "version": "0110",
        "valid_versions": ["0110"],
        "products": [
            {
                "product": "homeworld",
                "community_name": "Homeworld",
                "directory_root": "/Homeworld",
                "valid_versions_service": "HomeworldValidVersions",
                "routing_port": 15100,
                "routing_max_port": 15100,
                "version": "0110",
                "valid_versions": ["0110"],
                "backend_host": "127.0.0.1",
                "backend_port": 9100,
            }
        ],
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
            "product": "homeworld",
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
            "product": "homeworld",
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
            "product": "homeworld",
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
            "product": "homeworld",
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
            "product": "homeworld",
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
            "product": "homeworld",
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
            "product": "homeworld",
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


def test_gateway_stats_snapshot_reports_selected_product_identity() -> None:
    gateway = titan_binary_gateway.BinaryGatewayServer(
        "127.0.0.1",
        9100,
        public_host="cataclysm.kerrbell.dev",
        public_port=15101,
        routing_port=15100,
        product_profile=CATACLYSM_PRODUCT_PROFILE,
    )

    snapshot = gateway.stats_snapshot()

    assert snapshot["server"]["product"] == "cataclysm"
    assert snapshot["server"]["community_name"] == "Cataclysm"
    assert snapshot["server"]["directory_root"] == "/Cataclysm"
    assert snapshot["server"]["version"] == "1.0.0.1"
    assert snapshot["server"]["valid_versions"] == ["1.0.0.1", "1001"]
    assert snapshot["server"]["products"] == [
        {
            "product": "cataclysm",
            "community_name": "Cataclysm",
            "directory_root": "/Cataclysm",
            "valid_versions_service": "CataclysmValidVersions",
            "routing_port": 15100,
            "routing_max_port": 15100,
            "version": "1.0.0.1",
            "valid_versions": ["1.0.0.1", "1001"],
            "backend_host": "127.0.0.1",
            "backend_port": 9100,
        }
    ]


def test_gateway_dashboard_snapshot_tags_single_product_rows() -> None:
    gateway = titan_binary_gateway.BinaryGatewayServer(
        "127.0.0.1",
        9100,
        public_host="homeworld.kerrbell.dev",
        public_port=15101,
        routing_port=15100,
        valid_versions=["0110"],
    )
    gateway.routing_manager = _FakeRoutingManager()

    snapshot = gateway.dashboard_snapshot()

    assert snapshot["products"] == {
        "homeworld": {
            "community_name": "Homeworld",
            "directory_root": "/Homeworld",
            "valid_versions_service": "HomeworldValidVersions",
            "routing_port": 15100,
            "routing_max_port": 15100,
            "backend_host": "127.0.0.1",
            "backend_port": 9100,
            "version_str": "0110",
            "valid_versions": ["0110"],
        }
    }
    assert snapshot["routing_manager"]["products"] == ["homeworld"]
    assert snapshot["routing_manager"]["players"][0]["product"] == "homeworld"
    assert snapshot["routing_manager"]["servers"][0]["product"] == "homeworld"
    assert snapshot["routing_manager"]["games"][0]["product"] == "homeworld"
    assert snapshot["routing_manager"]["rooms"][0]["product"] == "homeworld"


def test_gateway_dashboard_activity_marks_paired_lobby_and_game_leaves_as_left_for_game() -> None:
    gateway = titan_binary_gateway.BinaryGatewayServer(
        "127.0.0.1",
        9100,
        public_host="homeworld.kerrbell.dev",
        public_port=15101,
        routing_port=15100,
        valid_versions=["0110"],
    )

    gateway.record_activity(
        "leave",
        room_port=15100,
        room_name="Homeworld Chat",
        player_name="Alpha",
        player_ip="1.2.3.4",
        details={"reason": "eof"},
    )
    gateway.record_activity(
        "leave",
        room_port=15102,
        room_name="Fleet Battle",
        player_name="Alpha",
        player_ip="1.2.3.4",
        details={"reason": "eof"},
    )

    activity = gateway.dashboard_snapshot()["activity"]

    assert len(activity) == 2
    assert activity[0]["details"]["left_for_game"] is True
    assert activity[1]["details"]["left_for_game"] is True
    assert activity[0]["details"]["reason"] == "eof"
    assert activity[1]["details"]["reason"] == "eof"


def test_gateway_probe_snapshots_report_readiness_state() -> None:
    gateway = titan_binary_gateway.BinaryGatewayServer(
        "127.0.0.1",
        9100,
        public_host="homeworld.kerrbell.dev",
        public_port=15101,
        routing_port=15100,
        valid_versions=["0110"],
    )

    health = gateway.health_snapshot()
    not_ready = gateway.readiness_snapshot()

    assert health["ok"] is True
    assert health["status"] == "ok"
    assert health["product"] == "homeworld"
    assert not_ready["ready"] is False
    assert not_ready["checks"] == {
        "auth_keys_loaded": False,
        "routing_manager_attached": False,
    }

    gateway._auth_keys_loaded = True
    gateway.routing_manager = object()  # type: ignore[assignment]

    ready = gateway.readiness_snapshot()

    assert ready["ready"] is True
    assert ready["checks"] == {
        "auth_keys_loaded": True,
        "routing_manager_attached": True,
    }


def test_peer_session_ttl_allows_long_post_game_return_window() -> None:
    gateway = titan_binary_gateway.BinaryGatewayServer(
        "127.0.0.1",
        9100,
        public_host="homeworld.kerrbell.dev",
        public_port=15101,
        routing_port=15100,
        valid_versions=["0110"],
    )

    freshish = titan_binary_gateway.PeerSession(
        session_key=b"12345678",
        session_id=7,
        role=titan_binary_gateway.PEER_ROLE_DIRECTORY,
        sequenced=True,
    )
    freshish.last_used_at = time.time() - 3600.0
    stale = titan_binary_gateway.PeerSession(
        session_key=b"12345678",
        session_id=8,
        role=titan_binary_gateway.PEER_ROLE_FACTORY,
        sequenced=True,
    )
    stale.last_used_at = time.time() - 15000.0
    gateway._peer_sessions = {
        freshish.session_id: freshish,
        stale.session_id: stale,
    }

    expired = gateway._expire_peer_sessions()

    assert expired == 1
    assert freshish.session_id in gateway._peer_sessions
    assert stale.session_id not in gateway._peer_sessions


def test_gateway_runtime_config_defaults_follow_selected_product() -> None:
    args = argparse.Namespace(
        product="cataclysm",
        db_path="",
        keys_dir="",
        version_str="",
        valid_version=[],
        valid_versions_file=None,
    )

    profile, version_str, valid_versions, db_path, keys_dir = (
        titan_binary_gateway._resolve_gateway_runtime_config(args)
    )

    assert profile.key == "cataclysm"
    assert version_str == "1.0.0.1"
    assert valid_versions == ["1.0.0.1", "1001"]
    assert db_path.replace("\\", "/").endswith("/data/cataclysm/won_server.db")
    assert keys_dir.replace("\\", "/").endswith("/keys")


def test_shared_gateway_config_splits_routing_ranges_and_defaults_cataclysm_backend() -> None:
    args = argparse.Namespace(
        product="homeworld",
        backend_host="127.0.0.1",
        backend_port=9100,
        routing_port=15100,
        routing_max_port=15120,
        homeworld_routing_max_port=0,
        cataclysm_backend_host="",
        cataclysm_backend_port=0,
        cataclysm_routing_port=0,
        cataclysm_routing_max_port=0,
        version_str="",
        valid_version=[],
        valid_versions_file=None,
        db_path="",
        keys_dir="",
        cataclysm_version_str="",
        cataclysm_valid_version=[],
        cataclysm_valid_versions_file=None,
        cataclysm_db_path="",
        cataclysm_keys_dir="",
        port=15101,
        firewall_port=2021,
    )

    config = titan_binary_gateway._resolve_shared_gateway_config(args)
    runtimes = config["runtimes"]
    home = runtimes["homeworld"]
    cat = runtimes["cataclysm"]

    assert home["routing_port"] == 15100
    assert home["routing_max_port"] == 15109
    assert cat["routing_port"] == 15110
    assert cat["routing_max_port"] == 15120
    assert cat["backend_host"] == "127.0.0.1"
    assert cat["backend_port"] == 9101
    assert home["peer_session_id_min"] == 1
    assert home["peer_session_id_max"] == 32767
    assert cat["peer_session_id_min"] == 32768
    assert cat["peer_session_id_max"] == titan_binary_gateway.MAX_PEER_SESSION_ID


def test_shared_routing_manager_dashboard_snapshot_tags_products() -> None:
    class _Manager:
        def __init__(self, product: str, base_port: int) -> None:
            self.host = "127.0.0.1"
            self.public_host = "games.example"
            self.base_port = base_port
            self.max_port = base_port + 1
            self._product = product

        def dashboard_snapshot(self) -> dict[str, object]:
            return {
                "listener_ports": [self.base_port],
                "next_port": self.base_port + 1,
                "current_game_room_count": 1 if self._product == "cataclysm" else 0,
                "players": [
                    {
                        "client_id": 1,
                        "client_name": self._product.title(),
                        "client_ip": "1.2.3.4" if self._product == "homeworld" else "5.6.7.8",
                        "room_name": self._product.title(),
                        "room_port": self.base_port,
                    }
                ],
                "servers": [
                    {
                        "listen_port": self.base_port,
                        "room_name": self._product.title(),
                        "published": self._product == "homeworld",
                    }
                ],
                "games": [
                    {
                        "name": f"{self._product}_game",
                        "room_name": self._product.title(),
                        "room_port": self.base_port,
                        "link_id": self.base_port,
                    }
                ],
                "rooms": [
                    {
                        "listen_port": self.base_port,
                        "room_display_name": self._product.title(),
                        "published": self._product == "homeworld",
                        "is_game_room": self._product == "cataclysm",
                    }
                ],
            }

        def get_server(self, _port: int):  # pragma: no cover - not used here
            return None

        async def admin_kick_player(self, _port: int, _client_id: int) -> bool:  # pragma: no cover
            return False

        async def admin_broadcast(self, _message: str, _room_port=None) -> int:  # pragma: no cover
            return 0

        async def close_all(self) -> None:  # pragma: no cover
            return None

    manager = titan_binary_gateway.SharedRoutingServerManager(
        {
            "homeworld": _Manager("homeworld", 15100),
            "cataclysm": _Manager("cataclysm", 15110),
        }
    )

    snapshot = manager.dashboard_snapshot()

    assert snapshot["products"] == ["cataclysm", "homeworld"]
    assert snapshot["listener_ports"] == [15100, 15110]
    assert snapshot["current_player_count"] == 2
    assert snapshot["current_unique_ip_count"] == 2
    assert snapshot["current_game_room_count"] == 1
    assert {player["product"] for player in snapshot["players"]} == {
        "homeworld",
        "cataclysm",
    }
    assert {room["product"] for room in snapshot["rooms"]} == {
        "homeworld",
        "cataclysm",
    }


def test_shared_gateway_tracks_product_from_user_and_peer_session_identity() -> None:
    home = titan_binary_gateway.BinaryGatewayServer(
        "127.0.0.1",
        9100,
        product_profile=HOMEWORLD_PRODUCT_PROFILE,
        user_id_start=1000,
        peer_session_id_min=1,
        peer_session_id_max=32767,
    )
    cat = titan_binary_gateway.BinaryGatewayServer(
        "127.0.0.1",
        9101,
        product_profile=CATACLYSM_PRODUCT_PROFILE,
        user_id_start=1_000_000,
        peer_session_id_min=32768,
        peer_session_id_max=titan_binary_gateway.MAX_PEER_SESSION_ID,
    )
    cat_user_id = cat._alloc_user_id()
    cat._peer_sessions[40000] = titan_binary_gateway.PeerSession(
        session_key=b"12345678",
        session_id=40000,
        role=titan_binary_gateway.PEER_ROLE_DIRECTORY,
        sequenced=True,
    )

    shared = titan_binary_gateway.SharedBinaryGatewayServer(
        {
            "homeworld": home,
            "cataclysm": cat,
        }
    )

    assert shared._runtime_for_native_login({"community_name": "Cataclysm"}) is cat
    assert shared._runtime_for_user_id(cat_user_id) is cat
    assert shared._runtime_for_peer_session(40000) is cat


def test_gateway_routes_chat_process_back_to_base_lobby_port() -> None:
    class _RoutingServer:
        def __init__(self) -> None:
            self._room_password = ""

    class _RoutingManager:
        def __init__(self) -> None:
            self.base_port = 15100
            self._servers = {15100: _RoutingServer()}
            self.allocate_calls: list[bool] = []

        async def allocate_server(self, *, publish_in_directory: bool = True) -> int:
            self.allocate_calls.append(bool(publish_in_directory))
            return 15102

        async def start_listener(self, port: int, publish_in_directory: bool = True):
            server = self._servers.setdefault(int(port), _RoutingServer())
            return server, object()

        def get_server(self, port: int):
            return self._servers.get(int(port))

    gateway = titan_binary_gateway.BinaryGatewayServer(
        "127.0.0.1",
        9100,
        routing_port=15100,
        product_profile=HOMEWORLD_PRODUCT_PROFILE,
    )
    manager = _RoutingManager()
    gateway.routing_manager = manager

    selected_port, managed_locally = asyncio.run(
        gateway._select_local_routing_process_port(  # type: ignore[attr-defined]
            HOMEWORLD_PRODUCT_PROFILE.routing_chat_process_name,
            room_password="",
        )
    )

    assert managed_locally is True
    assert selected_port == 15100
    assert manager.allocate_calls == []


def test_gateway_keeps_game_process_on_side_listener() -> None:
    class _RoutingManager:
        def __init__(self) -> None:
            self.base_port = 15100
            self.allocate_calls: list[bool] = []

        async def allocate_server(self, *, publish_in_directory: bool = True) -> int:
            self.allocate_calls.append(bool(publish_in_directory))
            return 15102

        def get_server(self, _port: int):
            return None

    gateway = titan_binary_gateway.BinaryGatewayServer(
        "127.0.0.1",
        9100,
        routing_port=15100,
        product_profile=HOMEWORLD_PRODUCT_PROFILE,
    )
    manager = _RoutingManager()
    gateway.routing_manager = manager

    selected_port, managed_locally = asyncio.run(
        gateway._select_local_routing_process_port(  # type: ignore[attr-defined]
            HOMEWORLD_PRODUCT_PROFILE.routing_game_process_name,
            room_password="",
        )
    )

    assert managed_locally is True
    assert selected_port == 15102
    assert manager.allocate_calls == [False]


def test_shared_gateway_dir_request_prefers_exact_valid_versions_service() -> None:
    home = titan_binary_gateway.BinaryGatewayServer(
        "127.0.0.1",
        9100,
        product_profile=HOMEWORLD_PRODUCT_PROFILE,
    )
    cat = titan_binary_gateway.BinaryGatewayServer(
        "127.0.0.1",
        9101,
        product_profile=CATACLYSM_PRODUCT_PROFILE,
    )
    shared = titan_binary_gateway.SharedBinaryGatewayServer(
        {
            "homeworld": home,
            "cataclysm": cat,
        }
    )

    assert shared._runtime_for_dir_request(
        {"path": "/TitanServers", "service_name": "HomeworldValidVersions"}
    ) is home
    assert shared._runtime_for_dir_request(
        {"path": "/TitanServers", "service_name": "CataclysmValidVersions"}
    ) is cat


def test_stats_token_is_scoped_to_stats_endpoint() -> None:
    dashboard = titan_binary_gateway.AdminDashboardServer(
        gateway=object(),
        db_path="won_server.db",
        log_handler=titan_binary_gateway.DashboardLogHandler(),
        admin_token="admin-secret",
        stats_token="stats-secret",
    )

    assert dashboard._is_authorized("/api/stats", {"token": ["stats-secret"]}, {})
    assert dashboard._is_authorized("/api/live-feed", {"token": ["stats-secret"]}, {})
    assert not dashboard._is_authorized("/api/snapshot", {"token": ["stats-secret"]}, {})
    assert dashboard._is_authorized("/api/stats", {"token": ["admin-secret"]}, {})
    assert dashboard._is_authorized("/api/live-feed", {"token": ["admin-secret"]}, {})
    assert dashboard._is_authorized("/api/snapshot", {"token": ["admin-secret"]}, {})


def test_admin_live_feed_sse_frame_uses_event_stream_format() -> None:
    dashboard = titan_binary_gateway.AdminDashboardServer(
        gateway=object(),
        db_path="won_server.db",
        log_handler=titan_binary_gateway.DashboardLogHandler(),
    )

    frame = dashboard._sse_frame(
        "peer_packet",
        {"event": "peer_packet", "room_port": 15102, "payload_preview_hex": "aabb"},
        event_id="7",
    )

    assert frame.startswith(b"id: 7\n")
    assert b"event: peer_packet\n" in frame
    assert b'data: {"event": "peer_packet", "payload_preview_hex": "aabb", "room_port": 15102}\n\n' in frame


class _LiveFeedRoutingServer:
    def __init__(self) -> None:
        self.snapshot = {
            "listen_port": 15102,
            "room_display_name": "Fleet Battle",
            "room_description": "1v1",
            "room_path": "/Homeworld",
            "published": False,
            "room_password_set": False,
            "is_game_room": True,
            "active_game_count": 1,
            "native_client_count": 2,
            "pending_reconnect_count": 0,
            "pending_reconnects": [],
            "clients": [
                {
                    "client_id": 1,
                    "client_name": "Alpha",
                    "client_ip": "1.1.1.1",
                    "connected_seconds": 30,
                    "idle_seconds": 0,
                    "last_activity_kind": "peer_data",
                    "peer_data_messages": 4,
                    "peer_data_bytes": 128,
                },
                {
                    "client_id": 2,
                    "client_name": "Bravo",
                    "client_ip": "2.2.2.2",
                    "connected_seconds": 28,
                    "idle_seconds": 0,
                    "last_activity_kind": "peer_data",
                    "peer_data_messages": 4,
                    "peer_data_bytes": 128,
                },
            ],
            "games": [
                {
                    "link_id": 44,
                    "owner_id": 2,
                    "owner_name": "Bravo",
                    "name": "hw_game",
                    "lifespan": 90,
                    "data_len": 64,
                    "data_preview_hex": "01020304",
                }
            ],
            "peer_data_messages": 8,
            "peer_data_bytes": 256,
            "data_object_count": 1,
            "data_objects": [],
        }

    def dashboard_snapshot(self) -> dict[str, object]:
        return dict(self.snapshot)


class _LiveFeedRoutingManager:
    def __init__(self, server: _LiveFeedRoutingServer) -> None:
        self.server = server

    def get_server(self, port: int) -> _LiveFeedRoutingServer | None:
        if port == 15102:
            return self.server
        return None


def test_gateway_live_feed_emits_match_lifecycle_and_packet_events() -> None:
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
    gateway.record_live_player_event(
        "player_joined",
        room_port=15102,
        player_id=1,
        player_name="Alpha",
        player_ip="1.1.1.1",
    )
    gateway.record_live_player_event(
        "player_joined",
        room_port=15102,
        player_id=2,
        player_name="Bravo",
        player_ip="2.2.2.2",
    )
    gateway.record_live_peer_packet(
        "peer_packet",
        room_port=15102,
        sender_client_id=2,
        sender_name="Bravo",
        recipient_client_ids=[1],
        recipient_count=1,
        payload=b"\xaa\xbb",
        packet_kind="SendData",
    )
    gateway.record_live_routing_object_event(
        "routing_object_upsert",
        room_port=15102,
        link_id=44,
        owner_id=2,
        owner_name="Bravo",
        data_type_text="hw_game",
        payload=b"\x01\x02\x03\x04",
        lifespan=90,
    )
    routing_server.snapshot.update(
        {
            "is_game_room": False,
            "active_game_count": 0,
            "native_client_count": 0,
            "clients": [],
            "peer_data_messages": 0,
            "peer_data_bytes": 0,
            "game_count": 0,
            "games": [],
            "data_object_count": 0,
        }
    )
    gateway.record_live_player_event(
        "player_left",
        room_port=15102,
        player_id=1,
        player_name="Alpha",
        player_ip="1.1.1.1",
    )

    events: list[dict[str, object]] = []
    while True:
        try:
            events.append(queue.get_nowait())
        except asyncio.QueueEmpty:
            break

    event_names = [str(event["event"]) for event in events]
    assert event_names[0] == "player_joined"
    assert event_names.count("player_joined") == 2
    assert "match_started" in event_names
    assert "peer_packet" in event_names
    assert "routing_object_upsert" in event_names
    assert "match_finished" in event_names

    match_started = next(event for event in events if event["event"] == "match_started")
    assert match_started["room_port"] == 15102
    assert match_started["participant_count"] == 2
    assert str(match_started["match_id"]).startswith("homeworld:15102:")

    peer_packet = next(event for event in events if event["event"] == "peer_packet")
    assert peer_packet["room_port"] == 15102
    assert peer_packet["sender_name"] == "Bravo"
    assert peer_packet["payload_preview_hex"] == "aabb"
    assert peer_packet["payload_base64"] == "qrs="
    assert peer_packet["recipient_count"] == 1

    match_finished = next(event for event in events if event["event"] == "match_finished")
    assert match_finished["room_port"] == 15102
    assert match_finished["duration_seconds"] >= 0


def test_gateway_emits_pending_match_slot_manifest_when_room_goes_live() -> None:
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
    gateway.queue_match_slot_manifest(
        room_port=15102,
        players=[
            {"player_id": "zero", "player_name": "&Z&e&r&o|&S&F", "gameplay_index": 0},
            {"player_id": "volans", "player_name": "Volans|SF", "gameplay_index": 1},
            {"player_id": "chainster", "player_name": "&Chainster", "gameplay_index": 2},
            {"player_id": "gravity", "player_name": "gravi&ty&P&S&A", "gameplay_index": 3},
        ],
    )

    queue = gateway.subscribe_live_feed()
    gateway.record_live_player_event(
        "player_joined",
        room_port=15102,
        player_id=1,
        player_name="&Z&e&r&o|&S&F",
        player_ip="1.1.1.1",
    )
    gateway.record_live_player_event(
        "player_joined",
        room_port=15102,
        player_id=2,
        player_name="Volans|SF",
        player_ip="2.2.2.2",
    )

    events: list[dict[str, object]] = []
    while True:
        try:
            events.append(queue.get_nowait())
        except asyncio.QueueEmpty:
            break

    match_started = next(event for event in events if event["event"] == "match_started")
    slot_manifest = next(event for event in events if event["event"] == "match_slot_manifest")

    assert slot_manifest["room_port"] == 15102
    assert slot_manifest["match_id"] == match_started["match_id"]
    assert slot_manifest["players"] == [
        {"player_id": "zero", "player_name": "&Z&e&r&o|&S&F", "gameplay_index": 0},
        {"player_id": "volans", "player_name": "Volans|SF", "gameplay_index": 1},
        {"player_id": "chainster", "player_name": "&Chainster", "gameplay_index": 2},
        {"player_id": "gravity", "player_name": "gravi&ty&P&S&A", "gameplay_index": 3},
    ]


def test_gateway_emits_pending_match_launch_config_when_room_goes_live() -> None:
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
        captain_identity={"player_id": "zero", "player_name": "&Z&e&r&o|&S&F", "role": "lobby_owner"},
        players=[
            {"player_id": "zero", "player_name": "&Z&e&r&o|&S&F", "gameplay_index": 0},
            {"player_id": "volans", "player_name": "Volans|SF", "gameplay_index": 1},
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
    gateway.record_live_player_event(
        "player_joined",
        room_port=15102,
        player_id=2,
        player_name="Volans|SF",
        player_ip="2.2.2.2",
    )

    events: list[dict[str, object]] = []
    while True:
        try:
            events.append(queue.get_nowait())
        except asyncio.QueueEmpty:
            break

    match_started = next(event for event in events if event["event"] == "match_started")
    launch_config = next(event for event in events if event["event"] == "match_launch_config")

    assert launch_config["match_id"] == match_started["match_id"]
    assert launch_config["room_port"] == 15102
    assert launch_config["transport_mode"] == "routed"
    assert launch_config["capture_source"] == "routed_live_feed"
    assert launch_config["lobby_title"] == "2v2 no rush"
    assert launch_config["map_name"] == "Clan Wars (2-6)"
    assert launch_config["map_code"] == "pkwar6"
    assert launch_config["settings"] == {"room_flags": 7, "allied_victory": True}
    assert launch_config["captain_identity"] == {
        "player_id": "zero",
        "player_name": "&Z&e&r&o|&S&F",
        "role": "lobby_owner",
    }
    assert launch_config["players"] == [
        {"player_id": "zero", "player_name": "&Z&e&r&o|&S&F", "gameplay_index": 0},
        {"player_id": "volans", "player_name": "Volans|SF", "gameplay_index": 1},
    ]


def test_gateway_infers_homeworld_match_metadata_from_peer_packet_payload() -> None:
    class _InferMetadataRoutingServer:
        def __init__(self) -> None:
            self.snapshot = {
                "listen_port": 15102,
                "room_display_name": "Homeworld Chat",
                "room_description": "Homeworld Chat",
                "room_path": "/Homeworld",
                "published": False,
                "room_password_set": False,
                "is_game_room": True,
                "active_game_count": 1,
                "native_client_count": 2,
                "pending_reconnect_count": 0,
                "pending_reconnects": [],
                "clients": [
                    {
                        "client_id": 1,
                        "client_name": "Alpha",
                        "client_ip": "1.1.1.1",
                        "connected_seconds": 30,
                        "idle_seconds": 0,
                        "last_activity_kind": "peer_data",
                        "peer_data_messages": 4,
                        "peer_data_bytes": 128,
                    },
                    {
                        "client_id": 2,
                        "client_name": "Bravo",
                        "client_ip": "2.2.2.2",
                        "connected_seconds": 28,
                        "idle_seconds": 0,
                        "last_activity_kind": "peer_data",
                        "peer_data_messages": 4,
                        "peer_data_bytes": 128,
                    },
                ],
                "games": [],
                "peer_data_messages": 8,
                "peer_data_bytes": 256,
                "data_object_count": 0,
                "data_objects": [],
            }

        def dashboard_snapshot(self) -> dict[str, object]:
            return dict(self.snapshot)

    class _InferMetadataRoutingManager:
        def __init__(self, server: _InferMetadataRoutingServer) -> None:
            self.server = server

        def get_server(self, port: int) -> _InferMetadataRoutingServer | None:
            if port == 15102:
                return self.server
            return None

        def dashboard_snapshot(self) -> dict[str, object]:
            room = dict(self.server.snapshot)
            players = [
                {
                    "client_id": client["client_id"],
                    "client_name": client["client_name"],
                    "client_ip": client["client_ip"],
                    "connected_seconds": client["connected_seconds"],
                    "idle_seconds": client["idle_seconds"],
                    "last_activity_kind": client["last_activity_kind"],
                    "peer_data_messages": client["peer_data_messages"],
                    "peer_data_bytes": client["peer_data_bytes"],
                    "room_name": room["room_display_name"],
                    "room_port": room["listen_port"],
                }
                for client in room["clients"]
            ]
            servers = [
                {
                    "listen_port": room["listen_port"],
                    "room_name": room["room_display_name"],
                    "room_description": room["room_description"],
                    "room_path": room["room_path"],
                    "published": room["published"],
                    "room_password_set": room["room_password_set"],
                    "player_count": len(players),
                    "game_count": len(room["games"]),
                    "active_game_count": room["active_game_count"],
                    "is_game_room": room["is_game_room"],
                }
            ]
            return {
                "current_unique_ip_count": len(players),
                "current_game_room_count": 1,
                "players": players,
                "servers": servers,
                "games": [],
                "rooms": [room],
            }

    gateway = titan_binary_gateway.BinaryGatewayServer(
        "127.0.0.1",
        9100,
        public_host="homeworld.kerrbell.dev",
        public_port=15101,
        routing_port=15100,
        valid_versions=["0110"],
    )
    routing_server = _InferMetadataRoutingServer()
    gateway.routing_manager = _InferMetadataRoutingManager(routing_server)

    queue = gateway.subscribe_live_feed()
    gateway.record_live_player_event(
        "player_joined",
        room_port=15102,
        player_id=1,
        player_name="Alpha",
        player_ip="1.1.1.1",
    )
    gateway.record_live_player_event(
        "player_joined",
        room_port=15102,
        player_id=2,
        player_name="Bravo",
        player_ip="2.2.2.2",
    )
    gateway.record_live_peer_packet(
        "peer_packet",
        room_port=15102,
        sender_client_id=1,
        sender_name="Alpha",
        recipient_client_ids=[2],
        recipient_count=1,
        payload=b"Multiplayer\\pkwar4\\pkwar4.level\x00Mothership_0.missphere\x00",
        packet_kind="SendDataBroadcast",
    )

    events: list[dict[str, object]] = []
    while True:
        try:
            events.append(queue.get_nowait())
        except asyncio.QueueEmpty:
            break

    peer_packet = next(event for event in events if event["event"] == "peer_packet")
    assert peer_packet["room_name"] == "pkwar4"

    match_updates = [event for event in events if event["event"] == "match_updated"]
    assert match_updates
    assert match_updates[-1]["room_name"] == "pkwar4"
    assert match_updates[-1]["game_name"] == "pkwar4"
    assert match_updates[-1]["game_count"] == 1

    snapshot = gateway.stats_snapshot()
    assert snapshot["rooms"][0]["name"] == "pkwar4"
    assert snapshot["rooms"][0]["game_count"] == 1


def test_gateway_infers_lobby_and_human_map_title_from_setup_payload() -> None:
    class _InferMetadataRoutingServer:
        def __init__(self) -> None:
            self.snapshot = {
                "listen_port": 15102,
                "room_display_name": "Homeworld Chat",
                "room_description": "Homeworld Chat",
                "room_path": "/Homeworld",
                "published": False,
                "room_password_set": False,
                "is_game_room": True,
                "active_game_count": 1,
                "native_client_count": 2,
                "pending_reconnect_count": 0,
                "pending_reconnects": [],
                "clients": [
                    {
                        "client_id": 1,
                        "client_name": "Alpha",
                        "client_ip": "1.1.1.1",
                        "connected_seconds": 30,
                        "idle_seconds": 0,
                        "last_activity_kind": "peer_data",
                        "peer_data_messages": 4,
                        "peer_data_bytes": 128,
                    },
                    {
                        "client_id": 2,
                        "client_name": "Bravo",
                        "client_ip": "2.2.2.2",
                        "connected_seconds": 28,
                        "idle_seconds": 0,
                        "last_activity_kind": "peer_data",
                        "peer_data_messages": 4,
                        "peer_data_bytes": 128,
                    },
                ],
                "games": [],
                "peer_data_messages": 8,
                "peer_data_bytes": 256,
                "data_object_count": 0,
                "data_objects": [],
            }

        def dashboard_snapshot(self) -> dict[str, object]:
            return dict(self.snapshot)

    class _InferMetadataRoutingManager:
        def __init__(self, server: _InferMetadataRoutingServer) -> None:
            self.server = server

        def get_server(self, port: int) -> _InferMetadataRoutingServer | None:
            if port == 15102:
                return self.server
            return None

    gateway = titan_binary_gateway.BinaryGatewayServer(
        "127.0.0.1",
        9100,
        public_host="homeworld.kerrbell.dev",
        public_port=15101,
        routing_port=15100,
        valid_versions=["0110"],
    )
    routing_server = _InferMetadataRoutingServer()
    gateway.routing_manager = _InferMetadataRoutingManager(routing_server)

    queue = gateway.subscribe_live_feed()
    gateway.record_live_player_event(
        "player_joined",
        room_port=15102,
        player_id=1,
        player_name="Alpha",
        player_ip="1.1.1.1",
    )
    gateway.record_live_player_event(
        "player_joined",
        room_port=15102,
        player_id=2,
        player_name="Bravo",
        player_ip="2.2.2.2",
    )
    gateway.record_live_peer_packet(
        "peer_packet",
        room_port=15102,
        sender_client_id=1,
        sender_name="Alpha",
        recipient_client_ids=[2],
        recipient_count=1,
        payload=(
            "Testing for Codex".encode("utf-16le")
            + b"\x00\x00"
            + b"pkwar4\x00"
            + b"Talos Crossroads\x00"
            + b"Multiplayer\\pkwar4\\pkwar4.level\x00"
        ),
        packet_kind="SendDataBroadcast",
    )

    events: list[dict[str, object]] = []
    while True:
        try:
            events.append(queue.get_nowait())
        except asyncio.QueueEmpty:
            break

    peer_packet = next(event for event in events if event["event"] == "peer_packet")
    assert peer_packet["room_name"] == "Testing for Codex"
    assert peer_packet["map_name"] == "Talos Crossroads"
    assert peer_packet["game_name"] == "pkwar4"

    match_updates = [event for event in events if event["event"] == "match_updated"]
    assert match_updates
    assert match_updates[-1]["room_name"] == "Testing for Codex"
    assert match_updates[-1]["display_name"] == "Testing for Codex"
    assert match_updates[-1]["map_name"] == "Talos Crossroads"
    assert match_updates[-1]["game_name"] == "pkwar4"


def test_gateway_prefers_custom_room_description_over_generic_lobby_name() -> None:
    class _RoomDescriptionRoutingServer:
        def __init__(self) -> None:
            self.snapshot = {
                "listen_port": 15102,
                "room_display_name": "Homeworld Chat",
                "room_description": "2v2 no rush",
                "room_path": "/Homeworld",
                "published": False,
                "room_password_set": False,
                "is_game_room": True,
                "active_game_count": 1,
                "native_client_count": 2,
                "pending_reconnect_count": 0,
                "pending_reconnects": [],
                "clients": [
                    {
                        "client_id": 1,
                        "client_name": "Alpha",
                        "client_ip": "1.1.1.1",
                        "connected_seconds": 30,
                        "idle_seconds": 0,
                        "last_activity_kind": "peer_data",
                        "peer_data_messages": 4,
                        "peer_data_bytes": 128,
                    },
                    {
                        "client_id": 2,
                        "client_name": "Bravo",
                        "client_ip": "2.2.2.2",
                        "connected_seconds": 28,
                        "idle_seconds": 0,
                        "last_activity_kind": "peer_data",
                        "peer_data_messages": 4,
                        "peer_data_bytes": 128,
                    },
                ],
                "games": [],
                "peer_data_messages": 8,
                "peer_data_bytes": 256,
                "data_object_count": 0,
                "data_objects": [],
            }

        def dashboard_snapshot(self) -> dict[str, object]:
            return dict(self.snapshot)

    class _RoomDescriptionRoutingManager:
        def __init__(self, server: _RoomDescriptionRoutingServer) -> None:
            self.server = server

        def get_server(self, port: int) -> _RoomDescriptionRoutingServer | None:
            if port == 15102:
                return self.server
            return None

        def dashboard_snapshot(self) -> dict[str, object]:
            room = dict(self.server.snapshot)
            players = [
                {
                    "client_id": client["client_id"],
                    "client_name": client["client_name"],
                    "client_ip": client["client_ip"],
                    "connected_seconds": client["connected_seconds"],
                    "idle_seconds": client["idle_seconds"],
                    "last_activity_kind": client["last_activity_kind"],
                    "peer_data_messages": client["peer_data_messages"],
                    "peer_data_bytes": client["peer_data_bytes"],
                    "room_name": room["room_display_name"],
                    "room_port": room["listen_port"],
                }
                for client in room["clients"]
            ]
            servers = [
                {
                    "listen_port": room["listen_port"],
                    "room_name": room["room_display_name"],
                    "room_description": room["room_description"],
                    "room_path": room["room_path"],
                    "published": room["published"],
                    "room_password_set": room["room_password_set"],
                    "player_count": len(players),
                    "game_count": len(room["games"]),
                    "active_game_count": room["active_game_count"],
                    "is_game_room": room["is_game_room"],
                }
            ]
            return {
                "current_unique_ip_count": len(players),
                "current_game_room_count": 1,
                "players": players,
                "servers": servers,
                "games": [],
                "rooms": [room],
            }

    gateway = titan_binary_gateway.BinaryGatewayServer(
        "127.0.0.1",
        9100,
        public_host="homeworld.kerrbell.dev",
        public_port=15101,
        routing_port=15100,
        valid_versions=["0110"],
    )
    routing_server = _RoomDescriptionRoutingServer()
    gateway.routing_manager = _RoomDescriptionRoutingManager(routing_server)

    queue = gateway.subscribe_live_feed()
    gateway.record_live_player_event(
        "player_joined",
        room_port=15102,
        player_id=1,
        player_name="Alpha",
        player_ip="1.1.1.1",
    )
    gateway.record_live_player_event(
        "player_joined",
        room_port=15102,
        player_id=2,
        player_name="Bravo",
        player_ip="2.2.2.2",
    )

    events: list[dict[str, object]] = []
    while True:
        try:
            events.append(queue.get_nowait())
        except asyncio.QueueEmpty:
            break

    match_started = next(event for event in events if event["event"] == "match_started")
    assert match_started["room_name"] == "2v2 no rush"
    assert match_started["display_name"] == "2v2 no rush"
    assert match_started["map_name"] == "2v2 no rush"

    match_updated = next(event for event in reversed(events) if event["event"] == "match_updated")
    assert match_updated["room_name"] == "2v2 no rush"
    assert match_updated["display_name"] == "2v2 no rush"
    assert match_updated["map_name"] == "2v2 no rush"
