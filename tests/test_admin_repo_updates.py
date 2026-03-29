from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
import sqlite3
import struct

import titan_binary_gateway


class _FakeGateway:
    def __init__(self) -> None:
        self.activities: list[dict[str, object]] = []
        self.routing_manager = _FakeRoutingManager()

    def dashboard_snapshot(self, activity_limit: int = 150) -> dict[str, object]:
        return {
            "public_host": "homeworld.kerrbell.dev",
            "public_port": 15101,
            "routing_port": 15100,
            "backend_host": "backend",
            "backend_port": 9100,
            "version_str": "0110",
            "valid_versions": ["0110"],
            "auth_keys_loaded": True,
            "peer_session_count": 0,
            "activity_metrics": {},
            "activity": [],
            "ip_metrics": [],
            "peer_sessions": {},
            "routing_manager": {
                "current_player_count": 0,
                "room_count": 0,
                "current_game_count": 0,
                "current_unique_ip_count": 0,
                "servers": [],
            },
            "banned_ips": [],
        }

    def record_activity(self, kind: str, **kwargs: object) -> None:
        entry = {"kind": kind}
        entry.update(kwargs)
        self.activities.append(entry)


class _FakeServer:
    _room_display_name = "Default"
    _room_path = "/Homeworld"


class _FakeRoutingManager:
    def __init__(self) -> None:
        self.last_message = ""
        self.last_room_port: int | None = None
        self._server = _FakeServer()

    async def admin_broadcast(self, message: str, room_port: int | None = None) -> int:
        self.last_message = message
        self.last_room_port = room_port
        return 2

    def get_server(self, port: int) -> _FakeServer | None:
        if port == 15100:
            return self._server
        return None


class _FakeRepoMonitor:
    def __init__(self) -> None:
        self.checked = 0
        self.updated = 0
        self._snapshot = {
            "available": True,
            "repo_path": "/repo",
            "remote_name": "origin",
            "remote_url": "https://github.com/example/repo.git",
            "branch": "main",
            "upstream": "origin/main",
            "local_commit": "111111111111",
            "local_short": "111111111111",
            "local_version": "installer-v1",
            "remote_commit": "222222222222",
            "remote_short": "222222222222",
            "remote_version": "installer-v2",
            "ahead": 0,
            "behind": 1,
            "dirty": False,
            "can_update": True,
            "update_available": True,
            "status": "update_available",
            "last_checked_at": 1000.0,
            "last_error": "",
            "check_interval_seconds": 900,
            "last_update_at": 0.0,
            "last_update_message": "",
            "restart_required": False,
        }

    def snapshot(self) -> dict[str, object]:
        return dict(self._snapshot)

    def start_background_tasks(self) -> None:
        return None

    async def stop_background_tasks(self) -> None:
        return None

    async def force_refresh(self, fetch_remote: bool = True) -> dict[str, object]:
        self.checked += 1
        self._snapshot["last_checked_at"] = 2000.0
        return self.snapshot()

    async def update_from_upstream(self) -> dict[str, object]:
        self.updated += 1
        self._snapshot["local_commit"] = "222222222222"
        self._snapshot["local_short"] = "222222222222"
        self._snapshot["local_version"] = "installer-v2"
        self._snapshot["behind"] = 0
        self._snapshot["can_update"] = False
        self._snapshot["update_available"] = False
        self._snapshot["last_update_at"] = 3000.0
        self._snapshot["last_update_message"] = "Updated from installer-v1 to installer-v2. Restart the gateway to load the new code."
        self._snapshot["restart_required"] = True
        return {
            "ok": True,
            "updated": True,
            "message": self._snapshot["last_update_message"],
            "git": self.snapshot(),
        }


def _init_user_db(path: Path, username: str, password: str) -> None:
    conn = sqlite3.connect(str(path))
    try:
        conn.execute(
            """
            CREATE TABLE users (
              username TEXT PRIMARY KEY,
              password_hash TEXT NOT NULL,
              created_at REAL NOT NULL,
              native_cd_key TEXT,
              native_login_key TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO users(username,password_hash,created_at,native_cd_key,native_login_key) VALUES(?,?,?,?,?)",
            (
                username,
                hashlib.sha256(password.encode("utf-8")).hexdigest(),
                0.0,
                "",
                "",
            ),
        )
        conn.commit()
    finally:
        conn.close()


def test_admin_snapshot_includes_repo_metadata() -> None:
    repo = _FakeRepoMonitor()
    dashboard = titan_binary_gateway.AdminDashboardServer(
        gateway=_FakeGateway(),
        db_path="won_server.db",
        log_handler=titan_binary_gateway.DashboardLogHandler(),
        repo_monitor=repo,
    )

    snapshot = dashboard.snapshot(rows_per_table=1, log_limit=1, activity_limit=1)

    assert snapshot["repo"]["local_version"] == "installer-v1"
    assert snapshot["repo"]["remote_version"] == "installer-v2"
    assert snapshot["repo"]["update_available"] is True


def test_admin_snapshot_includes_product_scoped_databases(tmp_path: Path) -> None:
    hw_db = tmp_path / "homeworld.db"
    cata_db = tmp_path / "cataclysm.db"
    _init_user_db(hw_db, "alpha", "pw1")
    _init_user_db(cata_db, "zero", "pw2")

    dashboard = titan_binary_gateway.AdminDashboardServer(
        gateway=_FakeGateway(),
        db_path=str(hw_db),
        log_handler=titan_binary_gateway.DashboardLogHandler(),
        db_paths={
            "homeworld": str(hw_db),
            "cataclysm": str(cata_db),
        },
        default_db_product="homeworld",
        repo_monitor=_FakeRepoMonitor(),
    )

    snapshot = dashboard.snapshot(rows_per_table=5, log_limit=1, activity_limit=1)

    assert snapshot["db_default_product"] == "homeworld"
    assert set(snapshot["dbs"]) == {"homeworld", "cataclysm"}
    assert snapshot["db"]["path"] == str(hw_db.resolve())
    assert snapshot["dbs"]["homeworld"]["tables"]["users"]["count"] == 1
    assert snapshot["dbs"]["cataclysm"]["tables"]["users"]["rows"][0]["username"] == "zero"


def test_admin_repo_check_endpoint_uses_repo_monitor() -> None:
    repo = _FakeRepoMonitor()
    dashboard = titan_binary_gateway.AdminDashboardServer(
        gateway=_FakeGateway(),
        db_path="won_server.db",
        log_handler=titan_binary_gateway.DashboardLogHandler(),
        repo_monitor=repo,
    )

    result = asyncio.run(dashboard._handle_admin_post("/api/admin/github-check", {}))

    assert result["ok"] is True
    assert "GitHub check complete" not in result["message"]
    assert result["message"] == "Update available from GitHub."
    assert repo.checked == 1


def test_admin_repo_update_endpoint_surfaces_restart_message() -> None:
    repo = _FakeRepoMonitor()
    dashboard = titan_binary_gateway.AdminDashboardServer(
        gateway=_FakeGateway(),
        db_path="won_server.db",
        log_handler=titan_binary_gateway.DashboardLogHandler(),
        repo_monitor=repo,
    )

    result = asyncio.run(dashboard._handle_admin_post("/api/admin/github-update", {}))

    assert result["ok"] is True
    assert result["updated"] is True
    assert "Restart the gateway" in result["message"]
    assert result["git"]["restart_required"] is True
    assert repo.updated == 1


def test_admin_broadcast_endpoint_records_activity() -> None:
    gateway = _FakeGateway()
    dashboard = titan_binary_gateway.AdminDashboardServer(
        gateway=gateway,
        db_path="won_server.db",
        log_handler=titan_binary_gateway.DashboardLogHandler(),
        repo_monitor=_FakeRepoMonitor(),
    )

    result = asyncio.run(
        dashboard._handle_admin_post(
            "/api/admin/broadcast",
            {"message": "Server notice", "room_port": 15100},
        )
    )

    assert result["ok"] is True
    assert result["delivered"] == 2
    assert gateway.activities
    activity = gateway.activities[-1]
    assert activity["kind"] == "broadcast"
    assert activity["player_name"] == "[ADMIN]"
    assert activity["text"] == "Server notice"
    assert activity["room_name"] == "Default"
    assert activity["details"] == {"delivered": 2, "scope": "room :15100"}


def test_admin_account_actions_target_selected_product_db(tmp_path: Path) -> None:
    hw_db = tmp_path / "homeworld.db"
    cata_db = tmp_path / "cataclysm.db"
    _init_user_db(hw_db, "shared_user", "homeworld-old")
    _init_user_db(cata_db, "shared_user", "cataclysm-old")

    dashboard = titan_binary_gateway.AdminDashboardServer(
        gateway=_FakeGateway(),
        db_path=str(hw_db),
        log_handler=titan_binary_gateway.DashboardLogHandler(),
        db_paths={
            "homeworld": str(hw_db),
            "cataclysm": str(cata_db),
        },
        default_db_product="homeworld",
        repo_monitor=_FakeRepoMonitor(),
    )

    reset_result = asyncio.run(
        dashboard._handle_admin_post(
            "/api/admin/reset-password",
            {
                "product": "cataclysm",
                "username": "shared_user",
                "new_password": "cataclysm-new",
            },
        )
    )
    assert reset_result["ok"] is True
    assert reset_result["product"] == "cataclysm"

    hw_conn = sqlite3.connect(str(hw_db))
    cata_conn = sqlite3.connect(str(cata_db))
    try:
        hw_hash = hw_conn.execute(
            "SELECT password_hash FROM users WHERE username=?",
            ("shared_user",),
        ).fetchone()[0]
        cata_hash = cata_conn.execute(
            "SELECT password_hash FROM users WHERE username=?",
            ("shared_user",),
        ).fetchone()[0]
    finally:
        hw_conn.close()
        cata_conn.close()

    assert hw_hash == hashlib.sha256("homeworld-old".encode("utf-8")).hexdigest()
    assert cata_hash == hashlib.sha256("cataclysm-new".encode("utf-8")).hexdigest()

    delete_result = asyncio.run(
        dashboard._handle_admin_post(
            "/api/admin/delete-user",
            {
                "product": "homeworld",
                "username": "shared_user",
            },
        )
    )
    assert delete_result["ok"] is True
    assert delete_result["product"] == "homeworld"

    hw_conn = sqlite3.connect(str(hw_db))
    cata_conn = sqlite3.connect(str(cata_db))
    try:
        assert hw_conn.execute(
            "SELECT COUNT(*) FROM users WHERE username=?",
            ("shared_user",),
        ).fetchone()[0] == 0
        assert cata_conn.execute(
            "SELECT COUNT(*) FROM users WHERE username=?",
            ("shared_user",),
        ).fetchone()[0] == 1
    finally:
        hw_conn.close()
        cata_conn.close()


def test_admin_broadcast_chat_uses_visible_room_chat_sender() -> None:
    async def _run() -> tuple[int, titan_binary_gateway.NativeRouteClientState, list[tuple[int, bytes]]]:
        server = titan_binary_gateway.SilencerRoutingServer()
        sent: list[tuple[int, bytes]] = []

        async def _fake_send(
            client: titan_binary_gateway.NativeRouteClientState,
            clear_msg: bytes,
        ) -> None:
            sent.append((client.client_id, clear_msg))

        server._send_native_route_client_reply = _fake_send  # type: ignore[method-assign]
        client = titan_binary_gateway.NativeRouteClientState(
            client_id=7,
            client_name_raw="Alpha".encode("utf-16-le"),
            client_name="Alpha",
            client_ip="1.2.3.4",
            client_ip_u32=0,
            writer=None,  # type: ignore[arg-type]
            session_key=b"",
            out_seq=None,
        )
        server._native_clients[client.client_id] = client

        delivered = await server.admin_broadcast_chat("Server notice")
        delivered2 = await server.admin_broadcast_chat("Second notice")
        assert delivered2 == 1
        return delivered, client, sent

    delivered, client, sent = asyncio.run(_run())

    assert delivered == 1
    assert client.admin_sender_announced is True
    assert len(sent) == 3

    service_type, message_type, payload = titan_binary_gateway._parse_mini_message(sent[0][1])
    assert service_type == titan_binary_gateway.MINI_ROUTING_SERVICE
    assert message_type == titan_binary_gateway.ROUTING_GROUP_CHANGE_EX

    service_type, message_type, payload = titan_binary_gateway._parse_mini_message(sent[1][1])
    assert service_type == titan_binary_gateway.MINI_ROUTING_SERVICE
    assert message_type == titan_binary_gateway.ROUTING_PEER_CHAT
    sender_id, _flags, chat_type, data_len = struct.unpack("<HBBH", payload[:6])
    assert sender_id == titan_binary_gateway.ADMIN_BROADCAST_CLIENT_ID
    assert chat_type == titan_binary_gateway.CHAT_GROUP_ID
    assert payload[6 : 6 + data_len].decode("utf-16-le") == "Server notice"

    service_type, message_type, payload = titan_binary_gateway._parse_mini_message(sent[2][1])
    assert service_type == titan_binary_gateway.MINI_ROUTING_SERVICE
    assert message_type == titan_binary_gateway.ROUTING_PEER_CHAT
    sender_id, _flags, chat_type, data_len = struct.unpack("<HBBH", payload[:6])
    assert sender_id == titan_binary_gateway.ADMIN_BROADCAST_CLIENT_ID
    assert chat_type == titan_binary_gateway.CHAT_GROUP_ID
    assert payload[6 : 6 + data_len].decode("utf-16-le") == "Second notice"


def test_routing_client_list_entries_include_admin_sender() -> None:
    server = titan_binary_gateway.SilencerRoutingServer()
    server._native_clients[5] = titan_binary_gateway.NativeRouteClientState(
        client_id=5,
        client_name_raw="Alpha".encode("utf-16-le"),
        client_name="Alpha",
        client_ip="1.2.3.4",
        client_ip_u32=0x01020304,
        writer=None,  # type: ignore[arg-type]
        session_key=b"",
        out_seq=None,
    )

    entries = server._routing_client_list_entries()

    assert [entry[0] for entry in entries] == [5, titan_binary_gateway.ADMIN_BROADCAST_CLIENT_ID]
    assert entries[-1][1] == titan_binary_gateway.ADMIN_BROADCAST_CLIENT_NAME_RAW
    assert entries[-1][2] == titan_binary_gateway.ADMIN_BROADCAST_CLIENT_IP_U32


def test_admin_dashboard_default_repo_monitor_uses_repo_root() -> None:
    dashboard = titan_binary_gateway.AdminDashboardServer(
        gateway=_FakeGateway(),
        db_path="won_server.db",
        log_handler=titan_binary_gateway.DashboardLogHandler(),
        admin_token="admin-secret",
    )

    assert dashboard.repo_monitor.repo_path == Path(titan_binary_gateway.__file__).resolve().parent
