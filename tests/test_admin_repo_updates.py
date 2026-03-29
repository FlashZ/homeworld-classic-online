from __future__ import annotations

import asyncio

import titan_binary_gateway


class _FakeGateway:
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
