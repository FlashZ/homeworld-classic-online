from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
import sys
import time
from types import SimpleNamespace
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gateway.web_auth import GatewayWebAuthBridge
from gateway.admin import AdminDashboardServer, DASHBOARD_LOG_HANDLER


def _seed_user(db_path: Path, username: str, password_hash: str) -> None:
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            created_at REAL NOT NULL,
            native_cd_key TEXT,
            native_login_key TEXT
        )
        """
    )
    conn.execute(
        "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
        (username, password_hash, time.time()),
    )
    conn.commit()
    conn.close()


def _make_bridge(
    db_paths: dict[str, str],
    *,
    default_product: str = "homeworld",
    shared_secret: str = "bridge-secret",
    code_ttl_seconds: float = 30.0,
) -> GatewayWebAuthBridge:
    return GatewayWebAuthBridge(
        db_paths=db_paths,
        default_product=default_product,
        shared_secret=shared_secret,
        code_ttl_seconds=code_ttl_seconds,
    )


def _make_dashboard(
    bridge: GatewayWebAuthBridge,
    db_path: Path,
    *,
    shared_secret: str = "bridge-secret",
) -> AdminDashboardServer:
    gateway = SimpleNamespace(
        product_profile=SimpleNamespace(key="homeworld"),
        default_product_key="homeworld",
        web_auth_bridge=bridge,
    )
    return AdminDashboardServer(
        gateway=gateway,
        db_path=str(db_path),
        log_handler=DASHBOARD_LOG_HANDLER,
        db_paths={"homeworld": str(db_path)},
        default_db_product="homeworld",
        admin_token="",
        stats_token="",
        web_auth_shared_secret=shared_secret,
        web_auth_public_base_url="https://stats.example.test",
    )


def test_web_auth_rejects_unknown_user_without_creating_account(tmp_path: Path) -> None:
    db_path = tmp_path / "won_server.db"
    bridge = _make_bridge({"homeworld": str(db_path)})

    with pytest.raises(ValueError, match="invalid_credentials"):
        bridge.start_login(
            product="homeworld",
            username="ghost",
            password="hunter2",
            return_to="https://stats.example.test/auth/callback",
        )

    conn = sqlite3.connect(db_path)
    try:
        count = conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='users'"
        ).fetchone()[0]
        if count == 0:
            assert True
            return
        user_count = conn.execute(
            "SELECT COUNT(*) FROM users WHERE username=?",
            ("ghost",),
        ).fetchone()[0]
    finally:
        conn.close()

    assert user_count == 0


def test_web_auth_authenticates_existing_user_and_consumes_code(tmp_path: Path) -> None:
    db_path = tmp_path / "won_server.db"
    bridge = _make_bridge({"homeworld": str(db_path)})
    _seed_user(db_path, "ZeroSF", bridge.hash_password("swordfish"))

    started = bridge.start_login(
        product="homeworld",
        username="ZeroSF",
        password="swordfish",
        return_to="https://stats.example.test/auth/callback",
    )

    exchanged = bridge.exchange_code(
        code=str(started["code"]),
        product="homeworld",
        shared_secret="bridge-secret",
    )

    assert exchanged["product"] == "homeworld"
    assert exchanged["username"] == "ZeroSF"
    assert exchanged["return_to"] == "https://stats.example.test/auth/callback"
    assert "issued_at" in exchanged
    assert "expires_at" in exchanged

    with pytest.raises(ValueError, match="invalid_or_consumed_code"):
        bridge.exchange_code(
            code=str(started["code"]),
            product="homeworld",
            shared_secret="bridge-secret",
        )


def test_web_auth_rejects_exchange_with_wrong_shared_secret(tmp_path: Path) -> None:
    db_path = tmp_path / "won_server.db"
    bridge = _make_bridge({"homeworld": str(db_path)})
    _seed_user(db_path, "ZeroSF", bridge.hash_password("swordfish"))

    started = bridge.start_login(
        product="homeworld",
        username="ZeroSF",
        password="swordfish",
        return_to="https://stats.example.test/auth/callback",
    )

    with pytest.raises(ValueError, match="invalid_shared_secret"):
        bridge.exchange_code(
            code=str(started["code"]),
            product="homeworld",
            shared_secret="wrong-secret",
        )


def test_web_auth_code_expires(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "won_server.db"
    bridge = _make_bridge({"homeworld": str(db_path)}, code_ttl_seconds=5.0)
    _seed_user(db_path, "ZeroSF", bridge.hash_password("swordfish"))

    current_time = 1_700_000_000.0
    monkeypatch.setattr("gateway.web_auth.time.time", lambda: current_time)

    started = bridge.start_login(
        product="homeworld",
        username="ZeroSF",
        password="swordfish",
        return_to="https://stats.example.test/auth/callback",
    )

    current_time += 6.0

    with pytest.raises(ValueError, match="expired_code"):
        bridge.exchange_code(
            code=str(started["code"]),
            product="homeworld",
            shared_secret="bridge-secret",
        )


def test_web_auth_login_page_and_redirect_route(tmp_path: Path) -> None:
    db_path = tmp_path / "won_server.db"
    bridge = _make_bridge({"homeworld": str(db_path)})
    _seed_user(db_path, "ZeroSF", bridge.hash_password("swordfish"))
    dashboard = _make_dashboard(bridge, db_path)

    login_target = "/web-auth/login?product=homeworld&return_to=https%3A%2F%2Fstats.example.test%2Fauth%2Fcallback"
    status, headers, body = asyncio.run(
        dashboard._dispatch_web_auth_request("GET", login_target, {}, b"")
    )

    assert status == 200
    page = body.decode("utf-8")
    assert "Sign in with your WON account" in page
    assert 'action="/web-auth/login?product=homeworld&return_to=https%3A%2F%2Fstats.example.test%2Fauth%2Fcallback"' in page

    status, headers, body = asyncio.run(
        dashboard._dispatch_web_auth_request(
            "POST",
            login_target,
            {"content-type": "application/x-www-form-urlencoded"},
            b"username=ZeroSF&password=swordfish",
        )
    )

    assert status == 302
    location = headers["location"]
    redirected = urlsplit(location)
    query = parse_qs(redirected.query)
    assert query["product"][0] == "homeworld"
    assert query["code"][0]
    assert redirected.scheme == "https"
    assert redirected.netloc == "stats.example.test"
    assert redirected.path == "/auth/callback"
    assert body == b""


def test_web_auth_exchange_route_returns_verified_identity(tmp_path: Path) -> None:
    db_path = tmp_path / "won_server.db"
    bridge = _make_bridge({"homeworld": str(db_path)})
    _seed_user(db_path, "ZeroSF", bridge.hash_password("swordfish"))
    dashboard = _make_dashboard(bridge, db_path)

    started = bridge.start_login(
        product="homeworld",
        username="ZeroSF",
        password="swordfish",
        return_to="https://stats.example.test/auth/callback",
    )

    status, headers, body = asyncio.run(
        dashboard._dispatch_web_auth_request(
            "POST",
            "/api/web-auth/exchange",
            {},
            json.dumps(
                {
                    "code": started["code"],
                    "product": "homeworld",
                    "shared_secret": "bridge-secret",
                }
            ).encode("utf-8"),
        )
    )

    assert status == 200
    assert headers["content-type"].startswith("application/json")
    payload = json.loads(body.decode("utf-8"))
    assert payload["product"] == "homeworld"
    assert payload["username"] == "ZeroSF"
    assert payload["return_to"] == "https://stats.example.test/auth/callback"


def test_web_auth_exchange_route_rejects_wrong_shared_secret(tmp_path: Path) -> None:
    db_path = tmp_path / "won_server.db"
    bridge = _make_bridge({"homeworld": str(db_path)})
    _seed_user(db_path, "ZeroSF", bridge.hash_password("swordfish"))
    dashboard = _make_dashboard(bridge, db_path)

    started = bridge.start_login(
        product="homeworld",
        username="ZeroSF",
        password="swordfish",
        return_to="https://stats.example.test/auth/callback",
    )

    status, headers, body = asyncio.run(
        dashboard._dispatch_web_auth_request(
            "POST",
            "/api/web-auth/exchange",
            {},
            json.dumps(
                {
                    "code": started["code"],
                    "product": "homeworld",
                    "shared_secret": "wrong-secret",
                }
            ).encode("utf-8"),
        )
    )

    assert status == 403
    payload = json.loads(body.decode("utf-8"))
    assert payload["error"] == "invalid_shared_secret"


def test_hash_password_uses_sha256() -> None:
    assert GatewayWebAuthBridge.hash_password("swordfish") == hashlib.sha256(
        b"swordfish"
    ).hexdigest()
