from __future__ import annotations

import asyncio
from collections import deque
import contextlib
import hashlib
import json
import logging
from pathlib import Path
import re
import secrets
import sqlite3
import time
from typing import TYPE_CHECKING, Any, Deque, Dict, Optional, Tuple
from urllib.parse import parse_qs, parse_qsl, urlencode, urlsplit, urlunsplit

from .repo_monitor import GitRepoMonitor

if TYPE_CHECKING:
    from .titan_service import BinaryGatewayServer

LOGGER = logging.getLogger(__name__)

# Legacy shared installer CD keys (normalized, no separators). Early installer
# builds shipped the same hardcoded key to everyone; the admin panel flags and
# can bulk-clear accounts still bound to them so the key can be retired.
LEGACY_SHARED_CD_KEYS: Dict[str, str] = {
    "homeworld": "NYX7ZEC9FYZ6GUX84253",
    "cataclysm": "GAF6CAB4SEX5ZYL62622",
}


def _normalize_cd_key(value: object) -> str:
    return "".join(ch for ch in str(value or "").upper() if ch.isalnum())


class DashboardLogHandler(logging.Handler):
    """In-memory ring buffer for the local admin dashboard."""

    def __init__(self, max_entries: int = 500) -> None:
        super().__init__()
        self.records: Deque[Dict[str, object]] = deque(maxlen=max_entries)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            rendered = self.format(record)
        except Exception:
            rendered = record.getMessage()
        self.records.append(
            {
                "created": record.created,
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
                "rendered": rendered,
            }
        )

    def snapshot(self, limit: int = 200) -> list[Dict[str, object]]:
        if limit <= 0:
            return []
        return list(self.records)[-limit:]

    def clear(self) -> int:
        count = len(self.records)
        self.records.clear()
        return count


DASHBOARD_LOG_HANDLER = DashboardLogHandler()

class AdminDashboardServer:
    """Local-only HTTP dashboard for live gateway state and backend DB inspection."""

    def __init__(
        self,
        gateway: BinaryGatewayServer,
        db_path: str,
        log_handler: DashboardLogHandler,
        db_paths: Optional[Dict[str, str]] = None,
        default_db_product: str = "",
        admin_token: str = "",
        stats_token: str = "",
        web_auth_shared_secret: str = "",
        web_auth_public_base_url: str = "",
        forward_auth_user_header: str = "",
        forward_auth_secret: str = "",
        forward_auth_secret_header: str = "x-admin-proxy-secret",
        forward_auth_groups_header: str = "",
        forward_auth_allowed_groups: str = "",
        repo_monitor: Optional[GitRepoMonitor] = None,
    ) -> None:
        self.gateway = gateway
        self.db_path = db_path
        self.db_paths = {
            str(product).strip(): str(path)
            for product, path in dict(db_paths or {}).items()
            if str(product).strip() and str(path).strip()
        }
        if not self.db_paths and str(db_path).strip():
            fallback_product = ""
            product_profile = getattr(gateway, "product_profile", None)
            if product_profile is not None:
                fallback_product = str(getattr(product_profile, "key", "") or "").strip()
            if not fallback_product:
                fallback_product = str(getattr(gateway, "default_product_key", "") or "").strip()
            if not fallback_product:
                fallback_product = "default"
            self.db_paths = {fallback_product: str(db_path)}
        self.default_db_product = str(default_db_product or "").strip()
        if self.default_db_product not in self.db_paths:
            self.default_db_product = next(iter(self.db_paths), "")
        self.log_handler = log_handler
        self.admin_token = admin_token.strip()
        self.stats_token = stats_token.strip()
        # Trusted reverse-proxy (forward-auth) config. When a front proxy
        # (Authelia, oauth2-proxy, Cloudflare Access, Tailscale, Authentik, ...)
        # authenticates the user and injects an identity header, the panel can
        # trust it. A shared secret header guards against header spoofing if the
        # admin port is ever reachable without going through the proxy.
        self.forward_auth_user_header = forward_auth_user_header.strip().lower()
        self.forward_auth_secret = forward_auth_secret.strip()
        self.forward_auth_secret_header = (
            forward_auth_secret_header.strip().lower() or "x-admin-proxy-secret"
        )
        self.forward_auth_groups_header = forward_auth_groups_header.strip().lower()
        self.forward_auth_allowed_groups = {
            g.strip()
            for g in re.split(r"[,;|]", forward_auth_allowed_groups or "")
            if g.strip()
        }
        self.web_auth_shared_secret = web_auth_shared_secret.strip()
        self.web_auth_public_base_url = web_auth_public_base_url.strip()
        self.web_auth_bridge = getattr(gateway, "web_auth_bridge", None)
        repo_root = Path(__file__).resolve().parents[1]
        self.repo_monitor = repo_monitor or GitRepoMonitor(str(repo_root))
        self.started_at = time.time()

    def start_background_tasks(self) -> None:
        self.repo_monitor.start_background_tasks()

    async def stop_background_tasks(self) -> None:
        await self.repo_monitor.stop_background_tasks()

    @staticmethod
    def _parse_headers(request_text: str) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        for line in request_text.splitlines()[1:]:
            if not line or ":" not in line:
                continue
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
        return headers

    @staticmethod
    def _matches_token(
        required_token: str,
        query: Dict[str, list[str]],
        headers: Dict[str, str],
        header_names: Tuple[str, ...] = (),
    ) -> bool:
        if not required_token:
            return True
        query_token = str(query.get("token", [""])[0] or "")
        if query_token and secrets.compare_digest(query_token, required_token):
            return True
        for header_name in header_names:
            header_token = str(headers.get(header_name, "") or "")
            if header_token and secrets.compare_digest(header_token, required_token):
                return True
        auth_header = str(headers.get("authorization", "") or "")
        if auth_header.lower().startswith("bearer "):
            bearer_token = auth_header[7:].strip()
            if bearer_token and secrets.compare_digest(bearer_token, required_token):
                return True
        return False

    @property
    def _forward_auth_enabled(self) -> bool:
        return bool(self.forward_auth_user_header)

    def _forward_auth_identity(self, headers: Dict[str, str]) -> str:
        """Return the authenticated username from a trusted forward-auth proxy,
        or "" if the request is not a valid, trusted forward-auth request.

        Guards, in order: forward-auth must be enabled; the identity header must
        be present; if a proxy secret is configured it must match (anti-spoof);
        if a group allowlist is configured the forwarded groups must intersect
        it."""
        if not self._forward_auth_enabled:
            return ""
        user = str(headers.get(self.forward_auth_user_header, "") or "").strip()
        if not user:
            return ""
        if self.forward_auth_secret:
            provided = str(headers.get(self.forward_auth_secret_header, "") or "")
            if not (provided and secrets.compare_digest(provided, self.forward_auth_secret)):
                LOGGER.warning(
                    "Rejected forward-auth request for %r: missing/invalid proxy secret",
                    user,
                )
                return ""
        if self.forward_auth_allowed_groups:
            groups_raw = (
                str(headers.get(self.forward_auth_groups_header, "") or "")
                if self.forward_auth_groups_header
                else ""
            )
            groups = {g.strip() for g in re.split(r"[,;|]", groups_raw) if g.strip()}
            if not (groups & self.forward_auth_allowed_groups):
                LOGGER.warning(
                    "Rejected forward-auth user %r: not in an allowed group", user
                )
                return ""
        return user

    def _is_authorized(
        self,
        path: str,
        query: Dict[str, list[str]],
        headers: Dict[str, str],
    ) -> bool:
        if path in {"/web-auth/login", "/api/web-auth/exchange"}:
            return True

        # A trusted forward-auth proxy authenticates every path (browser SSE and
        # fetch carry the proxy's session cookie transparently).
        if self._forward_auth_identity(headers):
            return True

        if path in {"/api/stats", "/api/live-feed"}:
            if self.stats_token and self._matches_token(
                self.stats_token,
                query,
                headers,
                header_names=("x-stats-token",),
            ):
                return True
            if self.admin_token and self._matches_token(
                self.admin_token,
                query,
                headers,
                header_names=("x-admin-token",),
            ):
                return True
            # Open only when no auth mechanism is configured at all.
            return not self.stats_token and not self.admin_token and not self._forward_auth_enabled

        if self.admin_token:
            return self._matches_token(
                self.admin_token,
                query,
                headers,
                header_names=("x-admin-token",),
            )
        # No admin token: if forward-auth is the configured mechanism, a request
        # that reached here failed it, so deny. Otherwise fall back to the legacy
        # loopback-open behavior.
        return not self._forward_auth_enabled

    def _get_web_auth_bridge(self) -> Any:
        bridge = getattr(self, "web_auth_bridge", None)
        if bridge is None:
            bridge = getattr(self.gateway, "web_auth_bridge", None)
            if bridge is not None:
                self.web_auth_bridge = bridge
        return bridge

    @staticmethod
    def _append_query_params(url: str, params: Dict[str, str]) -> str:
        parsed = urlsplit(url)
        query_map: Dict[str, str] = {}
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            query_map[key] = value
        for key, value in params.items():
            if value is None:
                continue
            value_str = str(value)
            if value_str:
                query_map[key] = value_str
        return urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, urlencode(list(query_map.items())), parsed.fragment)
        )

    def _normalize_return_to(self, return_to: str) -> str:
        candidate = str(return_to or "").strip()
        if not candidate:
            candidate = self.web_auth_public_base_url or "/"
        if not candidate:
            return "/"

        parsed = urlsplit(candidate)
        if not parsed.scheme and not parsed.netloc:
            return candidate

        allowed_base = self.web_auth_public_base_url.strip()
        if not allowed_base:
            raise ValueError("invalid_return_to")

        allowed = urlsplit(allowed_base)
        if parsed.scheme != allowed.scheme or parsed.netloc != allowed.netloc:
            raise ValueError("invalid_return_to")
        return candidate

    @staticmethod
    def _status_line(status_code: int) -> str:
        return {
            200: "200 OK",
            302: "302 Found",
            400: "400 Bad Request",
            401: "401 Unauthorized",
            403: "403 Forbidden",
            404: "404 Not Found",
            501: "501 Not Implemented",
        }.get(int(status_code), f"{int(status_code)} OK")

    @staticmethod
    async def _close_writer(writer: asyncio.StreamWriter) -> None:
        writer.close()
        with contextlib.suppress(ConnectionResetError, BrokenPipeError, ConnectionAbortedError, OSError):
            await writer.wait_closed()

    def _web_auth_login_page(self, *, product: str, return_to: str, error: str = "") -> bytes:
        bridge = self._get_web_auth_bridge()
        if bridge is None or not hasattr(bridge, "render_login_page"):
            return b"web auth unavailable"
        return bridge.render_login_page(product=product, return_to=return_to, error=error)

    async def _dispatch_web_auth_request(
        self,
        method: str,
        target: str,
        headers: Dict[str, str],
        body_raw: bytes,
    ) -> Optional[Tuple[int, Dict[str, str], bytes]]:
        parsed = urlsplit(target)
        if parsed.path not in {"/web-auth/login", "/api/web-auth/exchange"}:
            return None

        bridge = self._get_web_auth_bridge()
        if bridge is None:
            return (
                501,
                {"content-type": "text/plain; charset=utf-8"},
                b"web auth bridge unavailable",
            )

        query = parse_qs(parsed.query)
        product = str(query.get("product", [self.default_db_product])[0] or self.default_db_product or "homeworld")

        if method == "GET" and parsed.path == "/web-auth/login":
            try:
                return_to = self._normalize_return_to(
                    str(query.get("return_to", [self.web_auth_public_base_url or "/"])[0] or "")
                )
            except ValueError as exc:
                return (
                    400,
                    {"content-type": "text/html; charset=utf-8"},
                    self._web_auth_login_page(
                        product=product,
                        return_to=self.web_auth_public_base_url or "/",
                        error=str(exc),
                    ),
                )
            error = str(query.get("error", [""])[0] or "")
            return (
                200,
                {"content-type": "text/html; charset=utf-8"},
                self._web_auth_login_page(product=product, return_to=return_to, error=error),
            )

        if method == "POST" and parsed.path == "/web-auth/login":
            form = parse_qs(body_raw.decode("utf-8", errors="replace"), keep_blank_values=True)
            username = str(form.get("username", [""])[0] or "").strip()
            password = str(form.get("password", [""])[0] or "")
            if not username or not password:
                return (
                    400,
                    {"content-type": "text/html; charset=utf-8"},
                    self._web_auth_login_page(
                        product=product,
                        return_to=self.web_auth_public_base_url or "/",
                        error="missing_username_or_password",
                    ),
                )
            return_to = self._normalize_return_to(
                str(form.get("return_to", [query.get("return_to", [self.web_auth_public_base_url or "/"])[0]])[0] or "")
            )
            login_product = str(
                form.get("product", [query.get("product", [product])[0]])[0] or query.get("product", [product])[0] or product
            )
            try:
                result = bridge.start_login(
                    product=login_product,
                    username=username,
                    password=password,
                    return_to=return_to,
                )
            except ValueError as exc:
                error = str(exc) or "invalid_credentials"
                return (
                    401,
                    {"content-type": "text/html; charset=utf-8"},
                    self._web_auth_login_page(product=login_product, return_to=return_to, error=error),
                )
            location = self._append_query_params(
                return_to,
                {
                    "code": str(result.get("code", "")),
                    "product": str(result.get("product", login_product)),
                },
            )
            return 302, {"location": location, "content-length": "0"}, b""

        if method == "POST" and parsed.path == "/api/web-auth/exchange":
            try:
                body_json = json.loads(body_raw) if body_raw else {}
            except json.JSONDecodeError:
                return (
                    400,
                    {"content-type": "application/json; charset=utf-8"},
                    json.dumps({"ok": False, "error": "invalid json"}).encode("utf-8"),
                )
            shared_secret = str(body_json.get("shared_secret") or "").strip()
            configured_secret = self.web_auth_shared_secret or str(getattr(bridge, "shared_secret", "") or "").strip()
            if not configured_secret or not secrets.compare_digest(shared_secret, configured_secret):
                return (
                    403,
                    {"content-type": "application/json; charset=utf-8"},
                    json.dumps({"ok": False, "error": "invalid_shared_secret"}).encode("utf-8"),
                )
            try:
                payload = bridge.exchange_code(
                    code=str(body_json.get("code") or ""),
                    product=str(body_json.get("product") or product),
                    shared_secret=shared_secret,
                )
            except ValueError as exc:
                return (
                    400,
                    {"content-type": "application/json; charset=utf-8"},
                    json.dumps({"ok": False, "error": str(exc)}).encode("utf-8"),
                )
            return (
                200,
                {"content-type": "application/json; charset=utf-8"},
                json.dumps(payload).encode("utf-8"),
            )

        return None

    @staticmethod
    def _is_public_probe_path(path: str) -> bool:
        return path in {"/health", "/ready", "/api/health", "/api/ready"}

    def _health_snapshot(self) -> Dict[str, object]:
        gateway_health = {"ok": True, "status": "ok"}
        snapshot_fn = getattr(self.gateway, "health_snapshot", None)
        if callable(snapshot_fn):
            candidate = snapshot_fn()
            if isinstance(candidate, dict):
                gateway_health = dict(candidate)
        return {
            "ok": True,
            "status": "ok",
            "service": "admin",
            "admin_uptime_seconds": int(max(0.0, time.time() - self.started_at)),
            "gateway": gateway_health,
        }

    def _readiness_snapshot(self) -> Dict[str, object]:
        gateway_ready = {"ready": True, "status": "ready"}
        snapshot_fn = getattr(self.gateway, "readiness_snapshot", None)
        if callable(snapshot_fn):
            candidate = snapshot_fn()
            if isinstance(candidate, dict):
                gateway_ready = dict(candidate)
        ready = bool(gateway_ready.get("ready", gateway_ready.get("ok", False)))
        return {
            "ready": ready,
            "status": "ready" if ready else "not_ready",
            "service": "admin",
            "admin_uptime_seconds": int(max(0.0, time.time() - self.started_at)),
            "gateway": gateway_ready,
        }

    @staticmethod
    def _coerce_db_value(value: object) -> object:
        if isinstance(value, bytes):
            return value.hex()
        if isinstance(value, str):
            stripped = value.strip()
            if stripped and stripped[0] in "[{":
                with contextlib.suppress(Exception):
                    return json.loads(value)
        return value

    def _db_snapshot(self, rows_per_table: int = 25) -> Dict[str, object]:
        raw_path = str(self.db_path or "").strip()
        if not raw_path:
            return {
                "path": "",
                "exists": False,
                "table_count": 0,
                "nonempty_table_count": 0,
                "total_rows": 0,
                "tables": {},
            }
        path = Path(raw_path).resolve()
        return self._db_snapshot_for_path(path, rows_per_table=max(1, rows_per_table))

    def _db_snapshot_for_path(self, path: Path, rows_per_table: int = 25) -> Dict[str, object]:
        if not path.exists() or path.is_dir():
            return {
                "path": str(path),
                "exists": False,
                "table_count": 0,
                "nonempty_table_count": 0,
                "total_rows": 0,
                "tables": {},
            }

        conn = sqlite3.connect(str(path))
        conn.row_factory = sqlite3.Row
        try:
            cur = conn.cursor()
            table_rows = cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
            tables: Dict[str, object] = {}
            total_rows = 0
            nonempty_table_count = 0
            for row in table_rows:
                table = str(row["name"])
                count = cur.execute(f"SELECT COUNT(*) AS count FROM [{table}]").fetchone()["count"]
                total_rows += int(count)
                if int(count) > 0:
                    nonempty_table_count += 1
                preview_rows = cur.execute(f"SELECT * FROM [{table}] LIMIT ?", (rows_per_table,)).fetchall()
                tables[table] = {
                    "count": int(count),
                    "rows": [
                        {
                            key: self._coerce_db_value(value)
                            for key, value in dict(preview).items()
                        }
                        for preview in preview_rows
                    ],
                }
            return {
                "path": str(path),
                "exists": True,
                "table_count": len(tables),
                "nonempty_table_count": nonempty_table_count,
                "total_rows": total_rows,
                "tables": tables,
            }
        finally:
            conn.close()

    def _db_snapshots(self, rows_per_table: int = 25) -> Dict[str, Dict[str, object]]:
        snapshots: Dict[str, Dict[str, object]] = {}
        for product, path in self.db_paths.items():
            snapshots[product] = self._db_snapshot_for_path(
                Path(path).resolve(),
                rows_per_table=max(1, rows_per_table),
            )
        return snapshots

    def _resolve_db_path(self, product: str = "") -> Path:
        product_key = str(product or "").strip()
        if product_key and product_key in self.db_paths:
            return Path(self.db_paths[product_key]).resolve()
        if self.default_db_product and self.default_db_product in self.db_paths:
            return Path(self.db_paths[self.default_db_product]).resolve()
        if str(self.db_path).strip():
            return Path(self.db_path).resolve()
        return (Path(__file__).resolve().parent / "__admin_db_missing__.sqlite").resolve()

    def _accounts_page(
        self, product: str, query: str = "", offset: int = 0, limit: int = 50
    ) -> Dict[str, object]:
        """Server-side, paginated, searchable view of the users table for one
        product. Replaces the old client-side slice of the snapshot so accounts
        beyond the preview limit are reachable and search covers the whole
        table."""
        product_key = str(product or "").strip() or self.default_db_product
        offset = max(0, int(offset))
        limit = max(1, min(200, int(limit)))
        legacy = LEGACY_SHARED_CD_KEYS.get(product_key.lower(), "")
        result: Dict[str, object] = {
            "ok": True,
            "product": product_key,
            "total": 0,
            "offset": offset,
            "limit": limit,
            "rows": [],
            "legacy_cd_key": legacy,
            "legacy_count": 0,
        }
        db_path = self._resolve_db_path(product)
        if not db_path.exists():
            result["ok"] = False
            result["error"] = "database not found"
            return result
        # Normalize the stored key in SQL so display/plain forms both match.
        norm = "REPLACE(REPLACE(UPPER(COALESCE(native_cd_key,'')),'-',''),' ','')"
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        try:
            where = ""
            params: list = []
            q = str(query or "").strip()
            if q:
                where = "WHERE username LIKE ? OR native_cd_key LIKE ?"
                params = [f"%{q}%", f"%{q}%"]
            result["total"] = int(
                conn.execute(
                    f"SELECT COUNT(*) AS c FROM users {where}", params
                ).fetchone()["c"]
            )
            rows = conn.execute(
                "SELECT username, created_at, "
                "COALESCE(native_cd_key,'') AS native_cd_key, "
                "COALESCE(native_login_key,'') AS native_login_key "
                f"FROM users {where} ORDER BY created_at LIMIT ? OFFSET ?",
                params + [limit, offset],
            ).fetchall()
            result["rows"] = [
                {
                    "username": r["username"],
                    "created_at": r["created_at"],
                    "native_cd_key": r["native_cd_key"],
                    "native_login_key": r["native_login_key"],
                }
                for r in rows
            ]
            if legacy:
                result["legacy_count"] = int(
                    conn.execute(
                        f"SELECT COUNT(*) AS c FROM users WHERE {norm}=?", [legacy]
                    ).fetchone()["c"]
                )
        except sqlite3.Error as exc:
            result["ok"] = False
            result["error"] = str(exc)
        finally:
            conn.close()
        return result

    @staticmethod
    def _product_runtime_info(gateway_snapshot: Dict[str, object]) -> Dict[str, Dict[str, object]]:
        runtimes: Dict[str, Dict[str, object]] = {}
        for product, info in dict(gateway_snapshot.get("products") or {}).items():
            key = str(product or "").strip()
            if not key:
                continue
            runtimes[key] = {
                "community_name": str(dict(info or {}).get("community_name") or "").strip(),
                "directory_root": str(dict(info or {}).get("directory_root") or "").strip(),
                "valid_versions_service": str(dict(info or {}).get("valid_versions_service") or "").strip(),
                "routing_port": int(dict(info or {}).get("routing_port") or 0),
                "routing_max_port": int(
                    dict(info or {}).get("routing_max_port")
                    or dict(info or {}).get("routing_port")
                    or 0
                ),
            }
        if runtimes:
            return runtimes

        product = str(gateway_snapshot.get("product") or "").strip()
        if product and product != "shared-edge":
            runtimes[product] = {
                "community_name": str(gateway_snapshot.get("community_name") or "").strip(),
                "directory_root": str(gateway_snapshot.get("directory_root") or "").strip(),
                "valid_versions_service": str(gateway_snapshot.get("valid_versions_service") or "").strip(),
                "routing_port": int(gateway_snapshot.get("routing_port") or 0),
                "routing_max_port": int(
                    gateway_snapshot.get("routing_max_port")
                    or gateway_snapshot.get("routing_port")
                    or 0
                ),
            }
        return runtimes

    @staticmethod
    def _classify_log_products(
        entry: Dict[str, object],
        gateway_snapshot: Dict[str, object],
    ) -> list[str]:
        message = str(entry.get("rendered") or entry.get("message") or "")
        if not message:
            return []
        lowered = message.lower()
        matches: list[str] = []
        runtimes = AdminDashboardServer._product_runtime_info(gateway_snapshot)
        ports = [
            int(match.group(1))
            for match in re.finditer(r"(?:routing-|port=)(\d{2,5})", lowered)
        ]
        for product, info in runtimes.items():
            tokens = {
                str(product).strip().lower(),
                str(info.get("community_name") or "").strip().lower(),
                str(info.get("directory_root") or "").strip().lower(),
                str(info.get("valid_versions_service") or "").strip().lower(),
                f"product={str(product).strip().lower()}",
                f"product profile: {str(product).strip().lower()}",
                f"-> product={str(product).strip().lower()}",
            }
            if any(token and token in lowered for token in tokens):
                matches.append(product)
                continue
            start_port = int(info.get("routing_port") or 0)
            end_port = int(info.get("routing_max_port") or start_port)
            if start_port > 0 and any(start_port <= port <= end_port for port in ports):
                matches.append(product)
        return sorted(set(matches))

    @staticmethod
    def _annotate_logs(
        logs: list[Dict[str, object]],
        gateway_snapshot: Dict[str, object],
    ) -> list[Dict[str, object]]:
        annotated: list[Dict[str, object]] = []
        for entry in logs:
            row = dict(entry)
            row["products"] = AdminDashboardServer._classify_log_products(row, gateway_snapshot)
            annotated.append(row)
        return annotated

    def snapshot(
        self,
        rows_per_table: int = 25,
        log_limit: int = 200,
        activity_limit: int = 150,
    ) -> Dict[str, object]:
        dbs = self._db_snapshots(rows_per_table=max(1, rows_per_table))
        gateway_snapshot = self.gateway.dashboard_snapshot(activity_limit=max(1, activity_limit))
        default_db = (
            dbs.get(self.default_db_product)
            or next(iter(dbs.values()), self._db_snapshot(rows_per_table=max(1, rows_per_table)))
        )
        return {
            "generated_at": time.time(),
            "uptime_seconds": int(time.time() - self.started_at),
            "gateway": gateway_snapshot,
            "repo": self.repo_monitor.snapshot(),
            "db": default_db,
            "dbs": dbs,
            "db_default_product": self.default_db_product,
            "factories": self._factories_snapshot(),
            "logs": self._annotate_logs(
                self.log_handler.snapshot(limit=max(1, log_limit)),
                gateway_snapshot,
            ),
        }

    def _factories_snapshot(self) -> list[Dict[str, object]]:
        """Enumerate factory/region entries across product databases so the
        admin 'Gateways & Factories' view can show real regions.

        Two sources are merged: TitanFactoryServer directory entities (which
        carry the multi-region publish address via public_host/public_port) and
        runtime rows in the factories table (region + running/max)."""
        out: list[Dict[str, object]] = []
        for product, path in self.db_paths.items():
            db_path = Path(path).resolve()
            if not db_path.exists() or db_path.is_dir():
                continue
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            try:
                tables = {
                    str(r["name"])
                    for r in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                if "directory_entities" in tables:
                    for row in conn.execute(
                        "SELECT entity_name, entity_type, payload FROM directory_entities"
                    ):
                        name = str(row["entity_name"] or "")
                        etype = str(row["entity_type"] or "")
                        is_factory = (
                            etype == "factory"
                            or name == "TitanFactoryServer"
                            or name.startswith("Factory:")
                        )
                        if not is_factory:
                            continue
                        try:
                            payload = json.loads(row["payload"] or "{}")
                        except (ValueError, TypeError):
                            payload = {}
                        if not isinstance(payload, dict):
                            payload = {}
                        public_host = str(payload.get("public_host") or "").strip()
                        public_port = payload.get("public_port")
                        out.append(
                            {
                                "product": product,
                                "source": "directory",
                                "description": str(
                                    payload.get("Description")
                                    or name.split(":", 1)[-1]
                                    or "factory"
                                ),
                                "public_host": public_host,
                                "public_port": public_port,
                                "host": str(payload.get("host") or ""),
                                "port": payload.get("port"),
                                # A dedicated public address means this entry
                                # points clients at a remote region's gateway.
                                "remote": bool(public_host and public_port),
                            }
                        )
                if "factories" in tables:
                    for row in conn.execute(
                        "SELECT factory_id, host, region, max_processes, running, total_started FROM factories"
                    ):
                        out.append(
                            {
                                "product": product,
                                "source": "registered",
                                "description": str(row["region"] or row["factory_id"] or "factory"),
                                "factory_id": str(row["factory_id"] or ""),
                                "region": str(row["region"] or ""),
                                "host": str(row["host"] or ""),
                                "running": int(row["running"] or 0),
                                "max_processes": int(row["max_processes"] or 0),
                                "total_started": int(row["total_started"] or 0),
                                "remote": True,
                            }
                        )
            except sqlite3.Error as exc:
                LOGGER.debug("Factory snapshot failed for %s: %s", product, exc)
            finally:
                conn.close()
        return out

    @staticmethod
    def _http_response(
        body: bytes,
        content_type: str,
        status: str = "200 OK",
        extra_headers: Optional[list[str]] = None,
    ) -> bytes:
        headers = [
            f"HTTP/1.1 {status}",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(body)}",
            "Cache-Control: no-store",
            "Connection: close",
        ]
        if extra_headers:
            headers.extend(extra_headers)
        headers.extend(["", ""])
        return "\r\n".join(headers).encode("ascii") + body

    @staticmethod
    def _http_event_stream_headers() -> bytes:
        headers = [
            "HTTP/1.1 200 OK",
            "Content-Type: text/event-stream; charset=utf-8",
            "Cache-Control: no-store",
            "Connection: keep-alive",
            "X-Accel-Buffering: no",
            "",
            "",
        ]
        return "\r\n".join(headers).encode("ascii")

    @staticmethod
    def _sse_frame(
        event_name: str,
        payload: Dict[str, object],
        *,
        event_id: str = "",
    ) -> bytes:
        lines: list[str] = []
        if event_id:
            lines.append(f"id: {event_id}")
        lines.append(f"event: {event_name}")
        body = json.dumps(payload, sort_keys=True)
        for line in body.splitlines() or ["{}"]:
            lines.append(f"data: {line}")
        lines.extend(["", ""])
        return "\n".join(lines).encode("utf-8")

    def _html(self, embedded_token: str = "", identity: str = "") -> str:
        return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WON Admin</title>
  <link rel="icon" href="data:,">
  <style>
    :root {
      --bg-app:#0b0f14;--bg-shell:#101720;--bg-panel:#151d27;--bg-panel-2:#1b2430;--bg-panel-3:#223044;
      --line:#263241;--line-strong:#314255;--line-soft:rgba(255,255,255,.04);
      --text-hi:#f3f7fb;--text-mid:#9fb0c3;--text-low:#64748b;
      --accent:#4cc9f0;--accent-strong:#38bdf8;--accent-glow:rgba(76,201,240,.18);
      --success:#22c55e;--success-soft:rgba(34,197,94,.14);
      --warning:#f59e0b;--warning-soft:rgba(245,158,11,.14);
      --danger:#ef4444;--danger-soft:rgba(239,68,68,.14);
      --hw:#f2a154;--hw-soft:rgba(242,161,84,.14);
      --cata:#2dd4bf;--cata-soft:rgba(45,212,191,.14);
      --shadow-lg:0 18px 40px rgba(0,0,0,.32);
    }
    *{box-sizing:border-box;margin:0;padding:0;}
    body{
      font-family:"Segoe UI Variable Display","Aptos","Trebuchet MS",sans-serif;
      background:
        radial-gradient(circle at top left, rgba(76,201,240,.08), transparent 26%),
        radial-gradient(circle at top right, rgba(56,189,248,.05), transparent 24%),
        linear-gradient(180deg, #0b0f14 0%, #0e131b 100%);
      color:var(--text-hi);display:flex;height:100vh;overflow:hidden;
    }
    .sidebar-scrim{
      display:none;position:fixed;inset:0;background:rgba(7,10,15,.68);backdrop-filter:blur(3px);z-index:20;
    }
    .sidebar{
      width:260px;background:linear-gradient(180deg, rgba(16,23,32,.98) 0%, rgba(13,18,26,.98) 100%);
      border-right:1px solid var(--line);display:flex;flex-direction:column;flex-shrink:0;position:relative;z-index:30;
      box-shadow:var(--shadow-lg);
    }
    .brand-block{padding:18px 18px 16px;border-bottom:1px solid var(--line);}
    .brand-eyebrow{font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:var(--text-low);margin-bottom:8px;}
    .brand{font-size:24px;font-weight:800;letter-spacing:-.04em;color:var(--text-hi);}
    .brand span{color:var(--accent);font-weight:900;}
    .sidebar nav{flex:1;padding:12px 10px 10px;overflow-y:auto;}
    .nav-item{
      display:flex;align-items:center;gap:12px;padding:11px 13px;border-radius:12px;cursor:pointer;font-size:14px;color:var(--text-mid);
      transition:all .16s ease;border:1px solid transparent;background:none;width:100%;text-align:left;
    }
    .nav-item:hover{background:rgba(255,255,255,.04);border-color:var(--line);color:var(--text-hi);}
    .nav-item.active{
      background:linear-gradient(180deg, rgba(34,48,68,.88) 0%, rgba(27,36,48,.92) 100%);
      color:var(--text-hi);font-weight:700;border-color:var(--line-strong);box-shadow:0 0 0 1px rgba(255,255,255,.02) inset;
    }
    .nav-item svg{width:16px;height:16px;flex-shrink:0;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;}
    .nav-badge{
      margin-left:auto;background:rgba(255,255,255,.06);color:var(--text-mid);font-size:11px;padding:2px 7px;border-radius:999px;min-width:20px;text-align:center;
    }
    .nav-item.active .nav-badge{background:var(--accent);color:#06202b;}
    .sidebar-footer{padding:14px 18px;border-top:1px solid var(--line);font-size:11px;color:var(--text-low);line-height:1.5;}
    .sidebar-footer .status-dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px;}
    .sidebar-footer .status-dot.ok{background:var(--success);box-shadow:0 0 14px rgba(34,197,94,.5);}
    .sidebar-footer .status-dot.err{background:var(--danger);box-shadow:0 0 14px rgba(239,68,68,.45);}
    .main-wrap{flex:1;display:flex;flex-direction:column;overflow:hidden;}
    .topbar{
      padding:16px 24px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;
      background:rgba(11,15,20,.82);backdrop-filter:blur(16px);flex-shrink:0;gap:16px;
    }
    .topbar-main{display:flex;align-items:center;gap:14px;min-width:0;}
    .topbar-label{font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:var(--text-low);margin-bottom:4px;}
    .topbar h1{font-size:30px;line-height:1;font-weight:800;letter-spacing:-.045em;}
    .topbar-meta{text-align:right;display:flex;align-items:center;gap:10px;}
    .meta-stack{display:flex;flex-direction:column;gap:4px;align-items:flex-end;}
    .topbar-status{font-size:12px;color:var(--text-mid);font-weight:600;}
    .topbar .meta{font-size:12px;color:var(--text-low);}
    .shell-toggle{
      display:none;align-items:center;justify-content:center;gap:3px;flex-direction:column;
      width:42px;height:42px;border-radius:12px;border:1px solid var(--line);background:rgba(255,255,255,.03);cursor:pointer;
    }
    .shell-toggle span{display:block;width:16px;height:2px;background:var(--text-hi);border-radius:999px;}
    #content{flex:1;overflow-y:auto;padding:24px 24px 40px;}
    .ops-summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:16px;}
    .summary-card{
      background:linear-gradient(180deg, rgba(27,36,48,.9) 0%, rgba(21,29,39,.94) 100%);
      border:1px solid var(--line);border-radius:18px;padding:18px 18px 16px;box-shadow:var(--shadow-lg);
    }
    .summary-card .label{font-size:11px;color:var(--text-low);margin-bottom:10px;text-transform:uppercase;letter-spacing:.16em;}
    .summary-card .value{font-size:38px;font-weight:800;line-height:1;letter-spacing:-.05em;}
    .summary-card .hint{margin-top:8px;font-size:12px;color:var(--text-mid);}
    .value-live{color:var(--accent);}
    .value-ok{color:var(--success);}
    .value-warn{color:var(--warning);}
    .card{
      background:linear-gradient(180deg, rgba(21,29,39,.94) 0%, rgba(18,25,34,.96) 100%);
      border:1px solid var(--line);border-radius:20px;padding:20px;margin-bottom:14px;box-shadow:var(--shadow-lg);
    }
    .card h2{font-size:18px;font-weight:800;letter-spacing:-.03em;margin-bottom:14px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;}
    .card h3{font-size:13px;font-weight:700;margin:14px 0 10px;color:var(--text-mid);letter-spacing:.05em;text-transform:uppercase;}
    .card-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:12px;}
    .utility-grid{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(320px,1fr);gap:14px;align-items:start;}
    .kv{display:grid;grid-template-columns:150px minmax(0,1fr);gap:6px 14px;font-size:13px;align-items:start;}
    .kv .k{color:var(--text-low);}
    .kv .v{color:var(--text-hi);word-break:normal;overflow-wrap:anywhere;}
    .badge{display:inline-block;padding:2px 8px;border-radius:99px;font-size:11px;font-weight:600;}
    .badge-join{background:var(--success-soft);color:var(--success);}
    .badge-leave{background:var(--danger-soft);color:var(--danger);}
    .badge-chat{background:var(--accent-glow);color:var(--accent);}
    .badge-default{background:rgba(255,255,255,.06);color:var(--text-mid);}
    .pill{display:inline-block;padding:4px 10px;border-radius:999px;font-size:11px;background:rgba(255,255,255,.06);color:var(--text-mid);margin-left:6px;border:1px solid transparent;}
    .pill-ok{background:var(--success-soft);color:var(--success);border-color:rgba(34,197,94,.2);}
    .pill-warn{background:var(--warning-soft);color:var(--warning);border-color:rgba(245,158,11,.2);}
    .pill-danger{background:var(--danger-soft);color:var(--danger);border-color:rgba(239,68,68,.2);}
    .eyebrow{display:inline-block;font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:var(--text-low);margin-bottom:10px;}
    .hero-card{padding:22px;}
    .hero-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:18px;flex-wrap:wrap;}
    .hero-copy{max-width:760px;color:var(--text-mid);font-size:14px;line-height:1.6;}
    .hero-meta{display:flex;gap:8px;flex-wrap:wrap;align-items:center;}
    .alert-pill{
      display:inline-flex;align-items:center;gap:8px;padding:7px 11px;border-radius:999px;border:1px solid var(--line);font-size:12px;font-weight:700;
      background:rgba(255,255,255,.03);color:var(--text-mid);
    }
    .alert-pill.warn{background:var(--warning-soft);border-color:rgba(245,158,11,.22);color:var(--warning);}
    .alert-pill.ok{background:var(--success-soft);border-color:rgba(34,197,94,.2);color:var(--success);}
    .alert-pill.live{background:var(--accent-glow);border-color:rgba(76,201,240,.24);color:var(--accent);}
    .overview-grid{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(320px,1fr);gap:14px;margin-bottom:14px;align-items:start;}
    .status-strip{display:grid;grid-template-columns:1fr;gap:12px;align-content:start;}
    .status-panel{
      padding:16px;border-radius:16px;background:rgba(255,255,255,.03);border:1px solid var(--line);min-width:0;
    }
    .status-panel h3{margin:0 0 12px;font-size:12px;}
    .status-panel .kv{grid-template-columns:112px minmax(0,1fr);}
    .runtime-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px;}
    .runtime-card{padding:18px;border-radius:18px;background:rgba(255,255,255,.03);border:1px solid var(--line);}
    .runtime-card .runtime-head{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;margin-bottom:14px;}
    .runtime-card .runtime-title{font-size:22px;font-weight:800;letter-spacing:-.03em;}
    .runtime-card .kv{grid-template-columns:124px minmax(0,1fr);}
    .metric-stack{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px 14px;}
    .metric-inline{padding:10px 0;border-top:1px solid var(--line-soft);}
    .metric-inline .k{display:block;font-size:11px;letter-spacing:.13em;text-transform:uppercase;color:var(--text-low);margin-bottom:6px;}
    .metric-inline .v{display:block;font-size:20px;font-weight:700;letter-spacing:-.03em;}
    .table-wrap{width:100%;overflow-x:auto;border:1px solid var(--line);border-radius:16px;background:rgba(255,255,255,.02);}
    table{width:100%;border-collapse:collapse;font-size:13px;}
    th{text-align:left;padding:11px 12px;border-bottom:1px solid var(--line);color:var(--text-low);font-weight:700;font-size:11px;text-transform:uppercase;letter-spacing:.14em;background:rgba(255,255,255,.02);}
    td{padding:11px 12px;border-bottom:1px solid var(--line-soft);vertical-align:top;word-break:break-word;color:var(--text-hi);}
    tr:hover td{background:rgba(255,255,255,.03);}
    .mono{font-family:Consolas,"Cascadia Mono","Courier New",monospace;font-size:12px;}
    .muted{color:var(--text-low);}
    pre{margin:8px 0 0;padding:14px;background:#0c131b;border:1px solid var(--line);border-radius:14px;overflow:auto;font-size:12px;line-height:1.5;max-height:65vh;white-space:pre-wrap;overflow-wrap:anywhere;color:var(--text-mid);font-family:Consolas,"Cascadia Mono","Courier New",monospace;}
    .log-error{color:var(--danger);}
    .log-warn{color:var(--warning);}
    .log-info{color:var(--text-mid);}
    .btn{display:inline-flex;align-items:center;gap:5px;padding:7px 12px;border-radius:10px;font-size:12px;font-weight:700;cursor:pointer;border:1px solid var(--line);background:rgba(255,255,255,.04);color:var(--text-hi);transition:all .15s;}
    .btn:hover{background:rgba(255,255,255,.08);border-color:var(--line-strong);}
    .btn-danger{border-color:var(--danger);color:var(--danger);background:transparent;}
    .btn-danger:hover{background:var(--danger);color:#fff;}
    .btn-accent{border-color:var(--accent-strong);color:#03131b;background:linear-gradient(180deg, var(--accent) 0%, var(--accent-strong) 100%);}
    .btn-accent:hover{background:linear-gradient(180deg, #68d8f6 0%, #4cc9f0 100%);}
    .btn-sm{padding:3px 8px;font-size:11px;}
    .action-bar{display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap;}
    .action-bar input[type=text]{flex:1;min-width:200px;padding:8px 11px;border-radius:10px;border:1px solid var(--line);background:#0d141d;color:var(--text-hi);font-size:13px;outline:none;}
    .action-bar input[type=text]:focus{border-color:var(--accent);}
    .action-bar select{padding:8px 11px;border-radius:10px;border:1px solid var(--line);background:#0d141d;color:var(--text-hi);font-size:13px;outline:none;}
    details{margin-top:8px;}
    details summary{cursor:pointer;font-weight:700;font-size:13px;color:var(--text-mid);padding:9px 0;}
    details summary:hover{color:var(--text-hi);}
    details[open] summary{margin-bottom:8px;}
    .hw-strong{font-weight:700;color:var(--accent);}
    .db-tabs{display:flex;gap:4px;flex-wrap:wrap;margin-bottom:12px;}
    .db-tab{padding:6px 10px;border-radius:10px;font-size:12px;cursor:pointer;background:#0d141d;color:var(--text-low);border:1px solid transparent;}
    .db-tab:hover{color:var(--text-hi);}
    .db-tab.active{background:rgba(255,255,255,.05);color:var(--text-hi);border-color:var(--line);}
    .health-badge{display:inline-flex;align-items:center;gap:7px;padding:6px 10px;border-radius:999px;font-size:11px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;border:1px solid transparent;}
    .health-ok{background:var(--success-soft);color:var(--success);border-color:rgba(34,197,94,.22);}
    .health-watch{background:var(--accent-glow);color:var(--accent);border-color:rgba(76,201,240,.2);}
    .health-warn{background:var(--warning-soft);color:var(--warning);border-color:rgba(245,158,11,.2);}
    .health-badge .dot{display:inline-block;width:7px;height:7px;border-radius:999px;background:currentColor;box-shadow:0 0 14px currentColor;}
    .section-note{margin:0 0 14px;color:var(--text-mid);font-size:14px;line-height:1.6;}
    .row-stack{display:flex;flex-direction:column;gap:4px;}
    .detail-panel{padding:14px 16px;border-radius:16px;background:rgba(255,255,255,.03);border:1px solid var(--line);margin-top:10px;}
    .detail-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;}
    .room-shell{padding:18px;border-radius:18px;background:rgba(255,255,255,.03);border:1px solid var(--line);margin-top:14px;}
    #modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:100;align-items:center;justify-content:center;}
    #modal-overlay.show{display:flex;}
    .modal-box{background:var(--bg-panel);border:1px solid var(--line);border-radius:18px;padding:20px;width:420px;max-width:90vw;}
    .modal-box h3{font-size:15px;margin-bottom:12px;}
    .modal-box p{font-size:13px;color:var(--text-mid);margin-bottom:16px;line-height:1.5;}
    .modal-box .modal-actions{display:flex;gap:8px;justify-content:flex-end;}
    .modal-box input[type=text],.modal-box input[type=password]{width:100%;padding:8px 10px;border-radius:10px;border:1px solid var(--line);background:#0d141d;color:var(--text-hi);font-size:13px;margin-bottom:12px;outline:none;}
    .modal-box input:focus{border-color:var(--accent);}
    #toast-container{position:fixed;bottom:16px;right:16px;z-index:200;display:flex;flex-direction:column;gap:8px;}
    .toast{padding:10px 16px;border-radius:12px;font-size:13px;font-weight:700;animation:toastin .25s ease;min-width:200px;}
    .toast-success{background:#14532d;color:var(--success);border:1px solid #166534;}
    .toast-error{background:#450a0a;color:var(--danger);border:1px solid #7f1d1d;}
    @keyframes toastin{from{opacity:0;transform:translateY(10px);}to{opacity:1;transform:translateY(0);}}
    @media(max-width:1180px){.overview-grid,.utility-grid{grid-template-columns:1fr;}}
    @media(max-width:920px){
      .shell-toggle{display:inline-flex;}
      .sidebar{
        position:fixed;left:0;top:0;bottom:0;transform:translateX(-105%);transition:transform .2s ease;
        width:min(86vw,320px);
      }
      body.nav-open .sidebar{transform:translateX(0);}
      body.nav-open .sidebar-scrim{display:block;}
      .topbar{padding:14px 16px;}
      .topbar h1{font-size:24px;}
      #content{padding:16px 16px 28px;}
    }
    @media(max-width:760px){
      .card-grid,.runtime-grid,.ops-summary-grid,.status-strip,.metric-stack{grid-template-columns:1fr;}
      .topbar-meta{display:none;}
      .kv{grid-template-columns:1fr;}
      .summary-card .value{font-size:32px;}
    }
    /* product scope switcher (topbar) */
    .scope-switcher{display:flex;background:var(--bg-panel);border:1px solid var(--line);border-radius:11px;padding:3px;gap:2px;}
    .scope-switcher button{background:transparent;border:0;color:var(--text-mid);font:inherit;font-size:12.5px;font-weight:600;
      padding:6px 13px;border-radius:8px;cursor:pointer;display:flex;align-items:center;gap:7px;white-space:nowrap;}
    .scope-switcher button:hover{color:var(--text-hi);}
    .scope-switcher button.on{background:var(--bg-panel-3);color:var(--text-hi);}
    .scope-switcher button[data-scope="all"].on{background:var(--accent-glow);color:var(--accent);}
    .scope-switcher .sw{width:8px;height:8px;border-radius:2px;flex:none;}
    /* sub-tabs (Live / Activity & Logs) */
    .subtabs{display:flex;gap:4px;background:var(--bg-panel);border:1px solid var(--line);border-radius:10px;padding:3px;flex-wrap:wrap;}
    .subtabs button{background:transparent;border:0;color:var(--text-mid);font:inherit;font-size:12.5px;font-weight:600;padding:6px 13px;border-radius:7px;cursor:pointer;}
    .subtabs button:hover{color:var(--text-hi);}
    .subtabs button.on{background:var(--bg-panel-3);color:var(--text-hi);}
    .subtabs button .mono{font-family:ui-monospace,Menlo,Consolas,monospace;opacity:.7;margin-left:5px;}
    .sectionbar{display:flex;align-items:center;gap:14px;margin-bottom:16px;flex-wrap:wrap;}
    .sectionbar .spacer{flex:1;}
    .pill-hw{background:var(--hw-soft);color:var(--hw);border-color:rgba(242,161,84,.3);}
    .pill-cata{background:var(--cata-soft);color:var(--cata);border-color:rgba(45,212,191,.3);}
    .prod-swatch{display:inline-block;width:7px;height:7px;border-radius:2px;margin-right:5px;vertical-align:middle;}
    .region-map{display:flex;gap:14px;flex-wrap:wrap;}
    .region{flex:1;min-width:200px;border:1px solid var(--line);border-radius:12px;padding:15px;background:var(--bg-panel-2);}
    .region .rg-name{font-weight:700;font-size:15px;display:flex;align-items:center;gap:8px;}
    .region .rg-meta{margin-top:10px;font-size:12px;color:var(--text-low);line-height:1.7;}
  </style>
</head>
<body>
  <div class="sidebar-scrim" id="sidebar-scrim"></div>
  <aside class="sidebar">
    <div class="brand-block">
      <div class="brand-eyebrow">WON Relay Console</div>
      <div class="brand"><span>WON</span> Admin</div>
    </div>
    <nav id="nav"></nav>
    <div class="sidebar-footer" id="sidebar-footer">Loading...</div>
  </aside>
  <div class="main-wrap">
    <header class="topbar">
      <div class="topbar-main">
        <button class="shell-toggle" id="shell-toggle" aria-label="Open navigation"><span></span><span></span><span></span></button>
        <div>
          <div class="topbar-label">Operations Console</div>
          <h1 id="page-title">Overview</h1>
        </div>
      </div>
      <div class="topbar-meta">
        <div class="scope-switcher" id="scope-switcher"></div>
        <div class="meta-stack">
          <div class="topbar-status" id="topbar-status">Loading status...</div>
          <div class="meta" id="topbar-meta">Loading...</div>
        </div>
      </div>
    </header>
    <main id="content"></main>
  </div>
  <div id="modal-overlay"><div class="modal-box" id="modal-box"></div></div>
  <div id="toast-container"></div>
  <script>
    const content = document.getElementById("content");
    const nav = document.getElementById("nav");
    const pageTitle = document.getElementById("page-title");
    const topbarMeta = document.getElementById("topbar-meta");
    const topbarStatus = document.getElementById("topbar-status");
    const sidebarFooter = document.getElementById("sidebar-footer");
    const sidebarScrim = document.getElementById("sidebar-scrim");
    const shellToggle = document.getElementById("shell-toggle");
    const modalOverlay = document.getElementById("modal-overlay");
    const modalBox = document.getElementById("modal-box");
    const toastContainer = document.getElementById("toast-container");
    const adminToken = __ADMIN_TOKEN__;
    const adminIdentity = __ADMIN_IDENTITY__;
    let activePage = "overview";
    let pauseRefresh = false;
    let pauseRefreshUntil = 0;
    let pointerInteractionActive = false;
    let lastSnapshot = null;
    let activeDbProduct = "";
    let activeDbTable = "";
    let activeLogProduct = "all";
    let productScope = "all";          // global product filter: all | homeworld | cataclysm
    let liveTab = "players";           // Live page sub-tab
    let activityTab = "activity";      // Activity & Logs page sub-tab
    let accountsQuery = "";            // Accounts page search text
    const scopeSwitcher = document.getElementById("scope-switcher");
    let uiState = {
      pageId: "overview",
      contentScrollTop: 0,
      broadcastMsg: "",
      broadcastRoom: "",
      logScrollTop: 0,
      logStickToBottom: true,
    };

    const pages = [
      {id:"overview",label:"Overview",icon:'<path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/>'},
      {id:"live",label:"Live",icon:'<circle cx="12" cy="12" r="3"/><path d="M5 12a7 7 0 0 1 14 0M2 12a10 10 0 0 1 20 0"/>'},
      {id:"activity",label:"Activity & Logs",icon:'<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>'},
      {id:"accounts",label:"Accounts",icon:'<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>'},
      {id:"infra",label:"Infrastructure",icon:'<rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><path d="M7 7.5h.01M7 17h.01"/>'},
    ];

    function esc(v){return String(v??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}
    function pretty(v){return JSON.stringify(v,null,2);}
    function age(s){const n=Math.max(0,Math.floor(Number(s||0)));if(n<60)return n+"s";if(n<3600)return Math.floor(n/60)+"m "+n%60+"s";return Math.floor(n/3600)+"h "+Math.floor((n%3600)/60)+"m";}
    function stamp(ts){return ts?new Date(ts*1000).toLocaleTimeString():"";}
    function hwPlain(v){return String(v??"").replace(/&(.)/g,"$1");}
    function hwMarkup(v){const s=String(v??"");let o="";for(let i=0;i<s.length;i++){if(s[i]==="&"&&i+1<s.length){i++;o+=`<strong class="hw-strong">${esc(s[i])}</strong>`;}else{o+=esc(s[i]);}}return o;}
    function nameList(vs){return(vs||[]).map(v=>hwMarkup(v)).join(", ");}
    function kindBadge(k){const m={join:"badge-join",rejoin:"badge-join",leave:"badge-leave",chat:"badge-chat",broadcast:"badge-chat"};return `<span class="badge ${m[k]||"badge-default"}">${esc(k)}</span>`;}
    function shortHex(hex,maxChars=24){const s=String(hex||"").trim();if(!s)return "";return s.length>maxChars?`${s.slice(0,maxChars)}...`:s;}
    function slowPeerSummary(row){
      const slowEvents=Number((row&&row.slow_peer_data_events)||0);
      const slowestMs=Number((row&&row.slowest_peer_data_send_ms)||0);
      if(!slowEvents&&!slowestMs)return '<span class="muted">-</span>';
      return `${esc(slowEvents)} / ${esc(slowestMs)}ms`;
    }
    function slowPeerLast(row){
      const lastMs=Number((row&&row.last_slow_peer_data_send_ms)||0);
      const sinceRaw=row&&row.seconds_since_last_slow_peer_data;
      const since=sinceRaw==null?"":age(sinceRaw);
      if(!lastMs)return '<span class="muted">-</span>';
      return `${esc(lastMs)}ms${since?` <span class="muted">${esc(since)} ago</span>`:""}`;
    }
    function writeBufferSummary(row){
      const size=Number((row&&row.write_buffer_size)||0);
      const high=Number((row&&row.write_buffer_high_water)||0);
      if(!size)return '<span class="muted">-</span>';
      return `${esc(formatBytes(size))}${high?` <span class="muted">/ ${esc(formatBytes(high))} high</span>`:""}`;
    }
    function displayRoomName(snapshot,roomName,roomPort,isGameRoom=false){
      const gw=snapshot.gateway||{};
      const basePort=Number(gw.routing_port||0);
      const port=Number(roomPort||0);
      const name=String(roomName||"").trim();
      if((!name||name==="Homeworld Chat")&&port&&basePort&&port!==basePort){
        return isGameRoom?"Game Room":"Side Room";
      }
      return name||"Homeworld Chat";
    }
    function productHue(product){
      const p=String(product||"").toLowerCase();
      if(p==="homeworld")return "hw";
      if(p==="cataclysm")return "cata";
      return "";
    }
    function productBadge(product){
      const name=String(product||"").trim();
      if(!name||name==="shared-edge")return "";
      const hue=productHue(name);
      const cls=hue?`pill pill-${hue}`:"pill";
      const sw=hue?`<span class="prod-swatch" style="background:var(--${hue})"></span>`:"";
      const code=name==="homeworld"?"HW":name==="cataclysm"?"CA":name.slice(0,2).toUpperCase();
      return `<span class="${cls}" style="margin-left:0;margin-right:6px;">${sw}${esc(code)}</span>`;
    }
    // Global product scope helpers. When a scope is active, per-product page
    // sections collapse to the selected game instead of repeating both.
    function inScope(product){return productScope==="all"||String(product||"")===productScope;}
    function scopedKeys(metrics){
      const keys=(metrics&&metrics.keys)||[];
      return productScope==="all"?keys:keys.filter(k=>k===productScope);
    }
    function scopedOverall(metrics){
      if(productScope!=="all"&&metrics&&metrics.byProduct&&metrics.byProduct[productScope]){
        return metrics.byProduct[productScope];
      }
      return metrics?metrics.overall:{};
    }
    function productText(product){
      const name=String(product||"").trim();
      if(!name||name==="shared-edge")return "";
      return `[${name}] `;
    }
    function knownProductOrder(product){
      const name=String(product||"").trim().toLowerCase();
      if(name==="homeworld")return 0;
      if(name==="cataclysm")return 1;
      return 10;
    }
    function sortedProductKeys(values){
      return [...new Set((values||[]).map(v=>String(v||"").trim()).filter(Boolean))].sort((a,b)=>{
        const orderDiff=knownProductOrder(a)-knownProductOrder(b);
        return orderDiff||a.localeCompare(b);
      });
    }
    function defaultSnapshotProduct(snapshot){
      const gw=snapshot.gateway||{};
      const runtimeKeys=sortedProductKeys(Object.keys(gw.products||{}));
      if(runtimeKeys.length===1)return runtimeKeys[0];
      const product=String(gw.product||"").trim();
      if(product&&product!=="shared-edge")return product;
      return runtimeKeys[0]||"";
    }
    function snapshotProductKeys(snapshot){
      const gw=snapshot.gateway||{};
      const runtimeKeys=sortedProductKeys(Object.keys(gw.products||{}));
      if(runtimeKeys.length)return runtimeKeys;
      const fallback=defaultSnapshotProduct(snapshot);
      return fallback?[fallback]:[];
    }
    function snapshotProductInfo(snapshot,product){
      const gw=snapshot.gateway||{};
      if(gw.products&&gw.products[product])return gw.products[product]||{};
      return {
        community_name: gw.community_name||"",
        directory_root: gw.directory_root||"",
        routing_port: gw.routing_port||0,
        routing_max_port: gw.routing_max_port||gw.routing_port||0,
        backend_host: gw.backend_host||"",
        backend_port: gw.backend_port||0,
        version_str: gw.version_str||"",
        valid_versions: gw.valid_versions||[],
        valid_versions_service: gw.valid_versions_service||"",
      };
    }
    function rowProduct(snapshot,row){
      const product=String((row&&row.product)||"").trim();
      return product||defaultSnapshotProduct(snapshot)||"unknown";
    }
    function logProducts(entry){
      return sortedProductKeys((entry&&entry.products)||[]);
    }
    function logFilterState(snapshot,logs){
      const productKeys=sortedProductKeys((logs||[]).flatMap(entry=>logProducts(entry)));
      const hasUnclassified=(logs||[]).some(entry=>!logProducts(entry).length);
      const validKeys=["all",...productKeys];
      if(hasUnclassified)validKeys.push("unclassified");
      if(!validKeys.includes(activeLogProduct))activeLogProduct="all";
      return {productKeys,hasUnclassified};
    }
    function productMetrics(snapshot){
      const gw=snapshot.gateway||{};
      const rt=gw.routing_manager||{};
      const byProduct={};
      function freshBucket(product){
        return {
          product,
          info:snapshotProductInfo(snapshot,product),
          playersOnline:0,
          playersInGame:0,
          playersInLobby:0,
          reconnecting:0,
          activeRooms:0,
          publishedRooms:0,
          gameRooms:0,
          liveGames:0,
          liveGameObjects:0,
          uniqueIps:0,
          totalIpsSeen:0,
          peerMsgs:0,
          peerBytes:0,
          gameObjectBytes:0,
          joins:0,
          leaves:0,
          chats:0,
          broadcasts:0,
          gamePorts:new Set(),
          _ipSet:new Set(),
        };
      }
      function ensureBucket(product){
        const key=String(product||defaultSnapshotProduct(snapshot)||"unknown").trim();
        if(!byProduct[key])byProduct[key]=freshBucket(key);
        return byProduct[key];
      }
      const overall=freshBucket("all");
      overall.info={};
      const roomStateByKey=new Map();
      snapshotProductKeys(snapshot).forEach(product=>ensureBucket(product));

      for(const room of rt.servers||[]){
        const product=rowProduct(snapshot,room);
        const bucket=ensureBucket(product);
        const port=Number(room.listen_port||0);
        const isGameRoom=!!room.is_game_room||Number(room.active_game_count||0)>0;
        const games=Array.isArray(room.games)?room.games:[];
        roomStateByKey.set(`${product}:${port}`,isGameRoom);
        bucket.activeRooms+=1;
        overall.activeRooms+=1;
        if(room.published){
          bucket.publishedRooms+=1;
          overall.publishedRooms+=1;
        }
        if(isGameRoom){
          bucket.gameRooms+=1;
          bucket.liveGames+=1;
          overall.gameRooms+=1;
          overall.liveGames+=1;
          if(port){
            bucket.gamePorts.add(port);
            overall.gamePorts.add(port);
          }
        }
        bucket.liveGameObjects+=games.length;
        overall.liveGameObjects+=games.length;
        for(const game of games){
          const dataLen=Number(game.data_len||0);
          bucket.gameObjectBytes+=dataLen;
          overall.gameObjectBytes+=dataLen;
        }
      }

      for(const room of rt.rooms||[]){
        const product=rowProduct(snapshot,room);
        const bucket=ensureBucket(product);
        const port=Number(room.listen_port||0);
        const reconnectCount=Number(
          room.pending_reconnect_count!=null
            ? room.pending_reconnect_count
            : Array.isArray(room.pending_reconnects)
              ? room.pending_reconnects.length
              : 0
        );
        bucket.reconnecting+=reconnectCount;
        overall.reconnecting+=reconnectCount;
        if(!roomStateByKey.has(`${product}:${port}`)){
          roomStateByKey.set(
            `${product}:${port}`,
            !!room.is_game_room||Number(room.active_game_count||0)>0
          );
        }
      }

      for(const player of rt.players||[]){
        const product=rowProduct(snapshot,player);
        const bucket=ensureBucket(product);
        const port=Number(player.room_port||0);
        const isGameRoom=!!roomStateByKey.get(`${product}:${port}`);
        const peerMsgs=Number(player.peer_data_messages||0);
        const peerBytes=Number(player.peer_data_bytes||0);
        const clientIp=String(player.client_ip||"").trim();
        bucket.playersOnline+=1;
        overall.playersOnline+=1;
        bucket.peerMsgs+=peerMsgs;
        overall.peerMsgs+=peerMsgs;
        bucket.peerBytes+=peerBytes;
        overall.peerBytes+=peerBytes;
        if(clientIp){
          bucket._ipSet.add(clientIp);
          overall._ipSet.add(clientIp);
        }
        if(isGameRoom){
          bucket.playersInGame+=1;
          overall.playersInGame+=1;
        }else{
          bucket.playersInLobby+=1;
          overall.playersInLobby+=1;
        }
      }

      for(const entry of gw.activity||[]){
        const bucket=ensureBucket(rowProduct(snapshot,entry));
        const overallKind=String(entry.kind||"");
        if(overallKind==="join"||overallKind==="rejoin"){
          bucket.joins+=1;
          overall.joins+=1;
        }else if(overallKind==="leave"){
          bucket.leaves+=1;
          overall.leaves+=1;
        }else if(overallKind==="chat"){
          bucket.chats+=1;
          overall.chats+=1;
        }else if(overallKind==="broadcast"){
          bucket.broadcasts+=1;
          overall.broadcasts+=1;
        }
      }

      for(const row of gw.ip_metrics||[]){
        overall.totalIpsSeen+=1;
        const products=sortedProductKeys(row.products||[]);
        const targets=products.length?products:[defaultSnapshotProduct(snapshot)].filter(Boolean);
        for(const product of targets){
          ensureBucket(product).totalIpsSeen+=1;
        }
      }

      const keys=sortedProductKeys(Object.keys(byProduct));
      for(const product of keys){
        const bucket=byProduct[product];
        bucket.uniqueIps=bucket._ipSet.size;
        delete bucket._ipSet;
      }
      overall.uniqueIps=overall._ipSet.size;
      delete overall._ipSet;
      return {keys,byProduct,overall,roomStateByKey};
    }
    function routingGameStats(snapshot){
      const metrics=productMetrics(snapshot);
      return {
        gamePorts:metrics.overall.gamePorts,
        inGamePlayers:metrics.overall.playersInGame,
        lobbyPlayers:metrics.overall.playersInLobby,
        gameRooms:metrics.overall.gameRooms,
        liveGames:metrics.overall.liveGames,
        liveGameObjects:metrics.overall.liveGameObjects,
        reconnecting:metrics.overall.reconnecting,
        peerMsgs:metrics.overall.peerMsgs,
        peerBytes:metrics.overall.peerBytes,
        gameObjectBytes:metrics.overall.gameObjectBytes,
      };
    }
    function activityDetail(snapshot,event){
      const text=String(event.text||"").trim();
      if(text)return text;
      const details=event.details||{};
      if(details.left_for_game)return "left for a game";
      const port=Number(event.room_port||0);
      const basePort=Number(((snapshot.gateway||{}).routing_port)||0);
      if((event.kind==="join"||event.kind==="rejoin")&&port&&basePort&&port!==basePort){
        return event.kind==="rejoin"?"rejoined game room":"entered game room";
      }
      if(details.reason)return String(details.reason).replace(/_/g," ");
      if(details.description)return String(details.description);
      return "";
    }
    function pauseAutoRefresh(ms=6000){pauseRefreshUntil=Math.max(pauseRefreshUntil,Date.now()+ms);}
    function panelContainsNode(node){
      if(!node)return false;
      const el=node.nodeType===Node.ELEMENT_NODE?node:node.parentElement;
      return !!(el&&(content.contains(el)||modalOverlay.contains(el)));
    }
    function hasActiveEditor(){
      const el=document.activeElement;
      if(!el)return false;
      if(!(content.contains(el)||modalOverlay.contains(el)))return false;
      return !!(el.matches("input, textarea, select")||el.isContentEditable);
    }
    function hasActiveSelection(){
      const sel=window.getSelection?window.getSelection():null;
      if(!sel||sel.isCollapsed||!sel.rangeCount)return false;
      for(let i=0;i<sel.rangeCount;i++){
        if(panelContainsNode(sel.getRangeAt(i).commonAncestorContainer))return true;
      }
      return false;
    }
    function captureUiState(){
      uiState.pageId=activePage;
      uiState.contentScrollTop=content.scrollTop;
      const msg=document.getElementById("broadcast-msg");
      if(msg)uiState.broadcastMsg=msg.value||"";
      const room=document.getElementById("broadcast-room");
      if(room)uiState.broadcastRoom=room.value||"";
      const pre=document.getElementById("log-pre");
      if(pre){
        uiState.logScrollTop=pre.scrollTop;
        uiState.logStickToBottom=(pre.scrollHeight-pre.scrollTop-pre.clientHeight)<=24;
      }
    }
    function restoreUiState(){
      const onLogs=(activePage==="activity"&&activityTab==="logs");
      if(uiState.pageId===activePage&&!onLogs){
        content.scrollTop=uiState.contentScrollTop||0;
      }
      const msg=document.getElementById("broadcast-msg");
      if(msg)msg.value=uiState.broadcastMsg||"";
      const room=document.getElementById("broadcast-room");
      if(room&&typeof uiState.broadcastRoom!=="undefined")room.value=uiState.broadcastRoom||"";
      const pre=document.getElementById("log-pre");
      if(pre){
        pre.scrollTop=uiState.logStickToBottom?pre.scrollHeight:(uiState.logScrollTop||0);
      }
    }
    function shouldDeferRefresh(){
      if(pauseRefresh)return true;
      if(Date.now()<pauseRefreshUntil)return true;
      if(pointerInteractionActive)return true;
      if(hasActiveEditor())return true;
      if(hasActiveSelection())return true;
      return false;
    }
    function setNavOpen(open){
      document.body.classList.toggle("nav-open", !!open);
    }
    shellToggle?.addEventListener("click",()=>setNavOpen(true));
    sidebarScrim?.addEventListener("click",()=>setNavOpen(false));
    window.addEventListener("resize",()=>{if(window.innerWidth>920)setNavOpen(false);});
    function formatBytes(value){
      const num=Math.max(0,Number(value||0));
      if(num<1024)return `${Math.round(num)} B`;
      if(num<1024*1024)return `${(num/1024).toFixed(num<10240?1:0)} KB`;
      return `${(num/(1024*1024)).toFixed(1)} MB`;
    }
    function repoSummary(repo){
      if(!repo||!repo.available)return '<span class="muted">Git metadata unavailable.</span>';
      let label="Up to date",color="var(--success)";
      if(repo.last_error){label="Check failed";color="var(--danger)";}
      else if(repo.status==="diverged"){label="Diverged";color="var(--danger)";}
      else if(repo.status==="ahead"){label="Ahead of upstream";color="var(--warning)";}
      else if(repo.status==="no_upstream"){label="No upstream";color="var(--warning)";}
      else if(repo.update_available){label="Update available";color="var(--warning)";}
      const dirty=repo.dirty?` <span class="pill">dirty</span>`:"";
      return `<span style="color:${color};font-weight:600;">${esc(label)}</span>${dirty}`;
    }
    function dashboardAlerts(snapshot, overallMetrics=null){
      const gw=snapshot.gateway||{};
      const rt=gw.routing_manager||{};
      const metrics=overallMetrics||productMetrics(snapshot).overall;
      const rooms=rt.servers||[];
      const slowCount=rooms.reduce((sum,room)=>sum+Number(room.slow_peer_data_events||0),0);
      const bufferCount=rooms.filter(room=>Number(room.largest_write_buffer_size||0)>0).length;
      const items=[];
      if(slowCount>0)items.push({tone:"warn",label:"Slow Delivery Alerts",value:`${slowCount} events`});
      if(bufferCount>0)items.push({tone:"warn",label:"Queued Writes",value:`${bufferCount} rooms`});
      if(Number(metrics.reconnecting||0)>0)items.push({tone:"warn",label:"Reconnect Holds",value:String(metrics.reconnecting)});
      if(gw.auth_keys_loaded===false)items.push({tone:"danger",label:"Auth Keys",value:"Missing"});
      if((snapshot.repo||{}).update_available)items.push({tone:"warn",label:"GitHub Update",value:"Available"});
      if(!items.length)items.push({tone:"ok",label:"Transport Health",value:"Stable"});
      return {slowCount,items};
    }
    function renderAlertPill(alert){
      const tone=String(alert&&alert.tone||"ok").toLowerCase();
      const mapped=tone==="danger"?"warn":tone;
      return `<span class="alert-pill ${esc(mapped)}"><strong>${esc(alert.label||"")}</strong><span>${esc(alert.value||"")}</span></span>`;
    }
    function summaryMetricCard(label,value,tone="live",hint=""){
      return `<div class="summary-card">
        <div class="label">${esc(label)}</div>
        <div class="value value-${esc(tone)}">${esc(value)}</div>
        ${hint?`<div class="hint">${esc(hint)}</div>`:""}
      </div>`;
    }
    function connectionHealth(row){
      const slowEvents=Number((row&&row.slow_peer_data_events)||0);
      const bufferSize=Number((row&&row.write_buffer_size)||0);
      const highWater=Number((row&&row.write_buffer_high_water)||0);
      if(highWater>0&&bufferSize>=highWater)return {label:"Backpressure",tone:"warn"};
      if(bufferSize>0)return {label:"Queued Writes",tone:"watch"};
      if(slowEvents>=3)return {label:"Transport Warning",tone:"warn"};
      if(slowEvents>0)return {label:"Watch",tone:"watch"};
      return {label:"Stable",tone:"ok"};
    }
    function healthBadge(health){
      const tone=String(health&&health.tone||"ok");
      return `<span class="health-badge health-${esc(tone)}"><span class="dot"></span>${esc(health&&health.label||"Stable")}</span>`;
    }
    function roomHealth(room){
      const slowEvents=Number((room&&room.slow_peer_data_events)||0);
      const bufferSize=Number((room&&room.largest_write_buffer_size)||0);
      if(bufferSize>0)return {label:"Queued Writes",tone:"warn"};
      return slowEvents>0?{label:"Transport Warning",tone:"warn"}:{label:"Stable",tone:"ok"};
    }

    function accountCount(snapshot){
      const dbs=snapshot.dbs||{};let n=0;
      for(const key of Object.keys(dbs)){
        if(!inScope(key))continue;
        const t=((dbs[key]||{}).tables||{}).users;
        if(t)n+=Number(t.count||0);
      }
      return n;
    }
    function renderNav(snapshot){
      const gw=snapshot.gateway||{};const rt=gw.routing_manager||{};const act=(gw.activity||[]);const logs=snapshot.logs||[];
      const feedCount=act.length+logs.length;
      const counts={live:rt.current_player_count||0,activity:feedCount,accounts:accountCount(snapshot)};
      nav.innerHTML=pages.map(p=>{
        const badge=counts[p.id]!=null?`<span class="nav-badge">${counts[p.id]}</span>`:"";
        return `<button class="nav-item${activePage===p.id?" active":""}" data-page="${p.id}"><svg viewBox="0 0 24 24">${p.icon}</svg>${esc(p.label)}${badge}</button>`;
      }).join("");
      nav.querySelectorAll("[data-page]").forEach(btn=>{btn.addEventListener("click",()=>{activePage=btn.dataset.page;setNavOpen(false);renderAll(lastSnapshot);});});
    }
    function renderScopeSwitcher(snapshot){
      const products=sortedProductKeys(Object.keys((snapshot.gateway||{}).products||{}));
      if(products.length<2){scopeSwitcher.style.display="none";return;}
      scopeSwitcher.style.display="";
      if(productScope!=="all"&&products.indexOf(productScope)<0)productScope="all";
      const opts=[{k:"all",label:"All"}].concat(products.map(p=>({k:p,label:p.charAt(0).toUpperCase()+p.slice(1),hue:productHue(p)})));
      scopeSwitcher.innerHTML=opts.map(o=>{
        const sw=o.hue?`<span class="sw" style="background:var(--${o.hue})"></span>`:"";
        return `<button data-scope="${esc(o.k)}" class="${productScope===o.k?"on":""}">${sw}${esc(o.label)}</button>`;
      }).join("");
    }

    function renderSidebarFooter(snapshot){
      const up=snapshot.uptime_seconds||0;
      const gw=snapshot.gateway||{};
      const repo=snapshot.repo||{};
      const extra=repo.local_label?`<br>${esc(repo.local_label)}${repo.update_available?' &middot; update available':''}`:"";
      const who=adminIdentity?`<br><span style="color:var(--accent)">&#128100; ${esc(adminIdentity)}</span>`:"";
      sidebarFooter.innerHTML=`<span class="status-dot ok"></span> Online ${age(up)}<br>${esc(gw.product||"")} &middot; ${esc(gw.version_str||"")} &middot; ${esc(gw.public_host||"")}${extra}${who}`;
    }

    function renderTopbar(snapshot){
      const p=pages.find(x=>x.id===activePage);
      const metrics=productMetrics(snapshot);
      const alerts=dashboardAlerts(snapshot,metrics.overall);
      pageTitle.textContent=p?p.label:"Dashboard";
      topbarMeta.textContent="Last refresh: "+new Date((snapshot.generated_at||0)*1000).toLocaleTimeString();
      topbarStatus.textContent=alerts.slowCount>0?`${alerts.slowCount} slow-delivery events in view`:`${metrics.overall.liveGames} live games · transport stable`;
    }

    function renderOverview(snapshot){
      const gw=snapshot.gateway||{};const rt=gw.routing_manager||{};const am=gw.activity_metrics||{};const db=snapshot.db||{};const repo=snapshot.repo||{};
      const metrics=productMetrics(snapshot);
      const gameStats=scopedOverall(metrics);
      const banned=gw.banned_ips||[];
      const alerts=dashboardAlerts(snapshot,metrics.overall);
      const productCards=scopedKeys(metrics).map(product=>{
        const bucket=metrics.byProduct[product];
        const info=bucket.info||{};
        return `<article class="runtime-card">
          <div class="runtime-head">
            <div>
              ${productBadge(product)}
              <div class="runtime-title">${esc(info.community_name||product)}</div>
            </div>
            <div class="hero-meta">
              <span class="pill ${bucket.gameRooms?'pill-ok':''}">${esc(bucket.gameRooms)} game rooms</span>
              <span class="pill">${esc(bucket.playersOnline)} online</span>
            </div>
          </div>
          <div class="kv" style="margin-bottom:12px;">
            <div class="k">Directory Root</div><div class="v">${esc(info.directory_root||"")}</div>
            <div class="k">Routing Range</div><div class="v">${esc(info.routing_port||0)} - ${esc(info.routing_max_port||info.routing_port||0)}</div>
            <div class="k">Backend</div><div class="v">${esc(info.backend_host||"")}:${esc(info.backend_port||0)}</div>
            <div class="k">Version</div><div class="v">${esc(info.version_str||"")}</div>
            <div class="k">Valid Versions</div><div class="v">${(info.valid_versions||[]).map(v=>`<span class="pill" style="margin-left:0;margin-right:4px;">${esc(v)}</span>`).join("")||'<span class="muted">n/a</span>'}</div>
          </div>
          <div class="metric-stack">
            <div class="metric-inline"><span class="k">Players In Game</span><span class="v">${esc(bucket.playersInGame)}</span></div>
            <div class="metric-inline"><span class="k">Players In Lobby</span><span class="v">${esc(bucket.playersInLobby)}</span></div>
            <div class="metric-inline"><span class="k">Unique IPs</span><span class="v">${esc(bucket.uniqueIps)}</span></div>
            <div class="metric-inline"><span class="k">Reconnect Holds</span><span class="v">${esc(bucket.reconnecting)}</span></div>
            <div class="metric-inline"><span class="k">Peer Data Bytes</span><span class="v">${esc(formatBytes(bucket.peerBytes))}</span></div>
            <div class="metric-inline"><span class="k">Game Obj Bytes</span><span class="v">${esc(formatBytes(bucket.gameObjectBytes))}</span></div>
          </div>
        </article>`;
      }).join("");
      return `
        <section class="ops-summary-grid">
          ${summaryMetricCard("Players Online", gameStats.playersOnline, "live", `${gameStats.playersInLobby} in lobby`)}
          ${summaryMetricCard("Players In Game", gameStats.playersInGame, "ok", `${gameStats.activeRooms||rt.room_count||0} active rooms`)}
          ${summaryMetricCard("Live Games", gameStats.liveGames, "ok", `${gameStats.gameRooms} game rooms`)}
          ${summaryMetricCard("Reconnect Holds", gameStats.reconnecting, gameStats.reconnecting?"warn":"ok", gameStats.reconnecting?"needs operator attention":"none queued")}
          ${summaryMetricCard("Slow Delivery Alerts", alerts.slowCount, alerts.slowCount?"warn":"ok", alerts.slowCount?"transport degradation detected":"transport stable")}
          ${summaryMetricCard("Peer Data", formatBytes(gameStats.peerBytes), "live", `${gameStats.peerMsgs} messages routed`)}
        </section>
        <section class="card hero-card">
          <div class="hero-heading">
            <div>
              <span class="eyebrow">Operations Summary</span>
              <h2>Transport Health</h2>
              <p class="hero-copy">Live match transport, reconnect state, and runtime health are surfaced first so operators can spot pressure before digging into raw routing details.</p>
            </div>
            <div class="hero-meta">${alerts.items.map(renderAlertPill).join("")}</div>
          </div>
          <div class="overview-grid">
            <div class="status-panel">
              <h3>Connection Health</h3>
              <div class="kv">
                <div class="k">Unique IPs</div><div class="v">${esc(gameStats.uniqueIps||rt.current_unique_ip_count||0)}</div>
                <div class="k">Active Rooms</div><div class="v">${esc(gameStats.activeRooms||rt.room_count||0)}</div>
                <div class="k">Game Obj Bytes</div><div class="v">${esc(formatBytes(gameStats.gameObjectBytes))}</div>
                <div class="k">Live Game Objects</div><div class="v">${esc(gameStats.liveGameObjects)}</div>
                <div class="k">Rooms Opened</div><div class="v">${esc(am.room_open_count||0)}</div>
                <div class="k">Peer Sessions</div><div class="v">${esc(gw.peer_session_count)}</div>
              </div>
            </div>
            <div class="status-strip">
              <div class="status-panel">
                <h3>Auth And Update Status</h3>
                <div class="kv">
                  <div class="k">Auth Keys</div><div class="v">${gw.auth_keys_loaded?'<span class="pill pill-ok">Loaded</span>':'<span class="pill pill-danger">Missing</span>'}</div>
                  <div class="k">GitHub</div><div class="v">${repoSummary(repo)}</div>
                  <div class="k">Version</div><div class="v">${esc(gw.version_str)}</div>
                </div>
              </div>
              <div class="status-panel">
                <h3>Chat And Activity</h3>
                <div class="kv">
                  <div class="k">Joins / Leaves</div><div class="v">${esc(gameStats.joins||am.join_count||0)} / ${esc(gameStats.leaves||am.leave_count||0)}</div>
                  <div class="k">Chat / Broadcasts</div><div class="v">${esc(gameStats.chats||am.chat_count||0)} / ${esc(gameStats.broadcasts||0)}</div>
                  <div class="k">Last Refresh</div><div class="v">${esc(new Date((snapshot.generated_at||0)*1000).toLocaleTimeString())}</div>
                </div>
              </div>
            </div>
          </div>
        </section>
        ${productCards?`<section class="card">
          <span class="eyebrow">Runtime Status</span>
          <h2>Per-Product Live Status</h2>
          <div class="runtime-grid">${productCards}</div>
        </section>`:""}`;
    }

    function renderFactoriesCard(snapshot){
      const gw=snapshot.gateway||{};
      const factories=Array.isArray(snapshot.factories)?snapshot.factories:[];
      const regions=factories.filter(f=>inScope(f.product||""));
      const rows=regions.map(f=>{
        const name=esc(f.description||f.region||f.factory_id||"factory");
        const remote=!!f.remote;
        // Registered factory rows carry live process counts; directory rows
        // carry the published address (remote region) or fall back to local.
        const addr=(f.public_host&&f.public_port)?`${f.public_host}:${f.public_port}`
          :(f.host?`${f.host}${f.port?(":"+f.port):""}`:"");
        const tag=f.source==="registered"?"registered":(remote?"remote region":"local gateway");
        const tagCls=remote?"pill-ok":"pill";
        const detail=f.source==="registered"
          ?`${Number(f.running||0)}/${Number(f.max_processes||0)||"&infin;"} processes`
          :(remote?"published to clients":"served by this gateway");
        return `<div class="region"><div class="rg-name">${productBadge(f.product||"")}${name}<span class="pill ${tagCls}" style="margin-left:auto">${tag}</span></div><div class="rg-meta"><span class="mono">${esc(addr)||"&mdash;"}</span><br>${detail}</div></div>`;
      }).join("")||`<p class="muted">No factory entries found. In shared-edge single-region mode this gateway is the factory. Add a TitanFactoryServer directory entity with <span class="mono">public_host</span> / <span class="mono">public_port</span> to publish another region.</p>`;
      return `<section class="card">
        <span class="eyebrow">Topology</span>
        <h2>Gateways &amp; Factories <span class="pill">${regions.length}</span></h2>
        <div class="region-map">${rows}</div>
      </section>`;
    }

    function renderInfrastructure(snapshot){
      const gw=snapshot.gateway||{};const rt=gw.routing_manager||{};const am=gw.activity_metrics||{};const db=snapshot.db||{};const repo=snapshot.repo||{};
      const metrics=productMetrics(snapshot);
      const gameStats=scopedOverall(metrics);
      const banned=gw.banned_ips||[];
      return `
        ${renderFactoriesCard(snapshot)}
        <section class="utility-grid">
          <div class="card">
            <span class="eyebrow">Infrastructure</span>
            <h2>Server Info</h2>
            <div class="kv">
              <div class="k">Product</div><div class="v">${esc(gw.product||"")}${gw.community_name?` <span class="muted">(${esc(gw.community_name)})</span>`:""}</div>
              <div class="k">Directory Root</div><div class="v">${esc(gw.directory_root||"")}</div>
              <div class="k">Public Host</div><div class="v">${esc(gw.public_host)}</div>
              <div class="k">Gateway Port</div><div class="v">${esc(gw.public_port)}</div>
              <div class="k">Routing Port</div><div class="v">${esc(gw.routing_port)}</div>
              <div class="k">Backend</div><div class="v">${esc(gw.backend_host)}:${esc(gw.backend_port)}</div>
              <div class="k">Version</div><div class="v">${esc(gw.version_str)}</div>
              <div class="k">Auth Keys</div><div class="v">${gw.auth_keys_loaded?'<span style="color:var(--success)">Loaded</span>':'<span style="color:var(--danger)">Not loaded</span>'}</div>
              <div class="k">Peer Sessions</div><div class="v">${esc(gw.peer_session_count)}</div>
              <div class="k">Uptime</div><div class="v">${age(snapshot.uptime_seconds)}</div>
              <div class="k">Valid Versions</div><div class="v">${(gw.valid_versions||[]).map(v=>`<span class="pill" style="margin-left:0;margin-right:4px;">${esc(v)}</span>`).join("")}</div>
              ${Object.keys(gw.products||{}).length?`<div class="k">Runtimes</div><div class="v">${Object.entries(gw.products||{}).map(([name,info])=>`<span class="pill" style="margin-left:0;margin-right:4px;">${esc(name)}:${esc(info.routing_port||0)}</span>`).join("")}</div>`:""}
            </div>
          </div>
          <div class="card">
            <span class="eyebrow">Maintenance</span>
            <h2>Activity Counters</h2>
            <div class="kv">
              <div class="k">Joins</div><div class="v">${esc(gameStats.joins||am.join_count||0)}</div>
              <div class="k">Leaves</div><div class="v">${esc(gameStats.leaves||am.leave_count||0)}</div>
              <div class="k">Chat Messages</div><div class="v">${esc(gameStats.chats||am.chat_count||0)}</div>
              <div class="k">Broadcasts</div><div class="v">${esc(gameStats.broadcasts||0)}</div>
              <div class="k">Peer Data Msgs</div><div class="v">${esc(gameStats.peerMsgs)}</div>
              <div class="k">Rooms Opened</div><div class="v">${esc(am.room_open_count||0)}</div>
              <div class="k">Active Game Rooms</div><div class="v">${esc(gameStats.gameRooms)}</div>
              <div class="k">Live Game Objects</div><div class="v">${esc(gameStats.liveGameObjects)}</div>
              <div class="k">Reconnect Holds</div><div class="v">${esc(gameStats.reconnecting)}</div>
              <div class="k">IPs Seen (total)</div><div class="v">${esc(gameStats.totalIpsSeen||am.unique_ip_count||0)}</div>
            </div>
            <h3>Database</h3>
            <div class="kv">
              <div class="k">Tables</div><div class="v">${esc(db.table_count||0)}</div>
              <div class="k">Non-empty</div><div class="v">${esc(db.nonempty_table_count||0)}</div>
              <div class="k">Total Rows</div><div class="v">${esc(db.total_rows||0)}</div>
            </div>
          </div></section>
        <section class="card">
          <span class="eyebrow">Operator Utilities</span>
          <h2>GitHub Updates</h2>
          <div class="action-bar">
            <button class="btn" data-action="github-check">Check GitHub</button>
            <button class="btn ${repo.can_update?'btn-accent':''}" data-action="github-update">Update From GitHub</button>
          </div>
          <div class="kv">
            <div class="k">Status</div><div class="v">${repoSummary(repo)}</div>
            <div class="k">Branch</div><div class="v">${esc(repo.branch||"")}</div>
            <div class="k">Upstream</div><div class="v">${esc(repo.upstream||"")}</div>
            <div class="k">Local Commit</div><div class="v">${esc(repo.local_label||repo.local_short||"")}</div>
            <div class="k">GitHub Commit</div><div class="v">${esc(repo.remote_label||repo.remote_short||"")}</div>
            <div class="k">Ahead / Behind</div><div class="v">${esc(repo.ahead||0)} / ${esc(repo.behind||0)}</div>
            <div class="k">Last Checked</div><div class="v">${repo.last_checked_at?esc(new Date(repo.last_checked_at*1000).toLocaleString()):"Never"}</div>
            <div class="k">Remote</div><div class="v">${esc(repo.remote_url||"")}</div>
          </div>
          ${repo.last_error?`<p class="muted" style="margin-top:12px;color:var(--danger);">${esc(repo.last_error)}</p>`:""}
          ${repo.last_update_message?`<p class="muted" style="margin-top:12px;">${esc(repo.last_update_message)}</p>`:""}
          ${repo.restart_required?`<p class="muted" style="margin-top:8px;color:var(--warning);">Restart the gateway service to apply the updated code.</p>`:""}
        </section>
        ${banned.length?`
        <section class="card">
          <span class="eyebrow">Access Control</span>
          <h2>Banned IPs <span class="pill">${banned.length}</span></h2>
          <div class="table-wrap"><table>
            <thead><tr><th>IP</th><th>Reason</th><th style="width:80px">Action</th></tr></thead>
            <tbody>${banned.map(b=>`<tr><td class="mono">${esc(b.ip)}</td><td>${esc(b.reason)}</td><td><button class="btn btn-sm" data-action="unban-ip" data-ip="${esc(b.ip)}">Unban</button></td></tr>`).join("")}</tbody>
          </table></div>
        </section>`:""}
        ${renderDatabase(snapshot)}`;
    }

    function subtabBar(tabs, active, attr){
      return `<div class="subtabs">${tabs.map(t=>`<button class="${t.id===active?"on":""}" data-${attr}="${t.id}">${esc(t.label)}${t.count!=null?` <span class="mono">${esc(t.count)}</span>`:""}</button>`).join("")}</div>`;
    }

    // Live: Players + Rooms + Peer Sessions merged behind sub-tabs (IP data is
    // shown inline on Players rather than as its own near-empty page).
    function renderLive(snapshot){
      const rt=(snapshot.gateway||{}).routing_manager||{};
      const players=(rt.players||[]).filter(p=>inScope(p.product));
      const servers=(rt.servers||[]).filter(s=>inScope(s.product));
      const sessions=Object.values((snapshot.gateway||{}).peer_sessions||{}).filter(s=>inScope(s.product));
      const tabs=[
        {id:"players",label:"Players",count:players.length},
        {id:"rooms",label:"Rooms",count:servers.length},
        {id:"sessions",label:"Peer Sessions",count:sessions.length},
        {id:"ips",label:"IP Metrics"},
      ];
      if(!tabs.find(t=>t.id===liveTab))liveTab="players";
      const body=liveTab==="rooms"?renderRooms(snapshot)
        :liveTab==="sessions"?renderSessions(snapshot)
        :liveTab==="ips"?renderIPs(snapshot)
        :renderPlayers(snapshot);
      return `<div class="sectionbar">${subtabBar(tabs,liveTab,"live")}</div>${body}`;
    }

    // Activity & Logs: the activity feed and gateway logs share one page.
    function renderActivityAndLogs(snapshot){
      const act=(snapshot.gateway||{}).activity||[];
      const logs=snapshot.logs||[];
      const tabs=[
        {id:"activity",label:"Activity",count:act.length},
        {id:"logs",label:"Logs",count:logs.length},
      ];
      if(!tabs.find(t=>t.id===activityTab))activityTab="activity";
      const body=activityTab==="logs"?renderLogs(snapshot):renderActivity(snapshot);
      return `<div class="sectionbar">${subtabBar(tabs,activityTab,"activity-tab")}</div>${body}`;
    }

    // Accounts: the users table promoted to a first-class, searchable page with
    // duplicate legacy-CD-key detection. Reuses the same row actions.
    // Accounts data is served page-by-page from /api/accounts (server-side
    // search + pagination) rather than sliced from the 8s snapshot, so every
    // account is reachable and search covers the whole table. Cache is keyed by
    // product; the poll renders from cache and never refetches on its own.
    const ACCOUNTS_LIMIT=50;
    let accountsCache={};       // product -> {rows,total,offset,legacy_count,legacy_cd_key,q,loading,seq}
    let accountsReqSeq=0;
    function scheduleLoadAccounts(product,offset){
      const seq=++accountsReqSeq;
      const prev=accountsCache[product]||{};
      // Mark loading synchronously (with the current query) so the next render
      // does not re-schedule the same fetch.
      accountsCache[product]=Object.assign({},prev,{q:accountsQuery,offset:offset,loading:true,seq:seq});
      const url=`/api/accounts?product=${encodeURIComponent(product)}&q=${encodeURIComponent(accountsQuery)}&offset=${offset}&limit=${ACCOUNTS_LIMIT}`;
      fetch(withToken(url),{cache:"no-store"}).then(r=>r.json()).then(data=>{
        const cur=accountsCache[product];
        if(cur&&cur.seq!==seq)return;   // superseded by a newer request
        accountsCache[product]=Object.assign({},data,{q:accountsQuery,loading:false,seq:seq});
        if(activePage==="accounts"){lastContentHtml="";renderAll(lastSnapshot);}
      }).catch(()=>{const cur=accountsCache[product];if(cur&&cur.seq===seq)cur.loading=false;});
    }
    function renderAccountSection(product){
      const info=snapshotProductInfo(lastSnapshot||{},product);
      const c=accountsCache[product];
      const head=`${productBadge(product)}${esc(info.community_name||product)} Accounts`;
      if(!c||(c.loading&&!(c.rows&&c.rows.length))){
        return `<div class="card" style="margin-top:12px;"><h2 style="margin:0 0 8px;">${head}</h2><p class="muted">Loading accounts&hellip;</p></div>`;
      }
      if(c.ok===false){
        return `<div class="card" style="margin-top:12px;"><h2 style="margin:0 0 8px;">${head}</h2><p class="muted" style="color:var(--danger)">${esc(c.error||"Failed to load accounts.")}</p></div>`;
      }
      const rows=c.rows||[];
      const total=Number(c.total||0);
      const legacy=String(c.legacy_cd_key||"");
      const legacyCount=Number(c.legacy_count||0);
      const offset=Number(c.offset||0);
      const from=total?offset+1:0, to=offset+rows.length;
      const legacyPill=legacyCount?`<span class="pill pill-danger" title="Accounts still bound to the legacy shared installer key.">${legacyCount} on legacy key</span>
        <button class="btn accent" data-action="clear-legacy" data-product="${esc(product)}">Clear all ${legacyCount} legacy-key bindings</button>`:"";
      const body=rows.length?`<div class="table-wrap"><table>
          <thead><tr><th>Username</th><th>Created</th><th>CD Key</th><th>Login Key</th><th style="width:230px">Actions</th></tr></thead>
          <tbody>${rows.map(r=>{
            const cd=String(r.native_cd_key||"");
            const isDup=legacy&&cd.replace(/[^0-9A-Za-z]/g,"").toUpperCase()===legacy;
            const created=(r.created_at&&Number(r.created_at)>0)?`<span title="${esc(r.created_at)}">${esc(new Date(Number(r.created_at)*1000).toLocaleString())}</span>`:'<span class="muted">&mdash;</span>';
            const login=String(r.native_login_key||"");
            const loginShort=login.length>16?`<span class="mono" title="${esc(login)}">${esc(login.slice(0,10))}&hellip;${esc(login.slice(-4))}</span>`:esc(login);
            return `<tr>
              <td><span class="u" style="color:var(--text-hi);font-weight:600;">${esc(r.username)}</span></td>
              <td>${created}</td>
              <td class="mono">${esc(cd)||'<span class="muted">&mdash;</span>'}${isDup?' <span class="pill pill-danger">legacy</span>':""}</td>
              <td>${loginShort||'<span class="muted">&mdash;</span>'}</td>
              <td><button class="btn btn-sm" data-action="reset-pw" data-product="${esc(product)}" data-username="${esc(r.username)}">Reset PW</button> <button class="btn btn-sm" data-action="clear-cd-key" data-product="${esc(product)}" data-username="${esc(r.username)}">Clear CD Key</button> <button class="btn btn-danger btn-sm" data-action="delete-user" data-product="${esc(product)}" data-username="${esc(r.username)}">Delete</button></td>
            </tr>`;
          }).join("")}</tbody>
        </table></div>`:`<p class="muted">${accountsQuery?"No accounts match this search.":"No accounts yet."}</p>`;
      const pager=total>ACCOUNTS_LIMIT?`<div class="sectionbar" style="margin-top:12px;margin-bottom:0;">
          <span class="muted">Showing ${from}&ndash;${to} of ${total}</span><div class="spacer"></div>
          <button class="btn btn-sm" data-acct-page data-product="${esc(product)}" data-offset="${Math.max(0,offset-ACCOUNTS_LIMIT)}" ${offset<=0?"disabled":""}>&larr; Prev</button>
          <button class="btn btn-sm" data-acct-page data-product="${esc(product)}" data-offset="${offset+ACCOUNTS_LIMIT}" ${to>=total?"disabled":""}>Next &rarr;</button>
        </div>`:(total?`<p class="muted" style="margin-top:12px;">Showing all ${total}.</p>`:"");
      return `<div class="card" style="margin-top:12px;">
        <div class="sectionbar"><h2 style="margin:0;">${head} <span class="pill">${total}</span></h2>${legacyPill}<div class="spacer"></div></div>
        ${body}
        ${pager}
      </div>`;
    }
    function renderAccounts(snapshot){
      const products=sortedProductKeys(Object.keys(snapshot.dbs||{})).filter(inScope);
      // Kick off loads for products whose cache is missing or whose search term
      // is stale. Guarded so the poll's re-render does not spam the endpoint.
      products.forEach(p=>{
        const c=accountsCache[p];
        if(!c||c.q!==accountsQuery)scheduleLoadAccounts(p,0);
      });
      const sections=products.map(renderAccountSection).join("");
      return `<div class="sectionbar">
          <input type="search" id="accounts-search" placeholder="Search username or CD key..." value="${esc(accountsQuery)}" style="background:var(--bg-panel);border:1px solid var(--line);border-radius:9px;padding:8px 12px;color:var(--text-hi);font:inherit;font-size:13px;min-width:260px;">
          <div class="spacer"></div>
        </div>${sections||'<div class="card"><p class="muted">No account databases in scope.</p></div>'}`;
    }

    function renderPlayers(snapshot){
      const rt=(snapshot.gateway||{}).routing_manager||{};const players=rt.players||[];const metrics=productMetrics(snapshot);
      if(!players.length)return '<div class="card"><h2>Players</h2><p class="muted">No live players connected.</p></div>';
      const grouped={};
      for(const player of players){
        const product=rowProduct(snapshot,player);
        if(!grouped[product])grouped[product]=[];
        grouped[product].push(player);
      }
      return scopedKeys(metrics).map(product=>{
        const info=snapshotProductInfo(snapshot,product);
        const bucket=metrics.byProduct[product];
        const rows=grouped[product]||[];
        return `<section class="card">
          <span class="eyebrow">Roster</span>
          <h2>${productBadge(product)}${esc(info.community_name||product)} <span class="pill">${rows.length}</span></h2>
          <p class="section-note">${esc(bucket.playersInGame)} in game, ${esc(bucket.playersInLobby)} in lobby, ${esc(bucket.uniqueIps)} unique IPs. Connection Health highlights transport drag while Player Activity keeps recent operator context visible.</p>
          ${rows.length?`<div class="table-wrap"><table>
            <thead><tr><th>Player</th><th>State</th><th>Room</th><th>Connection Health</th><th>Player Activity</th><th style="width:140px">Actions</th></tr></thead>
            <tbody>${rows.map(p=>{
              const isGameRoom=!!metrics.roomStateByKey.get(`${product}:${Number(p.room_port||0)}`);
              const health=connectionHealth(p);
              return `<tr>
                <td>
                  <div class="row-stack">
                    <strong>${hwMarkup(p.client_name)}</strong>
                    <span class="mono muted">${esc(p.client_ip)}</span>
                  </div>
                </td>
                <td>${isGameRoom?'<span class="badge badge-join">game</span>':'<span class="badge badge-default">lobby</span>'}</td>
                <td>
                  <div class="row-stack">
                    <span>${esc(displayRoomName(snapshot,p.room_name,p.room_port,isGameRoom))}</span>
                    <span class="muted">:${esc(p.room_port)}</span>
                  </div>
                </td>
                <td>
                  <div class="row-stack">
                    ${healthBadge(health)}
                    <span class="muted">${slowPeerSummary(p)}</span>
                  </div>
                </td>
                <td>
                  <div class="row-stack">
                    <span>${age(p.connected_seconds)} connected</span>
                    <span class="muted">${age(p.idle_seconds)} idle · ${esc(p.chat_count)} chats · ${esc(p.last_activity_kind||"none")}</span>
                  </div>
                </td>
                <td><button class="btn btn-danger btn-sm" data-action="kick" data-room-port="${esc(p.room_port)}" data-client-id="${esc(p.client_id)}">Kick</button> <button class="btn btn-danger btn-sm" data-action="ban-ip" data-ip="${esc(p.client_ip)}">Ban</button></td>
              </tr>`;
            }).join("")}</tbody>
          </table></div>`:'<p class="muted">No live players connected for this product.</p>'}
          ${rows.map(p=>{
            const isGameRoom=!!metrics.roomStateByKey.get(`${product}:${Number(p.room_port||0)}`);
            const health=connectionHealth(p);
            return `<details class="detail-panel"><summary>${hwMarkup(p.client_name)} <span class="muted">${esc(p.client_ip)} &middot; ${esc(displayRoomName(snapshot,p.room_name,p.room_port,isGameRoom))}:${esc(p.room_port)}</span></summary>
              <div class="detail-grid">
                <div class="kv">
                  <div class="k">Product</div><div class="v">${esc(product)}</div>
                  <div class="k">Client ID</div><div class="v">${esc(p.client_id)}</div>
                  <div class="k">State</div><div class="v">${isGameRoom?"In Game":"Lobby"}</div>
                  <div class="k">Connection Health</div><div class="v">${healthBadge(health)}</div>
                  <div class="k">Player Activity</div><div class="v">${esc(p.last_activity_kind||"")}</div>
                  <div class="k">Subscriptions</div><div class="v">${esc(p.subscription_count)}</div>
                </div>
                <div class="kv">
                  <div class="k">Peer Data Msgs</div><div class="v">${esc(p.peer_data_messages)}</div>
                  <div class="k">Peer Data Bytes</div><div class="v">${esc(formatBytes(p.peer_data_bytes||0))}</div>
                  <div class="k">Slow Send Events</div><div class="v">${esc(p.slow_peer_data_events||0)}</div>
                  <div class="k">Slowest Send</div><div class="v">${Number(p.slowest_peer_data_send_ms||0)>0?`${esc(p.slowest_peer_data_send_ms)}ms`:'-'}</div>
                  <div class="k">Last Slow Send</div><div class="v">${slowPeerLast(p)}</div>
                  <div class="k">Write Buffer</div><div class="v">${writeBufferSummary(p)}</div>
                  <div class="k">Idle</div><div class="v">${age(p.idle_seconds)}</div>
                </div>
              </div></details>`;
          }).join("")}
        </section>`;
      }).join("");
    }

    function renderRooms(snapshot){
      const rt=(snapshot.gateway||{}).routing_manager||{};const servers=rt.servers||[];const metrics=productMetrics(snapshot);
      if(!servers.length)return '<div class="card"><h2>Rooms</h2><p class="muted">No routing rooms yet.</p></div>';
      const grouped={};
      for(const room of servers){
        const product=rowProduct(snapshot,room);
        if(!grouped[product])grouped[product]=[];
        grouped[product].push(room);
      }
      return scopedKeys(metrics).map(product=>{
        const info=snapshotProductInfo(snapshot,product);
        const bucket=metrics.byProduct[product];
        const rooms=grouped[product]||[];
        return `<section class="card">
          <span class="eyebrow">Room Index</span>
          <h2>${productBadge(product)}${esc(info.community_name||product)} Rooms <span class="pill">${rooms.length}</span></h2>
          <p class="section-note">${esc(bucket.activeRooms)} active rooms, ${esc(bucket.gameRooms)} active game rooms, ${esc(bucket.reconnecting)} reconnect holds. Room Health highlights the rooms most likely to need operator attention first.</p>
          ${rooms.length?rooms.map(room=>{
            const isGameRoom=!!room.is_game_room||Number(room.active_game_count||0)>0;
            const roomName=displayRoomName(snapshot,room.room_name,room.listen_port,isGameRoom);
            const peerMsgs=Number(room.peer_data_messages||0);
            const peerBytes=Number(room.peer_data_bytes||0);
            const gameBytes=(room.games||[]).reduce((sum,g)=>sum+Number(g.data_len||0),0);
            const activeGames=Number(room.active_game_count||0);
            const health=roomHealth(room);
            return `<article class="room-shell">
              <div class="hero-heading">
                <div>
                  <h2>${esc(roomName)} <span class="muted" style="font-weight:500;font-size:13px;">:${esc(room.listen_port)}</span></h2>
                  <p class="section-note">${esc(room.room_description||"No description")} · ${isGameRoom?(room.published?"Game / Published":"Game Routing"):"Lobby / Published"}</p>
                </div>
                <div class="hero-meta">
                  <span class="pill">${esc(room.player_count)} players</span>
                  <span class="pill">${esc(activeGames)} games</span>
                  ${healthBadge(health)}
                </div>
              </div>
              <div class="detail-grid">
                <div class="status-panel">
                  <h3>Room Health</h3>
                  <div class="kv">
                    <div class="k">Path</div><div class="v">${esc(room.room_path)}</div>
                    <div class="k">Published</div><div class="v">${esc(room.published)}</div>
                    <div class="k">Password Set</div><div class="v">${esc(room.room_password_set)}</div>
                    <div class="k">Flags</div><div class="v">0x${Number(room.room_flags||0).toString(16)}</div>
                    <div class="k">Peer Data Msgs</div><div class="v">${esc(peerMsgs)}</div>
                    <div class="k">Peer Data Bytes</div><div class="v">${esc(formatBytes(peerBytes))}</div>
                    <div class="k">Slow Send Events</div><div class="v">${esc(room.slow_peer_data_events||0)}</div>
                    <div class="k">Slowest Send</div><div class="v">${Number(room.slowest_peer_data_send_ms||0)>0?`${esc(room.slowest_peer_data_send_ms)}ms`:'-'}</div>
                    <div class="k">Largest Write Buffer</div><div class="v">${esc(formatBytes(room.largest_write_buffer_size||0))}</div>
                    <div class="k">Game/Object Bytes</div><div class="v">${esc(formatBytes(gameBytes))}</div>
                  </div>
                </div>
                <div class="status-panel">
                  <h3>Roster Summary</h3>
                  ${(room.players||[]).length?`<div class="table-wrap"><table>
                    <thead><tr><th>Name</th><th>Connection Health</th><th>Player Activity</th><th style="width:60px">Action</th></tr></thead>
                    <tbody>${room.players.map(p=>{
                      const playerHealth=connectionHealth(p);
                      return `<tr>
                        <td><div class="row-stack"><strong>${hwMarkup(p.client_name)}</strong><span class="mono muted">${esc(p.client_ip)}</span></div></td>
                        <td><div class="row-stack">${healthBadge(playerHealth)}<span class="muted">${slowPeerSummary(p)}</span></div></td>
                        <td><div class="row-stack"><span>${age(p.idle_seconds)} idle</span><span class="muted">${esc(p.chat_count)} chats</span></div></td>
                        <td><button class="btn btn-danger btn-sm" data-action="kick" data-room-port="${esc(room.listen_port)}" data-client-id="${esc(p.client_id)}">Kick</button></td>
                      </tr>`;
                    }).join("")}</tbody>
                  </table></div>`:'<p class="muted">No players in this room.</p>'}
                </div>
              </div>
              ${(room.games||[]).length?`<h3>Live Game Objects</h3><div class="table-wrap"><table>
                <thead><tr><th>Name</th><th>Owner</th><th>Link</th><th>Data</th><th>Life</th><th>Preview</th></tr></thead>
                <tbody>${room.games.map(g=>`<tr><td>${esc(g.name)}</td><td>${hwMarkup(g.owner_name||String(g.owner_id))}</td><td>${esc(g.link_id)}</td><td>${esc(g.data_len)} bytes</td><td>${esc(g.lifespan)}</td><td class="mono">${esc(shortHex(g.data_preview_hex,32))}</td></tr>`).join("")}</tbody>
              </table></div>`:`<p class="muted" style="margin-top:8px;">${isGameRoom?"No live game objects.":"No published games."}</p>`}
            </article>`;
          }).join(""):'<p class="muted">No routing rooms for this product.</p>'}
        </section>`;
      }).join("");
    }

    function renderActivity(snapshot){
      const gw=snapshot.gateway||{};const activity=gw.activity||[];const servers=(gw.routing_manager||{}).servers||[];const metrics=productMetrics(snapshot);
      const roomOpts=servers.map(r=>`<option value="${esc(r.listen_port)}">${esc(productText(r.product)+displayRoomName(snapshot,r.room_name,r.listen_port,!!r.is_game_room||Number(r.active_game_count||0)>0))}:${esc(r.listen_port)}</option>`).join("");
      const grouped={};
      for(const entry of activity){
        const product=rowProduct(snapshot,entry);
        if(!grouped[product])grouped[product]=[];
        grouped[product].push(entry);
      }
      const summaryCards=scopedKeys(metrics).map(product=>{
        const bucket=metrics.byProduct[product];
        const info=bucket.info||{};
        return `<div class="stat-card">
          <div class="label">${esc(info.community_name||product)}</div>
          <div class="value">${esc((grouped[product]||[]).length)}</div>
          <div class="muted" style="margin-top:8px;">${esc(bucket.joins)} joins, ${esc(bucket.leaves)} leaves, ${esc(bucket.chats)} chats, ${esc(bucket.broadcasts)} broadcasts</div>
        </div>`;
      }).join("");
      return `<div class="card">
        <h2>Activity Feed <span class="pill">${activity.length}</span></h2>
        <div class="action-bar">
          <input type="text" id="broadcast-msg" placeholder="Broadcast message...">
          <select id="broadcast-room"><option value="">All rooms</option>${roomOpts}</select>
          <button class="btn btn-accent" data-action="broadcast">Send</button>
          <button class="btn btn-danger" data-action="clear-activity">Clear</button>
        </div>
        ${summaryCards?`<div class="stat-grid">${summaryCards}</div>`:""}
        ${activity.length?scopedKeys(metrics).map(product=>{
          const info=snapshotProductInfo(snapshot,product);
          const rows=grouped[product]||[];
          return `<div class="card" style="margin-top:12px;">
            <h2>${productBadge(product)}${esc(info.community_name||product)} Activity <span class="pill">${rows.length}</span></h2>
            ${rows.length?`<div class="table-wrap"><table>
              <thead><tr><th style="width:80px">Time</th><th style="width:70px">Event</th><th>Player</th><th>Room</th><th>IP</th><th>Detail</th></tr></thead>
              <tbody>${rows.map(e=>{
                const isGameRoom=!!metrics.roomStateByKey.get(`${product}:${Number(e.room_port||0)}`);
                return `<tr>
                  <td class="mono">${esc(stamp(e.ts))}</td>
                  <td>${kindBadge(e.kind)}</td>
                  <td>${hwMarkup(e.player_name||"")}</td>
                  <td>${esc(displayRoomName(snapshot,e.room_name,e.room_port,isGameRoom))}${e.room_port?` <span class="muted">:${esc(e.room_port)}</span>`:""}</td>
                  <td class="mono">${esc(e.player_ip||"")}</td>
                  <td>${hwMarkup(activityDetail(snapshot,e))}</td>
                </tr>`;
              }).join("")}</tbody>
            </table></div>`:'<p class="muted">No activity recorded yet for this product.</p>'}
          </div>`;
        }).join(""):'<p class="muted">No activity recorded yet.</p>'}
      </div>`;
    }

    function renderIPs(snapshot){
      const gw=snapshot.gateway||{};const ips=gw.ip_metrics||[];const metrics=productMetrics(snapshot);
      const grouped={};
      for(const row of ips){
        const products=sortedProductKeys(row.products||[]);
        const targets=products.length?products:[defaultSnapshotProduct(snapshot)].filter(Boolean);
        for(const product of targets){
          if(!grouped[product])grouped[product]=[];
          grouped[product].push(row);
        }
      }
      return `<div class="card"><h2>IP Metrics <span class="pill">${ips.length}</span></h2>
        ${ips.length?scopedKeys(metrics).map(product=>{
          const info=snapshotProductInfo(snapshot,product);
          const rows=grouped[product]||[];
          return `<div class="card" style="margin-top:12px;">
            <h2>${productBadge(product)}${esc(info.community_name||product)} IPs <span class="pill">${rows.length}</span></h2>
            ${rows.length?`<div class="table-wrap"><table>
              <thead><tr><th>IP</th><th>Products</th><th>Players Seen</th><th>Joins</th><th>Chats</th><th>Last Seen</th><th style="width:60px">Action</th></tr></thead>
              <tbody>${rows.map(e=>`<tr>
                <td class="mono">${esc(e.ip)}</td>
                <td>${(e.products||[]).map(productBadge).join("")||'<span class="muted">n/a</span>'}</td>
                <td>${nameList(e.player_names)}</td>
                <td>${esc(e.join_count)}</td>
                <td>${esc(e.chat_count)}</td>
                <td>${esc(stamp(e.last_seen))}</td>
                <td><button class="btn btn-danger btn-sm" data-action="ban-ip" data-ip="${esc(e.ip)}">Ban</button></td>
              </tr>`).join("")}</tbody>
            </table></div>`:'<p class="muted">No IP activity recorded yet for this product.</p>'}
          </div>`;
        }).join(""):'<p class="muted">No IP activity recorded yet.</p>'}
      </div>`;
    }

    function renderDatabase(snapshot){
      const dbs=snapshot.dbs||{};
      const productKeys=sortedProductKeys(Object.keys(dbs));
      if(!productKeys.length)return '<div class="card"><h2>Database</h2><p class="muted">No databases configured.</p></div>';
      if(!activeDbProduct||!dbs[activeDbProduct]){
        activeDbProduct=snapshot.db_default_product&&dbs[snapshot.db_default_product]?snapshot.db_default_product:productKeys[0];
      }
      const db=dbs[activeDbProduct]||snapshot.db||{};
      const infoCardProduct=snapshotProductInfo(snapshot,activeDbProduct);
      const tables=Object.entries(db.tables||{});
      if(!tables.length){
        return `<div class="card">
          <h2>Database ${productBadge(activeDbProduct)}${esc(infoCardProduct.community_name||activeDbProduct)}</h2>
          ${productKeys.length>1?`<div class="db-tabs">${productKeys.map(product=>`<button class="db-tab${product===activeDbProduct?" active":""}" data-db-product="${esc(product)}">${esc(snapshotProductInfo(snapshot,product).community_name||product)}</button>`).join("")}</div>`:""}
          <p class="muted">No tables found in this database.</p>
        </div>`;
      }
      if(!activeDbTable||!db.tables[activeDbTable])activeDbTable=tables[0][0];
      const info=db.tables[activeDbTable]||{count:0,rows:[]};
      const rows=info.rows||[];
      const cols=rows.length?Object.keys(rows[0]):[];
      const isUsersTable=activeDbTable==="users";
      const totalCount=Number(info.count||0);
      const truncated=totalCount>rows.length;
      const fmtCell=(col,v)=>{
        if(v===null||v===undefined)return '<span class="muted">—</span>';
        if((col==="created_at"||col.endsWith("_at"))&&typeof v==="number"&&v>0){
          return `<span title="${esc(v)}">${esc(new Date(v*1000).toLocaleString())}</span>`;
        }
        const s=String(v);
        if(/^[0-9a-fA-F]{24,}$/.test(s)){
          return `<span class="mono" title="${esc(s)}">${esc(s.slice(0,10))}…${esc(s.slice(-4))}</span>`;
        }
        return esc(s);
      };
      return `<div class="card">
        <h2>Database ${productBadge(activeDbProduct)}${esc(infoCardProduct.community_name||activeDbProduct)} <span class="pill">${esc(db.table_count||0)} tables</span> <span class="pill">${esc(db.total_rows||0)} rows</span></h2>
        <div class="kv" style="margin-bottom:12px;">
          <div class="k">Product</div><div class="v">${esc(activeDbProduct)}</div>
          <div class="k">Path</div><div class="v">${esc(db.path||"")}</div>
          <div class="k">Non-empty Tables</div><div class="v">${esc(db.nonempty_table_count||0)}</div>
        </div>
        ${productKeys.length>1?`<div class="db-tabs">${productKeys.map(product=>`<button class="db-tab${product===activeDbProduct?" active":""}" data-db-product="${esc(product)}">${esc(snapshotProductInfo(snapshot,product).community_name||product)}</button>`).join("")}</div>`:""}
        <div class="db-tabs">${tables.map(([name,info])=>`<button class="db-tab${name===activeDbTable?" active":""}" data-db-table="${esc(name)}">${esc(name)} <span class="muted">(${info.count})</span></button>`).join("")}</div>
        ${rows.length?`<div class="table-wrap"><table>
          <thead><tr>${cols.map(c=>`<th>${esc(c)}</th>`).join("")}${isUsersTable?'<th style="width:220px">Actions</th>':""}</tr></thead>
          <tbody>${rows.map(r=>`<tr>${cols.map(c=>{
            const v=r[c];
            if(v&&typeof v==="object")return '<td class="mono">'+esc(JSON.stringify(v))+"</td>";
            return "<td>"+fmtCell(c,v)+"</td>";
          }).join("")}${isUsersTable?`<td><button class="btn btn-sm" data-action="reset-pw" data-product="${esc(activeDbProduct)}" data-username="${esc(r.username)}">Reset PW</button> <button class="btn btn-sm" data-action="clear-cd-key" data-product="${esc(activeDbProduct)}" data-username="${esc(r.username)}">Clear CD Key</button> <button class="btn btn-danger btn-sm" data-action="delete-user" data-product="${esc(activeDbProduct)}" data-username="${esc(r.username)}">Delete</button></td>`:""}</tr>`).join("")}</tbody>
        </table></div>${truncated?`<p class="muted" style="margin-top:8px;">Showing first ${esc(rows.length)} of ${esc(totalCount)} rows.</p>`:""}`:'<p class="muted">Table is empty.</p>'}
      </div>`;
    }

    function renderSessions(snapshot){
      const gw=snapshot.gateway||{};const sessions=Object.entries(gw.peer_sessions||{});
      return `<div class="card"><h2>Peer Sessions <span class="pill">${sessions.length}</span></h2>
        ${sessions.length?`<div class="table-wrap"><table>
          <thead><tr><th>ID</th><th>Role</th><th>Sequenced</th><th>In Seq</th><th>Out Seq</th><th>Created</th><th>Last Used</th><th>Key Len</th></tr></thead>
          <tbody>${sessions.map(([id,s])=>`<tr>
            <td>${esc(id)}</td><td>${esc(s.role)}</td><td>${esc(s.sequenced)}</td>
            <td>${esc(s.in_seq)}</td><td>${esc(s.out_seq)}</td>
            <td>${esc(stamp(s.created_at))}</td><td>${esc(stamp(s.last_used_at))}</td>
            <td>${esc(s.session_key_len)}</td>
          </tr>`).join("")}</tbody>
        </table></div>`:'<p class="muted">No peer sessions.</p>'}
      </div>`;
    }

    function renderLogs(snapshot){
      const logs=snapshot.logs||[];
      const {productKeys,hasUnclassified}=logFilterState(snapshot,logs);
      const filtered=logs.filter(entry=>{
        const products=logProducts(entry);
        if(activeLogProduct==="all")return true;
        if(activeLogProduct==="unclassified")return !products.length;
        return products.includes(activeLogProduct);
      });
      const filterTabs=productKeys.length||hasUnclassified?`<div class="db-tabs">
        <button class="db-tab${activeLogProduct==="all"?" active":""}" data-log-product="all">All <span class="muted">(${logs.length})</span></button>
        ${productKeys.map(product=>{
          const count=logs.filter(entry=>logProducts(entry).includes(product)).length;
          return `<button class="db-tab${activeLogProduct===product?" active":""}" data-log-product="${esc(product)}">${esc(snapshotProductInfo(snapshot,product).community_name||product)} <span class="muted">(${count})</span></button>`;
        }).join("")}
        ${hasUnclassified?`<button class="db-tab${activeLogProduct==="unclassified"?" active":""}" data-log-product="unclassified">Unclassified <span class="muted">(${logs.filter(entry=>!logProducts(entry).length).length})</span></button>`:""}
      </div>`:"";
      const colored=filtered.map(e=>{
        const tags=logProducts(e).map(productBadge).join("");
        const r=esc(e.rendered||"");
        if(e.level==="ERROR")return `${tags?`${tags} `:""}<span class="log-error">${r}</span>`;
        if(e.level==="WARNING")return `${tags?`${tags} `:""}<span class="log-warn">${r}</span>`;
        return `${tags?`${tags} `:""}<span class="log-info">${r}</span>`;
      }).join("\\n");
      return `<div class="card">
        <h2>Logs <span class="pill">${filtered.length}</span>${filtered.length!==logs.length?` <span class="pill">of ${logs.length}</span>`:""}</h2>
        <div class="action-bar"><button class="btn btn-danger" data-action="clear-logs">Clear Logs</button></div>
        ${filterTabs}
        ${(productKeys.length>1||hasUnclassified)?'<p class="muted" style="margin-bottom:12px;">Product filters are inferred from runtime metadata, room ports, and known product markers in each log line. Unclassified entries are shared/admin/system logs.</p>':""}
        <pre id="log-pre">${colored||'<span class="muted">No logs yet.</span>'}</pre>
      </div>`;
    }

    // --- Non-destructive DOM updates -------------------------------------
    // Instead of nuking content.innerHTML on every 8s poll (which drops focus,
    // caret position, text selection and scroll), we morph the existing DOM in
    // place: unchanged nodes keep their identity, so interaction survives a
    // refresh. A full innerHTML write is still used on page switches, where
    // there is no in-page state worth preserving.
    let lastRenderedPage=null;
    let lastContentHtml="";
    function morphSyncAttrs(oldEl,newEl){
      const keep={value:1,checked:1,selected:1};
      for(let i=oldEl.attributes.length-1;i>=0;i--){
        const name=oldEl.attributes[i].name;
        if(!newEl.hasAttribute(name)&&!keep[name])oldEl.removeAttribute(name);
      }
      for(let i=0;i<newEl.attributes.length;i++){
        const a=newEl.attributes[i];
        if(keep[a.name])continue; // never clobber live form-control state
        if(oldEl.getAttribute(a.name)!==a.value)oldEl.setAttribute(a.name,a.value);
      }
    }
    function morphNode(oldN,newN){
      if(oldN.nodeType!==newN.nodeType||(oldN.nodeType===1&&(oldN.tagName!==newN.tagName||oldN.id!==newN.id))){
        oldN.replaceWith(newN);
        return;
      }
      if(oldN.nodeType===1){
        morphSyncAttrs(oldN,newN);
        morphChildren(oldN,newN);
      }else if(oldN.nodeType===3||oldN.nodeType===8){
        if(oldN.nodeValue!==newN.nodeValue)oldN.nodeValue=newN.nodeValue;
      }
    }
    function morphChildren(oldParent,newParent){
      let o=oldParent.firstChild,n=newParent.firstChild;
      while(o&&n){
        const nextO=o.nextSibling,nextN=n.nextSibling;
        morphNode(o,n);
        o=nextO;n=nextN;
      }
      while(o){const nx=o.nextSibling;o.remove();o=nx;}
      while(n){const nx=n.nextSibling;oldParent.appendChild(n);n=nx;}
    }
    function morphContent(container,html){
      const tmp=document.createElement(container.tagName);
      tmp.innerHTML=html;
      morphChildren(container,tmp);
    }
    function renderAll(snapshot){
      if(!snapshot)return;
      captureUiState();
      lastSnapshot=snapshot;
      renderNav(snapshot);
      renderScopeSwitcher(snapshot);
      renderSidebarFooter(snapshot);
      renderTopbar(snapshot);
      const renderers={overview:renderOverview,live:renderLive,activity:renderActivityAndLogs,accounts:renderAccounts,infra:renderInfrastructure};
      const fn=renderers[activePage]||renderOverview;
      const html=fn(snapshot);
      if(activePage!==lastRenderedPage){
        content.innerHTML=html;       // clean slate on navigation
      }else if(html!==lastContentHtml){
        morphContent(content,html);   // in-place update, preserves interaction
      }
      lastRenderedPage=activePage;
      lastContentHtml=html;
      restoreUiState();
    }

    function withToken(path){
      if(!adminToken)return path;
      const sep=path.includes("?")?"&":"?";
      return `${path}${sep}token=${encodeURIComponent(adminToken)}`;
    }

    async function adminAction(endpoint,payload){
      pauseAutoRefresh(10000);
      pauseRefresh=true;
      try{
        const res=await fetch(withToken(`/api/admin/${endpoint}`),{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
        const data=await res.json();
        if(data.ok){showToast(data.message||"Action succeeded","success");}else{showToast(data.error||"Action failed","error");}
        accountsCache={};   // account rows may have changed; force a re-fetch
        await refresh();
      }catch(err){showToast("Request failed: "+err,"error");}
      finally{pauseRefresh=false;pauseAutoRefresh(6000);}
    }

    function showToast(msg,type){
      const t=document.createElement("div");
      t.className="toast toast-"+(type||"success");
      t.textContent=msg;
      toastContainer.appendChild(t);
      setTimeout(()=>t.remove(),3500);
    }

    function showModal(title,bodyHtml,onConfirm){
      pauseRefresh=true;
      pauseAutoRefresh(15000);
      modalBox.innerHTML=`<h3>${esc(title)}</h3>${bodyHtml}<div class="modal-actions"><button class="btn" id="modal-cancel">Cancel</button><button class="btn btn-danger" id="modal-confirm">Confirm</button></div>`;
      modalOverlay.classList.add("show");
      document.getElementById("modal-cancel").addEventListener("click",closeModal);
      document.getElementById("modal-confirm").addEventListener("click",()=>{closeModal();onConfirm();});
    }
    function closeModal(){modalOverlay.classList.remove("show");pauseRefresh=false;}
    modalOverlay.addEventListener("click",e=>{if(e.target===modalOverlay)closeModal();});

    // Database tab / log-filter switches use event delegation on the stable
    // content container. Direct per-button binding would double-attach now that
    // morphContent reuses buttons across refreshes.
    content.addEventListener("click",e=>{
      const dbP=e.target.closest("[data-db-product]");
      if(dbP){activeDbProduct=dbP.dataset.dbProduct||"";activeDbTable="";renderAll(lastSnapshot);return;}
      const dbT=e.target.closest("[data-db-table]");
      if(dbT){activeDbTable=dbT.dataset.dbTable||"";renderAll(lastSnapshot);return;}
      const lgP=e.target.closest("[data-log-product]");
      if(lgP){activeLogProduct=lgP.dataset.logProduct||"all";renderAll(lastSnapshot);return;}
      const lv=e.target.closest("[data-live]");
      if(lv){liveTab=lv.dataset.live||"players";renderAll(lastSnapshot);return;}
      const av=e.target.closest("[data-activity-tab]");
      if(av){activityTab=av.dataset.activityTab||"activity";renderAll(lastSnapshot);return;}
      const ap=e.target.closest("[data-acct-page]");
      if(ap&&!ap.disabled){scheduleLoadAccounts(ap.dataset.product,Math.max(0,Number(ap.dataset.offset||0)));return;}
    });

    // Global product scope switcher.
    scopeSwitcher.addEventListener("click",e=>{
      const b=e.target.closest("[data-scope]");
      if(!b)return;
      productScope=b.dataset.scope||"all";
      lastContentHtml="";           // force re-render of the scoped content
      renderAll(lastSnapshot);
    });

    // Accounts search. morphContent preserves the input's caret across the
    // re-render, so filtering as you type does not steal focus.
    content.addEventListener("input",e=>{
      const s=e.target.closest("#accounts-search");
      if(s){accountsQuery=s.value;lastContentHtml="";renderAll(lastSnapshot);}
    });

    content.addEventListener("click",e=>{
      const btn=e.target.closest("[data-action]");
      if(!btn)return;
      const action=btn.dataset.action;

      if(action==="kick"){
        const port=btn.dataset.roomPort,cid=btn.dataset.clientId;
        showModal("Kick Player",`<p>Kick client #${esc(cid)} from room :${esc(port)}?</p>`,()=>adminAction("kick",{room_port:Number(port),client_id:Number(cid)}));
      }
      if(action==="ban-ip"){
        const ip=btn.dataset.ip;
        showModal("Ban IP",`<p>Ban <strong>${esc(ip)}</strong>?</p><input type="text" id="ban-reason" placeholder="Reason (optional)">`,()=>{
          const reason=(document.getElementById("ban-reason")||{}).value||"admin ban";
          adminAction("ban-ip",{ip,reason});
        });
      }
      if(action==="unban-ip"){
        const ip=btn.dataset.ip;
        adminAction("unban-ip",{ip});
      }
      if(action==="broadcast"){
        const msg=(document.getElementById("broadcast-msg")||{}).value||"";
        const roomPort=(document.getElementById("broadcast-room")||{}).value||"";
        if(!msg.trim()){showToast("Enter a message","error");return;}
        adminAction("broadcast",{message:msg,room_port:roomPort?Number(roomPort):null});
      }
      if(action==="github-check"){
        adminAction("github-check",{});
      }
      if(action==="github-update"){
        showModal("Update From GitHub","<p>Fetch the latest code from GitHub and fast-forward this checkout if possible? This refuses dirty or diverged branches, and you still need to restart the gateway afterwards.</p>",()=>adminAction("github-update",{}));
      }
      if(action==="clear-activity"){
        showModal("Clear Activity","<p>Clear all activity logs and counters?</p>",()=>adminAction("clear-activity",{}));
      }
      if(action==="clear-logs"){
        showModal("Clear Logs","<p>Clear the gateway log buffer?</p>",()=>adminAction("clear-logs",{}));
      }
      if(action==="delete-user"){
        const u=btn.dataset.username;
        const product=btn.dataset.product||activeDbProduct||"";
        showModal("Delete User",`<p>Permanently delete user <strong>${esc(u)}</strong>${product?` from <strong>${esc(product)}</strong>`:""}?</p>`,()=>adminAction("delete-user",{product,username:u}));
      }
      if(action==="reset-pw"){
        const u=btn.dataset.username;
        const product=btn.dataset.product||activeDbProduct||"";
        showModal("Reset Password",`<p>Reset password for <strong>${esc(u)}</strong>${product?` in <strong>${esc(product)}</strong>`:""}:</p><input type="password" id="new-pw" placeholder="New password">`,()=>{
          const pw=(document.getElementById("new-pw")||{}).value||"";
          if(!pw){showToast("Enter a password","error");return;}
          adminAction("reset-password",{product,username:u,new_password:pw});
        });
      }
      if(action==="clear-cd-key"){
        const u=btn.dataset.username;
        const product=btn.dataset.product||activeDbProduct||"";
        showModal("Clear CD Key",`<p>Clear the native CD key and login key binding for <strong>${esc(u)}</strong>${product?` in <strong>${esc(product)}</strong>`:""}?</p><p class="muted">This lets the next retail login bind a fresh key for that account.</p>`,()=>adminAction("clear-cd-key",{product,username:u}));
      }
      if(action==="clear-legacy"){
        const product=btn.dataset.product||activeDbProduct||"";
        showModal("Clear Legacy CD Keys",`<p>Clear the legacy shared installer CD key from <strong>all</strong> accounts still bound to it${product?` in <strong>${esc(product)}</strong>`:""}?</p><p class="muted">Each affected player re-binds a fresh unique key on their next retail login. This cannot be undone.</p>`,()=>adminAction("clear-legacy-cd-keys",{product}));
      }
    });

    async function refresh(){
      const res=await fetch(withToken(`/api/snapshot?rows=50&logs=300&activity=200`),{cache:"no-store"});
      if(!res.ok)throw new Error("HTTP "+res.status);
      renderAll(await res.json());
    }

    ["keydown","focusin","mouseover","copy","cut","paste","selectionchange"].forEach(evt=>{
      const handler=()=>pauseAutoRefresh(12000);
      if(evt==="selectionchange"){
        document.addEventListener(evt,handler,true);
      }else{
        content.addEventListener(evt,handler,true);
        modalOverlay.addEventListener(evt,()=>pauseAutoRefresh(15000),true);
      }
    });
    ["pointerdown","mousedown"].forEach(evt=>{
      content.addEventListener(evt,()=>{pointerInteractionActive=true;pauseAutoRefresh(15000);},true);
      modalOverlay.addEventListener(evt,()=>{pointerInteractionActive=true;pauseAutoRefresh(15000);},true);
    });
    ["pointerup","mouseup","dragend","touchend"].forEach(evt=>{
      window.addEventListener(evt,()=>{pointerInteractionActive=false;pauseAutoRefresh(4000);},true);
    });

    async function loop(){
      try{if(!shouldDeferRefresh())await refresh();}catch(err){topbarMeta.textContent="Refresh failed: "+err;}
      setTimeout(loop,8000);
    }

    // Live-match telemetry pushes updates as they happen so active games do not
    // wait up to 8s for the next poll. The poll remains the fallback for state
    // the feed does not cover (idle lobbies, account/db changes).
    function startLiveFeed(){
      if(typeof EventSource==="undefined")return;
      let pending=null;
      const bump=()=>{
        if(pending)return;
        pending=setTimeout(()=>{pending=null;if(!shouldDeferRefresh())refresh().catch(()=>{});},400);
      };
      try{
        const es=new EventSource(withToken("/api/live-feed"));
        es.addEventListener("message",bump);
        ["match_checkpoint_hint","match_resolution_hint","match_slot_manifest","match_launch_config"].forEach(n=>es.addEventListener(n,bump));
      }catch(e){/* fall back to polling */}
    }

    loop();
    startLiveFeed();
  </script>
</body>
</html>""".replace("__ADMIN_TOKEN__", json.dumps(embedded_token)).replace("__ADMIN_IDENTITY__", json.dumps(identity))

    def _record_admin_action(
        self, action: str, product: str, *, username: str = ""
    ) -> None:
        """Record a destructive admin account action in the activity feed so
        delete/reset/clear operations leave an audit trail, mirroring how
        admin broadcasts are already logged."""
        recorder = getattr(self.gateway, "record_activity", None)
        if not callable(recorder):
            return
        try:
            recorder(
                "admin-action",
                product=str(product or "").strip(),
                player_name="[ADMIN]",
                text=f"{action}: {username}" if username else action,
                details={"action": action, "username": username},
            )
        except Exception as exc:  # never let auditing break the action itself
            LOGGER.debug("Failed to record admin action %s: %s", action, exc)

    async def _handle_admin_post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch POST admin action requests."""
        try:
            if path == "/api/admin/kick":
                room_port = int(body.get("room_port", 0))
                client_id = int(body.get("client_id", 0))
                if not room_port or not client_id:
                    return {"ok": False, "error": "room_port and client_id required"}
                if self.gateway.routing_manager is None:
                    return {"ok": False, "error": "routing manager not available"}
                result = await self.gateway.routing_manager.admin_kick_player(room_port, client_id)
                return {"ok": result, "error": "" if result else "client not found"}

            if path == "/api/admin/ban-ip":
                ip = str(body.get("ip", "")).strip()
                reason = str(body.get("reason", "admin ban")).strip()
                if not ip:
                    return {"ok": False, "error": "ip required"}
                self.gateway.ban_ip(ip, reason)
                return {"ok": True, "banned": ip, "reason": reason}

            if path == "/api/admin/unban-ip":
                ip = str(body.get("ip", "")).strip()
                if not ip:
                    return {"ok": False, "error": "ip required"}
                result = self.gateway.unban_ip(ip)
                return {"ok": result, "error": "" if result else "ip not in ban list"}

            if path == "/api/admin/broadcast":
                message = str(body.get("message", "")).strip()
                if not message:
                    return {"ok": False, "error": "message required"}
                room_port = body.get("room_port")
                if room_port is not None:
                    room_port = int(room_port)
                if self.gateway.routing_manager is None:
                    return {"ok": False, "error": "routing manager not available"}
                delivered = await self.gateway.routing_manager.admin_broadcast(message, room_port)
                scope = f"room :{room_port}" if room_port is not None else "all rooms"
                room_name = "All Rooms"
                room_path = ""
                room_product = ""
                if room_port is not None and hasattr(self.gateway.routing_manager, "get_server"):
                    server = self.gateway.routing_manager.get_server(room_port)
                    if server is not None:
                        room_name = str(getattr(server, "_room_display_name", "") or room_name)
                        room_path = str(getattr(server, "_room_path", "") or "")
                        room_product = str(
                            getattr(getattr(server, "product_profile", None), "key", "") or ""
                        )
                self.gateway.record_activity(
                    "broadcast",
                    product=room_product,
                    room_port=room_port,
                    room_name=room_name,
                    room_path=room_path,
                    player_name="[ADMIN]",
                    text=message,
                    details={
                        "delivered": delivered,
                        "scope": scope,
                    },
                )
                return {
                    "ok": True,
                    "delivered": delivered,
                    "message": f"Broadcast delivered to {delivered} client(s) in {scope}.",
                }

            if path == "/api/admin/clear-activity":
                self.gateway.clear_activity()
                return {"ok": True}

            if path == "/api/admin/clear-logs":
                count = self.log_handler.clear()
                return {"ok": True, "cleared": count}

            if path == "/api/admin/github-check":
                git_state = await self.repo_monitor.force_refresh(fetch_remote=True)
                if git_state.get("last_error"):
                    return {"ok": False, "error": git_state["last_error"], "git": git_state}
                if git_state.get("update_available"):
                    return {
                        "ok": True,
                        "message": "Update available from GitHub.",
                        "git": git_state,
                    }
                return {
                    "ok": True,
                    "message": "GitHub check complete. Already up to date.",
                    "git": git_state,
                }

            if path == "/api/admin/github-update":
                return await self.repo_monitor.update_from_upstream()

            if path == "/api/admin/delete-user":
                username = str(body.get("username", "")).strip()
                if not username:
                    return {"ok": False, "error": "username required"}
                product = str(body.get("product", "")).strip()
                db_path = self._resolve_db_path(product)
                if not db_path.exists():
                    return {"ok": False, "error": "database not found"}
                conn = sqlite3.connect(str(db_path))
                try:
                    cur = conn.execute("DELETE FROM users WHERE username=?", (username,))
                    conn.commit()
                    if cur.rowcount > 0:
                        self._record_admin_action(
                            "delete-user", product, username=username
                        )
                    return {
                        "ok": cur.rowcount > 0,
                        "error": "" if cur.rowcount > 0 else "user not found",
                        "product": product or self.default_db_product,
                    }
                finally:
                    conn.close()

            if path == "/api/admin/reset-password":
                username = str(body.get("username", "")).strip()
                new_password = str(body.get("new_password", ""))
                if not username or not new_password:
                    return {"ok": False, "error": "username and new_password required"}
                product = str(body.get("product", "")).strip()
                db_path = self._resolve_db_path(product)
                if not db_path.exists():
                    return {"ok": False, "error": "database not found"}
                password_hash = hashlib.sha256(new_password.encode("utf-8")).hexdigest()
                conn = sqlite3.connect(str(db_path))
                try:
                    cur = conn.execute("UPDATE users SET password_hash=? WHERE username=?", (password_hash, username))
                    conn.commit()
                    if cur.rowcount > 0:
                        self._record_admin_action(
                            "reset-password", product, username=username
                        )
                    return {
                        "ok": cur.rowcount > 0,
                        "error": "" if cur.rowcount > 0 else "user not found",
                        "product": product or self.default_db_product,
                    }
                finally:
                    conn.close()

            if path == "/api/admin/clear-cd-key":
                username = str(body.get("username", "")).strip()
                if not username:
                    return {"ok": False, "error": "username required"}
                product = str(body.get("product", "")).strip()
                db_path = self._resolve_db_path(product)
                if not db_path.exists():
                    return {"ok": False, "error": "database not found"}
                conn = sqlite3.connect(str(db_path))
                try:
                    cur = conn.execute(
                        "UPDATE users SET native_cd_key='', native_login_key='' WHERE username=?",
                        (username,),
                    )
                    conn.commit()
                    if cur.rowcount > 0:
                        self._record_admin_action(
                            "clear-cd-key", product, username=username
                        )
                    return {
                        "ok": cur.rowcount > 0,
                        "error": "" if cur.rowcount > 0 else "user not found",
                        "product": product or self.default_db_product,
                    }
                finally:
                    conn.close()

            if path == "/api/admin/clear-legacy-cd-keys":
                product = str(body.get("product", "")).strip()
                product_key = product or self.default_db_product
                legacy = LEGACY_SHARED_CD_KEYS.get(str(product_key).lower(), "")
                if not legacy:
                    return {"ok": False, "error": "no legacy key known for this product"}
                db_path = self._resolve_db_path(product)
                if not db_path.exists():
                    return {"ok": False, "error": "database not found"}
                norm = "REPLACE(REPLACE(UPPER(COALESCE(native_cd_key,'')),'-',''),' ','')"
                conn = sqlite3.connect(str(db_path))
                try:
                    cur = conn.execute(
                        "UPDATE users SET native_cd_key='', native_login_key='' "
                        f"WHERE {norm}=?",
                        (legacy,),
                    )
                    conn.commit()
                    cleared = cur.rowcount
                    if cleared > 0:
                        self._record_admin_action(
                            "clear-legacy-cd-keys",
                            product,
                            username=f"{cleared} account(s)",
                        )
                    return {
                        "ok": True,
                        "cleared": cleared,
                        "message": (
                            f"Cleared the legacy shared key from {cleared} account(s)."
                            if cleared
                            else "No accounts were bound to the legacy key."
                        ),
                        "product": product_key,
                    }
                finally:
                    conn.close()

            return {"ok": False, "error": "unknown endpoint"}
        except Exception as exc:
            LOGGER.warning("Admin POST %s failed: %s", path, exc)
            return {"ok": False, "error": str(exc)}

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            raw = await reader.readuntil(b"\r\n\r\n")
        except asyncio.IncompleteReadError:
            await self._close_writer(writer)
            return
        except asyncio.LimitOverrunError:
            writer.write(self._http_response(b"request header too large", "text/plain; charset=utf-8", "413 Payload Too Large"))
            await writer.drain()
            await self._close_writer(writer)
            return

        request_text = raw.decode("iso-8859-1", errors="replace")
        headers = self._parse_headers(request_text)
        first_line = request_text.splitlines()[0] if request_text.splitlines() else ""
        parts = first_line.split(" ")
        if len(parts) < 2:
            writer.write(self._http_response(b"bad request", "text/plain; charset=utf-8", "400 Bad Request"))
            await writer.drain()
            await self._close_writer(writer)
            return

        method, target = parts[0], parts[1]
        if method not in ("GET", "POST"):
            writer.write(self._http_response(b"method not allowed", "text/plain; charset=utf-8", "405 Method Not Allowed"))
            await writer.drain()
            await self._close_writer(writer)
            return

        parsed = urlsplit(target)
        query = parse_qs(parsed.query)
        if method == "GET" and self._is_public_probe_path(parsed.path):
            payload = (
                self._health_snapshot()
                if parsed.path.endswith("health")
                else self._readiness_snapshot()
            )
            body = json.dumps(payload, indent=2).encode("utf-8")
            status = "200 OK" if payload.get("ready", payload.get("ok", False)) or parsed.path.endswith("health") else "503 Service Unavailable"
            writer.write(self._http_response(body, "application/json; charset=utf-8", status))
            await writer.drain()
            await self._close_writer(writer)
            return
        if not self._is_authorized(parsed.path, query, headers):
            writer.write(
                self._http_response(
                    b"authentication required",
                    "text/plain; charset=utf-8",
                    "401 Unauthorized",
                    extra_headers=["WWW-Authenticate: Bearer"],
                )
            )
            await writer.drain()
            await self._close_writer(writer)
            return

        if method == "GET":
            web_auth_response = await self._dispatch_web_auth_request(method, target, headers, b"")
            if web_auth_response is not None:
                status_code, response_headers, response_body = web_auth_response
                writer.write(
                    self._http_response(
                        response_body,
                        response_headers.get("content-type", "text/plain; charset=utf-8"),
                        self._status_line(status_code),
                        extra_headers=[f"{key}: {value}" for key, value in response_headers.items() if key.lower() != "content-type"],
                    )
                )
                await writer.drain()
                await self._close_writer(writer)
                return

        if method == "POST":
            content_length = 0
            with contextlib.suppress(TypeError, ValueError):
                content_length = int(headers.get("content-length", "0"))
            if content_length < 0 or content_length > 65536:
                writer.write(self._http_response(b"bad content length", "text/plain; charset=utf-8", "400 Bad Request"))
                await writer.drain()
                await self._close_writer(writer)
                return
            body_raw = b""
            if content_length > 0:
                try:
                    body_raw = await asyncio.wait_for(reader.readexactly(content_length), timeout=5.0)
                except Exception:
                    writer.write(self._http_response(b"failed to read body", "text/plain; charset=utf-8", "400 Bad Request"))
                    await writer.drain()
                    await self._close_writer(writer)
                    return
            web_auth_response = await self._dispatch_web_auth_request(method, target, headers, body_raw)
            if web_auth_response is not None:
                status_code, response_headers, response_body = web_auth_response
                writer.write(
                    self._http_response(
                        response_body,
                        response_headers.get("content-type", "text/plain; charset=utf-8"),
                        self._status_line(status_code),
                        extra_headers=[
                            f"{key}: {value}" for key, value in response_headers.items() if key.lower() != "content-type"
                        ],
                    )
                )
                await writer.drain()
                await self._close_writer(writer)
                return
            try:
                body_json = json.loads(body_raw) if body_raw else {}
            except json.JSONDecodeError:
                writer.write(self._http_response(b"invalid json", "text/plain; charset=utf-8", "400 Bad Request"))
                await writer.drain()
                await self._close_writer(writer)
                return
            resp = await self._handle_admin_post(parsed.path, body_json)
            resp_body = json.dumps(resp).encode("utf-8")
            status_code = "200 OK" if resp.get("ok") else "400 Bad Request"
            writer.write(self._http_response(resp_body, "application/json; charset=utf-8", status_code))
            await writer.drain()
            await self._close_writer(writer)
            return

        # GET requests
        rows = 25
        log_limit = 200
        activity_limit = 150
        with contextlib.suppress(TypeError, ValueError):
            rows = max(1, min(250, int(query.get("rows", ["25"])[0] or "25")))
        with contextlib.suppress(TypeError, ValueError):
            log_limit = max(1, min(1000, int(query.get("logs", ["200"])[0] or "200")))
        with contextlib.suppress(TypeError, ValueError):
            activity_limit = max(1, min(500, int(query.get("activity", ["150"])[0] or "150")))

        if parsed.path == "/api/snapshot":
            body = json.dumps(
                self.snapshot(
                    rows_per_table=rows,
                    log_limit=log_limit,
                    activity_limit=activity_limit,
                ),
                indent=2,
            ).encode("utf-8")
            writer.write(self._http_response(body, "application/json; charset=utf-8"))
        elif parsed.path == "/api/stats":
            body = json.dumps(self.gateway.stats_snapshot(), indent=2).encode("utf-8")
            writer.write(self._http_response(body, "application/json; charset=utf-8"))
        elif parsed.path == "/api/accounts":
            acct_product = str(query.get("product", [""])[0] or "")
            acct_q = str(query.get("q", [""])[0] or "")
            acct_offset = 0
            acct_limit = 50
            with contextlib.suppress(TypeError, ValueError):
                acct_offset = max(0, int(query.get("offset", ["0"])[0] or "0"))
            with contextlib.suppress(TypeError, ValueError):
                acct_limit = max(1, min(200, int(query.get("limit", ["50"])[0] or "50")))
            body = json.dumps(
                self._accounts_page(acct_product, acct_q, acct_offset, acct_limit)
            ).encode("utf-8")
            writer.write(self._http_response(body, "application/json; charset=utf-8"))
        elif parsed.path == "/api/replay-journal":
            match_id = str(query.get("match_id", [""])[0] or "")
            read_journal = getattr(self.gateway, "read_replay_journal", None)
            body = read_journal(match_id) if callable(read_journal) else None
            if body is None:
                writer.write(self._http_response(b"journal not found", "text/plain; charset=utf-8", "404 Not Found"))
            else:
                writer.write(self._http_response(body, "application/x-ndjson; charset=utf-8"))
        elif parsed.path == "/api/live-feed":
            subscribe = getattr(self.gateway, "subscribe_live_feed", None)
            unsubscribe = getattr(self.gateway, "unsubscribe_live_feed", None)
            if not callable(subscribe) or not callable(unsubscribe):
                writer.write(
                    self._http_response(
                        b"live feed unavailable",
                        "text/plain; charset=utf-8",
                        "501 Not Implemented",
                    )
                )
                await writer.drain()
                await self._close_writer(writer)
                return

            queue = subscribe()
            writer.write(self._http_event_stream_headers())
            await writer.drain()
            try:
                hello = {
                    "event": "ready",
                    "ts": time.time(),
                    "service": "admin-live-feed",
                }
                writer.write(self._sse_frame("ready", hello))
                await writer.drain()
                while True:
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=15.0)
                    except asyncio.TimeoutError:
                        writer.write(b": heartbeat\n\n")
                        await writer.drain()
                        continue
                    event_name = str(event.get("event") or "message")
                    event_id = str(event.get("id") or "")
                    writer.write(self._sse_frame(event_name, dict(event), event_id=event_id))
                    await writer.drain()
            except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, asyncio.CancelledError):
                pass
            finally:
                unsubscribe(queue)
                await self._close_writer(writer)
            return
        elif parsed.path == "/":
            writer.write(
                self._http_response(
                    self._html(
                        str(query.get("token", [""])[0] or ""),
                        identity=self._forward_auth_identity(headers),
                    ).encode("utf-8"),
                    "text/html; charset=utf-8",
                )
            )
        else:
            writer.write(self._http_response(b"not found", "text/plain; charset=utf-8", "404 Not Found"))

        await writer.drain()
        await self._close_writer(writer)


