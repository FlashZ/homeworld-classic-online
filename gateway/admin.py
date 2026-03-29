from __future__ import annotations

import asyncio
from collections import deque
import contextlib
import hashlib
import json
import logging
from pathlib import Path
import secrets
import sqlite3
import time
from typing import TYPE_CHECKING, Any, Deque, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlsplit

from .repo_monitor import GitRepoMonitor

if TYPE_CHECKING:
    from .titan_service import BinaryGatewayServer

LOGGER = logging.getLogger(__name__)

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

    def _is_authorized(
        self,
        path: str,
        query: Dict[str, list[str]],
        headers: Dict[str, str],
    ) -> bool:
        if path == "/api/stats":
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
            return not self.stats_token and not self.admin_token

        return self._matches_token(
            self.admin_token,
            query,
            headers,
            header_names=("x-admin-token",),
        )

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

    def snapshot(
        self,
        rows_per_table: int = 25,
        log_limit: int = 200,
        activity_limit: int = 150,
    ) -> Dict[str, object]:
        dbs = self._db_snapshots(rows_per_table=max(1, rows_per_table))
        default_db = (
            dbs.get(self.default_db_product)
            or next(iter(dbs.values()), self._db_snapshot(rows_per_table=max(1, rows_per_table)))
        )
        return {
            "generated_at": time.time(),
            "uptime_seconds": int(time.time() - self.started_at),
            "gateway": self.gateway.dashboard_snapshot(activity_limit=max(1, activity_limit)),
            "repo": self.repo_monitor.snapshot(),
            "db": default_db,
            "dbs": dbs,
            "db_default_product": self.default_db_product,
            "logs": self.log_handler.snapshot(limit=max(1, log_limit)),
        }

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

    def _html(self, embedded_token: str = "") -> str:
        return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>WON Admin</title>
  <style>
    :root {
      --bg-0:#09090b;--bg-1:#111113;--bg-2:#1a1a1e;--bg-3:#252529;
      --border:#2e2e33;--border-active:#3e3e44;
      --text-0:#fafafa;--text-1:#a1a1aa;--text-2:#71717a;
      --accent:#3b82f6;--accent-hover:#2563eb;
      --success:#22c55e;--warning:#eab308;--danger:#ef4444;--danger-hover:#dc2626;
    }
    *{box-sizing:border-box;margin:0;padding:0;}
    body{font-family:Inter,-apple-system,system-ui,sans-serif;background:var(--bg-1);color:var(--text-0);display:flex;height:100vh;overflow:hidden;}
    .sidebar{width:220px;background:var(--bg-0);border-right:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0;}
    .brand{padding:20px 16px 16px;font-size:15px;font-weight:700;letter-spacing:-.3px;color:var(--text-0);border-bottom:1px solid var(--border);}
    .brand span{color:var(--accent);font-weight:800;}
    .sidebar nav{flex:1;padding:8px;overflow-y:auto;}
    .nav-item{display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:6px;cursor:pointer;font-size:13px;color:var(--text-1);transition:all .15s;border:none;background:none;width:100%;text-align:left;}
    .nav-item:hover{background:var(--bg-2);color:var(--text-0);}
    .nav-item.active{background:var(--bg-3);color:var(--text-0);font-weight:600;}
    .nav-item svg{width:16px;height:16px;flex-shrink:0;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;}
    .nav-badge{margin-left:auto;background:var(--bg-3);color:var(--text-1);font-size:11px;padding:1px 6px;border-radius:99px;min-width:18px;text-align:center;}
    .nav-item.active .nav-badge{background:var(--accent);color:#fff;}
    .sidebar-footer{padding:12px 16px;border-top:1px solid var(--border);font-size:11px;color:var(--text-2);}
    .sidebar-footer .status-dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px;}
    .sidebar-footer .status-dot.ok{background:var(--success);}
    .sidebar-footer .status-dot.err{background:var(--danger);}
    .main-wrap{flex:1;display:flex;flex-direction:column;overflow:hidden;}
    .topbar{padding:14px 24px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;background:var(--bg-1);flex-shrink:0;}
    .topbar h1{font-size:16px;font-weight:600;}
    .topbar .meta{font-size:12px;color:var(--text-2);}
    #content{flex:1;overflow-y:auto;padding:20px 24px 32px;}
    .stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:16px;}
    .stat-card{background:var(--bg-2);border:1px solid var(--border);border-radius:8px;padding:16px;}
    .stat-card .label{font-size:12px;color:var(--text-2);margin-bottom:4px;text-transform:uppercase;letter-spacing:.5px;}
    .stat-card .value{font-size:28px;font-weight:700;line-height:1.2;}
    .stat-card .value.accent{color:var(--accent);}
    .stat-card .value.success{color:var(--success);}
    .stat-card .value.warning{color:var(--warning);}
    .card{background:var(--bg-2);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:12px;}
    .card h2{font-size:14px;font-weight:600;margin-bottom:12px;display:flex;align-items:center;gap:8px;}
    .card h3{font-size:13px;font-weight:600;margin:12px 0 8px;color:var(--text-1);}
    .card-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:12px;}
    .kv{display:grid;grid-template-columns:140px minmax(0,1fr);gap:4px 12px;font-size:13px;}
    .kv .k{color:var(--text-2);}
    .kv .v{color:var(--text-0);word-break:break-all;}
    .badge{display:inline-block;padding:2px 8px;border-radius:99px;font-size:11px;font-weight:600;}
    .badge-join{background:rgba(34,197,94,.15);color:var(--success);}
    .badge-leave{background:rgba(239,68,68,.15);color:var(--danger);}
    .badge-chat{background:rgba(59,130,246,.15);color:var(--accent);}
    .badge-default{background:var(--bg-3);color:var(--text-1);}
    .pill{display:inline-block;padding:2px 8px;border-radius:99px;font-size:11px;background:var(--bg-3);color:var(--text-1);margin-left:6px;}
    .table-wrap{width:100%;overflow-x:auto;}
    table{width:100%;border-collapse:collapse;font-size:13px;}
    th{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);color:var(--text-2);font-weight:500;font-size:12px;text-transform:uppercase;letter-spacing:.3px;}
    td{padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top;word-break:break-word;color:var(--text-0);}
    tr:hover td{background:var(--bg-3);}
    .mono{font-family:Consolas,"Courier New",monospace;font-size:12px;}
    .muted{color:var(--text-2);}
    pre{margin:8px 0 0;padding:14px;background:var(--bg-0);border:1px solid var(--border);border-radius:6px;overflow:auto;font-size:12px;line-height:1.5;max-height:65vh;white-space:pre-wrap;overflow-wrap:anywhere;color:var(--text-1);font-family:Consolas,"Courier New",monospace;}
    .log-error{color:var(--danger);}
    .log-warn{color:var(--warning);}
    .log-info{color:var(--text-1);}
    .btn{display:inline-flex;align-items:center;gap:5px;padding:5px 12px;border-radius:6px;font-size:12px;font-weight:500;cursor:pointer;border:1px solid var(--border);background:var(--bg-3);color:var(--text-0);transition:all .15s;}
    .btn:hover{background:var(--border-active);border-color:var(--border-active);}
    .btn-danger{border-color:var(--danger);color:var(--danger);background:transparent;}
    .btn-danger:hover{background:var(--danger);color:#fff;}
    .btn-accent{border-color:var(--accent);color:#fff;background:var(--accent);}
    .btn-accent:hover{background:var(--accent-hover);}
    .btn-sm{padding:3px 8px;font-size:11px;}
    .action-bar{display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap;}
    .action-bar input[type=text]{flex:1;min-width:200px;padding:6px 10px;border-radius:6px;border:1px solid var(--border);background:var(--bg-0);color:var(--text-0);font-size:13px;outline:none;}
    .action-bar input[type=text]:focus{border-color:var(--accent);}
    .action-bar select{padding:6px 10px;border-radius:6px;border:1px solid var(--border);background:var(--bg-0);color:var(--text-0);font-size:13px;outline:none;}
    details{margin-top:8px;}
    details summary{cursor:pointer;font-weight:600;font-size:13px;color:var(--text-1);padding:6px 0;}
    details summary:hover{color:var(--text-0);}
    details[open] summary{margin-bottom:8px;}
    .hw-strong{font-weight:700;color:var(--accent);}
    .db-tabs{display:flex;gap:4px;flex-wrap:wrap;margin-bottom:12px;}
    .db-tab{padding:4px 10px;border-radius:6px;font-size:12px;cursor:pointer;background:var(--bg-0);color:var(--text-2);border:1px solid transparent;}
    .db-tab:hover{color:var(--text-0);}
    .db-tab.active{background:var(--bg-3);color:var(--text-0);border-color:var(--border);}
    #modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:100;align-items:center;justify-content:center;}
    #modal-overlay.show{display:flex;}
    .modal-box{background:var(--bg-2);border:1px solid var(--border);border-radius:10px;padding:20px;width:420px;max-width:90vw;}
    .modal-box h3{font-size:15px;margin-bottom:12px;}
    .modal-box p{font-size:13px;color:var(--text-1);margin-bottom:16px;line-height:1.5;}
    .modal-box .modal-actions{display:flex;gap:8px;justify-content:flex-end;}
    .modal-box input[type=text],.modal-box input[type=password]{width:100%;padding:7px 10px;border-radius:6px;border:1px solid var(--border);background:var(--bg-0);color:var(--text-0);font-size:13px;margin-bottom:12px;outline:none;}
    .modal-box input:focus{border-color:var(--accent);}
    #toast-container{position:fixed;bottom:16px;right:16px;z-index:200;display:flex;flex-direction:column;gap:8px;}
    .toast{padding:10px 16px;border-radius:8px;font-size:13px;font-weight:500;animation:toastin .25s ease;min-width:200px;}
    .toast-success{background:#14532d;color:var(--success);border:1px solid #166534;}
    .toast-error{background:#450a0a;color:var(--danger);border:1px solid #7f1d1d;}
    @keyframes toastin{from{opacity:0;transform:translateY(10px);}to{opacity:1;transform:translateY(0);}}
    @media(max-width:760px){.sidebar{display:none;}.card-grid{grid-template-columns:1fr;}}
  </style>
</head>
<body>
  <aside class="sidebar">
    <div class="brand"><span>WON</span> Admin</div>
    <nav id="nav"></nav>
    <div class="sidebar-footer" id="sidebar-footer">Loading...</div>
  </aside>
  <div class="main-wrap">
    <header class="topbar">
      <h1 id="page-title">Overview</h1>
      <div class="meta" id="topbar-meta">Loading...</div>
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
    const sidebarFooter = document.getElementById("sidebar-footer");
    const modalOverlay = document.getElementById("modal-overlay");
    const modalBox = document.getElementById("modal-box");
    const toastContainer = document.getElementById("toast-container");
    const adminToken = __ADMIN_TOKEN__;
    let activePage = "overview";
    let pauseRefresh = false;
    let pauseRefreshUntil = 0;
    let pointerInteractionActive = false;
    let lastSnapshot = null;
    let activeDbProduct = "";
    let activeDbTable = "";
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
      {id:"players",label:"Players",icon:'<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>'},
      {id:"rooms",label:"Rooms",icon:'<rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>'},
      {id:"activity",label:"Activity",icon:'<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>'},
      {id:"ips",label:"IP Metrics",icon:'<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'},
      {id:"database",label:"Database",icon:'<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>'},
      {id:"sessions",label:"Sessions",icon:'<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>'},
      {id:"logs",label:"Logs",icon:'<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>'},
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
    function productBadge(product){
      const name=String(product||"").trim();
      if(!name||name==="shared-edge")return "";
      return `<span class="pill" style="margin-left:0;margin-right:6px;">${esc(name)}</span>`;
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
        backend_host: gw.backend_host||"",
        backend_port: gw.backend_port||0,
        version_str: gw.version_str||"",
        valid_versions: gw.valid_versions||[],
      };
    }
    function rowProduct(snapshot,row){
      const product=String((row&&row.product)||"").trim();
      return product||defaultSnapshotProduct(snapshot)||"unknown";
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
      if(uiState.pageId===activePage&&activePage!=="logs"){
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
    function repoSummary(repo){
      if(!repo||!repo.available)return '<span class="muted">Git metadata unavailable.</span>';
      let label="Up to date",color="var(--success)";
      if(repo.last_error){label="Check failed";color="var(--danger)";}
      else if(repo.status==="diverged"){label="Diverged";color="var(--danger)";}
      else if(repo.status==="ahead"){label="Local ahead";color="var(--warning)";}
      else if(repo.status==="no_upstream"){label="No upstream";color="var(--warning)";}
      else if(repo.update_available){label="Update available";color="var(--warning)";}
      const dirty=repo.dirty?` <span class="pill">dirty</span>`:"";
      return `<span style="color:${color};font-weight:600;">${esc(label)}</span>${dirty}`;
    }

    function renderNav(snapshot){
      const gw=snapshot.gateway||{};const rt=gw.routing_manager||{};const act=gw.activity||[];const logs=snapshot.logs||[];
      const counts={players:rt.current_player_count||0,rooms:rt.room_count||0,activity:act.length,logs:logs.length};
      nav.innerHTML=pages.map(p=>{
        const badge=counts[p.id]!=null?`<span class="nav-badge">${counts[p.id]}</span>`:"";
        return `<button class="nav-item${activePage===p.id?" active":""}" data-page="${p.id}"><svg viewBox="0 0 24 24">${p.icon}</svg>${esc(p.label)}${badge}</button>`;
      }).join("");
      nav.querySelectorAll("[data-page]").forEach(btn=>{btn.addEventListener("click",()=>{activePage=btn.dataset.page;renderAll(lastSnapshot);});});
    }

    function renderSidebarFooter(snapshot){
      const up=snapshot.uptime_seconds||0;
      const gw=snapshot.gateway||{};
      const repo=snapshot.repo||{};
      const extra=repo.local_version?`<br>${esc(repo.local_version)}${repo.update_available?' &middot; update available':''}`:"";
      sidebarFooter.innerHTML=`<span class="status-dot ok"></span> Online ${age(up)}<br>${esc(gw.product||"")} &middot; ${esc(gw.version_str||"")} &middot; ${esc(gw.public_host||"")}${extra}`;
    }

    function renderTopbar(snapshot){
      const p=pages.find(x=>x.id===activePage);
      pageTitle.textContent=p?p.label:"Dashboard";
      topbarMeta.textContent="Last refresh: "+new Date((snapshot.generated_at||0)*1000).toLocaleTimeString();
    }

    function renderOverview(snapshot){
      const gw=snapshot.gateway||{};const rt=gw.routing_manager||{};const am=gw.activity_metrics||{};const db=snapshot.db||{};const repo=snapshot.repo||{};
      const metrics=productMetrics(snapshot);
      const gameStats=metrics.overall;
      const banned=gw.banned_ips||[];
      const productCards=metrics.keys.map(product=>{
        const bucket=metrics.byProduct[product];
        const info=bucket.info||{};
        return `<div class="card">
          <h2>${productBadge(product)}${esc(info.community_name||product)}</h2>
          <div class="kv">
            <div class="k">Directory Root</div><div class="v">${esc(info.directory_root||"")}</div>
            <div class="k">Routing Port</div><div class="v">${esc(info.routing_port||0)}</div>
            <div class="k">Backend</div><div class="v">${esc(info.backend_host||"")}:${esc(info.backend_port||0)}</div>
            <div class="k">Version</div><div class="v">${esc(info.version_str||"")}</div>
            <div class="k">Valid Versions</div><div class="v">${(info.valid_versions||[]).map(v=>`<span class="pill" style="margin-left:0;margin-right:4px;">${esc(v)}</span>`).join("")||'<span class="muted">n/a</span>'}</div>
            <div class="k">Players Online</div><div class="v">${esc(bucket.playersOnline)}</div>
            <div class="k">Players In Game</div><div class="v">${esc(bucket.playersInGame)}</div>
            <div class="k">Players In Lobby</div><div class="v">${esc(bucket.playersInLobby)}</div>
            <div class="k">Reconnect Holds</div><div class="v">${esc(bucket.reconnecting)}</div>
            <div class="k">Active Rooms</div><div class="v">${esc(bucket.activeRooms)}</div>
            <div class="k">Game Rooms</div><div class="v">${esc(bucket.gameRooms)}</div>
            <div class="k">Live Games</div><div class="v">${esc(bucket.liveGames)}</div>
            <div class="k">Unique IPs</div><div class="v">${esc(bucket.uniqueIps)}</div>
            <div class="k">IPs Seen</div><div class="v">${esc(bucket.totalIpsSeen)}</div>
            <div class="k">Peer Data Msgs</div><div class="v">${esc(bucket.peerMsgs)}</div>
            <div class="k">Peer Data Bytes</div><div class="v">${esc(bucket.peerBytes)}</div>
            <div class="k">Game Obj Bytes</div><div class="v">${esc(bucket.gameObjectBytes)}</div>
            <div class="k">Joins / Leaves</div><div class="v">${esc(bucket.joins)} / ${esc(bucket.leaves)}</div>
            <div class="k">Chat / Broadcasts</div><div class="v">${esc(bucket.chats)} / ${esc(bucket.broadcasts)}</div>
          </div>
        </div>`;
      }).join("");
      return `
        <div class="stat-grid">
          <div class="stat-card"><div class="label">Players Online</div><div class="value accent">${esc(gameStats.playersOnline)}</div></div>
          <div class="stat-card"><div class="label">Players In Game</div><div class="value success">${esc(gameStats.playersInGame)}</div></div>
          <div class="stat-card"><div class="label">Players In Lobby</div><div class="value">${esc(gameStats.playersInLobby)}</div></div>
          <div class="stat-card"><div class="label">Reconnecting</div><div class="value warning">${esc(gameStats.reconnecting)}</div></div>
          <div class="stat-card"><div class="label">Active Rooms</div><div class="value">${esc(gameStats.activeRooms||rt.room_count||0)}</div></div>
          <div class="stat-card"><div class="label">Game Rooms</div><div class="value">${esc(gameStats.gameRooms)}</div></div>
          <div class="stat-card"><div class="label">Live Games</div><div class="value success">${esc(gameStats.liveGames)}</div></div>
          <div class="stat-card"><div class="label">Unique IPs</div><div class="value">${esc(gameStats.uniqueIps||rt.current_unique_ip_count||0)}</div></div>
          <div class="stat-card"><div class="label">Peer Data</div><div class="value">${esc(gameStats.peerBytes)}<span style="font-size:13px;color:var(--text-2);margin-left:6px;">bytes</span></div></div>
          <div class="stat-card"><div class="label">Game Obj Bytes</div><div class="value">${esc(gameStats.gameObjectBytes)}<span style="font-size:13px;color:var(--text-2);margin-left:6px;">bytes</span></div></div>
        </div>
        ${productCards?`<div class="card">
          <h2>Per-Product Live Status</h2>
          <div class="card-grid">${productCards}</div>
        </div>`:""}
        <div class="card-grid">
          <div class="card">
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
          </div>
          <div class="card">
            <h2>GitHub Updates</h2>
            <div class="action-bar">
              <button class="btn" data-action="github-check">Check GitHub</button>
              <button class="btn ${repo.can_update?'btn-accent':''}" data-action="github-update">Update From GitHub</button>
            </div>
            <div class="kv">
              <div class="k">Status</div><div class="v">${repoSummary(repo)}</div>
              <div class="k">Branch</div><div class="v">${esc(repo.branch||"")}</div>
              <div class="k">Upstream</div><div class="v">${esc(repo.upstream||"")}</div>
              <div class="k">Local Version</div><div class="v">${esc(repo.local_version||repo.local_short||"")}</div>
              <div class="k">GitHub Version</div><div class="v">${esc(repo.remote_version||repo.remote_short||"")}</div>
              <div class="k">Ahead / Behind</div><div class="v">${esc(repo.ahead||0)} / ${esc(repo.behind||0)}</div>
              <div class="k">Last Checked</div><div class="v">${repo.last_checked_at?esc(new Date(repo.last_checked_at*1000).toLocaleString()):"Never"}</div>
              <div class="k">Last Updated</div><div class="v">${repo.last_update_at?esc(new Date(repo.last_update_at*1000).toLocaleString()):"Never"}</div>
              <div class="k">Remote</div><div class="v">${esc(repo.remote_url||"")}</div>
            </div>
            ${repo.last_error?`<p class="muted" style="margin-top:12px;color:var(--danger);">${esc(repo.last_error)}</p>`:""}
            ${repo.last_update_message?`<p class="muted" style="margin-top:12px;">${esc(repo.last_update_message)}</p>`:""}
            ${repo.restart_required?`<p class="muted" style="margin-top:8px;color:var(--warning);">Restart the gateway service to apply the updated code.</p>`:""}
          </div>
        </div>
        ${banned.length?`
        <div class="card">
          <h2>Banned IPs <span class="pill">${banned.length}</span></h2>
          <div class="table-wrap"><table>
            <thead><tr><th>IP</th><th>Reason</th><th style="width:80px">Action</th></tr></thead>
            <tbody>${banned.map(b=>`<tr><td class="mono">${esc(b.ip)}</td><td>${esc(b.reason)}</td><td><button class="btn btn-sm" data-action="unban-ip" data-ip="${esc(b.ip)}">Unban</button></td></tr>`).join("")}</tbody>
          </table></div>
        </div>`:""}`;
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
      return metrics.keys.map(product=>{
        const info=snapshotProductInfo(snapshot,product);
        const bucket=metrics.byProduct[product];
        const rows=grouped[product]||[];
        return `<div class="card"><h2>${productBadge(product)}${esc(info.community_name||product)} <span class="pill">${rows.length}</span></h2>
          <p class="muted" style="margin-bottom:12px;">${esc(bucket.playersInGame)} in game, ${esc(bucket.playersInLobby)} in lobby, ${esc(bucket.uniqueIps)} unique IPs.</p>
          ${rows.length?`<div class="table-wrap"><table>
            <thead><tr><th>Player</th><th>State</th><th>IP</th><th>Room</th><th>Chat</th><th>Connected</th><th>Idle</th><th style="width:120px">Actions</th></tr></thead>
            <tbody>${rows.map(p=>{
              const isGameRoom=!!metrics.roomStateByKey.get(`${product}:${Number(p.room_port||0)}`);
              return `<tr>
                <td>${hwMarkup(p.client_name)}</td>
                <td>${isGameRoom?'<span class="badge badge-join">game</span>':'<span class="badge badge-default">lobby</span>'}</td>
                <td class="mono">${esc(p.client_ip)}</td>
                <td>${esc(displayRoomName(snapshot,p.room_name,p.room_port,isGameRoom))} <span class="muted">:${esc(p.room_port)}</span></td>
                <td>${esc(p.chat_count)}</td>
                <td>${age(p.connected_seconds)}</td>
                <td>${age(p.idle_seconds)}</td>
                <td><button class="btn btn-danger btn-sm" data-action="kick" data-room-port="${esc(p.room_port)}" data-client-id="${esc(p.client_id)}">Kick</button> <button class="btn btn-danger btn-sm" data-action="ban-ip" data-ip="${esc(p.client_ip)}">Ban</button></td>
              </tr>`;
            }).join("")}</tbody>
          </table></div>`:'<p class="muted">No live players connected for this product.</p>'}
          ${rows.map(p=>{
            const isGameRoom=!!metrics.roomStateByKey.get(`${product}:${Number(p.room_port||0)}`);
            return `<details><summary>${hwMarkup(p.client_name)} <span class="muted">${esc(p.client_ip)} &middot; ${esc(displayRoomName(snapshot,p.room_name,p.room_port,isGameRoom))}:${esc(p.room_port)}</span></summary>
              <div class="kv" style="padding:8px 0;">
                <div class="k">Product</div><div class="v">${esc(product)}</div>
                <div class="k">Client ID</div><div class="v">${esc(p.client_id)}</div>
                <div class="k">Name</div><div class="v">${hwPlain(p.client_name)}</div>
                <div class="k">State</div><div class="v">${isGameRoom?"In Game":"Lobby"}</div>
                <div class="k">Subscriptions</div><div class="v">${esc(p.subscription_count)}</div>
                <div class="k">Peer Data Msgs</div><div class="v">${esc(p.peer_data_messages)}</div>
                <div class="k">Peer Data Bytes</div><div class="v">${esc(p.peer_data_bytes)}</div>
                <div class="k">Last Activity</div><div class="v">${esc(p.last_activity_kind)}</div>
              </div></details>`;
          }).join("")}
        </div>`;
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
      return metrics.keys.map(product=>{
        const info=snapshotProductInfo(snapshot,product);
        const bucket=metrics.byProduct[product];
        const rooms=grouped[product]||[];
        return `<div class="card">
          <h2>${productBadge(product)}${esc(info.community_name||product)} Rooms <span class="pill">${rooms.length}</span></h2>
          <p class="muted" style="margin-bottom:12px;">${esc(bucket.activeRooms)} active rooms, ${esc(bucket.gameRooms)} active game rooms, ${esc(bucket.reconnecting)} reconnect holds.</p>
          ${rooms.length?rooms.map(room=>{
            const isGameRoom=!!room.is_game_room||Number(room.active_game_count||0)>0;
            const roomName=displayRoomName(snapshot,room.room_name,room.listen_port,isGameRoom);
            const peerMsgs=Number(room.peer_data_messages||0);
            const peerBytes=Number(room.peer_data_bytes||0);
            const gameBytes=(room.games||[]).reduce((sum,g)=>sum+Number(g.data_len||0),0);
            const activeGames=Number(room.active_game_count||0);
            return `<div class="card" style="margin-bottom:12px;">
              <h2>${esc(roomName)} <span class="muted" style="font-weight:400;font-size:12px;">:${esc(room.listen_port)}</span> <span class="pill">${esc(room.player_count)} players</span> <span class="pill">${esc(activeGames)} games</span></h2>
              <div class="kv">
                <div class="k">Description</div><div class="v">${esc(room.room_description)}</div>
                <div class="k">Path</div><div class="v">${esc(room.room_path)}</div>
                <div class="k">Room Type</div><div class="v">${isGameRoom?"Game Routing":"Lobby / Published"}</div>
                <div class="k">Published</div><div class="v">${esc(room.published)}</div>
                <div class="k">Password Set</div><div class="v">${esc(room.room_password_set)}</div>
                <div class="k">Flags</div><div class="v">0x${Number(room.room_flags||0).toString(16)}</div>
                <div class="k">Peer Data Msgs</div><div class="v">${esc(peerMsgs)}</div>
                <div class="k">Peer Data Bytes</div><div class="v">${esc(peerBytes)}</div>
                <div class="k">Game/Object Bytes</div><div class="v">${esc(gameBytes)}</div>
              </div>
              ${(room.players||[]).length?`<h3>Players</h3><div class="table-wrap"><table>
                <thead><tr><th>Name</th><th>IP</th><th>Chat</th><th>Idle</th><th style="width:60px">Action</th></tr></thead>
                <tbody>${room.players.map(p=>`<tr><td>${hwMarkup(p.client_name)}</td><td class="mono">${esc(p.client_ip)}</td><td>${esc(p.chat_count)}</td><td>${age(p.idle_seconds)}</td><td><button class="btn btn-danger btn-sm" data-action="kick" data-room-port="${esc(room.listen_port)}" data-client-id="${esc(p.client_id)}">Kick</button></td></tr>`).join("")}</tbody>
              </table></div>`:'<p class="muted" style="margin-top:8px;">No players in this room.</p>'}
              ${(room.games||[]).length?`<h3>Live Game Objects</h3><div class="table-wrap"><table>
                <thead><tr><th>Name</th><th>Owner</th><th>Link</th><th>Data</th><th>Life</th><th>Preview</th></tr></thead>
                <tbody>${room.games.map(g=>`<tr><td>${esc(g.name)}</td><td>${hwMarkup(g.owner_name||String(g.owner_id))}</td><td>${esc(g.link_id)}</td><td>${esc(g.data_len)} bytes</td><td>${esc(g.lifespan)}</td><td class="mono">${esc(shortHex(g.data_preview_hex,32))}</td></tr>`).join("")}</tbody>
              </table></div>`:`<p class="muted" style="margin-top:8px;">${isGameRoom?"No live game objects.":"No published games."}</p>`}
            </div>`;
          }).join(""):'<p class="muted">No routing rooms for this product.</p>'}
        </div>`;
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
      const summaryCards=metrics.keys.map(product=>{
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
        ${activity.length?metrics.keys.map(product=>{
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
        ${ips.length?metrics.keys.map(product=>{
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
            return "<td>"+esc(v)+"</td>";
          }).join("")}${isUsersTable?`<td><button class="btn btn-sm" data-action="reset-pw" data-product="${esc(activeDbProduct)}" data-username="${esc(r.username)}">Reset PW</button> <button class="btn btn-sm" data-action="clear-cd-key" data-product="${esc(activeDbProduct)}" data-username="${esc(r.username)}">Clear CD Key</button> <button class="btn btn-danger btn-sm" data-action="delete-user" data-product="${esc(activeDbProduct)}" data-username="${esc(r.username)}">Delete</button></td>`:""}</tr>`).join("")}</tbody>
        </table></div>`:'<p class="muted">Table is empty.</p>'}
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
      const productKeys=snapshotProductKeys(snapshot);
      const colored=logs.map(e=>{
        const r=esc(e.rendered||"");
        if(e.level==="ERROR")return '<span class="log-error">'+r+"</span>";
        if(e.level==="WARNING")return '<span class="log-warn">'+r+"</span>";
        return '<span class="log-info">'+r+"</span>";
      }).join("\\n");
      return `<div class="card">
        <h2>Logs <span class="pill">${logs.length}</span></h2>
        <div class="action-bar"><button class="btn btn-danger" data-action="clear-logs">Clear Logs</button></div>
        ${productKeys.length>1?'<p class="muted" style="margin-bottom:12px;">Raw gateway logs are combined across Homeworld and Cataclysm. Use the overview, players, rooms, and activity pages for product-separated live state.</p>':""}
        <pre id="log-pre">${colored||'<span class="muted">No logs yet.</span>'}</pre>
      </div>`;
    }

    function renderAll(snapshot){
      if(!snapshot)return;
      captureUiState();
      lastSnapshot=snapshot;
      renderNav(snapshot);
      renderSidebarFooter(snapshot);
      renderTopbar(snapshot);
      const renderers={overview:renderOverview,players:renderPlayers,rooms:renderRooms,activity:renderActivity,ips:renderIPs,database:renderDatabase,sessions:renderSessions,logs:renderLogs};
      const fn=renderers[activePage]||renderOverview;
      content.innerHTML=fn(snapshot);
      restoreUiState();
      bindDbTabs();
    }
    function bindDbTabs(){
      content.querySelectorAll("[data-db-product]").forEach(btn=>{
        btn.addEventListener("click",()=>{
          activeDbProduct=btn.dataset.dbProduct||"";
          activeDbTable="";
          content.innerHTML=renderDatabase(lastSnapshot);
          bindDbTabs();
        });
      });
      content.querySelectorAll("[data-db-table]").forEach(btn=>{
        btn.addEventListener("click",()=>{
          activeDbTable=btn.dataset.dbTable||"";
          content.innerHTML=renderDatabase(lastSnapshot);
          bindDbTabs();
        });
      });
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
    loop();
  </script>
</body>
</html>""".replace("__ADMIN_TOKEN__", json.dumps(embedded_token))

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
                    return {
                        "ok": cur.rowcount > 0,
                        "error": "" if cur.rowcount > 0 else "user not found",
                        "product": product or self.default_db_product,
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
            writer.close()
            await writer.wait_closed()
            return
        except asyncio.LimitOverrunError:
            writer.write(self._http_response(b"request header too large", "text/plain; charset=utf-8", "413 Payload Too Large"))
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        request_text = raw.decode("iso-8859-1", errors="replace")
        headers = self._parse_headers(request_text)
        first_line = request_text.splitlines()[0] if request_text.splitlines() else ""
        parts = first_line.split(" ")
        if len(parts) < 2:
            writer.write(self._http_response(b"bad request", "text/plain; charset=utf-8", "400 Bad Request"))
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        method, target = parts[0], parts[1]
        if method not in ("GET", "POST"):
            writer.write(self._http_response(b"method not allowed", "text/plain; charset=utf-8", "405 Method Not Allowed"))
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        parsed = urlsplit(target)
        query = parse_qs(parsed.query)
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
            writer.close()
            await writer.wait_closed()
            return

        if method == "POST":
            content_length = 0
            with contextlib.suppress(TypeError, ValueError):
                content_length = int(headers.get("content-length", "0"))
            if content_length < 0 or content_length > 65536:
                writer.write(self._http_response(b"bad content length", "text/plain; charset=utf-8", "400 Bad Request"))
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return
            body_raw = b""
            if content_length > 0:
                try:
                    body_raw = await asyncio.wait_for(reader.readexactly(content_length), timeout=5.0)
                except Exception:
                    writer.write(self._http_response(b"failed to read body", "text/plain; charset=utf-8", "400 Bad Request"))
                    await writer.drain()
                    writer.close()
                    await writer.wait_closed()
                    return
            try:
                body_json = json.loads(body_raw) if body_raw else {}
            except json.JSONDecodeError:
                writer.write(self._http_response(b"invalid json", "text/plain; charset=utf-8", "400 Bad Request"))
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return
            resp = await self._handle_admin_post(parsed.path, body_json)
            resp_body = json.dumps(resp).encode("utf-8")
            status_code = "200 OK" if resp.get("ok") else "400 Bad Request"
            writer.write(self._http_response(resp_body, "application/json; charset=utf-8", status_code))
            await writer.drain()
            writer.close()
            await writer.wait_closed()
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
        elif parsed.path == "/":
            writer.write(
                self._http_response(
                    self._html(str(query.get("token", [""])[0] or "")).encode("utf-8"),
                    "text/html; charset=utf-8",
                )
            )
        else:
            writer.write(self._http_response(b"not found", "text/plain; charset=utf-8", "404 Not Found"))

        await writer.drain()
        writer.close()
        await writer.wait_closed()


