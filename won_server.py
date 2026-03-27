#!/usr/bin/env python3
"""Open-source WON-inspired lobby/matchmaking server with Titan-oriented bridge support."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import ipaddress
import json
import logging
import os
import secrets
import signal
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import won_crypto

LOGGER = logging.getLogger("won_oss_server")

SESSION_TTL_SECONDS = 24 * 60 * 60
RATE_WINDOW_SECONDS = 5 * 60
MAX_LOGIN_ATTEMPTS = 20
MAX_EVENTS_PER_PLAYER = 256
PROTECTED_PATHS: Set[str] = {"/Homeworld", "/TitanServers"}
_login_attempts: Dict[str, List[float]] = {}

# Homeworld/Titan-oriented data object names from TitanInterface.cpp
OBJ_VALID_VERSIONS = "HomeworldValidVersions"
OBJ_DESCRIPTION = "Description"
OBJ_ROOM_FLAGS = "RoomFlags"
OBJ_ROOM_CLIENTCOUNT = "__RSClientCount"
OBJ_FACT_CUR_SERVER_COUNT = "__FactCur_RoutingServHWGame"
OBJ_FACT_TOTAL_SERVER_COUNT = "__FactTotal_RoutingServHWGame"
OBJ_SERVER_UPTIME = "__ServerUptime"
DEFAULT_FACTORY_DISPLAY_NAME = "Melbourne"


def _is_loopback_ip(value: Optional[str]) -> bool:
    if not value:
        return False
    candidate = str(value).strip()
    if not candidate:
        return False
    if candidate.startswith("::ffff:"):
        candidate = candidate[7:]
    if candidate.lower() == "localhost":
        return True
    with contextlib.suppress(ValueError):
        return ipaddress.ip_address(candidate).is_loopback
    return False


@dataclass
class Player:
    player_id: str
    nickname: str
    rating: int = 1000
    regions: Set[str] = field(default_factory=set)


@dataclass
class Lobby:
    lobby_id: str
    name: str
    owner_id: str
    map_name: str
    max_players: int
    region: str
    password: str = ""
    created_at: float = field(default_factory=time.time)
    players: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GameServer:
    server_id: str
    host: str
    port: int
    region: str
    current_players: int
    max_players: int
    game_type: str
    source: str = "manual"
    started_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)


@dataclass
class Factory:
    factory_id: str
    host: str
    region: str
    max_processes: int
    running: int = 0
    total_started: int = 0


@dataclass
class SessionRecord:
    username: str
    created_at: float


class StateStore:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False, timeout=10)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=10000")
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        cur = self.conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
              username TEXT PRIMARY KEY,
              password_hash TEXT NOT NULL,
              created_at REAL NOT NULL,
              native_cd_key TEXT,
              native_login_key TEXT
            );
            CREATE TABLE IF NOT EXISTS players (
              player_id TEXT PRIMARY KEY,
              nickname TEXT NOT NULL,
              rating INTEGER NOT NULL,
              regions TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS lobbies (
              lobby_id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              owner_id TEXT NOT NULL,
              map_name TEXT NOT NULL,
              max_players INTEGER NOT NULL,
              region TEXT NOT NULL,
              password TEXT NOT NULL,
              metadata TEXT NOT NULL,
              created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS lobby_players (
              lobby_id TEXT NOT NULL,
              player_id TEXT NOT NULL,
              position INTEGER NOT NULL,
              PRIMARY KEY (lobby_id, player_id)
            );
            CREATE TABLE IF NOT EXISTS game_servers (
              server_id TEXT PRIMARY KEY,
              host TEXT NOT NULL,
              port INTEGER NOT NULL,
              region TEXT NOT NULL,
              current_players INTEGER NOT NULL,
              max_players INTEGER NOT NULL,
              game_type TEXT NOT NULL,
              source TEXT NOT NULL,
              started_at REAL NOT NULL,
              last_seen REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS factories (
              factory_id TEXT PRIMARY KEY,
              host TEXT NOT NULL,
              region TEXT NOT NULL,
              max_processes INTEGER NOT NULL,
              running INTEGER NOT NULL,
              total_started INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS directory_entities (
              path TEXT NOT NULL,
              entity_name TEXT NOT NULL,
              entity_type TEXT NOT NULL,
              payload TEXT NOT NULL,
              PRIMARY KEY(path, entity_name)
            );
            CREATE TABLE IF NOT EXISTS sessions (
              token TEXT PRIMARY KEY,
              username TEXT NOT NULL,
              created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              seq INTEGER NOT NULL,
              player_id TEXT NOT NULL,
              event_json TEXT NOT NULL
            );
            """
        )
        session_columns = {
            str(row["name"])
            for row in cur.execute("PRAGMA table_info(sessions)")
        }
        user_columns = {
            str(row["name"])
            for row in cur.execute("PRAGMA table_info(users)")
        }
        if "native_cd_key" not in user_columns:
            cur.execute("ALTER TABLE users ADD COLUMN native_cd_key TEXT")
        if "native_login_key" not in user_columns:
            cur.execute("ALTER TABLE users ADD COLUMN native_login_key TEXT")
        if "created_at" not in session_columns:
            cur.execute("ALTER TABLE sessions ADD COLUMN created_at REAL")
        cur.execute(
            "UPDATE sessions SET created_at=? WHERE created_at IS NULL",
            (time.time(),),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()


class WONLikeState:
    def __init__(self, store: StateStore, heartbeat_timeout_s: int = 45) -> None:
        self.store = store
        self.players: Dict[str, Player] = {}
        self.lobbies: Dict[str, Lobby] = {}
        self.game_servers: Dict[str, GameServer] = {}
        self.factories: Dict[str, Factory] = {}
        self.sessions: Dict[str, SessionRecord] = {}
        self.directory: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self.events_by_player: Dict[str, List[Dict[str, Any]]] = {}
        self.route_membership: Dict[str, Set[str]] = {}
        self.protected_paths: Set[str] = set(PROTECTED_PATHS)
        self.event_seq = 0
        self.heartbeat_timeout_s = heartbeat_timeout_s
        self.started_at = time.time()
        self.metrics: Dict[str, int] = {"requests": 0, "errors": 0}
        self._load_from_db()
        self.cleanup_expired_sessions()
        self._bootstrap_directory()

    def _load_from_db(self) -> None:
        cur = self.store.conn.cursor()
        for r in cur.execute("SELECT player_id,nickname,rating,regions FROM players"):
            self.players[r["player_id"]] = Player(r["player_id"], r["nickname"], int(r["rating"]), set(json.loads(r["regions"])))
        for r in cur.execute("SELECT * FROM lobbies"):
            self.lobbies[r["lobby_id"]] = Lobby(
                lobby_id=r["lobby_id"],
                name=r["name"],
                owner_id=r["owner_id"],
                map_name=r["map_name"],
                max_players=int(r["max_players"]),
                region=r["region"],
                password=r["password"],
                metadata=json.loads(r["metadata"]),
                created_at=float(r["created_at"]),
                players=[],
            )
        for r in cur.execute("SELECT lobby_id,player_id,position FROM lobby_players ORDER BY position ASC"):
            if r["lobby_id"] in self.lobbies:
                self.lobbies[r["lobby_id"]].players.append(r["player_id"])
        for lid, lob in self.lobbies.items():
            self.route_membership[lid] = set(lob.players)
        for r in cur.execute("SELECT * FROM game_servers"):
            self.game_servers[r["server_id"]] = GameServer(
                r["server_id"], r["host"], int(r["port"]), r["region"], int(r["current_players"]), int(r["max_players"]),
                r["game_type"], r["source"], float(r["started_at"]), float(r["last_seen"])
            )
        for r in cur.execute("SELECT * FROM factories"):
            self.factories[r["factory_id"]] = Factory(r["factory_id"], r["host"], r["region"], int(r["max_processes"]), int(r["running"]), int(r["total_started"]))
        for r in cur.execute("SELECT path,entity_name,entity_type,payload FROM directory_entities"):
            self.directory.setdefault(r["path"], {})[r["entity_name"]] = {"entity_type": r["entity_type"], "payload": json.loads(r["payload"])}
        for r in cur.execute("SELECT token,username,created_at FROM sessions"):
            created_at = float(r["created_at"] or time.time())
            self.sessions[r["token"]] = SessionRecord(r["username"], created_at)
        for r in cur.execute("SELECT seq,player_id,event_json FROM events ORDER BY seq ASC, id ASC"):
            evt = json.loads(r["event_json"])
            self.events_by_player.setdefault(r["player_id"], []).append(evt)
            self.event_seq = max(self.event_seq, int(r["seq"]))
        for player_id, events in list(self.events_by_player.items()):
            if len(events) > MAX_EVENTS_PER_PLAYER:
                self.events_by_player[player_id] = events[-MAX_EVENTS_PER_PLAYER:]

    @staticmethod
    def _directory_entity_path(path: str, entity_name: str) -> str:
        if path == "/":
            return f"/{entity_name}"
        return f"{path.rstrip('/')}/{entity_name}"

    def _bootstrap_directory(self) -> None:
        self.directory.setdefault("/Homeworld", {})
        titan = self.directory.setdefault("/TitanServers", {})
        defaults = {
            "AuthServer": {"host": "127.0.0.1", "port": 9000},
            "TitanRoutingServer": {"host": "127.0.0.1", "port": 9000},
            "TitanFactoryServer": {
                "host": "127.0.0.1",
                "port": 9000,
                OBJ_DESCRIPTION: DEFAULT_FACTORY_DISPLAY_NAME,
            },
            "TitanFirewallDetector": {"host": "127.0.0.1", "port": 0},
            "TitanEventServer": {"host": "127.0.0.1", "port": 9000},
            OBJ_VALID_VERSIONS: {"versions": ["1.00"]},
        }
        for name, payload in defaults.items():
            entry = titan.setdefault(name, {"entity_type": "service", "payload": payload})
            if name == "TitanFactoryServer":
                existing_payload = entry.get("payload", {})
                if isinstance(existing_payload, dict):
                    existing_payload.setdefault(OBJ_DESCRIPTION, DEFAULT_FACTORY_DISPLAY_NAME)
            self.protected_paths.add(self._directory_entity_path("/TitanServers", name))
        self._persist_directory()

    def _persist_table_replace(self, table: str, rows: List[Tuple[str, ...]], sql: str) -> None:
        cur = self.store.conn.cursor()
        cur.execute(f"DELETE FROM {table}")
        cur.executemany(sql, rows)
        self.store.conn.commit()

    def _persist_players(self) -> None:
        rows = [(p.player_id, p.nickname, p.rating, json.dumps(sorted(p.regions))) for p in self.players.values()]
        self._persist_table_replace("players", rows, "INSERT INTO players(player_id,nickname,rating,regions) VALUES(?,?,?,?)")

    def _persist_lobbies(self) -> None:
        cur = self.store.conn.cursor()
        cur.execute("DELETE FROM lobbies")
        cur.execute("DELETE FROM lobby_players")
        for l in self.lobbies.values():
            cur.execute("INSERT INTO lobbies(lobby_id,name,owner_id,map_name,max_players,region,password,metadata,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                        (l.lobby_id, l.name, l.owner_id, l.map_name, l.max_players, l.region, l.password, json.dumps(l.metadata), l.created_at))
            for idx, pid in enumerate(l.players):
                cur.execute("INSERT INTO lobby_players(lobby_id,player_id,position) VALUES(?,?,?)", (l.lobby_id, pid, idx))
        self.store.conn.commit()

    def _persist_servers(self) -> None:
        rows = [(s.server_id, s.host, s.port, s.region, s.current_players, s.max_players, s.game_type, s.source, s.started_at, s.last_seen) for s in self.game_servers.values()]
        self._persist_table_replace("game_servers", rows, "INSERT INTO game_servers(server_id,host,port,region,current_players,max_players,game_type,source,started_at,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?)")

    def _persist_factories(self) -> None:
        rows = [(f.factory_id, f.host, f.region, f.max_processes, f.running, f.total_started) for f in self.factories.values()]
        self._persist_table_replace("factories", rows, "INSERT INTO factories(factory_id,host,region,max_processes,running,total_started) VALUES(?,?,?,?,?,?)")

    def _persist_directory(self) -> None:
        rows: List[Tuple[str, str, str, str]] = []
        for path, entities in self.directory.items():
            for name, ent in entities.items():
                rows.append((path, name, ent["entity_type"], json.dumps(ent["payload"])))
        self._persist_table_replace("directory_entities", rows, "INSERT INTO directory_entities(path,entity_name,entity_type,payload) VALUES(?,?,?,?)")

    def _persist_sessions(self) -> None:
        rows = [
            (tok, session.username, session.created_at)
            for tok, session in self.sessions.items()
        ]
        self._persist_table_replace("sessions", rows, "INSERT INTO sessions(token,username,created_at) VALUES(?,?,?)")

    def _persist_events(self) -> None:
        rows: List[Tuple[int, str, str]] = []
        for pid, evts in self.events_by_player.items():
            for e in evts:
                rows.append((e["seq"], pid, json.dumps(e)))
        self._persist_table_replace("events", rows, "INSERT INTO events(seq,player_id,event_json) VALUES(?,?,?)")

    def _room_data_objects(self, lobby: Lobby) -> Dict[str, Any]:
        return {
            OBJ_DESCRIPTION: lobby.metadata.get("description", lobby.name),
            OBJ_ROOM_FLAGS: int(lobby.metadata.get("room_flags", 0)),
            OBJ_ROOM_CLIENTCOUNT: len(lobby.players),
            "MapName": lobby.map_name,
            "Region": lobby.region,
        }

    def _factory_data_objects(self, fac: Factory) -> Dict[str, Any]:
        return {
            OBJ_DESCRIPTION: DEFAULT_FACTORY_DISPLAY_NAME,
            OBJ_FACT_CUR_SERVER_COUNT: fac.running,
            OBJ_FACT_TOTAL_SERVER_COUNT: fac.total_started,
            OBJ_SERVER_UPTIME: int(time.time() - self.started_at),
        }

    def _emit_event(self, player_ids: List[str], evt_type: str, payload: Dict[str, Any]) -> None:
        self.event_seq += 1
        event = {"seq": self.event_seq, "type": evt_type, "payload": payload, "ts": time.time()}
        for pid in player_ids:
            events = self.events_by_player.setdefault(pid, [])
            events.append(event)
            if len(events) > MAX_EVENTS_PER_PLAYER:
                del events[:-MAX_EVENTS_PER_PLAYER]
        self._persist_events()

    @staticmethod
    def _hash_password(password: str) -> str:
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    @staticmethod
    def _normalize_native_key(value: str) -> str:
        return "".join(ch for ch in value.upper() if ch.isalnum())

    def create_user(
        self,
        username: str,
        password: str,
        native_cd_key: str = "",
        native_login_key: str = "",
    ) -> None:
        h = self._hash_password(password)
        cur = self.store.conn.cursor()
        cur.execute(
            """
            INSERT INTO users(username,password_hash,created_at,native_cd_key,native_login_key)
            VALUES(?,?,?,?,?)
            """,
            (
                username,
                h,
                time.time(),
                self._normalize_native_key(native_cd_key),
                native_login_key.strip(),
            ),
        )
        self.store.conn.commit()

    @staticmethod
    def _login_attempt_key(username: str, client_ip: Optional[str]) -> str:
        if client_ip:
            return client_ip.strip()
        return f"user:{username.lower()}"

    @staticmethod
    def _prune_login_attempts(key: str, now: float) -> List[float]:
        attempts = [ts for ts in _login_attempts.get(key, []) if now - ts <= RATE_WINDOW_SECONDS]
        if attempts:
            _login_attempts[key] = attempts
        else:
            _login_attempts.pop(key, None)
        return attempts

    def _allow_login_attempt(self, username: str, client_ip: Optional[str]) -> bool:
        now = time.time()
        key = self._login_attempt_key(username, client_ip)
        attempts = self._prune_login_attempts(key, now)
        if len(attempts) >= MAX_LOGIN_ATTEMPTS:
            return False
        attempts.append(now)
        _login_attempts[key] = attempts
        return True

    def cleanup_expired_sessions(self) -> int:
        now = time.time()
        expired_tokens = [
            token
            for token, session in self.sessions.items()
            if now - session.created_at > SESSION_TTL_SECONDS
        ]
        for token in expired_tokens:
            self.sessions.pop(token, None)
        if expired_tokens:
            self._persist_sessions()
        return len(expired_tokens)

    def cleanup_login_attempts(self) -> int:
        now = time.time()
        removed_entries = 0
        for key in list(_login_attempts):
            current = _login_attempts.get(key, [])
            pruned = [ts for ts in current if now - ts <= RATE_WINDOW_SECONDS]
            removed_entries += max(0, len(current) - len(pruned))
            if pruned:
                _login_attempts[key] = pruned
            else:
                _login_attempts.pop(key, None)
        return removed_entries

    def is_session_valid(self, token: str) -> bool:
        session = self.sessions.get(token)
        if session is None:
            return False
        if time.time() - session.created_at > SESSION_TTL_SECONDS:
            self.sessions.pop(token, None)
            self._persist_sessions()
            return False
        return True

    def login(self, username: str, password: str, client_ip: Optional[str] = None) -> str:
        self.cleanup_expired_sessions()
        if not self._allow_login_attempt(username, client_ip):
            raise ValueError("rate_limited")
        cur = self.store.conn.cursor()
        row = cur.execute("SELECT password_hash FROM users WHERE username=?", (username,)).fetchone()
        if row is None:
            self.create_user(username, password)
            row = cur.execute("SELECT password_hash FROM users WHERE username=?", (username,)).fetchone()
        if self._hash_password(password) != row["password_hash"]:
            raise ValueError("invalid_credentials")
        token = f"tok_{secrets.token_hex(16)}"
        self.sessions[token] = SessionRecord(username=username, created_at=time.time())
        self._persist_sessions()
        return token

    def login_native(
        self,
        username: str,
        password: str,
        *,
        cd_key: str = "",
        login_key: str = "",
        client_ip: Optional[str] = None,
        create_account: bool = False,
        new_password: str = "",
    ) -> Dict[str, Any]:
        self.cleanup_expired_sessions()
        username = username.strip()
        if not username:
            raise ValueError("missing_username")
        if not self._allow_login_attempt(username, client_ip):
            raise ValueError("rate_limited")

        normalized_cd_key = self._normalize_native_key(cd_key)
        normalized_login_key = login_key.strip()
        requested_password = new_password if (create_account and new_password) else password
        if not normalized_cd_key:
            raise ValueError("missing_cd_key")
        if not won_crypto.validate_cd_key(won_crypto.CDKEY_PRODUCT_HOMEWORLD, normalized_cd_key):
            raise ValueError("invalid_cd_key")

        cur = self.store.conn.cursor()
        row = cur.execute(
            """
            SELECT password_hash, COALESCE(native_cd_key, '') AS native_cd_key,
                   COALESCE(native_login_key, '') AS native_login_key
            FROM users
            WHERE username=?
            """,
            (username,),
        ).fetchone()

        if row is None:
            if not create_account:
                raise ValueError("create_account_required")
            self.create_user(
                username,
                requested_password,
                native_cd_key=normalized_cd_key,
                native_login_key=normalized_login_key,
            )
            return {
                "username": username,
                "created": True,
                "cd_key_bound": bool(normalized_cd_key),
            }

        if create_account:
            raise ValueError("username_taken")

        if self._hash_password(password) != row["password_hash"]:
            raise ValueError("invalid_credentials")

        existing_cd_key = self._normalize_native_key(str(row["native_cd_key"]))
        binding_changed = False

        if existing_cd_key:
            if normalized_cd_key and normalized_cd_key != existing_cd_key:
                raise ValueError("cd_key_mismatch")
        elif normalized_cd_key:
            cur.execute(
                "UPDATE users SET native_cd_key=? WHERE username=?",
                (normalized_cd_key, username),
            )
            binding_changed = True

        if normalized_login_key and normalized_login_key != str(row["native_login_key"]):
            cur.execute(
                "UPDATE users SET native_login_key=? WHERE username=?",
                (normalized_login_key, username),
            )
            binding_changed = True

        if new_password and new_password != password:
            cur.execute(
                "UPDATE users SET password_hash=? WHERE username=?",
                (self._hash_password(new_password), username),
            )
            binding_changed = True

        if binding_changed:
            self.store.conn.commit()

        return {
            "username": username,
            "created": False,
            "cd_key_bound": bool(existing_cd_key or normalized_cd_key),
            "binding_changed": binding_changed,
        }

    def require_token(self, token: str) -> str:
        if not self.is_session_valid(token):
            raise ValueError("invalid_token")
        return self.sessions[token].username

    def upsert_player(self, player_id: str, nickname: str, rating: int = 1000, regions: Optional[List[str]] = None) -> Player:
        p = self.players.get(player_id) or Player(player_id, nickname, rating, set(regions or []))
        p.nickname = nickname
        p.rating = rating
        if regions:
            p.regions.update(regions)
        self.players[player_id] = p
        self._persist_players()
        return p

    def create_lobby(self, owner_id: str, name: str, map_name: str, max_players: int, region: str, password: str = "", metadata: Optional[Dict[str, Any]] = None) -> Lobby:
        lobby = Lobby(f"lob_{secrets.token_hex(4)}", name, owner_id, map_name, max_players, region, password=password, players=[owner_id], metadata=metadata or {})
        self.lobbies[lobby.lobby_id] = lobby
        self.dir_upsert("/Homeworld", lobby.lobby_id, "routing_room", self._room_data_objects(lobby), internal=True)
        self.route_membership[lobby.lobby_id] = set(lobby.players)
        self._persist_lobbies()
        self._emit_event(lobby.players, "lobby_created", {"lobby_id": lobby.lobby_id})
        return lobby

    def join_lobby(self, lobby_id: str, player_id: str, password: str = "") -> Lobby:
        lobby = self.lobbies[lobby_id]
        if lobby.password and lobby.password != password:
            raise ValueError("invalid_lobby_password")
        if player_id not in lobby.players:
            if len(lobby.players) >= lobby.max_players:
                raise ValueError("lobby_full")
            lobby.players.append(player_id)
        self.dir_upsert("/Homeworld", lobby_id, "routing_room", self._room_data_objects(lobby), internal=True)
        self.route_membership[lobby_id] = set(lobby.players)
        self._persist_lobbies()
        self._emit_event(lobby.players, "lobby_join", {"lobby_id": lobby_id, "player_id": player_id})
        return lobby

    def leave_lobby(self, lobby_id: str, player_id: str) -> None:
        lobby = self.lobbies[lobby_id]
        with contextlib.suppress(ValueError):
            lobby.players.remove(player_id)
        if not lobby.players:
            del self.lobbies[lobby_id]
            with contextlib.suppress(KeyError):
                del self.directory["/Homeworld"][lobby_id]
            self.route_membership.pop(lobby_id, None)
            self._persist_directory()
            self._persist_lobbies()
            return
        if lobby.owner_id == player_id:
            lobby.owner_id = lobby.players[0]
        self.dir_upsert("/Homeworld", lobby_id, "routing_room", self._room_data_objects(lobby), internal=True)
        self.route_membership[lobby_id] = set(lobby.players)
        self._persist_lobbies()
        self._emit_event(lobby.players, "lobby_leave", {"lobby_id": lobby_id, "player_id": player_id})

    def register_server(self, server_id: str, host: str, port: int, region: str, current_players: int, max_players: int, game_type: str, source: str = "manual") -> GameServer:
        now = time.time()
        s = self.game_servers.get(server_id)
        if not s:
            s = GameServer(server_id, host, port, region, current_players, max_players, game_type, source=source, started_at=now, last_seen=now)
            self.game_servers[server_id] = s
        else:
            s.host, s.port, s.region = host, port, region
            s.current_players, s.max_players, s.game_type = current_players, max_players, game_type
            s.source, s.last_seen = source, now
        self._persist_servers()
        return s

    def register_factory(self, factory_id: str, host: str, region: str, max_processes: int) -> Factory:
        fac = self.factories.get(factory_id) or Factory(factory_id, host, region, max_processes)
        fac.host, fac.region, fac.max_processes = host, region, max_processes
        self.factories[factory_id] = fac
        self.dir_upsert("/TitanServers", f"Factory:{factory_id}", "factory", self._factory_data_objects(fac), internal=True)
        self._persist_factories()
        return fac

    def factory_start_process(self, factory_id: str, process_name: str, game_name: str, port: int) -> GameServer:
        fac = self.factories[factory_id]
        if fac.running >= fac.max_processes:
            raise ValueError("factory_capacity_exceeded")
        fac.running += 1
        fac.total_started += 1
        self.dir_upsert("/TitanServers", f"Factory:{factory_id}", "factory", self._factory_data_objects(fac), internal=True)
        self._persist_factories()
        return self.register_server(f"srv_{factory_id}_{secrets.token_hex(3)}", fac.host, port, fac.region, 0, 8, game_name, source=f"factory:{process_name}")

    def factory_process_stopped(self, factory_id: str) -> None:
        fac = self.factories.get(factory_id)
        if not fac:
            return
        fac.running = max(0, fac.running - 1)
        self.dir_upsert("/TitanServers", f"Factory:{factory_id}", "factory", self._factory_data_objects(fac), internal=True)
        self._persist_factories()

    def prune_stale_servers(self) -> int:
        now = time.time()
        stale = [sid for sid, gs in self.game_servers.items() if now - gs.last_seen > self.heartbeat_timeout_s]
        for sid in stale:
            del self.game_servers[sid]
        if stale:
            self._persist_servers()
        return len(stale)

    def list_lobbies(self, region: Optional[str] = None) -> List[Lobby]:
        items = list(self.lobbies.values())
        if region:
            items = [l for l in items if l.region == region]
        return sorted(items, key=lambda l: l.created_at)

    def matchmaking(self, player_id: str, region: Optional[str], game_type: Optional[str], map_name: Optional[str]) -> Dict[str, Any]:
        candidates = list(self.game_servers.values())
        if region:
            candidates = [s for s in candidates if s.region == region]
        if game_type:
            candidates = [s for s in candidates if s.game_type == game_type]
        if not candidates:
            return {"match": None, "reason": "no_servers"}
        lobbies = [l for l in self.lobbies.values() if (not region or l.region == region) and len(l.players) < l.max_players and (not map_name or l.map_name == map_name)]
        if lobbies:
            lobby = sorted(lobbies, key=lambda l: len(l.players), reverse=True)[0]
            self.join_lobby(lobby.lobby_id, player_id)
            return {"match": "lobby", "lobby": serialize_lobby(lobby)}
        server = sorted(candidates, key=lambda s: (s.max_players - s.current_players), reverse=True)[0]
        return {"match": "server", "server": serialize_server(server)}


    def start_game_from_lobby(self, lobby_id: str, requester_id: str, game_port: Optional[int] = None) -> Dict[str, Any]:
        lobby = self.lobbies[lobby_id]
        if lobby.owner_id != requester_id:
            raise ValueError("only_owner_can_start")
        if len(lobby.players) < 2:
            raise ValueError("not_enough_players")

        selected = None
        candidates = [s for s in self.game_servers.values() if s.region == lobby.region]
        if candidates:
            selected = sorted(candidates, key=lambda s: (s.max_players - s.current_players), reverse=True)[0]
        elif self.factories:
            fac = sorted(self.factories.values(), key=lambda f: f.running)[0]
            port = int(game_port or (2300 + fac.running))
            selected = self.factory_start_process(fac.factory_id, "RoutingServHWGame", "homeworld", port)
        else:
            raise ValueError("no_game_capacity")

        selected.current_players = min(selected.max_players, len(lobby.players))
        self._persist_servers()
        launch = {
            "lobby_id": lobby_id,
            "server": serialize_server(selected),
            "players": list(lobby.players),
            "map_name": lobby.map_name,
        }
        self._emit_event(lobby.players, "game_launch", launch)
        return launch

    def dir_upsert(self, path: str, entity_name: str, entity_type: str, payload: Dict[str, Any], internal: bool = False) -> None:
        full_path = self._directory_entity_path(path, entity_name)
        if not internal and (path in self.protected_paths or full_path in self.protected_paths):
            raise ValueError("protected_directory")
        self.directory.setdefault(path, {})[entity_name] = {"entity_type": entity_type, "payload": payload}
        self._persist_directory()

    def dir_list(self, path: str) -> Dict[str, Dict[str, Any]]:
        return self.directory.get(path, {})

    def route_join(self, lobby_id: str, player_id: str) -> None:
        self.join_lobby(lobby_id, player_id)

    def route_set_data_object(self, lobby_id: str, key: str, value: str) -> None:
        lobby = self.lobbies[lobby_id]
        lobby.metadata.setdefault("data_objects", {})[key] = value
        self._persist_lobbies()

    def route_get_data_object(self, lobby_id: str, key: str) -> str:
        lobby = self.lobbies[lobby_id]
        return str(lobby.metadata.get("data_objects", {}).get(key, ""))

    def register_route_client(self, lobby_id: str, player_id: str) -> None:
        lobby = self.lobbies[lobby_id]
        if player_id not in lobby.players:
            raise ValueError("not_in_lobby")
        self.route_membership.setdefault(lobby_id, set()).add(player_id)

    def route_send_chat(self, lobby_id: str, from_player: str, message: str) -> None:
        if from_player not in self.route_membership.get(lobby_id, set()):
            raise ValueError("route_not_registered")
        self._emit_event(self.lobbies[lobby_id].players, "chat", {"lobby_id": lobby_id, "from": from_player, "message": message})

    def poll_events(self, player_id: str, after_seq: int = 0) -> List[Dict[str, Any]]:
        return [e for e in self.events_by_player.get(player_id, []) if e["seq"] > after_seq]


def serialize_lobby(lobby: Lobby) -> Dict[str, Any]:
    return {
        "lobby_id": lobby.lobby_id,
        "name": lobby.name,
        "owner_id": lobby.owner_id,
        "map_name": lobby.map_name,
        "max_players": lobby.max_players,
        "region": lobby.region,
        "players": list(lobby.players),
        "password_protected": bool(lobby.password),
        "metadata": lobby.metadata,
        "created_at": lobby.created_at,
    }


def serialize_server(gs: GameServer) -> Dict[str, Any]:
    return {
        "server_id": gs.server_id,
        "host": gs.host,
        "port": gs.port,
        "region": gs.region,
        "current_players": gs.current_players,
        "max_players": gs.max_players,
        "game_type": gs.game_type,
        "source": gs.source,
        "started_at": gs.started_at,
        "last_seen": gs.last_seen,
        OBJ_SERVER_UPTIME: int(time.time() - gs.started_at),
    }


class WONLikeProtocolServer:
    def __init__(self, state: WONLikeState, shared_secret: str = ""):
        self.state = state
        self.shared_secret = shared_secret.strip()
        self.managed_procs: Dict[str, asyncio.subprocess.Process] = {}

    @staticmethod
    def _client_ip(writer: asyncio.StreamWriter) -> Optional[str]:
        peer = writer.get_extra_info("peername")
        if isinstance(peer, tuple) and peer:
            return str(peer[0])
        return None

    def _request_is_authorized(self, req: Dict[str, Any], client_ip: Optional[str]) -> bool:
        if self.shared_secret:
            supplied = req.get("_backend_secret")
            return isinstance(supplied, str) and secrets.compare_digest(supplied, self.shared_secret)
        return _is_loopback_ip(client_ip)

    async def _spawn_managed_process(self, key: str) -> None:
        # Legacy-friendly placeholder process supervisor; replace cmd with real dedicated binary as needed.
        import sys
        proc = await asyncio.create_subprocess_exec(sys.executable, "-c", "import time; time.sleep(300)")
        self.managed_procs[key] = proc

        async def _waiter() -> None:
            await proc.wait()
            self.managed_procs.pop(key, None)
            if key.startswith("factory:"):
                self.state.factory_process_stopped(key.split(":", 1)[1])

        asyncio.create_task(_waiter())

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        client_ip = self._client_ip(writer)
        try:
            while True:
                raw = await reader.readline()
                if not raw:
                    break
                self.state.metrics["requests"] += 1
                try:
                    decoded = json.loads(raw.decode("utf-8"))
                    if not isinstance(decoded, dict):
                        raise ValueError("invalid_request")
                    req = dict(decoded)
                    if not self._request_is_authorized(req, client_ip):
                        self.state.metrics["errors"] += 1
                        resp = {"ok": False, "error": "unauthorized_backend_request"}
                    else:
                        req.pop("_backend_secret", None)
                        resp = await self.handle_request(req)
                except Exception as exc:
                    self.state.metrics["errors"] += 1
                    resp = {"ok": False, "error": str(exc)}
                writer.write((json.dumps(resp) + "\n").encode("utf-8"))
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    async def handle_request(self, req: Dict[str, Any]) -> Dict[str, Any]:
        action = req.get("action")
        LOGGER.info("action=%s", action)

        if action == "PING":
            return {"ok": True, "pong": int(time.time())}
        if action == "HEALTH":
            return {"ok": True, "uptime_s": int(time.time() - self.state.started_at), "managed_processes": len(self.managed_procs)}
        if action == "METRICS":
            return {"ok": True, "metrics": self.state.metrics, "counts": {"players": len(self.state.players), "lobbies": len(self.state.lobbies), "servers": len(self.state.game_servers), "factories": len(self.state.factories)}}

        if action == "AUTH_LOGIN":
            return {
                "ok": True,
                "token": self.state.login(
                    req["username"],
                    req.get("password", ""),
                    req.get("client_ip"),
                ),
            }
        if action == "AUTH_LOGIN_NATIVE":
            return {
                "ok": True,
                "result": self.state.login_native(
                    req["username"],
                    req.get("password", ""),
                    cd_key=req.get("cd_key", ""),
                    login_key=req.get("login_key", ""),
                    client_ip=req.get("client_ip"),
                    create_account=bool(req.get("create_account", False)),
                    new_password=req.get("new_password", ""),
                ),
            }
        if action == "AUTH_VALIDATE":
            return {"ok": True, "username": self.state.require_token(req["token"])}

        if action == "REGISTER_PLAYER":
            p = self.state.upsert_player(req["player_id"], req.get("nickname", req["player_id"]), int(req.get("rating", 1000)), req.get("regions"))
            return {"ok": True, "player": p.__dict__ | {"regions": sorted(p.regions)}}

        if action == "CREATE_LOBBY":
            self.state.require_token(req["token"])
            lobby = self.state.create_lobby(req["owner_id"], req["name"], req.get("map_name", "unknown"), int(req.get("max_players", 8)), req.get("region", "global"), req.get("password", ""), req.get("metadata"))
            return {"ok": True, "lobby": serialize_lobby(lobby)}
        if action == "JOIN_LOBBY":
            return {"ok": True, "lobby": serialize_lobby(self.state.join_lobby(req["lobby_id"], req["player_id"], req.get("password", "")))}
        if action == "LEAVE_LOBBY":
            self.state.leave_lobby(req["lobby_id"], req["player_id"])
            return {"ok": True}
        if action == "LIST_LOBBIES":
            return {"ok": True, "lobbies": [serialize_lobby(l) for l in self.state.list_lobbies(req.get("region"))]}

        if action == "REGISTER_SERVER":
            gs = self.state.register_server(req["server_id"], req["host"], int(req["port"]), req.get("region", "global"), int(req.get("current_players", 0)), int(req.get("max_players", 8)), req.get("game_type", "homeworld"), req.get("source", "manual"))
            return {"ok": True, "server": serialize_server(gs)}
        if action == "LIST_SERVERS":
            self.state.prune_stale_servers()
            return {"ok": True, "servers": [serialize_server(s) for s in self.state.game_servers.values()]}
        if action == "MATCHMAKE":
            return {"ok": True, "ticket": self.state.matchmaking(req["player_id"], req.get("region"), req.get("game_type"), req.get("map_name"))}

        if action == "DIR_LIST":
            return {"ok": True, "path": req["path"], "entities": self.state.dir_list(req["path"])}
        if action == "DIR_UPSERT":
            self.state.dir_upsert(req["path"], req["entity_name"], req.get("entity_type", "generic"), req.get("payload", {}))
            return {"ok": True}

        if action == "ROUTE_SEND_CHAT":
            self.state.route_send_chat(req["lobby_id"], req["from_player"], req["message"])
            return {"ok": True}
        if action == "ROUTE_POLL":
            return {"ok": True, "events": self.state.poll_events(req["player_id"], int(req.get("after_seq", 0)))}

        if action == "REGISTER_FACTORY":
            return {"ok": True, "factory": self.state.register_factory(req["factory_id"], req["host"], req.get("region", "global"), int(req.get("max_processes", 4))).__dict__}
        if action == "FACTORY_START_PROCESS":
            gs = self.state.factory_start_process(req["factory_id"], req.get("process_name", "RoutingServHWGame"), req.get("game_name", "homeworld"), int(req["port"]))
            await self._spawn_managed_process(f"factory:{req['factory_id']}")
            return {"ok": True, "server": serialize_server(gs)}

        # stricter bridge/Titan-style mapped actions
        if action == "TITAN_DIR_GET":
            return {"ok": True, "entities": self.state.dir_list(req["path"])}
        if action == "TITAN_ROUTE_CHAT":
            self.state.route_send_chat(req["lobby_id"], req["from_player"], req["message"])
            return {"ok": True}
        if action == "TITAN_ROUTE_REGISTER":
            self.state.register_route_client(req["lobby_id"], req["player_id"])
            return {"ok": True, "registered": req.get("player_id"), "lobby_id": req.get("lobby_id")}
        if action == "TITAN_ROUTE_JOIN":
            self.state.route_join(req["lobby_id"], req["player_id"])
            return {"ok": True}
        if action == "TITAN_ROUTE_SET_DATA_OBJECT":
            self.state.route_set_data_object(req["lobby_id"], req["key"], req["value"])
            return {"ok": True}
        if action == "TITAN_ROUTE_GET_DATA_OBJECT":
            return {"ok": True, "key": req["key"], "value": self.state.route_get_data_object(req["lobby_id"], req["key"])}
        if action == "TITAN_START_GAME":
            launch = self.state.start_game_from_lobby(req["lobby_id"], req["requester_id"], req.get("port"))
            return {"ok": True, "launch": launch}

        return {"ok": False, "error": f"unknown_action:{action}"}


async def prune_loop(state: WONLikeState, every_s: int = 10) -> None:
    while True:
        removed = state.prune_stale_servers()
        if removed:
            LOGGER.info("stale_servers_removed=%d", removed)
        expired_sessions = state.cleanup_expired_sessions()
        if expired_sessions:
            LOGGER.info("expired_sessions_removed=%d", expired_sessions)
        expired_login_attempts = state.cleanup_login_attempts()
        if expired_login_attempts:
            LOGGER.info("expired_login_attempts_removed=%d", expired_login_attempts)
        await asyncio.sleep(every_s)


async def run_server(
    host: str,
    port: int,
    timeout_s: int,
    db_path: str,
    shared_secret: str = "",
) -> Tuple[asyncio.AbstractServer, WONLikeState, StateStore]:
    store = StateStore(db_path)
    state = WONLikeState(store=store, heartbeat_timeout_s=timeout_s)
    proto = WONLikeProtocolServer(state, shared_secret=shared_secret)
    srv = await asyncio.start_server(proto.handle_client, host=host, port=port)
    return srv, state, store


async def main_async(args: argparse.Namespace) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    server, state, store = await run_server(
        args.host,
        args.port,
        args.heartbeat_timeout,
        args.db_path,
        shared_secret=args.shared_secret,
    )
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
    except NotImplementedError:
        # Windows: loop.add_signal_handler is not supported; Ctrl-C raises KeyboardInterrupt
        pass
    prune_task = asyncio.create_task(prune_loop(state))
    LOGGER.info("WON OSS server listening on %s", ", ".join(str(s.getsockname()) for s in (server.sockets or [])))
    try:
        async with server:
            await stop.wait()
    finally:
        prune_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await prune_task
        store.close()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="WON-inspired open source lobby/matchmaking server")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9100,
                   help="Internal backend port (gateway connects here; NOT the Homeworld-facing port)")
    p.add_argument("--heartbeat-timeout", type=int, default=45)
    p.add_argument("--db-path", default=str(Path(__file__).resolve().parent / "won_server.db"))
    p.add_argument(
        "--shared-secret",
        default=os.environ.get("BACKEND_SHARED_SECRET", ""),
        help="Optional shared secret required by backend JSON-RPC clients. Without this, only loopback clients are accepted.",
    )
    return p


if __name__ == "__main__":
    asyncio.run(main_async(build_parser().parse_args()))
