#!/usr/bin/env python3
"""Binary Titan gateway with session state machine.

MVP wire format:
- 4-byte big-endian frame length
- body:
  - 1-byte opcode
  - 2-byte field count
  - repeated fields: [1-byte key_len][key][2-byte val_len][value]

Values are UTF-8 strings; numeric values are stringified.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow direct execution from either:
# - a flat checkout with modules at repo root
# - a package checkout where the repo itself is named won_oss_server
# - the older nested layout under tools/
_module_dir = Path(__file__).resolve().parent
_package_parent = _module_dir.parent
for _candidate in (_module_dir, _package_parent):
    if str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

import argparse
import asyncio
from collections import deque
import contextlib
import ipaddress
import logging
import os
import secrets
import socket as _socket
import sqlite3
import struct
import subprocess
import time
import unicodedata
from urllib.parse import parse_qs, urlsplit
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Deque, Dict, Optional, Tuple
import hashlib
import json
import binascii

try:
    from won_oss_server import won_crypto
except ModuleNotFoundError:
    import won_crypto

LOGGER = logging.getLogger(__name__)


def _is_loopback_host(value: Optional[str]) -> bool:
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

REPO_CHECK_INTERVAL_SECONDS = 900


class GitRepoMonitor:
    """Cache local/upstream git state for the admin dashboard."""

    def __init__(
        self,
        repo_path: str,
        remote_name: str = "origin",
        check_interval_s: int = REPO_CHECK_INTERVAL_SECONDS,
    ) -> None:
        self.repo_path = Path(repo_path).resolve()
        self.remote_name = str(remote_name or "origin").strip() or "origin"
        self.check_interval_s = max(60, int(check_interval_s or REPO_CHECK_INTERVAL_SECONDS))
        self._lock = asyncio.Lock()
        self._refresh_task: Optional[asyncio.Task] = None
        self._startup_task: Optional[asyncio.Task] = None
        self._last_update_at = 0.0
        self._last_update_message = ""
        self._restart_required = False
        self._snapshot_cache = self._finalize_snapshot(
            {
                "available": False,
                "repo_path": str(self.repo_path),
                "remote_name": self.remote_name,
                "remote_url": "",
                "branch": "",
                "upstream": "",
                "local_commit": "",
                "local_short": "",
                "local_version": "",
                "remote_commit": "",
                "remote_short": "",
                "remote_version": "",
                "ahead": 0,
                "behind": 0,
                "dirty": False,
                "can_update": False,
                "update_available": False,
                "status": "pending",
                "last_checked_at": 0.0,
                "last_error": "",
            }
        )

    def _finalize_snapshot(self, snapshot: Dict[str, object]) -> Dict[str, object]:
        snapshot["check_interval_seconds"] = self.check_interval_s
        snapshot["last_update_at"] = float(self._last_update_at)
        snapshot["last_update_message"] = self._last_update_message
        snapshot["restart_required"] = bool(self._restart_required)
        return snapshot

    def snapshot(self) -> Dict[str, object]:
        return dict(self._snapshot_cache)

    def start_background_tasks(self) -> None:
        if self._startup_task is None or self._startup_task.done():
            self._startup_task = asyncio.create_task(self.force_refresh())
        if self._refresh_task is None:
            self._refresh_task = asyncio.create_task(self._refresh_loop())

    async def stop_background_tasks(self) -> None:
        tasks = [self._startup_task, self._refresh_task]
        self._startup_task = None
        self._refresh_task = None
        for task in tasks:
            if task is None:
                continue
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    async def _refresh_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(self.check_interval_s)
                try:
                    await self.force_refresh()
                except Exception as exc:
                    LOGGER.warning("Dashboard(repo): background refresh failed: %s", exc)
        except asyncio.CancelledError:
            raise

    def _run_git(self, *args: str, timeout: float = 20.0) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.setdefault("GIT_TERMINAL_PROMPT", "0")
        return subprocess.run(
            ["git", *args],
            cwd=str(self.repo_path),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=env,
            check=False,
        )

    def _git_text(self, *args: str, timeout: float = 20.0) -> str:
        result = self._run_git(*args, timeout=timeout)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"git {' '.join(args)} failed")
        return result.stdout.strip()

    def _collect_snapshot_sync(self, fetch_remote: bool = True) -> Dict[str, object]:
        snapshot: Dict[str, object] = {
            "available": False,
            "repo_path": str(self.repo_path),
            "remote_name": self.remote_name,
            "remote_url": "",
            "branch": "",
            "upstream": "",
            "local_commit": "",
            "local_short": "",
            "local_version": "",
            "remote_commit": "",
            "remote_short": "",
            "remote_version": "",
            "ahead": 0,
            "behind": 0,
            "dirty": False,
            "can_update": False,
            "update_available": False,
            "status": "unavailable",
            "last_checked_at": time.time(),
            "last_error": "",
        }
        try:
            inside = self._git_text("rev-parse", "--is-inside-work-tree")
            if inside.lower() != "true":
                snapshot["last_error"] = "not a git work tree"
                return self._finalize_snapshot(snapshot)

            snapshot["available"] = True
            snapshot["status"] = "up_to_date"
            snapshot["repo_path"] = self._git_text("rev-parse", "--show-toplevel")
            snapshot["branch"] = self._git_text("rev-parse", "--abbrev-ref", "HEAD")
            snapshot["local_commit"] = self._git_text("rev-parse", "HEAD")
            snapshot["local_short"] = str(snapshot["local_commit"])[:12]
            with contextlib.suppress(Exception):
                snapshot["local_version"] = self._git_text("describe", "--tags", "--always", "--dirty")
            with contextlib.suppress(Exception):
                snapshot["remote_url"] = self._git_text("remote", "get-url", self.remote_name)

            status_lines = self._git_text("status", "--porcelain").splitlines()
            snapshot["dirty"] = bool(status_lines)

            fetch_error = ""
            if fetch_remote and snapshot["remote_url"]:
                fetch = self._run_git("fetch", "--quiet", "--tags", self.remote_name, timeout=60.0)
                if fetch.returncode != 0:
                    fetch_error = fetch.stderr.strip() or fetch.stdout.strip() or "git fetch failed"

            upstream = self._run_git("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
            if upstream.returncode == 0:
                upstream_ref = upstream.stdout.strip()
                snapshot["upstream"] = upstream_ref
                with contextlib.suppress(Exception):
                    snapshot["remote_commit"] = self._git_text("rev-parse", "@{u}")
                snapshot["remote_short"] = str(snapshot["remote_commit"])[:12] if snapshot["remote_commit"] else ""
                with contextlib.suppress(Exception):
                    snapshot["remote_version"] = self._git_text("describe", "--tags", "--always", "@{u}")
                counts = self._git_text("rev-list", "--left-right", "--count", "HEAD...@{u}")
                ahead_str, behind_str = (counts.split() + ["0", "0"])[:2]
                snapshot["ahead"] = int(ahead_str or "0")
                snapshot["behind"] = int(behind_str or "0")
                snapshot["update_available"] = int(snapshot["behind"]) > 0 and int(snapshot["ahead"]) == 0
                if int(snapshot["ahead"]) > 0 and int(snapshot["behind"]) > 0:
                    snapshot["status"] = "diverged"
                elif int(snapshot["behind"]) > 0:
                    snapshot["status"] = "update_available"
                elif int(snapshot["ahead"]) > 0:
                    snapshot["status"] = "ahead"
                else:
                    snapshot["status"] = "up_to_date"
            else:
                snapshot["status"] = "no_upstream"

            snapshot["can_update"] = bool(
                snapshot["available"]
                and snapshot["upstream"]
                and not snapshot["dirty"]
                and int(snapshot["behind"]) > 0
                and int(snapshot["ahead"]) == 0
            )
            if fetch_error:
                snapshot["last_error"] = fetch_error
        except FileNotFoundError:
            snapshot["last_error"] = "git is not installed in this environment"
        except subprocess.TimeoutExpired:
            snapshot["last_error"] = "git command timed out"
            snapshot["status"] = "error"
        except Exception as exc:
            snapshot["last_error"] = str(exc)
            snapshot["status"] = "error"
        return self._finalize_snapshot(snapshot)

    async def force_refresh(self, fetch_remote: bool = True) -> Dict[str, object]:
        async with self._lock:
            snapshot = await asyncio.to_thread(self._collect_snapshot_sync, fetch_remote)
            self._snapshot_cache = snapshot
            return dict(snapshot)

    async def update_from_upstream(self) -> Dict[str, object]:
        async with self._lock:
            result = await asyncio.to_thread(self._update_from_upstream_sync)
            self._snapshot_cache = dict(result.get("git") or self._snapshot_cache)
            return result

    def _update_from_upstream_sync(self) -> Dict[str, object]:
        before = self._collect_snapshot_sync(fetch_remote=True)
        if not before.get("available"):
            return {"ok": False, "error": before.get("last_error") or "git repo unavailable", "git": before}
        if before.get("last_error"):
            return {"ok": False, "error": before["last_error"], "git": before}
        if not before.get("upstream"):
            return {"ok": False, "error": "no upstream branch configured", "git": before}
        if before.get("dirty"):
            return {"ok": False, "error": "working tree has local changes", "git": before}
        if int(before.get("ahead") or 0) > 0 and int(before.get("behind") or 0) > 0:
            return {"ok": False, "error": "branch has diverged from upstream", "git": before}
        if int(before.get("ahead") or 0) > 0:
            return {"ok": False, "error": "local branch is ahead of upstream", "git": before}
        if int(before.get("behind") or 0) <= 0:
            return {"ok": True, "updated": False, "message": "Already up to date.", "git": before}

        old_commit = str(before.get("local_commit") or "")
        old_label = str(before.get("local_version") or before.get("local_short") or old_commit[:12])
        merge = self._run_git("merge", "--ff-only", str(before["upstream"]), timeout=60.0)
        if merge.returncode != 0:
            after_fail = self._collect_snapshot_sync(fetch_remote=False)
            error = merge.stderr.strip() or merge.stdout.strip() or "git merge --ff-only failed"
            after_fail["last_error"] = error
            after_fail = self._finalize_snapshot(after_fail)
            return {"ok": False, "error": error, "git": after_fail}

        self._last_update_at = time.time()
        self._restart_required = True

        after = self._collect_snapshot_sync(fetch_remote=False)
        new_commit = str(after.get("local_commit") or "")
        new_label = str(after.get("local_version") or after.get("local_short") or new_commit[:12])
        diff = self._run_git("diff", "--name-only", f"{old_commit}..{new_commit}", timeout=20.0)
        changed_files = [line.strip() for line in diff.stdout.splitlines() if line.strip()]
        self._last_update_message = (
            f"Updated from {old_label} to {new_label}. Restart the gateway to load the new code."
        )
        after = self._finalize_snapshot(after)
        return {
            "ok": True,
            "updated": old_commit != new_commit,
            "message": self._last_update_message,
            "changed_files": changed_files,
            "git": after,
        }

try:
    from won_oss_server.titan_messages import (
        STATUS_FAIL,
        STATUS_OK,
        AuthLoginReply,
        DirGetReply,
        RoutingChatEvent,
        RoutingDataObjectReply,
        RoutingStatusReply,
        decode_request,
    )
except ModuleNotFoundError:
    from titan_messages import (
        STATUS_FAIL,
        STATUS_OK,
        AuthLoginReply,
        DirGetReply,
        RoutingChatEvent,
        RoutingDataObjectReply,
        RoutingStatusReply,
        decode_request,
    )

OP_PING = 0x01
OP_DIR_GET = 0x10
OP_ROUTE_CHAT = 0x20
OP_AUTH_LOGIN = 0x30
OP_REGISTER_PLAYER = 0x31
OP_CREATE_LOBBY = 0x32
OP_JOIN_LOBBY = 0x33
OP_START_GAME = 0x34
OP_POLL_EVENTS = 0x35
OP_ROUTE_REGISTER = 0x36
OP_TITAN_MESSAGE = 0x70
OP_SERVER_EVENT = 0x40

# ---------------------------------------------------------------------------
# Titan native protocol helpers
# (Homeworld 1 speaks this directly; byte layout confirmed from Wireshark)
# ---------------------------------------------------------------------------

TITAN_MAX_FRAME = 65536
ROUTING_MAX_CHAT_CHARS = 220
ROUTING_IDLE_TIMEOUT_SECONDS = 1800.0
ROUTING_RECONNECT_GRACE_SECONDS = 90.0
ROOM_ALLOCATION_GRACE_SECONDS = 120.0
ROUTING_HEARTBEAT_INTERVAL_SECONDS = 15.0
ROUTING_HEARTBEAT_IDLE_SECONDS = 20.0
ROUTING_MAINTENANCE_INTERVAL_SECONDS = 5.0
PEER_SESSION_TTL_SECONDS = 300.0
PEER_SESSION_SWEEP_INTERVAL_SECONDS = 60.0
BACKEND_RPC_TIMEOUT_SECONDS = 5.0
IP_ACTIVITY_TTL_SECONDS = 24 * 60 * 60.0
MAX_IP_ACTIVITY_ROWS = 1024
MAX_NATIVE_CLIENT_ID = 0xFFFF
MAX_PEER_SESSION_ID = 0xFFFF
FIREWALL_PROBE_REPLY = b"\x00" * 16

AUTH1_PEER_SERVICE_TYPE = 203
AUTH1_PEER_REQUEST = 50
AUTH1_PEER_CHALLENGE1 = 51
AUTH1_PEER_CHALLENGE2 = 52
AUTH1_PEER_COMPLETE = 53

MINI_HEADER_TYPE = 0x03
MINI_COMMON_SERVICE = 0x01
MINI_COMM_PING = 0x05
MINI_COMM_PING_REPLY = 0x06
MINI_ROUTING_SERVICE = 0x02

ROUTING_STATUS_REPLY = 0x28
ROUTING_CREATE_DATA_OBJECT = 0x09
ROUTING_DELETE_DATA_OBJECT = 0x0B
ROUTING_GET_CLIENT_LIST = 0x0F
ROUTING_GET_CLIENT_LIST_REPLY = 0x10
ROUTING_PEER_DATA = 0x1A
ROUTING_RECONNECT_CLIENT = 0x1E
ROUTING_DISCONNECT_CLIENT = 0x0D
ROUTING_KEEP_ALIVE = 0x16
ROUTING_READ_DATA_OBJECT_REPLY = 0x1D
ROUTING_REGISTER_CLIENT = 0x1F
ROUTING_REGISTER_CLIENT_REPLY = 0x20
ROUTING_RENEW_DATA_OBJECT = 0x22
ROUTING_REPLACE_DATA_OBJECT = 0x23
ROUTING_SEND_DATA = 0x24
ROUTING_SEND_DATA_BROADCAST = 0x25
ROUTING_SUBSCRIBE_DATA_OBJECT = 0x29
ROUTING_GROUP_CHANGE = 0x33
ROUTING_GROUP_CHANGE_EX = 0x34
ROUTING_SEND_CHAT = 0x35
ROUTING_PEER_CHAT = 0x36
ROUTING_OPTIONAL_FIELD_IP = 0x01
CHAT_GROUP_ID = 4
ROUTING_REASON_VOLUNTARY_DISCONNECT = 0x00
ROUTING_REASON_NEW_CLIENT = 0x80
STATUS_ROUTING_INVALID_PASSWORD = -2008

SMALL_HEADER_TYPE = 0x05
SMALL_COMMON_SERVICE = 0x01
SMALL_FACTORY_SERVER = 0x05
SMALL_COMM_REGISTER_REQUEST = 0x01
SMALL_COMM_REGISTER_REQUEST_EX = 0x02
SMALL_COMM_STATUS_REPLY = 0x0F
SMALL_FACT_STATUS_REPLY = 0x03
SMALL_FACT_START_PROCESS = 0x0D
SMALL_FACT_START_PROCESS_UNICODE = 0x0E

PEER_ROLE_DIRECTORY = "directory"
PEER_ROLE_FACTORY = "factory"

# ---------------------------------------------------------------------------
# WON Dir GetFlags constants  (wonapi/WONDir/DirTypes.h  DIR_GF_*)
# These control which fields are present in each DirEntity in a reply and are
# stored in the 4-byte GetFlags u32 (LE) inside a DirG2MultiEntityReply.
# ---------------------------------------------------------------------------
DIR_GF_DECOMPROOT     = 0x00000001  # Include the root dir itself
DIR_GF_DECOMPSERVICES = 0x00000002  # Include dir services
DIR_GF_DECOMPSUBDIRS  = 0x00000004  # Include dir sub-dirs
DIR_GF_ADDTYPE        = 0x00000010  # Include entity type byte ('S'/'D')
DIR_GF_ADDDISPLAYNAME = 0x00000020  # Include display name
DIR_GF_ADDCREATED     = 0x00000040  # Include creation timestamp
DIR_GF_ADDTOUCHED     = 0x00000080  # Include last-touched timestamp
DIR_GF_ADDLIFESPAN    = 0x00000100  # Include lifespan
DIR_GF_ADDDOTYPE      = 0x00000200  # Include DataObject types
DIR_GF_ADDDODATA      = 0x00000400  # Include DataObject data blobs
DIR_GF_ADDDATAOBJECTS = 0x00000800  # Include DataObjects section
DIR_GF_ADDCRC         = 0x00002000  # Include entity CRC
DIR_GF_ADDUIDS        = 0x00004000  # Include create/touch user IDs
DIR_GF_DIRADDPATH     = 0x00010000  # Include directory path
DIR_GF_DIRADDNAME     = 0x00020000  # Include directory name
DIR_GF_DIRADDVISIBLE  = 0x00040000  # Include directory visibility flag
DIR_GF_SERVADDPATH    = 0x01000000  # Include service path
DIR_GF_SERVADDNAME    = 0x02000000  # Include service name
DIR_GF_SERVADDNETADDR = 0x04000000  # Include service net address


def _is_titan_native(first4: bytes) -> Tuple[bool, int]:
    """Return (is_titan_native, le_size).

    Homeworld 1 uses a little-endian u32 total-size prefix.
    Our custom gateway protocol uses a big-endian u32.

    Heuristic: if LE interpretation lands in [8, TITAN_MAX_FRAME] but the BE
    interpretation would be a huge number (> 10 million), treat as Titan native.
    """
    le = struct.unpack("<I", first4)[0]
    be = struct.unpack(">I", first4)[0]
    return (8 <= le <= TITAN_MAX_FRAME and be > 10_000_000), le


def _twstr(s: str) -> bytes:
    """Encode a WON wstring: [u16 LE char-count][UCS-2 LE bytes].

    Confirmed from ReadBuffer::ReadShort (ShortFromLittleEndian) and
    ReadRawWString which reads each char via ReadShort (LE) on BE platforms,
    or memcpy on LE platforms — both give identical LE-ordered bytes.
    """
    enc = s.encode("utf-16-le") if s else b""
    return struct.pack("<H", len(s)) + enc


def _rwstr(data: bytes, off: int) -> Tuple[str, int]:
    """Decode a UCS-2 BE wstring from *data* at byte offset *off*.

    Returns (string, new_offset).
    """
    n, = struct.unpack(">H", data[off:off + 2])
    off += 2
    s = data[off:off + n * 2].decode("utf-16-be") if n else ""
    return s, off + n * 2


async def _titan_recv(reader: asyncio.StreamReader,
                      first4: Optional[bytes] = None) -> bytes:
    """Read one Titan LE-framed message body (without the 4-byte size header)."""
    hdr = first4 if first4 is not None else await reader.readexactly(4)
    size, = struct.unpack("<I", hdr)
    if size < 4 or size > TITAN_MAX_FRAME:
        raise ValueError(f"titan_bad_frame_size:{size}")
    return await reader.readexactly(size - 4)


def _titan_wrap(body: bytes) -> bytes:
    """Prepend LE u32 total-size to *body* (size includes the 4-byte header)."""
    return struct.pack("<I", len(body) + 4) + body


async def _routing_recv(reader: asyncio.StreamReader) -> bytes:
    """Read one ptUnsignedShort-framed routing payload."""
    hdr = await reader.readexactly(2)
    total_len, = struct.unpack("<H", hdr)
    if total_len < 3 or total_len > TITAN_MAX_FRAME:
        raise ValueError(f"routing_bad_frame_size:{total_len}")
    return await reader.readexactly(total_len - 2)


def _routing_wrap(payload: bytes) -> bytes:
    """Wrap a routing payload with LE u16 total-size."""
    total_len = len(payload) + 2
    if total_len > 0xFFFF:
        raise ValueError("routing_frame_too_large")
    return struct.pack("<H", total_len) + payload


def _routing_tmessage_payload(frame: bytes) -> bytes:
    """Convert a full TMessage frame into routing-pipe payload bytes."""
    if len(frame) < 4:
        raise ValueError("routing_tmessage_frame_too_short")
    return frame[4:]


def _parse_auth1_certificate(cert: bytes) -> Dict[str, object]:
    """Parse an Auth1Certificate enough for peer-auth server use.

    Layout:
      [u16 LE family]
      [u32 LE issue_time]
      [u32 LE expire_time]
      [u32 LE user_id]
      [u32 LE community_id]
      [u16 LE trust_level]
      [u16 LE pub_key_len]
      [pub_key_len bytes: DER public key]
      [sig bytes]
    """
    if len(cert) < 22:
        raise ValueError("auth1_certificate_too_short")
    (
        family,
        issue_time,
        expire_time,
        user_id,
        community_id,
        trust_level,
        pub_key_len,
    ) = struct.unpack("<HIIIIHH", cert[:22])
    if len(cert) < 22 + pub_key_len:
        raise ValueError("auth1_certificate_truncated")
    pub_der = cert[22:22 + pub_key_len]
    sig = cert[22 + pub_key_len:]
    p, q, g, y = won_crypto.decode_public_key(pub_der)
    return {
        "family": family,
        "issue_time": issue_time,
        "expire_time": expire_time,
        "user_id": user_id,
        "community_id": community_id,
        "trust_level": trust_level,
        "pub_der": pub_der,
        "sig": sig,
        "p": p,
        "q": q,
        "g": g,
        "y": y,
        "unsigned": cert[:22 + pub_key_len],
    }


def _parse_auth1_peer_request(body: bytes) -> Dict[str, object]:
    """Parse Auth1Request body."""
    if len(body) < 6:
        raise ValueError("auth1_peer_request_too_short")
    auth_mode = body[0]
    encrypt_mode = body[1]
    encrypt_flags, cert_len = struct.unpack("<HH", body[2:6])
    if len(body) < 6 + cert_len:
        raise ValueError("auth1_peer_request_truncated")
    cert = body[6:6 + cert_len]
    return {
        "auth_mode": auth_mode,
        "encrypt_mode": encrypt_mode,
        "encrypt_flags": encrypt_flags,
        "certificate": cert,
    }


def _parse_auth1_peer_challenge2(body: bytes) -> bytes:
    """Parse Auth1Challenge2 body and return the encrypted blob."""
    if len(body) < 2:
        raise ValueError("auth1_peer_challenge2_too_short")
    raw_len, = struct.unpack("<H", body[:2])
    if len(body) < 2 + raw_len:
        raise ValueError("auth1_peer_challenge2_truncated")
    return body[2:2 + raw_len]


def _build_auth1_peer_challenge1(secret_b_cipher: bytes, server_cert: bytes) -> bytes:
    body = (
        struct.pack("<H", len(secret_b_cipher))
        + secret_b_cipher
        + struct.pack("<H", len(server_cert))
        + server_cert
    )
    return won_crypto.build_tmessage(
        AUTH1_PEER_SERVICE_TYPE,
        AUTH1_PEER_CHALLENGE1,
        body,
    )


def _build_auth1_peer_complete(secret_a_cipher: bytes, session_id: int = 0) -> bytes:
    body = struct.pack("<h", 0)
    body += struct.pack("<H", len(secret_a_cipher))
    body += secret_a_cipher
    if session_id:
        body += struct.pack("<H", session_id)
    return won_crypto.build_tmessage(
        AUTH1_PEER_SERVICE_TYPE,
        AUTH1_PEER_COMPLETE,
        body,
    )


def _encode_bf_payload(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt a BFSymmetricKey-compatible payload."""
    return won_crypto.bf_encrypt(plaintext, key)


def _decode_bf_payload(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt a BFSymmetricKey-compatible payload."""
    return won_crypto.bf_decrypt(ciphertext, key)


def _encrypt_small_session(
    clear_msg: bytes,
    key: bytes,
    session_id: int,
    seq_num: Optional[int],
) -> bytes:
    """Encrypt a SmallMessage into a SmallEncryptedService frame."""
    if len(clear_msg) < 1 or clear_msg[0] != SMALL_HEADER_TYPE:
        raise ValueError("small_message_header_expected")
    plaintext = clear_msg[1:]
    if seq_num is not None:
        plaintext = struct.pack("<H", seq_num) + plaintext
    ciphertext = _encode_bf_payload(plaintext, key)
    return bytes([0x06]) + struct.pack("<H", session_id) + ciphertext


def _decrypt_small_session(
    body: bytes,
    key: bytes,
    session_id: int,
    expected_seq: Optional[int],
) -> bytes:
    """Decrypt a SmallEncryptedService frame into a clear SmallMessage."""
    if len(body) < 4 or body[0] != 0x06:
        raise ValueError("small_encrypted_service_expected")
    got_session_id, = struct.unpack("<H", body[1:3])
    if got_session_id != session_id:
        raise ValueError(f"dir_session_id_mismatch:{got_session_id}!={session_id}")
    plaintext = _decode_bf_payload(body[3:], key)
    if expected_seq is not None:
        if len(plaintext) < 2:
            raise ValueError("dir_encrypted_plaintext_too_short")
        seq_num, = struct.unpack("<H", plaintext[:2])
        if seq_num != expected_seq:
            raise ValueError(f"dir_seq_mismatch:{seq_num}!={expected_seq}")
        plaintext = plaintext[2:]
    return bytes([SMALL_HEADER_TYPE]) + plaintext


def _encrypt_persistent_non_t(
    clear_msg: bytes,
    key: bytes,
    seq_num: Optional[int] = None,
) -> bytes:
    """Encrypt a clear Mini/Small message for persistent Auth1Peer sessions."""
    if len(clear_msg) < 1 or clear_msg[0] not in {MINI_HEADER_TYPE, SMALL_HEADER_TYPE}:
        raise ValueError("persistent_non_t_header_expected")
    plaintext = clear_msg[1:]
    if seq_num is not None:
        plaintext = struct.pack("<H", seq_num) + plaintext
    ciphertext = _encode_bf_payload(plaintext, key)
    return bytes([clear_msg[0] + 1]) + ciphertext


def _decrypt_persistent_non_t(
    body: bytes,
    key: bytes,
    expected_seq: Optional[int] = None,
) -> bytes:
    """Decrypt a persistent Auth1Peer Mini/Small payload."""
    if len(body) < 1 or body[0] not in {0x04, 0x06}:
        raise ValueError("persistent_non_t_encrypted_header_expected")
    plaintext = _decode_bf_payload(body[1:], key)
    if expected_seq is not None:
        if len(plaintext) < 2:
            raise ValueError("persistent_non_t_plaintext_too_short")
        seq_num, = struct.unpack("<H", plaintext[:2])
        if seq_num != expected_seq:
            raise ValueError(f"route_seq_mismatch:{seq_num}!={expected_seq}")
        plaintext = plaintext[2:]
    return bytes([body[0] - 1]) + plaintext


def _pack_directory_data_object(obj_type: str, value: object) -> Tuple[bytes, bytes]:
    """Convert backend /Homeworld payload values into native Titan data objects."""
    if obj_type == "Description":
        return obj_type.encode("ascii"), str(value).encode("utf-16-le")
    if obj_type in {
        "RoomFlags",
        "__RSClientCount",
        "__FactCur_RoutingServHWGame",
        "__FactTotal_RoutingServHWGame",
        "__ServerUptime",
    }:
        return obj_type.encode("ascii"), struct.pack("<I", int(value))
    if isinstance(value, bytes):
        return obj_type.encode("ascii"), value
    return obj_type.encode("ascii"), str(value).encode("ascii", errors="replace")


def _parse_mini_ping(body: bytes) -> Dict[str, object]:
    """Parse a clear MiniCommonService Ping message."""
    if len(body) < 8 or body[0] != MINI_HEADER_TYPE:
        raise ValueError("mini_ping_bad_header")
    if body[1] != MINI_COMMON_SERVICE or body[2] != MINI_COMM_PING:
        raise ValueError("mini_ping_wrong_type")
    start_tick, = struct.unpack("<I", body[3:7])
    return {
        "start_tick": start_tick,
        "extended": body[7] != 0,
    }


def _build_mini_ping_reply(start_tick: int) -> bytes:
    """Build a clear MiniCommonService PingReply body."""
    return (
        bytes([MINI_HEADER_TYPE, MINI_COMMON_SERVICE, MINI_COMM_PING_REPLY])
        + struct.pack("<I", start_tick)
    )


def _parse_mini_message(clear: bytes) -> Tuple[int, int, bytes]:
    """Parse a clear MiniMessage header."""
    if len(clear) < 3 or clear[0] != MINI_HEADER_TYPE:
        raise ValueError("mini_message_bad_header")
    return clear[1], clear[2], clear[3:]


def _parse_small_message(clear: bytes) -> Tuple[int, int, bytes]:
    """Parse a clear SmallMessage header."""
    if len(clear) < 5 or clear[0] != SMALL_HEADER_TYPE:
        raise ValueError("small_message_bad_header")
    service_type, message_type = struct.unpack("<HH", clear[1:5])
    return service_type, message_type, clear[5:]


def _read_pa_string_le(data: bytes, off: int) -> Tuple[str, int]:
    """Read a Titan PA_STRING ([u16 LE len][bytes])."""
    if off + 2 > len(data):
        raise ValueError("pa_string_truncated_len")
    slen, = struct.unpack("<H", data[off:off + 2])
    off += 2
    if off + slen > len(data):
        raise ValueError("pa_string_truncated_data")
    s = data[off:off + slen].decode("ascii", errors="replace") if slen else ""
    return s, off + slen


def _read_pw_string_le(data: bytes, off: int) -> Tuple[str, int]:
    """Read a Titan PW_STRING ([u16 LE chars][utf-16-le bytes])."""
    if off + 2 > len(data):
        raise ValueError("pw_string_truncated_len")
    nchar, = struct.unpack("<H", data[off:off + 2])
    off += 2
    blen = nchar * 2
    if off + blen > len(data):
        raise ValueError("pw_string_truncated_data")
    s = data[off:off + blen].decode("utf-16-le", errors="replace") if nchar else ""
    return s, off + blen


def _read_raw_string_le(data: bytes, off: int) -> Tuple[bytes, int]:
    """Read a Titan RawString ([u16 LE len][raw bytes])."""
    if off + 2 > len(data):
        raise ValueError("raw_string_truncated_len")
    slen, = struct.unpack("<H", data[off:off + 2])
    off += 2
    if off + slen > len(data):
        raise ValueError("raw_string_truncated_data")
    return data[off:off + slen], off + slen


def _decode_client_name(raw: bytes) -> str:
    """Best-effort decoding of a routing RawString client name."""
    if not raw:
        return ""
    if len(raw) % 2 == 0:
        with contextlib.suppress(UnicodeDecodeError):
            return raw.decode("utf-16-le")
    return raw.decode("ascii", errors="replace")


def _parse_small_common_register_request(clear: bytes) -> Dict[str, object]:
    """Parse a SmallCommRegisterRequest(Ex)."""
    service_type, message_type, payload = _parse_small_message(clear)
    if service_type != SMALL_COMMON_SERVICE:
        raise ValueError(f"small_common_service_unexpected:{service_type}")
    if message_type not in {SMALL_COMM_REGISTER_REQUEST, SMALL_COMM_REGISTER_REQUEST_EX}:
        raise ValueError(f"small_common_message_unexpected:{message_type}")

    off = 0
    if off + 2 > len(payload):
        raise ValueError("small_register_request_truncated")
    require_unique = payload[off] != 0
    off += 1
    num_addrs = payload[off]
    off += 1

    dir_addresses: list[str] = []
    for _ in range(num_addrs):
        addr, off = _read_pa_string_le(payload, off)
        dir_addresses.append(addr)

    display_name, off = _read_pw_string_le(payload, off)
    path, off = _read_pw_string_le(payload, off)

    data_objects: list[Tuple[bytes, bytes]] = []
    if message_type == SMALL_COMM_REGISTER_REQUEST_EX:
        if off + 2 > len(payload):
            raise ValueError("small_register_request_ex_truncated")
        object_count, = struct.unpack("<H", payload[off:off + 2])
        off += 2
        for _ in range(object_count):
            if off >= len(payload):
                raise ValueError("small_register_request_ex_type_len_truncated")
            type_len = payload[off]
            off += 1
            if off + type_len > len(payload):
                raise ValueError("small_register_request_ex_type_truncated")
            obj_type = payload[off:off + type_len]
            off += type_len
            if off + 2 > len(payload):
                raise ValueError("small_register_request_ex_data_len_truncated")
            data_len, = struct.unpack("<H", payload[off:off + 2])
            off += 2
            if off + data_len > len(payload):
                raise ValueError("small_register_request_ex_data_truncated")
            obj_data = payload[off:off + data_len]
            off += data_len
            data_objects.append((obj_type, obj_data))

    return {
        "require_unique_display_name": require_unique,
        "dir_addresses": dir_addresses,
        "display_name": display_name,
        "path": path,
        "data_objects": data_objects,
        "extended": message_type == SMALL_COMM_REGISTER_REQUEST_EX,
    }


def _build_small_common_status_reply(status: int) -> bytes:
    """Build a SmallCommStatusReply."""
    return (
        bytes([SMALL_HEADER_TYPE])
        + struct.pack("<HHh", SMALL_COMMON_SERVICE, SMALL_COMM_STATUS_REPLY, int(status))
    )


def _parse_mini_routing_register_client(clear: bytes) -> Dict[str, object]:
    """Parse MMsgRoutingRegisterClient."""
    service_type, message_type, payload = _parse_mini_message(clear)
    if service_type != MINI_ROUTING_SERVICE or message_type != ROUTING_REGISTER_CLIENT:
        raise ValueError(f"routing_register_client_unexpected:{service_type}:{message_type}")
    off = 0
    client_name_raw, off = _read_raw_string_le(payload, off)
    password, off = _read_pw_string_le(payload, off)
    if off >= len(payload):
        raise ValueError("routing_register_client_flags_truncated")
    flags = payload[off]
    return {
        "client_name_raw": client_name_raw,
        "client_name": _decode_client_name(client_name_raw),
        "password": password,
        "trying_to_become_host": bool(flags & 0x01),
        "become_spectator": bool(flags & 0x02),
        "setup_chat": bool(flags & 0x04),
    }


def _build_mini_routing_register_client_reply(
    status: int,
    client_id: int,
    host_name_raw: bytes,
    host_comment: str,
) -> bytes:
    """Build MMsgRoutingRegisterClientReply."""
    body = (
        struct.pack("<h", int(status))
        + struct.pack("<H", len(host_name_raw))
        + host_name_raw
        + _twstr(host_comment)
    )
    if status == 0:
        body += struct.pack("<H", client_id)
    return bytes([MINI_HEADER_TYPE, MINI_ROUTING_SERVICE, ROUTING_REGISTER_CLIENT_REPLY]) + body


def _build_mini_routing_get_client_list_reply(
    clients: list[Tuple[int, bytes, int]],
) -> bytes:
    """Build MMsgRoutingGetClientListReply with IP addresses included."""
    body = struct.pack("<hHHB", 0, 0, len(clients), 1)
    body += bytes([ROUTING_OPTIONAL_FIELD_IP, 4])
    for client_id, client_name_raw, client_ip_u32 in clients:
        body += struct.pack("<H", client_id)
        body += struct.pack("<H", len(client_name_raw))
        body += client_name_raw
        body += struct.pack("<I", int(client_ip_u32))
    return bytes([MINI_HEADER_TYPE, MINI_ROUTING_SERVICE, ROUTING_GET_CLIENT_LIST_REPLY]) + body


def _build_mini_routing_group_change(group_id: int, client_id: int, reason: int) -> bytes:
    """Build MMsgRoutingGroupChange."""
    body = struct.pack("<HHB", int(group_id), int(client_id), int(reason) & 0xFF)
    return bytes([MINI_HEADER_TYPE, MINI_ROUTING_SERVICE, ROUTING_GROUP_CHANGE]) + body


def _build_mini_routing_group_change_ex(
    group_id: int,
    client_id: int,
    reason: int,
    client_name_raw: bytes,
    client_ip_u32: int,
) -> bytes:
    """Build MMsgRoutingGroupChangeEx with the optional IP field."""
    body = (
        struct.pack("<HHB", int(group_id), int(client_id), int(reason) & 0xFF)
        + struct.pack("<H", len(client_name_raw))
        + client_name_raw
        + bytes([1, ROUTING_OPTIONAL_FIELD_IP, 4])
        + struct.pack("<I", int(client_ip_u32))
    )
    return bytes([MINI_HEADER_TYPE, MINI_ROUTING_SERVICE, ROUTING_GROUP_CHANGE_EX]) + body


def _decode_routing_chat_text(chat_type: int, data: bytes) -> str:
    """Decode routing chat bytes into a readable string for logging."""
    if chat_type in {3, 4}:
        with contextlib.suppress(UnicodeDecodeError):
            return data.decode("utf-16-le")
        return data.decode("utf-16-le", errors="replace")
    if chat_type in {1, 2}:
        return data.decode("latin-1", errors="replace")
    return binascii.hexlify(data).decode("ascii")


def _sanitize_routing_chat_text(text: str) -> str:
    """Strip control characters and clamp lobby chat to a safe length."""
    cleaned: list[str] = []
    last_was_space = False
    for ch in text:
        if ch in "\r\n\t":
            ch = " "
        if unicodedata.category(ch).startswith("C"):
            continue
        if ch.isspace():
            if last_was_space:
                continue
            cleaned.append(" ")
            last_was_space = True
            continue
        cleaned.append(ch)
        last_was_space = False
    return "".join(cleaned).strip()[:ROUTING_MAX_CHAT_CHARS]


def _mask_account_key(value: str) -> str:
    """Return a short, non-sensitive representation of a CD/login key."""
    normalized = "".join(ch for ch in value if ch.isalnum())
    if not normalized:
        return "<empty>"
    if len(normalized) <= 8:
        return normalized[0] + ("*" * max(0, len(normalized) - 2)) + normalized[-1]
    return f"{normalized[:4]}...{normalized[-4:]}"


def _native_auth_error_to_status(error: str) -> int:
    """Map backend native-auth failures to retail Auth1 status codes."""
    mapping = {
        "missing_username": won_crypto.STATUS_AUTH_INVALID_USER_NAME,
        "create_account_required": won_crypto.STATUS_AUTH_USER_NOT_FOUND,
        "username_taken": won_crypto.STATUS_AUTH_USER_EXISTS,
        "invalid_credentials": won_crypto.STATUS_AUTH_BAD_PASSWORD,
        "missing_cd_key": won_crypto.STATUS_AUTH_INVALID_CD_KEY,
        "invalid_cd_key": won_crypto.STATUS_AUTH_INVALID_CD_KEY,
        "cd_key_mismatch": won_crypto.STATUS_AUTH_INVALID_CD_KEY,
        "rate_limited": won_crypto.STATUS_AUTH_BAD_PASSWORD,
    }
    return mapping.get(str(error), won_crypto.STATUS_COMMON_INVALID_PARAMETERS)


def _encode_routing_chat_text(chat_type: int, text: str, fallback: bytes) -> bytes:
    """Encode sanitized chat back into the original wire format."""
    if chat_type in {3, 4}:
        return text.encode("utf-16-le")
    if chat_type in {1, 2}:
        return text.encode("latin-1", errors="replace")
    return fallback


def _parse_mini_routing_send_chat(clear: bytes) -> Dict[str, object]:
    """Parse MMsgRoutingSendChat."""
    service_type, message_type, payload = _parse_mini_message(clear)
    if service_type != MINI_ROUTING_SERVICE or message_type != ROUTING_SEND_CHAT:
        raise ValueError(f"routing_send_chat_unexpected:{service_type}:{message_type}")
    if len(payload) < 4:
        raise ValueError("routing_send_chat_too_short")

    flags = payload[0]
    chat_type = payload[1]
    data_len, = struct.unpack("<H", payload[2:4])
    off = 4
    if off + data_len > len(payload):
        raise ValueError("routing_send_chat_data_truncated")
    data = payload[off:off + data_len]
    off += data_len

    addressees: list[int] = []
    while off < len(payload):
        if off + 2 > len(payload):
            raise ValueError("routing_send_chat_addressee_truncated")
        addressee, = struct.unpack("<H", payload[off:off + 2])
        off += 2
        addressees.append(addressee)

    raw_text = _decode_routing_chat_text(chat_type, data)
    text = _sanitize_routing_chat_text(raw_text)
    encoded = _encode_routing_chat_text(chat_type, text, data)

    return {
        "should_send_reply": bool(flags & 0x01),
        "include_exclude_flag": bool(flags & 0x02),
        "chat_type": chat_type,
        "data": encoded,
        "text": text,
        "raw_text": raw_text,
        "addressees": addressees,
    }


def _build_mini_routing_status_reply(status: int) -> bytes:
    """Build MMsgRoutingStatusReply."""
    return (
        bytes([MINI_HEADER_TYPE, MINI_ROUTING_SERVICE, ROUTING_STATUS_REPLY])
        + struct.pack("<h", int(status))
    )


def _build_mini_routing_keep_alive() -> bytes:
    """Build MMsgRoutingKeepAlive."""
    return bytes([MINI_HEADER_TYPE, MINI_ROUTING_SERVICE, ROUTING_KEEP_ALIVE])


def _build_mini_routing_peer_chat(
    client_id: int,
    chat_type: int,
    data: bytes,
    addressees: list[int],
    include_exclude_flag: bool,
) -> bytes:
    """Build MMsgRoutingPeerChat."""
    flags = 0x02 if include_exclude_flag else 0x00
    body = struct.pack("<HBBH", client_id, flags, chat_type, len(data)) + data
    for addressee in addressees:
        body += struct.pack("<H", addressee)
    return bytes([MINI_HEADER_TYPE, MINI_ROUTING_SERVICE, ROUTING_PEER_CHAT]) + body


def _build_mini_routing_peer_data(client_id: int, data: bytes) -> bytes:
    """Build MMsgRoutingPeerData."""
    return (
        bytes([MINI_HEADER_TYPE, MINI_ROUTING_SERVICE, ROUTING_PEER_DATA])
        + struct.pack("<H", int(client_id))
        + bytes(data)
    )


def _parse_mini_routing_reconnect_client(clear: bytes) -> Dict[str, object]:
    """Parse MMsgRoutingReconnectClient."""
    service_type, message_type, payload = _parse_mini_message(clear)
    if service_type != MINI_ROUTING_SERVICE or message_type != ROUTING_RECONNECT_CLIENT:
        raise ValueError(
            f"routing_reconnect_client_unexpected:{service_type}:{message_type}"
        )
    if len(payload) < 2:
        raise ValueError("routing_reconnect_client_too_short")
    client_id, = struct.unpack("<H", payload[:2])
    want_missed_messages = bool(payload[2]) if len(payload) >= 3 else False
    return {
        "client_id": int(client_id),
        "want_missed_messages": want_missed_messages,
    }


def _parse_mini_routing_send_data(clear: bytes) -> Dict[str, object]:
    """Parse MMsgRoutingSendData."""
    service_type, message_type, payload = _parse_mini_message(clear)
    if service_type != MINI_ROUTING_SERVICE or message_type != ROUTING_SEND_DATA:
        raise ValueError(f"routing_send_data_unexpected:{service_type}:{message_type}")
    if len(payload) < 3:
        raise ValueError("routing_send_data_too_short")

    flags = payload[0]
    data_len, = struct.unpack("<H", payload[1:3])
    off = 3
    if off + data_len > len(payload):
        raise ValueError("routing_send_data_truncated")
    data = payload[off:off + data_len]
    off += data_len

    addressees: list[int] = []
    while off < len(payload):
        if off + 2 > len(payload):
            raise ValueError("routing_send_data_addressee_truncated")
        addressee, = struct.unpack("<H", payload[off:off + 2])
        off += 2
        addressees.append(addressee)

    return {
        "should_send_reply": bool(flags & 0x01),
        "include_exclude_flag": bool(flags & 0x02),
        "data": data,
        "addressees": addressees,
    }


def _parse_mini_routing_send_data_broadcast(clear: bytes) -> Dict[str, object]:
    """Parse MMsgRoutingSendDataBroadcast."""
    service_type, message_type, payload = _parse_mini_message(clear)
    if service_type != MINI_ROUTING_SERVICE or message_type != ROUTING_SEND_DATA_BROADCAST:
        raise ValueError(f"routing_send_data_broadcast_unexpected:{service_type}:{message_type}")
    if not payload:
        raise ValueError("routing_send_data_broadcast_too_short")
    flags = payload[0]
    return {
        "should_send_reply": bool(flags & 0x01),
        "data": payload[1:],
    }


def _parse_mini_routing_subscribe_data_object(clear: bytes) -> Dict[str, object]:
    """Parse MMsgRoutingSubscribeDataObject."""
    service_type, message_type, payload = _parse_mini_message(clear)
    if service_type != MINI_ROUTING_SERVICE or message_type != ROUTING_SUBSCRIBE_DATA_OBJECT:
        raise ValueError(f"routing_subscribe_data_object_unexpected:{service_type}:{message_type}")
    if len(payload) < 4:
        raise ValueError("routing_subscribe_data_object_too_short")
    link_id, = struct.unpack("<H", payload[:2])
    type_len = payload[2]
    if 3 + type_len >= len(payload):
        raise ValueError("routing_subscribe_data_object_truncated")
    data_type = payload[3:3 + type_len]
    flags = payload[3 + type_len]
    return {
        "link_id": link_id,
        "data_type": data_type,
        "exact_or_recursive": bool(flags & 0x01),
        "group_or_members": bool(flags & 0x02),
    }


def _build_mini_routing_read_data_object_reply(
    data_objects: list[Tuple[int, int, bytes, bytes]],
) -> bytes:
    """Build MMsgRoutingReadDataObjectReply."""
    body = struct.pack("<hH", 0, len(data_objects))
    for link_id, owner_id, data_type, data in data_objects:
        body += struct.pack("<HHB", link_id, owner_id, len(data_type))
        body += data_type
        body += struct.pack("<H", len(data))
        body += data
    return bytes([MINI_HEADER_TYPE, MINI_ROUTING_SERVICE, ROUTING_READ_DATA_OBJECT_REPLY]) + body


def _decode_routing_data_type(data_type: bytes) -> str:
    """Best-effort decoding of routing DataObject type bytes for logs."""
    if data_type.startswith(b"HW") and (len(data_type) - 2) % 2 == 0:
        payload = data_type[2:]
        with contextlib.suppress(UnicodeDecodeError):
            return payload.decode("utf-16-le")
        return payload.decode("utf-16-le", errors="replace")
    return data_type.decode("ascii", errors="replace")


def _extract_factory_password(cmd_line: str) -> str:
    """Best-effort extraction of `-Password <value>` from a factory cmdline."""
    if not cmd_line:
        return ""
    marker = "-Password"
    idx = cmd_line.find(marker)
    if idx < 0:
        return ""
    tail = cmd_line[idx + len(marker):].lstrip()
    if not tail:
        return ""
    if tail[0] in {"'", '"'}:
        quote = tail[0]
        end = tail.find(quote, 1)
        return tail[1:] if end < 0 else tail[1:end]
    return tail.split(None, 1)[0]


def _parse_mini_routing_create_data_object(clear: bytes) -> Dict[str, object]:
    """Parse MMsgRoutingCreateDataObject."""
    service_type, message_type, payload = _parse_mini_message(clear)
    if service_type != MINI_ROUTING_SERVICE or message_type != ROUTING_CREATE_DATA_OBJECT:
        raise ValueError(f"routing_create_data_object_unexpected:{service_type}:{message_type}")
    if len(payload) < 7:
        raise ValueError("routing_create_data_object_too_short")
    link_id, owner_id, lifespan = struct.unpack("<HHH", payload[:6])
    type_len = payload[6]
    off = 7
    if off + type_len + 2 > len(payload):
        raise ValueError("routing_create_data_object_truncated")
    data_type = payload[off:off + type_len]
    off += type_len
    data_len, = struct.unpack("<H", payload[off:off + 2])
    off += 2
    if off + data_len > len(payload):
        raise ValueError("routing_create_data_object_data_truncated")
    data = payload[off:off + data_len]
    return {
        "link_id": link_id,
        "owner_id": owner_id,
        "lifespan": lifespan,
        "data_type": data_type,
        "data": data,
    }


def _build_mini_routing_create_data_object(
    link_id: int,
    owner_id: int,
    lifespan: int,
    data_type: bytes,
    data: bytes,
) -> bytes:
    """Build MMsgRoutingCreateDataObject."""
    body = (
        struct.pack("<HHHB", link_id, owner_id, lifespan, len(data_type))
        + data_type
        + struct.pack("<H", len(data))
        + data
    )
    return bytes([MINI_HEADER_TYPE, MINI_ROUTING_SERVICE, ROUTING_CREATE_DATA_OBJECT]) + body


def _parse_mini_routing_delete_data_object(clear: bytes) -> Dict[str, object]:
    """Parse MMsgRoutingDeleteDataObject."""
    service_type, message_type, payload = _parse_mini_message(clear)
    if service_type != MINI_ROUTING_SERVICE or message_type != ROUTING_DELETE_DATA_OBJECT:
        raise ValueError(f"routing_delete_data_object_unexpected:{service_type}:{message_type}")
    if len(payload) < 3:
        raise ValueError("routing_delete_data_object_too_short")
    link_id, = struct.unpack("<H", payload[:2])
    type_len = payload[2]
    if 3 + type_len > len(payload):
        raise ValueError("routing_delete_data_object_truncated")
    return {
        "link_id": link_id,
        "data_type": payload[3:3 + type_len],
    }


def _build_mini_routing_delete_data_object(link_id: int, data_type: bytes) -> bytes:
    """Build MMsgRoutingDeleteDataObject."""
    body = struct.pack("<HB", link_id, len(data_type)) + data_type
    return bytes([MINI_HEADER_TYPE, MINI_ROUTING_SERVICE, ROUTING_DELETE_DATA_OBJECT]) + body


def _parse_mini_routing_replace_data_object(clear: bytes) -> Dict[str, object]:
    """Parse MMsgRoutingReplaceDataObject."""
    service_type, message_type, payload = _parse_mini_message(clear)
    if service_type != MINI_ROUTING_SERVICE or message_type != ROUTING_REPLACE_DATA_OBJECT:
        raise ValueError(f"routing_replace_data_object_unexpected:{service_type}:{message_type}")
    if len(payload) < 5:
        raise ValueError("routing_replace_data_object_too_short")
    link_id, = struct.unpack("<H", payload[:2])
    type_len = payload[2]
    off = 3
    if off + type_len + 2 > len(payload):
        raise ValueError("routing_replace_data_object_truncated")
    data_type = payload[off:off + type_len]
    off += type_len
    data_len, = struct.unpack("<H", payload[off:off + 2])
    off += 2
    if off + data_len > len(payload):
        raise ValueError("routing_replace_data_object_data_truncated")
    return {
        "link_id": link_id,
        "data_type": data_type,
        "data": payload[off:off + data_len],
    }


def _build_mini_routing_replace_data_object(link_id: int, data_type: bytes, data: bytes) -> bytes:
    """Build MMsgRoutingReplaceDataObject."""
    body = (
        struct.pack("<HB", link_id, len(data_type))
        + data_type
        + struct.pack("<H", len(data))
        + data
    )
    return bytes([MINI_HEADER_TYPE, MINI_ROUTING_SERVICE, ROUTING_REPLACE_DATA_OBJECT]) + body


def _parse_mini_routing_renew_data_object(clear: bytes) -> Dict[str, object]:
    """Parse MMsgRoutingRenewDataObject."""
    service_type, message_type, payload = _parse_mini_message(clear)
    if service_type != MINI_ROUTING_SERVICE or message_type != ROUTING_RENEW_DATA_OBJECT:
        raise ValueError(f"routing_renew_data_object_unexpected:{service_type}:{message_type}")
    if len(payload) < 5:
        raise ValueError("routing_renew_data_object_too_short")
    link_id, = struct.unpack("<H", payload[:2])
    type_len = payload[2]
    off = 3
    if off + type_len + 2 > len(payload):
        raise ValueError("routing_renew_data_object_truncated")
    data_type = payload[off:off + type_len]
    off += type_len
    new_lifespan, = struct.unpack("<H", payload[off:off + 2])
    return {
        "link_id": link_id,
        "data_type": data_type,
        "new_lifespan": new_lifespan,
    }


def _parse_fact_start_process(clear: bytes) -> Dict[str, object]:
    """Parse a SmallFactStartProcess / SmallFactStartProcessUnicode request."""
    service_type, message_type, payload = _parse_small_message(clear)
    if service_type != SMALL_FACTORY_SERVER:
        raise ValueError(f"factory_service_unexpected:{service_type}")
    if message_type not in {SMALL_FACT_START_PROCESS, SMALL_FACT_START_PROCESS_UNICODE}:
        raise ValueError(f"factory_message_unexpected:{message_type}")

    off = 0
    process_name, off = _read_pa_string_le(payload, off)
    if off >= len(payload):
        raise ValueError("factory_start_process_truncated_cmdline_flag")
    add_cmd_line = payload[off] != 0
    off += 1
    if message_type == SMALL_FACT_START_PROCESS_UNICODE:
        cmd_line, off = _read_pw_string_le(payload, off)
    else:
        cmd_line, off = _read_pa_string_le(payload, off)
    if off + 4 > len(payload):
        raise ValueError("factory_start_process_truncated_wait_time")
    wait_time, = struct.unpack("<I", payload[off:off + 4])
    off += 4
    dir_server_address, off = _read_pa_string_le(payload, off)
    display_name, off = _read_pw_string_le(payload, off)
    register_dir, off = _read_pw_string_le(payload, off)
    if off + 3 > len(payload):
        raise ValueError("factory_start_process_truncated_port_info")
    abort_reg_fail = payload[off] != 0
    off += 1
    total_ports = payload[off]
    off += 1
    port_count = payload[off]
    off += 1
    port_set: list[int] = []
    for _ in range(port_count):
        if off + 2 > len(payload):
            raise ValueError("factory_start_process_truncated_port_set")
        port, = struct.unpack("<H", payload[off:off + 2])
        off += 2
        port_set.append(port)
    if off + 2 > len(payload):
        raise ValueError("factory_start_process_truncated_ip_count")
    ip_count, = struct.unpack("<H", payload[off:off + 2])
    off += 2
    authorized_ips: list[str] = []
    for _ in range(ip_count):
        ip, off = _read_pa_string_le(payload, off)
        authorized_ips.append(ip.split(":", 1)[0])
    return {
        "service_type": service_type,
        "message_type": message_type,
        "process_name": process_name,
        "add_cmd_line": add_cmd_line,
        "cmd_line": cmd_line,
        "wait_time": wait_time,
        "dir_server_address": dir_server_address,
        "display_name": display_name,
        "register_dir": register_dir,
        "abort_reg_fail": abort_reg_fail,
        "total_ports": total_ports,
        "port_set": port_set,
        "authorized_ips": authorized_ips,
    }


def _build_small_fact_status_reply(process_status: int, ports: list[int]) -> bytes:
    """Build a SmallFactoryServer SmallFactStatusReply."""
    body = bytes([SMALL_HEADER_TYPE]) + struct.pack(
        "<HHhB",
        SMALL_FACTORY_SERVER,
        SMALL_FACT_STATUS_REPLY,
        process_status,
        len(ports),
    )
    for port in ports:
        body += struct.pack("<H", port)
    return body


def _decode_dir_get(body: bytes) -> Dict[str, object]:
    """Parse a Titan Dir Get request body.

    Byte layout confirmed from Homeworld 1 Wireshark capture (68-byte frame):
      offset  content
         0    version byte       (0x05)
         1    msg_type byte      (0x02 = DirGetReq)
       2–3    request_id         u16 BE
       4–5    path_byte_len      u16 BE = char_count*2 + 1 (incl. null)
         6    get_type flags     (0x06)
         7    0x00 padding
         8    get_opts flags     (0x06)
         9    0x00 padding
      10–11   path_char_count    u16 BE
      12..    path               UCS-2 BE, path_char_count chars
       ...    0x00               UCS-2 null terminator (1 byte in stream)
       ...    has_svc_filter     0x00 or 0x01
       ...    svc_name_len       u16 BE
       ...    svc_name           ASCII bytes
    """
    if len(body) < 12:
        raise ValueError("dir_get_too_short")
    version = body[0]
    msg_type = body[1]
    request_id, = struct.unpack(">H", body[2:4])
    get_type = body[6]
    get_opts = body[8]
    path, off = _rwstr(body, 10)
    off += 1  # skip null byte
    has_filter = body[off] if off < len(body) else 0
    off += 1
    svc_name = ""
    if has_filter and off + 2 <= len(body):
        slen, = struct.unpack(">H", body[off:off + 2])
        off += 2
        svc_name = body[off:off + slen].decode("ascii", errors="replace")
    return {
        "version": version,
        "msg_type": msg_type,
        "request_id": request_id,
        "get_type": get_type,
        "get_opts": get_opts,
        "path": path,
        "service_name": svc_name,
    }


def _encode_dir_reply_body(flags: int, entries: list) -> bytes:
    """Encode a clear WON SmallMessage DirG2MultiEntityReply (message type 3).

    ParseMultiEntityReply (wonapi/WONDir/DirEntityReplyParser.cpp) validates:
        headerType  == 5   (SmallMessage header)
        serviceType == 2   (DirServer)
        messageType == 3   (DirG2MultiEntityReply)

    Wire layout (all integers LE unless noted):
        [u8]   SmallHeader = 5
        [u16]  DirServer service_type = 2
        [u16]  DirG2MultiEntityReply msg_type = 3
        [u16]  status = 0 (success)
        [u8]   sequence = 0x80 (seq=0 | LastReply bit)
        [u32]  flags  (DIR_GF_* GetFlags — controls which fields follow per entity)
        [u16]  entity count
        [entities ...]   each packed according to flags

    Entry dict keys (used when the corresponding flag bit is set):
        "data_objects"  list of (type_bytes, data_bytes) tuples
                        When DIR_GF_ADDDATAOBJECTS is in flags.
                        DataObject.mDataType (= type bytes) is what
                        GetVersionOp.BuildValidVersionSet inserts into the
                        valid-version set, and what Homeworld's version check
                        matches against.
        "type"          str, entity type char ('S' service or 'D' dir)
                        Used when DIR_GF_ADDTYPE is set.
        "name"          str, service or dir name
        "path"          str, path string
        "net_addr"      bytes, raw binary network address for SERVADDNETADDR
        "display_name"  str, display name for ADDDISPLAYNAME

    DataObject wire format (inside the DataObjects section):
        [u16 LE]  count of DataObjects
        Per DataObject:
            if DIR_GF_ADDDOTYPE:  [u8 typeLen][typeLen bytes of type]
            if DIR_GF_ADDDODATA:  [u16 LE dataLen][dataLen bytes of data]
    """
    body = bytes([0x05])                     # SmallHeader = 5
    body += struct.pack("<H", 2)             # DirServer service_type = 2
    body += struct.pack("<H", 3)             # DirG2MultiEntityReply msg_type = 3
    body += struct.pack("<H", 0)             # status = 0 (success)
    body += bytes([0x80])                    # sequence = 0x80 (LastReply bit)
    body += struct.pack("<I", flags)         # GetFlags (u32 LE)
    body += struct.pack("<H", len(entries))  # entity count (u16 LE)

    for e in entries:
        eb = b""

        # Determine entity type — needed both for the type byte and for
        # branching between service-specific vs. directory-specific fields.
        # DirEntityReplyParser reads service fields OR dir fields (else-if),
        # never both, so we must match that structure exactly.
        entity_type = e.get("type", "D")

        # Optional entity type byte
        if flags & DIR_GF_ADDTYPE:
            eb += bytes([ord(entity_type[0]) if entity_type else ord("D")])

        if entity_type == "S":
            # Service-specific fields
            if flags & DIR_GF_SERVADDPATH:
                eb += _twstr(e.get("path", ""))
            if flags & DIR_GF_SERVADDNAME:
                eb += _twstr(e.get("name", ""))
            if flags & DIR_GF_SERVADDNETADDR:
                net = e.get("net_addr", b"")
                if isinstance(net, str):
                    net = net.encode()
                eb += bytes([len(net)]) + net
        else:
            # Directory-specific fields
            if flags & DIR_GF_DIRADDPATH:
                eb += _twstr(e.get("path", ""))
            if flags & DIR_GF_DIRADDNAME:
                eb += _twstr(e.get("name", ""))
            if flags & DIR_GF_DIRADDVISIBLE:
                eb += bytes([1])  # visible = true

        # Common fields (ordered as DirEntity::Unpack reads them)
        if flags & DIR_GF_ADDDISPLAYNAME:
            eb += _twstr(e.get("display_name", e.get("name", "")))
        if flags & DIR_GF_ADDLIFESPAN:
            eb += struct.pack("<I", e.get("lifespan", 0))
        if flags & DIR_GF_ADDCREATED:
            eb += struct.pack("<I", e.get("created", 0))
        if flags & DIR_GF_ADDTOUCHED:
            eb += struct.pack("<I", e.get("touched", 0))
        if flags & DIR_GF_ADDCRC:
            eb += struct.pack("<I", e.get("crc", 0))
        if flags & DIR_GF_ADDUIDS:
            eb += struct.pack("<II", e.get("create_id", 0), e.get("touch_id", 0))

        # DataObjects section
        if flags & DIR_GF_ADDDATAOBJECTS:
            dos = e.get("data_objects", [])
            eb += struct.pack("<H", len(dos))          # u16 LE count
            for do_type, do_data in dos:
                if isinstance(do_type, str):
                    do_type = do_type.encode("ascii")
                if isinstance(do_data, str):
                    do_data = do_data.encode("ascii")
                if flags & DIR_GF_ADDDOTYPE:
                    eb += bytes([len(do_type)]) + do_type   # u8 len + bytes
                if flags & DIR_GF_ADDDODATA:
                    eb += struct.pack("<H", len(do_data)) + do_data  # u16 LE len + bytes

        body += eb

    return body


def _encode_dir_reply(flags: int, entries: list) -> bytes:
    """Encode and length-wrap a WON SmallMessage DirG2MultiEntityReply."""
    return _titan_wrap(_encode_dir_reply_body(flags, entries))


# ---------------------------------------------------------------------------
# Silencer packet builders
# (byte sequences from Silencer_Routing_Server/{connectedclientclass,SrvrNtwk}.cc)
# ---------------------------------------------------------------------------


def _spaced(s: str) -> bytes:
    """Encode a string in the Silencer 'spaced' format: each ASCII char + 0x20.

    The Silencer uses this instead of UCS-2 LE nulls.
    E.g. "Auth" → b"A u t h " (8 bytes).
    """
    return b"".join(bytes([ord(c), 0x20]) for c in s)


def _host_to_ip4(host: str) -> bytes:
    """Convert a hostname/dotted-IP to 4 raw network-order bytes."""
    try:
        return _socket.inet_aton(host)
    except Exception:
        return b"\x7f\x00\x00\x01"


def _parse_valid_versions_text(raw: str) -> list[str]:
    """Parse exact Homeworld valid-version strings from text.

    Homeworld tokenizes the ValidVersions blob on CR/LF boundaries, so we do the
    same here and keep each non-empty line as one exact accepted versionString.
    """
    versions: list[str] = []
    for line in raw.replace("\r", "\n").split("\n"):
        item = line.strip()
        if item:
            versions.append(item)
    return versions


def _silencer_version_response(key_name: str = "SilencerValidVersions",
                               version_str: str = "0110",
                               request_id: int = 3) -> bytes:
    """Build a Titan VERSIONCHECK_RESPONSE using the supplied key name.

    The key name is echoed back from the client's Dir Get request so that the
    client recognises the reply.  E.g. Homeworld sends 'HomeworldValidVersions'
    so we must respond with that same key, not 'SilencerValidVersions'.

    request_id is also echoed from the client's Dir Get request (bytes [2:4]
    of the body, big-endian u16).  Homeworld sends 0x0067 (103); if we reply
    with the wrong ID the client silently discards the response and hangs.

    Layout (all sizes derived dynamically):
        [LE u32 total]
        [2-byte fixed prefix: version + msg_type]
        [2-byte request_id  (BE u16, echoed from request)]
        [11-byte fixed tail of header]
        [0x00][u8 key_len][key ASCII]
        [0x00][u8 val_len][val ASCII]
        [0x00 0x00]
    """
    key = key_name.encode("ascii")
    val = version_str.encode("ascii")
    fixed_header = (
        b"\x05\x02"                       # version=5, msg_type=2
        + struct.pack(">H", request_id)   # request_id echoed (BE u16)
        + b"\x00\x00\x00\x80\x01"        # remaining 5 bytes of first chunk
        + b"\x0a\x00\x00\x01\x00\x01"    # 6-byte second chunk
    )
    body = (
        fixed_header
        + bytes([0x00, len(key)]) + key
        + bytes([0x00, len(val)]) + val
        + b"\x00\x00"
    )
    return struct.pack("<I", len(body) + 4) + body


def _silencer_auth_packet(host: str, port: int) -> bytes:
    """Return the 48-byte auth-server address packet (PAYLOAD2 from SrvrNtwk.cc).

    Port patched at offset 42 (big-endian u16).
    IP   patched at offset 44 (4 bytes, network order).
    """
    header = (
        b"\x30\x00\x00\x00"                # LE u32 total = 48
        b"\x45\x52\x60\x73\x80"            # magic [4..8]
        b"\x90\xa0\xb0\xc1\xda\xe0\xf0"   # magic [9..15]
        b"\x01\x00"                         # entry count = 1
        b"\x53\x0a\x00"                    # entry tag + name char-count (10)
    )
    name = _spaced("AuthServer")           # 10 chars × 2 = 20 bytes
    footer = b"\x06\x00\x00\x00\x00\x00\x00"  # port-flag + port(0) + IP(0)
    data = bytearray(header + name + footer)
    assert len(data) == 48, f"auth packet length mismatch: {len(data)}"
    struct.pack_into(">H", data, 42, port)
    data[44:48] = _host_to_ip4(host)
    return bytes(data)


def _silencer_routing_packet(host: str, port: int) -> bytes:
    """Return the 110-byte routing-server address packet (PAYLOAD3 from SrvrNtwk.cc).

    Two entries: TitanFactoryServer and TitanRoutingServer, both pointing at host:port.
    Port at offsets 58 and 104 (big-endian u16); IP at offsets 60 and 106 (4 bytes).
    """
    header = (
        b"\x6e\x00\x00\x00"                # LE u32 total = 110
        b"\x45\x52\x60\x73\x80"            # magic [4..8]
        b"\x90\xa0\xb0\xc1\xda\xe0\xf0"   # magic [9..15]
        b"\x02\x00"                         # entry count = 2
        b"\x53\x12\x00"                    # entry-1 tag + char-count (18)
    )
    entry1_name = _spaced("TitanFactoryServer")   # 18×2 = 36 bytes  [21..56]
    entry1_tail = b"\x06\x00\x00\x00\x00\x00\x00"  # flag + port(0) + IP(0)
    entry2_head = b"\x53\x12\x00"                   # entry-2 tag + char-count
    entry2_name = _spaced("TitanRoutingServer")    # 18×2 = 36 bytes [67..102]
    entry2_tail = b"\x06\x00\x00\x00\x00\x00\x00"
    data = bytearray(
        header + entry1_name + entry1_tail
        + entry2_head + entry2_name + entry2_tail
    )
    assert len(data) == 110, f"routing packet length mismatch: {len(data)}"
    ip_raw = _host_to_ip4(host)
    struct.pack_into(">H", data, 58, port)
    data[60:64] = ip_raw
    struct.pack_into(">H", data, 104, port)
    data[106:110] = ip_raw
    return bytes(data)


# ---------------------------------------------------------------------------
# Silencer port-15100 routing/lobby server constants
# (from connectedclientclass.cc: UserAcknowledgementPacket, USAGE)
# ---------------------------------------------------------------------------

# UserAcknowledgementPacket: Silencer sends sizeof() = 152 bytes on INIT.
# The C source patches user_id=0 at positions [149..150]; C null lands at [151].
_SILENCER_ROUTING_ACK: bytes = (
    b"\x9d\x00"                              # protocol header (NOT a size prefix)
    b"\x05\x02\x20\x00\x00"                 # packet type bytes
    b"\x13\x00"                              # name char-count = 19
    + _spaced("BetaRoutingServer07")         # 38 bytes
    + b"\x32\x00"                            # message char-count = 50
    + _spaced("Won2. Reviving Old Games. One reversing at a time.")  # 100 bytes
    + b"\x00\x00"                            # user_id = 0x0000
    + b"\x00"                                # C null included by Silencer sizeof()
)  # total: 2+5+2+38+2+100+2+1 = 152 bytes

# USAGE: Silencer sends sizeof()-1 = 51 bytes after the ACK.
_SILENCER_ROUTING_USAGE: bytes = (
    b"\x00\x00\x00\x00\x36\xff\xff\x00\x00"  # 9-byte header
    b"\x28\x00"                               # message byte-length = 40
    b"*To query for conflicts, type something."  # 40 ASCII bytes
)  # total: 9+2+40 = 51 bytes

# Initial conflict packet: 151 all-zero bytes (no game listed).
_SILENCER_EMPTY_CONFLICT: bytes = bytes(0x97)

# Header prepended to conflict data by ProcessNewConflict.
_SILENCER_CONFLICT_HDR: bytes = b"\x97\x00\x05\x02\x09"
_SILENCER_CONFLICT_DATA_LEN: int = 0x92   # 136 bytes of opaque blob from client
_SILENCER_CONFLICT_TOTAL: int = 0x97      # 151 bytes returned by GetConflictPacket


# ---------------------------------------------------------------------------
# SilencerRoutingServer  —  port 15100 lobby / conflict server
# ---------------------------------------------------------------------------

@dataclass
class NativeRouteSubscription:
    link_id: int
    data_type: bytes
    exact_or_recursive: bool
    group_or_members: bool


@dataclass
class NativeRouteDataObject:
    link_id: int
    owner_id: int
    lifespan: int
    data_type: bytes
    data: bytes


@dataclass
class NativeRouteClientState:
    client_id: int
    client_name_raw: bytes
    client_name: str
    client_ip: str
    client_ip_u32: int
    writer: asyncio.StreamWriter
    session_key: bytes
    out_seq: Optional[int]
    connected_at: float = field(default_factory=time.time)
    last_activity_at: float = field(default_factory=time.time)
    last_activity_kind: str = "register"
    last_server_keepalive_at: float = 0.0
    chat_count: int = 0
    peer_data_messages: int = 0
    peer_data_bytes: int = 0
    subscriptions: list[NativeRouteSubscription] = field(default_factory=list)
    write_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


@dataclass
class PendingNativeReconnect:
    client_id: int
    client_name_raw: bytes
    client_name: str
    client_ip: str
    client_ip_u32: int
    connected_at: float
    last_activity_at: float
    last_activity_kind: str
    chat_count: int
    peer_data_messages: int
    peer_data_bytes: int
    subscriptions: list[NativeRouteSubscription] = field(default_factory=list)
    reserved_at: float = field(default_factory=time.time)
    expires_at: float = field(
        default_factory=lambda: time.time() + ROUTING_RECONNECT_GRACE_SECONDS
    )


class SilencerRoutingServer:
    """Replication of the Silencer Routing Server's port-15100 logic.

    Protocol framing (client → server):
        [LE u16 total_len][payload]
        where payload_size = total_len - 2

    Payload layout:
        [0x03][0x02][type_byte][data...]

    Server responses are raw (no length prefix).
    """

    # Packet type IDs (from connectedclientclass.cc)
    _NEW_CONFLICT_ID  = 0x09
    _ABORT_CONFLICT   = 0x0b
    _CLIENTQUERY_ID   = 0x0f
    _USER_TERMINATION = 0x1d
    _INIT_ID          = 0x1f
    _CONFLICTQUERY_ID = 0x29
    _CHATMESSAGE_ID   = 0x35

    def __init__(
        self,
        gateway: Optional["BinaryGatewayServer"] = None,
        listen_port: Optional[int] = None,
        publish_in_directory: bool = True,
    ) -> None:
        # Shared across all concurrent connections (mirrors StaticConflict global).
        self.gateway = gateway
        self.listen_port = listen_port
        self._publish_in_directory = publish_in_directory
        self._published = False
        self._room_allocated = False
        self._room_allocated_at = 0.0
        self._conflict_data: bytes = _SILENCER_EMPTY_CONFLICT
        self._next_native_client_id = 1
        self._native_clients: Dict[int, NativeRouteClientState] = {}
        self._data_objects: Dict[Tuple[int, bytes], NativeRouteDataObject] = {}
        self._room_display_name = "Homeworld Chat"
        self._room_description = "Homeworld Chat"
        self._room_password = ""
        self._room_flags = 0
        self._room_path = "/Homeworld"
        self._pending_reconnects: Dict[int, PendingNativeReconnect] = {}
        self._maintenance_task: Optional[asyncio.Task] = None
        self._solo_peer_data_log_state: Dict[Tuple[str, int], Dict[str, object]] = {}

    def start_background_tasks(self) -> None:
        if self._maintenance_task is None:
            self._maintenance_task = asyncio.create_task(self._maintenance_loop())

    async def stop_background_tasks(self) -> None:
        task = self._maintenance_task
        self._maintenance_task = None
        if task is None:
            return
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    def _room_has_state(self) -> bool:
        return any(
            (
                self._room_allocated,
                self._room_allocated_at > 0.0,
                self._published,
                self._native_clients,
                self._pending_reconnects,
                self._data_objects,
                self._room_password,
                self._room_flags,
                self._room_path != "/Homeworld",
                self._room_display_name != "Homeworld Chat",
                self._room_description != "Homeworld Chat",
                self._conflict_data != _SILENCER_EMPTY_CONFLICT,
            )
        )

    def _reset_room_state(self, reason: str) -> None:
        if self._native_clients or self._pending_reconnects:
            return
        if not self._room_has_state():
            return
        LOGGER.info(
            "Routing(native): ResetRoom port=%s reason=%s published=%s data_objects=%d",
            self.listen_port,
            reason,
            self._published,
            len(self._data_objects),
        )
        if self.gateway is not None and (
            self._published
            or self._room_allocated
            or self._data_objects
            or self._room_password
        ):
            self.gateway.record_activity(
                "room_close",
                room_port=self.listen_port,
                room_name=self._room_display_name,
                room_path=self._room_path,
            )
        self._published = False
        self._room_allocated = False
        self._room_allocated_at = 0.0
        self._conflict_data = _SILENCER_EMPTY_CONFLICT
        self._next_native_client_id = 1
        self._data_objects.clear()
        self._room_display_name = "Homeworld Chat"
        self._room_description = "Homeworld Chat"
        self._room_password = ""
        self._room_flags = 0
        self._room_path = "/Homeworld"
        self._solo_peer_data_log_state.clear()

    def mark_room_allocated(self) -> None:
        self._room_allocated = True
        self._room_allocated_at = time.time()

    def _reap_unused_room_allocation(self) -> None:
        if not self._room_allocated:
            return
        if self._published or self._native_clients or self._pending_reconnects:
            return
        if self._room_allocated_at <= 0.0:
            return
        if time.time() - self._room_allocated_at < ROOM_ALLOCATION_GRACE_SECONDS:
            return
        self._reset_room_state("allocation_timeout")

    def _should_offer_reconnect(
        self,
        client: NativeRouteClientState,
        disconnect_reason: str,
    ) -> bool:
        if disconnect_reason not in {"transport_lost", "connection_reset", "eof"}:
            return False
        return bool(self._native_clients or self._data_objects or self._published)

    def _park_disconnected_client(
        self,
        client: NativeRouteClientState,
        disconnect_reason: str,
    ) -> None:
        reservation = PendingNativeReconnect(
            client_id=client.client_id,
            client_name_raw=bytes(client.client_name_raw),
            client_name=str(client.client_name),
            client_ip=str(client.client_ip),
            client_ip_u32=int(client.client_ip_u32),
            connected_at=float(client.connected_at),
            last_activity_at=float(client.last_activity_at),
            last_activity_kind=str(client.last_activity_kind),
            chat_count=int(client.chat_count),
            peer_data_messages=int(client.peer_data_messages),
            peer_data_bytes=int(client.peer_data_bytes),
            subscriptions=[
                NativeRouteSubscription(
                    link_id=sub.link_id,
                    data_type=bytes(sub.data_type),
                    exact_or_recursive=bool(sub.exact_or_recursive),
                    group_or_members=bool(sub.group_or_members),
                )
                for sub in client.subscriptions
            ],
        )
        self._pending_reconnects[reservation.client_id] = reservation
        LOGGER.info(
            "Routing(native): ReconnectReservation id=%d name=%r ip=%s grace=%.1fs reason=%s",
            reservation.client_id,
            reservation.client_name,
            reservation.client_ip,
            max(0.0, reservation.expires_at - reservation.reserved_at),
            disconnect_reason,
        )

    async def _claim_pending_reconnect(
        self,
        client_name_raw: bytes,
        client_ip: str,
    ) -> Optional[PendingNativeReconnect]:
        await self._expire_pending_reconnects()
        for client_id, reservation in list(self._pending_reconnects.items()):
            if reservation.client_ip != client_ip:
                continue
            if reservation.client_name_raw != bytes(client_name_raw):
                continue
            self._pending_reconnects.pop(client_id, None)
            LOGGER.info(
                "Routing(native): ReconnectClaim id=%d name=%r ip=%s",
                reservation.client_id,
                reservation.client_name,
                reservation.client_ip,
            )
            return reservation
        return None

    async def _claim_pending_reconnect_by_id(
        self,
        client_id: int,
        client_ip: str,
    ) -> Optional[PendingNativeReconnect]:
        await self._expire_pending_reconnects()
        reservation = self._pending_reconnects.get(int(client_id))
        if reservation is None:
            return None
        if reservation.client_ip != client_ip:
            return None
        self._pending_reconnects.pop(int(client_id), None)
        LOGGER.info(
            "Routing(native): ReconnectClaim id=%d name=%r ip=%s (client-id path)",
            reservation.client_id,
            reservation.client_name,
            reservation.client_ip,
        )
        return reservation

    async def _finalize_client_departure(
        self,
        client_id: int,
        client_name: str,
        client_ip: str,
        *,
        disconnect_reason: str,
        remove_owned_objects: bool = True,
        broadcast_leave: bool = True,
    ) -> None:
        if self.gateway is not None:
            self.gateway.record_activity(
                "leave",
                room_port=self.listen_port,
                room_name=self._room_display_name,
                room_path=self._room_path,
                player_id=client_id,
                player_name=client_name,
                player_ip=client_ip,
                details={"reason": disconnect_reason},
            )
        LOGGER.info(
            "Routing(native): Client disconnected id=%d name=%r reason=%s",
            client_id,
            client_name,
            disconnect_reason,
        )
        if remove_owned_objects:
            removed_objects = await self._remove_owned_data_objects(client_id)
            if removed_objects:
                LOGGER.info(
                    "Routing(native): removed %d owned data objects for disconnected client_id=%d",
                    removed_objects,
                    client_id,
                )
        if broadcast_leave:
            delivered = await self._broadcast_native_route_group_change(
                _build_mini_routing_group_change(
                    CHAT_GROUP_ID,
                    client_id,
                    ROUTING_REASON_VOLUNTARY_DISCONNECT,
                ),
                exclude_client_id=client_id,
            )
            if delivered:
                LOGGER.info(
                    "Routing(native): GroupChange leave broadcast sent to %d clients",
                    delivered,
                )
        if not self._native_clients and not self._pending_reconnects:
            self._reset_room_state(f"empty_after_{disconnect_reason}")

    async def admin_kick_client(self, client_id: int) -> bool:
        """Admin action: forcibly disconnect a client by id."""
        client = self._native_clients.get(client_id)
        if client is None:
            return False
        LOGGER.info(
            "Routing(admin): kicking client_id=%d name=%r ip=%s",
            client.client_id, client.client_name, client.client_ip,
        )
        try:
            client.writer.close()
            await client.writer.wait_closed()
        except Exception:
            pass
        return True

    async def admin_broadcast_chat(self, text: str) -> int:
        """Admin action: send a chat message from [ADMIN] to all clients."""
        data = text.encode("utf-8", errors="replace")
        peer_chat = _build_mini_routing_peer_chat(
            client_id=0,
            chat_type=CHAT_GROUP_ID,
            data=data,
            addressees=[],
            include_exclude_flag=False,
        )
        delivered = 0
        for client in list(self._native_clients.values()):
            try:
                await self._send_native_route_client_reply(client, peer_chat)
                delivered += 1
            except Exception as exc:
                LOGGER.warning(
                    "Routing(admin): failed broadcast to client_id=%d: %s",
                    client.client_id, exc,
                )
        LOGGER.info("Routing(admin): broadcast delivered to %d clients", delivered)
        return delivered

    async def _expire_pending_reconnects(self) -> None:
        now = time.time()
        expired_ids = [
            client_id
            for client_id, reservation in list(self._pending_reconnects.items())
            if reservation.expires_at <= now
        ]
        for client_id in expired_ids:
            reservation = self._pending_reconnects.pop(client_id, None)
            if reservation is None:
                continue
            LOGGER.info(
                "Routing(native): ReconnectReservation expired id=%d name=%r idle_for=%.1fs",
                reservation.client_id,
                reservation.client_name,
                max(0.0, now - reservation.reserved_at),
            )
            await self._finalize_client_departure(
                reservation.client_id,
                reservation.client_name,
                reservation.client_ip,
                disconnect_reason="reconnect_expired",
            )

    async def _send_server_keepalives(self) -> None:
        now = time.time()
        keepalive = _build_mini_routing_keep_alive()
        for client in list(self._native_clients.values()):
            if now - client.last_activity_at < ROUTING_HEARTBEAT_IDLE_SECONDS:
                continue
            if (
                client.last_server_keepalive_at > 0.0
                and now - client.last_server_keepalive_at < ROUTING_HEARTBEAT_INTERVAL_SECONDS
            ):
                continue
            try:
                await self._send_native_route_client_reply(client, keepalive)
                client.last_server_keepalive_at = now
                LOGGER.debug(
                    "Routing(native): ServerKeepAlive sent to client_id=%d name=%r",
                    client.client_id,
                    client.client_name,
                )
            except Exception as exc:
                LOGGER.warning(
                    "Routing(native): ServerKeepAlive failed for client_id=%d name=%r: %s",
                    client.client_id,
                    client.client_name,
                    exc,
                )
                with contextlib.suppress(Exception):
                    client.writer.close()

    async def _maintenance_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(ROUTING_MAINTENANCE_INTERVAL_SECONDS)
                self._reap_unused_room_allocation()
                await self._expire_pending_reconnects()
                await self._send_server_keepalives()
        except asyncio.CancelledError:
            raise

    def _touch_native_client(
        self,
        client_id: Optional[int],
        activity_kind: str,
        payload_len: int = 0,
    ) -> Optional[NativeRouteClientState]:
        if not client_id:
            return None
        client = self._native_clients.get(int(client_id))
        if client is None:
            return None
        client.last_activity_at = time.time()
        client.last_activity_kind = activity_kind
        if activity_kind == "chat":
            client.chat_count += 1
        elif activity_kind == "peer_data":
            client.peer_data_messages += 1
            client.peer_data_bytes += max(0, int(payload_len))
        return client

    def _alloc_native_client_id(self) -> int:
        reserved_ids = set(self._native_clients) | set(self._pending_reconnects)
        for _ in range(MAX_NATIVE_CLIENT_ID):
            client_id = self._next_native_client_id
            self._next_native_client_id = 1 if client_id >= MAX_NATIVE_CLIENT_ID else client_id + 1
            if client_id not in reserved_ids:
                return client_id
        raise RuntimeError("native_client_id_exhausted")

    def _flush_solo_peer_data_logs(self, client_id: Optional[int] = None) -> None:
        keys = [
            key
            for key in list(self._solo_peer_data_log_state)
            if client_id is None or key[1] == int(client_id)
        ]
        now = time.monotonic()
        for key in keys:
            state = self._solo_peer_data_log_state.pop(key, None)
            if not state:
                continue
            suppressed = int(state.get("suppressed", 0))
            if suppressed <= 0:
                continue
            kind, tracked_client_id = key
            window_started = float(state.get("window_started_monotonic", now))
            LOGGER.info(
                "Routing(native): %s from client_id=%d suppressed %d additional no-recipient packets over %.1fs (latest_len=%d reply=%s)",
                kind,
                tracked_client_id,
                suppressed,
                max(0.0, now - window_started),
                int(state.get("latest_len", 0)),
                bool(state.get("latest_reply", False)),
            )

    def _log_native_peer_data_event(
        self,
        kind: str,
        client_id: int,
        data_len: int,
        recipients: int,
        should_send_reply: bool,
    ) -> None:
        if recipients > 0 or client_id <= 0:
            self._flush_solo_peer_data_logs(client_id if client_id > 0 else None)
            LOGGER.info(
                "Routing(native): %s from client_id=%d data_len=%d recipients=%d reply=%s",
                kind,
                client_id,
                data_len,
                recipients,
                should_send_reply,
            )
            return

        now = time.monotonic()
        key = (kind, int(client_id))
        state = self._solo_peer_data_log_state.get(key)
        if state is None:
            self._solo_peer_data_log_state[key] = {
                "window_started_monotonic": now,
                "last_emit_monotonic": now,
                "suppressed": 0,
                "latest_len": int(data_len),
                "latest_reply": bool(should_send_reply),
            }
            LOGGER.info(
                "Routing(native): %s from client_id=%d data_len=%d recipients=0 reply=%s (no peers connected; suppressing repeats)",
                kind,
                client_id,
                data_len,
                should_send_reply,
            )
            return

        state["latest_len"] = int(data_len)
        state["latest_reply"] = bool(should_send_reply)
        last_emit = float(state.get("last_emit_monotonic", now))
        if now - last_emit < 5.0:
            state["suppressed"] = int(state.get("suppressed", 0)) + 1
            return

        suppressed = int(state.get("suppressed", 0))
        window_started = float(state.get("window_started_monotonic", now))
        if suppressed > 0:
            LOGGER.info(
                "Routing(native): %s from client_id=%d suppressed %d additional no-recipient packets over %.1fs (latest_len=%d reply=%s)",
                kind,
                client_id,
                suppressed,
                max(0.0, now - window_started),
                int(state.get("latest_len", 0)),
                bool(state.get("latest_reply", False)),
            )

        state["window_started_monotonic"] = now
        state["last_emit_monotonic"] = now
        state["suppressed"] = 0
        LOGGER.info(
            "Routing(native): %s from client_id=%d data_len=%d recipients=0 reply=%s (still no peers connected; suppressing repeats)",
            kind,
            client_id,
            data_len,
            should_send_reply,
        )

    def can_host_room(self) -> bool:
        return (
            not self._room_allocated
            and not self._published
            and not self._native_clients
            and not self._pending_reconnects
        )

    def is_directory_visible(self) -> bool:
        return self._publish_in_directory and self._published

    def native_directory_entry(self, public_host: str) -> Optional[Dict[str, object]]:
        if not self.is_directory_visible() or self.listen_port is None:
            return None
        try:
            ip_raw = _socket.inet_aton(public_host)
        except Exception:
            ip_raw = b"\x7f\x00\x00\x01"
        return {
            "type": "S",
            "name": "TitanRoutingServer",
            "display_name": self._room_display_name or "TitanRoutingServer",
            "net_addr": struct.pack(">H", int(self.listen_port)) + ip_raw,
            "data_objects": [
                _pack_directory_data_object(
                    "Description",
                    self._room_description or self._room_display_name,
                ),
                _pack_directory_data_object("RoomFlags", self._room_flags),
                _pack_directory_data_object("__RSClientCount", len(self._native_clients)),
            ],
        }

    def dashboard_snapshot(self) -> Dict[str, object]:
        now = time.time()
        data_objects = []
        for key in sorted(self._data_objects):
            obj = self._data_objects[key]
            data_objects.append(
                {
                    "link_id": obj.link_id,
                    "owner_id": obj.owner_id,
                    "lifespan": obj.lifespan,
                    "data_type_hex": obj.data_type.hex(),
                    "data_type_text": _decode_routing_data_type(obj.data_type),
                    "data_len": len(obj.data),
                    "data_preview_hex": obj.data[:32].hex(),
                }
            )

        clients = []
        client_lookup: Dict[int, NativeRouteClientState] = {}
        for client_id in sorted(self._native_clients):
            client = self._native_clients[client_id]
            client_lookup[client.client_id] = client
            clients.append(
                {
                    "client_id": client.client_id,
                    "client_name": client.client_name,
                    "client_name_hex": client.client_name_raw.hex(),
                    "client_ip": client.client_ip,
                    "client_ip_u32": client.client_ip_u32,
                    "out_seq": client.out_seq,
                    "connected_at": client.connected_at,
                    "connected_seconds": int(max(0.0, now - client.connected_at)),
                    "last_activity_at": client.last_activity_at,
                    "idle_seconds": int(max(0.0, now - client.last_activity_at)),
                    "last_activity_kind": client.last_activity_kind,
                    "chat_count": client.chat_count,
                    "peer_data_messages": client.peer_data_messages,
                    "peer_data_bytes": client.peer_data_bytes,
                    "subscription_count": len(client.subscriptions),
                    "subscriptions": [
                        {
                            "link_id": sub.link_id,
                            "data_type_hex": sub.data_type.hex(),
                            "data_type_text": _decode_routing_data_type(sub.data_type),
                            "exact_or_recursive": sub.exact_or_recursive,
                            "group_or_members": sub.group_or_members,
                        }
                        for sub in client.subscriptions
                    ],
                }
            )

        games = []
        for data_object in self._data_objects.values():
            owner = client_lookup.get(data_object.owner_id)
            games.append(
                {
                    "link_id": data_object.link_id,
                    "owner_id": data_object.owner_id,
                    "owner_name": owner.client_name if owner is not None else "",
                    "name": _decode_routing_data_type(data_object.data_type),
                    "data_len": len(data_object.data),
                    "lifespan": data_object.lifespan,
                    "data_preview_hex": data_object.data[:32].hex(),
                }
            )
        games.sort(key=lambda item: (item["owner_name"], item["name"], item["link_id"]))

        pending_reconnects = []
        for client_id in sorted(self._pending_reconnects):
            reservation = self._pending_reconnects[client_id]
            pending_reconnects.append(
                {
                    "client_id": reservation.client_id,
                    "client_name": reservation.client_name,
                    "client_ip": reservation.client_ip,
                    "reserved_at": reservation.reserved_at,
                    "seconds_remaining": max(0, int(reservation.expires_at - now)),
                    "last_activity_kind": reservation.last_activity_kind,
                    "peer_data_messages": reservation.peer_data_messages,
                    "peer_data_bytes": reservation.peer_data_bytes,
                }
            )

        return {
            "listen_port": self.listen_port,
            "publish_in_directory": self._publish_in_directory,
            "published": self._published,
            "room_allocated": self._room_allocated,
            "room_display_name": self._room_display_name,
            "room_description": self._room_description,
            "room_password_set": bool(self._room_password),
            "room_flags": self._room_flags,
            "room_path": self._room_path,
            "native_client_count": len(clients),
            "pending_reconnect_count": len(pending_reconnects),
            "pending_reconnects": pending_reconnects,
            "client_names": [client["client_name"] for client in clients],
            "clients": clients,
            "game_count": len(games),
            "games": games,
            "data_object_count": len(data_objects),
            "data_objects": data_objects,
            "conflict_data_len": len(self._conflict_data),
        }

    def _is_native_auth_request(self, payload: bytes) -> bool:
        try:
            svc, msg, _body = won_crypto.parse_tmessage(payload)
        except Exception:
            return False
        return svc == AUTH1_PEER_SERVICE_TYPE and msg == AUTH1_PEER_REQUEST

    async def _send_native_route_reply(
        self,
        writer: asyncio.StreamWriter,
        clear_msg: bytes,
        session_key: bytes,
        seq_num: Optional[int],
    ) -> Optional[int]:
        reply_enc = _encrypt_persistent_non_t(clear_msg, session_key, seq_num)
        writer.write(_routing_wrap(reply_enc))
        await writer.drain()
        return None if seq_num is None else seq_num + 1

    async def _send_native_route_client_reply(
        self,
        client: NativeRouteClientState,
        clear_msg: bytes,
    ) -> None:
        async with client.write_lock:
            client.out_seq = await self._send_native_route_reply(
                client.writer,
                clear_msg,
                client.session_key,
                client.out_seq,
            )

    async def _broadcast_native_route_chat(
        self,
        sender_client_id: int,
        chat_type: int,
        data: bytes,
        addressees: list[int],
        include_exclude_flag: bool,
    ) -> int:
        addressee_set = set(addressees)
        peer_chat = _build_mini_routing_peer_chat(
            sender_client_id,
            chat_type,
            data,
            addressees,
            include_exclude_flag,
        )

        targets: list[NativeRouteClientState] = []
        for client_id, client in list(self._native_clients.items()):
            if client_id == sender_client_id:
                continue
            listed = client_id in addressee_set
            if addressees:
                if include_exclude_flag and not listed:
                    continue
                if not include_exclude_flag and listed:
                    continue
            elif include_exclude_flag:
                continue
            targets.append(client)

        delivered = 0
        for client in targets:
            try:
                await self._send_native_route_client_reply(client, peer_chat)
                delivered += 1
            except Exception as exc:
                LOGGER.warning(
                    "Routing(native): failed chat delivery to client_id=%d name=%r: %s",
                    client.client_id,
                    client.client_name,
                    exc,
                )
        return delivered

    async def _broadcast_native_route_peer_data(
        self,
        sender_client_id: int,
        data: bytes,
        addressees: list[int],
        include_exclude_flag: bool,
    ) -> int:
        addressee_set = set(addressees)
        peer_data = _build_mini_routing_peer_data(sender_client_id, data)

        targets: list[NativeRouteClientState] = []
        for client_id, client in list(self._native_clients.items()):
            if client_id == sender_client_id:
                continue
            listed = client_id in addressee_set
            if addressees:
                if include_exclude_flag and not listed:
                    continue
                if not include_exclude_flag and listed:
                    continue
            elif include_exclude_flag:
                continue
            targets.append(client)

        delivered = 0
        for client in targets:
            try:
                await self._send_native_route_client_reply(client, peer_data)
                delivered += 1
            except Exception as exc:
                LOGGER.warning(
                    "Routing(native): failed peer-data delivery to client_id=%d name=%r: %s",
                    client.client_id,
                    client.client_name,
                    exc,
                )
        return delivered

    async def _broadcast_native_route_group_change(
        self,
        clear_msg: bytes,
        exclude_client_id: int = 0,
    ) -> int:
        delivered = 0
        for client_id, client in list(self._native_clients.items()):
            if exclude_client_id and client_id == exclude_client_id:
                continue
            try:
                await self._send_native_route_client_reply(client, clear_msg)
                delivered += 1
            except Exception as exc:
                LOGGER.warning(
                    "Routing(native): failed group-change delivery to client_id=%d name=%r: %s",
                    client.client_id,
                    client.client_name,
                    exc,
                )
        return delivered

    @staticmethod
    def _route_data_key(link_id: int, data_type: bytes) -> Tuple[int, bytes]:
        return int(link_id), bytes(data_type)

    @staticmethod
    def _route_data_matches_subscription(
        data_object: NativeRouteDataObject,
        subscription: NativeRouteSubscription,
    ) -> bool:
        if subscription.link_id not in {0, int(data_object.link_id)}:
            return False
        if not subscription.data_type:
            return True
        if subscription.exact_or_recursive:
            return data_object.data_type == subscription.data_type
        return data_object.data_type.startswith(subscription.data_type)

    def _route_reply_tuple(self, data_object: NativeRouteDataObject) -> Tuple[int, int, bytes, bytes]:
        return (
            data_object.link_id,
            data_object.owner_id,
            bytes(data_object.data_type),
            bytes(data_object.data),
        )

    def _route_data_objects_for_subscription(
        self,
        subscription: NativeRouteSubscription,
    ) -> list[Tuple[int, int, bytes, bytes]]:
        matches = [
            self._route_reply_tuple(data_object)
            for data_object in self._data_objects.values()
            if self._route_data_matches_subscription(data_object, subscription)
        ]
        matches.sort(key=lambda item: (item[0], item[2]))
        return matches

    async def _broadcast_native_route_data_object(
        self,
        clear_msg: bytes,
        data_object: NativeRouteDataObject,
    ) -> int:
        delivered = 0
        for client in list(self._native_clients.values()):
            if not any(
                self._route_data_matches_subscription(data_object, subscription)
                for subscription in client.subscriptions
            ):
                continue
            try:
                await self._send_native_route_client_reply(client, clear_msg)
                delivered += 1
            except Exception as exc:
                LOGGER.warning(
                    "Routing(native): failed data-object delivery to client_id=%d name=%r: %s",
                    client.client_id,
                    client.client_name,
                    exc,
                )
        return delivered

    async def _remove_owned_data_objects(self, owner_id: int) -> int:
        removed = 0
        for key, data_object in list(self._data_objects.items()):
            if data_object.owner_id != owner_id:
                continue
            self._data_objects.pop(key, None)
            removed += 1
            LOGGER.info(
                "Routing(native): AutoDeleteDataObject owner_id=%d link_id=%d type=%r name=%r on disconnect",
                owner_id,
                data_object.link_id,
                data_object.data_type,
                _decode_routing_data_type(data_object.data_type),
            )
            delivered = await self._broadcast_native_route_data_object(
                _build_mini_routing_delete_data_object(
                    data_object.link_id,
                    data_object.data_type,
                ),
                data_object,
            )
            LOGGER.info(
                "Routing(native): AutoDeleteDataObject broadcast sent to %d subscribed clients",
                delivered,
            )
        return removed

    async def _handle_native_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        first_payload: bytes,
    ) -> None:
        peer = writer.get_extra_info("peername", ("?", 0))
        if self.gateway is None or not self.gateway._auth_keys_loaded:
            LOGGER.warning(
                "Routing(native): rejecting %s:%s because Auth1 keys are not available",
                *peer,
            )
            return

        registered_client_id = 0
        session_key = b""
        in_seq: Optional[int] = None
        out_seq: Optional[int] = None
        disconnect_reason = "transport_lost"

        try:
            svc, msg, req_body = won_crypto.parse_tmessage(first_payload)
            LOGGER.info(
                "Routing(native): Auth1Peer first message from %s:%s (svc=%d msg=%d, %d bytes)",
                *peer, svc, msg, len(req_body),
            )
            if svc != AUTH1_PEER_SERVICE_TYPE or msg != AUTH1_PEER_REQUEST:
                LOGGER.warning(
                    "Routing(native): unexpected first message svc=%d msg=%d from %s:%s",
                    svc, msg, *peer,
                )
                return

            req = _parse_auth1_peer_request(req_body)
            client_cert = _parse_auth1_certificate(bytes(req["certificate"]))
            if client_cert["sig"] and not won_crypto.nr_md5_verify(
                bytes(client_cert["unsigned"]),
                bytes(client_cert["sig"]),
                self.gateway._auth_p,
                self.gateway._auth_q,
                self.gateway._auth_g,
                self.gateway._auth_y,
            ):
                LOGGER.warning("Routing(native): client certificate failed auth-key verification")
                return

            LOGGER.info(
                "Routing(native): Auth1Peer request auth_mode=%d encrypt_mode=%d flags=0x%04x user_id=%d",
                req["auth_mode"], req["encrypt_mode"], req["encrypt_flags"], client_cert["user_id"],
            )

            server_user_id = self.gateway._next_user_id
            self.gateway._next_user_id += 1
            server_cert, _server_y, server_x = self.gateway._build_user_cert(server_user_id)
            secret_b = os.urandom(8)
            secret_b_plain = struct.pack("<H", len(secret_b)) + secret_b
            secret_b_cipher = won_crypto.eg_encrypt(
                secret_b_plain,
                int(client_cert["p"]),
                int(client_cert["g"]),
                int(client_cert["y"]),
            )

            challenge1 = _routing_tmessage_payload(
                _build_auth1_peer_challenge1(secret_b_cipher, server_cert)
            )
            writer.write(_routing_wrap(challenge1))
            await writer.drain()
            LOGGER.info("Routing(native): Auth1Peer Challenge1 sent to %s:%s", *peer)

            payload = await _routing_recv(reader)
            svc, msg, challenge2_body = won_crypto.parse_tmessage(payload)
            LOGGER.info(
                "Routing(native): Auth1Peer next message from %s:%s (svc=%d msg=%d, %d bytes)",
                *peer, svc, msg, len(challenge2_body),
            )
            if svc != AUTH1_PEER_SERVICE_TYPE or msg != AUTH1_PEER_CHALLENGE2:
                LOGGER.warning(
                    "Routing(native): expected Challenge2, got svc=%d msg=%d from %s:%s",
                    svc, msg, *peer,
                )
                return

            challenge2_cipher = _parse_auth1_peer_challenge2(challenge2_body)
            challenge2_plain = won_crypto.eg_decrypt(
                challenge2_cipher,
                self.gateway._auth_p,
                self.gateway._auth_g,
                server_x,
            )
            if len(challenge2_plain) < 2:
                LOGGER.warning("Routing(native): Challenge2 plaintext too short from %s:%s", *peer)
                return
            secret_b_len, = struct.unpack("<H", challenge2_plain[:2])
            secret_b_echo = challenge2_plain[2:2 + secret_b_len]
            secret_a = challenge2_plain[2 + secret_b_len:]
            if secret_b_echo != secret_b:
                LOGGER.warning("Routing(native): SecretB mismatch from %s:%s", *peer)
                return
            if not secret_a:
                LOGGER.warning("Routing(native): empty SecretA from %s:%s", *peer)
                return

            secret_a_cipher = won_crypto.eg_encrypt(
                struct.pack("<H", len(secret_a)) + secret_a,
                int(client_cert["p"]),
                int(client_cert["g"]),
                int(client_cert["y"]),
            )
            complete = _routing_tmessage_payload(_build_auth1_peer_complete(secret_a_cipher))
            writer.write(_routing_wrap(complete))
            await writer.drain()
            LOGGER.info("Routing(native): Auth1Peer Complete sent to %s:%s", *peer)

            session_key = secret_b
            if (int(req["encrypt_flags"]) & 0x0001) == 0:
                in_seq = 1
                out_seq = 1

            while True:
                try:
                    payload = await asyncio.wait_for(
                        _routing_recv(reader),
                        timeout=ROUTING_IDLE_TIMEOUT_SECONDS,
                    )
                except asyncio.TimeoutError:
                    disconnect_reason = "idle_timeout"
                    if registered_client_id and registered_client_id in self._native_clients:
                        idle_client = self._native_clients[registered_client_id]
                        LOGGER.info(
                            "Routing(native): idle timeout from %s:%s (id=%d name=%r idle_for=%.1fs)",
                            *peer,
                            idle_client.client_id,
                            idle_client.client_name,
                            max(0.0, time.time() - idle_client.last_activity_at),
                        )
                    else:
                        LOGGER.info(
                            "Routing(native): idle timeout from %s:%s before RegisterClient",
                            *peer,
                        )
                    return
                if payload[0] not in {0x04, 0x06}:
                    disconnect_reason = "protocol_error"
                    LOGGER.warning(
                        "Routing(native): unexpected post-auth header 0x%02x from %s:%s",
                        payload[0], *peer,
                    )
                    return

                clear = _decrypt_persistent_non_t(payload, session_key, in_seq)
                if in_seq is not None:
                    in_seq += 1

                if clear[0] == SMALL_HEADER_TYPE:
                    service_type, message_type, _msg_body = _parse_small_message(clear)
                    if service_type == SMALL_COMMON_SERVICE and message_type in {
                        SMALL_COMM_REGISTER_REQUEST,
                        SMALL_COMM_REGISTER_REQUEST_EX,
                    }:
                        req = _parse_small_common_register_request(clear)
                        for obj_type, obj_data in req["data_objects"]:
                            if obj_type == b"Description":
                                with contextlib.suppress(UnicodeDecodeError):
                                    self._room_description = obj_data.decode("utf-16-le")
                            elif obj_type == b"RoomFlags" and len(obj_data) >= 4:
                                self._room_flags, = struct.unpack("<I", obj_data[:4])
                        if req["display_name"]:
                            self._room_display_name = str(req["display_name"])
                        if req["path"]:
                            self._room_path = str(req["path"])
                        self._published = True
                        if self.gateway is not None:
                            self.gateway.record_activity(
                                "room_open",
                                room_port=self.listen_port,
                                room_name=self._room_display_name,
                                room_path=self._room_path,
                                details={
                                    "description": self._room_description,
                                    "room_flags": self._room_flags,
                                    "protected": bool(self._room_password),
                                },
                            )
                        LOGGER.info(
                            "Routing(native): RegisterRequest port=%s display=%r desc=%r path=%r room_flags=0x%08x dirs=%d",
                            self.listen_port,
                            self._room_display_name,
                            self._room_description,
                            self._room_path,
                            self._room_flags,
                            len(req["dir_addresses"]),
                        )
                        out_seq = await self._send_native_route_reply(
                            writer,
                            _build_small_common_status_reply(0),
                            session_key,
                            out_seq,
                        )
                        LOGGER.info("Routing(native): RegisterRequest success sent to %s:%s", *peer)
                        continue

                if clear[0] == MINI_HEADER_TYPE:
                    service_type, message_type, _msg_body = _parse_mini_message(clear)
                    if service_type == MINI_COMMON_SERVICE and message_type == MINI_COMM_PING:
                        ping = _parse_mini_ping(clear)
                        self._touch_native_client(registered_client_id, "ping")
                        LOGGER.info(
                            "Routing(native): MiniPing start_tick=%d extended=%s",
                            ping["start_tick"], ping["extended"],
                        )
                        out_seq = await self._send_native_route_reply(
                            writer,
                            _build_mini_ping_reply(int(ping["start_tick"])),
                            session_key,
                            out_seq,
                        )
                        if registered_client_id and registered_client_id in self._native_clients:
                            self._native_clients[registered_client_id].out_seq = out_seq
                        continue

                    if service_type == MINI_ROUTING_SERVICE and message_type == ROUTING_REGISTER_CLIENT:
                        req = _parse_mini_routing_register_client(clear)
                        if self._room_password and str(req["password"]) != self._room_password:
                            LOGGER.info(
                                "Routing(native): RegisterClient rejected name=%r supplied_password=%s protected=%s",
                                req["client_name"],
                                bool(req["password"]),
                                True,
                            )
                            out_seq = await self._send_native_route_reply(
                                writer,
                                _build_mini_routing_register_client_reply(
                                    STATUS_ROUTING_INVALID_PASSWORD,
                                    0,
                                    b"",
                                    self._room_description,
                                ),
                                session_key,
                                out_seq,
                            )
                            LOGGER.info(
                                "Routing(native): RegisterClientReply sent to %s:%s (status=%d)",
                                *peer,
                                STATUS_ROUTING_INVALID_PASSWORD,
                            )
                            continue
                        client_ip = str(peer[0]) if peer and len(peer) > 0 and isinstance(peer[0], str) else "127.0.0.1"
                        client_ip_u32 = int.from_bytes(_host_to_ip4(client_ip), "little")
                        reconnect = await self._claim_pending_reconnect(
                            bytes(req["client_name_raw"]),
                            client_ip,
                        )
                        registered_client_id = (
                            reconnect.client_id
                            if reconnect is not None
                            else self._alloc_native_client_id()
                        )
                        self._native_clients[registered_client_id] = NativeRouteClientState(
                            client_id=registered_client_id,
                            client_name_raw=bytes(req["client_name_raw"]),
                            client_name=str(req["client_name"]),
                            client_ip=client_ip,
                            client_ip_u32=client_ip_u32,
                            writer=writer,
                            session_key=session_key,
                            out_seq=out_seq,
                            connected_at=(
                                reconnect.connected_at
                                if reconnect is not None
                                else time.time()
                            ),
                            last_activity_at=time.time(),
                            last_activity_kind=(
                                "reconnect" if reconnect is not None else "register"
                            ),
                            chat_count=(
                                reconnect.chat_count
                                if reconnect is not None
                                else 0
                            ),
                            peer_data_messages=(
                                reconnect.peer_data_messages
                                if reconnect is not None
                                else 0
                            ),
                            peer_data_bytes=(
                                reconnect.peer_data_bytes
                                if reconnect is not None
                                else 0
                            ),
                            subscriptions=(
                                [
                                    NativeRouteSubscription(
                                        link_id=sub.link_id,
                                        data_type=bytes(sub.data_type),
                                        exact_or_recursive=bool(sub.exact_or_recursive),
                                        group_or_members=bool(sub.group_or_members),
                                    )
                                    for sub in reconnect.subscriptions
                                ]
                                if reconnect is not None
                                else []
                            ),
                        )
                        LOGGER.info(
                            "Routing(native): RegisterClient %s id=%d name=%r setup_chat=%s host=%s spectator=%s",
                            "resume" if reconnect is not None else "new",
                            registered_client_id,
                            req["client_name"],
                            req["setup_chat"],
                            req["trying_to_become_host"],
                            req["become_spectator"],
                        )
                        out_seq = await self._send_native_route_reply(
                            writer,
                            _build_mini_routing_register_client_reply(
                                0,
                                registered_client_id,
                                bytes(req["client_name_raw"]),
                                self._room_description,
                            ),
                            session_key,
                            out_seq,
                        )
                        self._native_clients[registered_client_id].out_seq = out_seq
                        LOGGER.info(
                            "Routing(native): RegisterClientReply sent to %s:%s (client_id=%d)",
                            *peer, registered_client_id,
                        )
                        self._touch_native_client(
                            registered_client_id,
                            "reconnect" if reconnect is not None else "join",
                        )
                        if self.gateway is not None:
                            self.gateway.record_activity(
                                "rejoin" if reconnect is not None else "join",
                                room_port=self.listen_port,
                                room_name=self._room_display_name,
                                room_path=self._room_path,
                                player_id=registered_client_id,
                                player_name=str(req["client_name"]),
                                player_ip=client_ip,
                            )
                        if reconnect is None:
                            delivered = await self._broadcast_native_route_group_change(
                                _build_mini_routing_group_change_ex(
                                    CHAT_GROUP_ID,
                                    registered_client_id,
                                    ROUTING_REASON_NEW_CLIENT,
                                    bytes(req["client_name_raw"]),
                                    client_ip_u32,
                                ),
                                exclude_client_id=registered_client_id,
                            )
                            if delivered:
                                LOGGER.info(
                                    "Routing(native): GroupChangeEx join broadcast sent to %d clients",
                                    delivered,
                                )
                        continue

                    if service_type == MINI_ROUTING_SERVICE and message_type == ROUTING_GET_CLIENT_LIST:
                        clients = [
                            (client.client_id, client.client_name_raw, client.client_ip_u32)
                            for client in self._native_clients.values()
                        ]
                        LOGGER.info(
                            "Routing(native): GetClientList from %s:%s (%d clients)",
                            *peer, len(clients),
                        )
                        out_seq = await self._send_native_route_reply(
                            writer,
                            _build_mini_routing_get_client_list_reply(clients),
                            session_key,
                            out_seq,
                        )
                        if registered_client_id and registered_client_id in self._native_clients:
                            self._native_clients[registered_client_id].out_seq = out_seq
                        continue

                    if service_type == MINI_ROUTING_SERVICE and message_type == ROUTING_SUBSCRIBE_DATA_OBJECT:
                        req = _parse_mini_routing_subscribe_data_object(clear)
                        subscription = NativeRouteSubscription(
                            link_id=int(req["link_id"]),
                            data_type=bytes(req["data_type"]),
                            exact_or_recursive=bool(req["exact_or_recursive"]),
                            group_or_members=bool(req["group_or_members"]),
                        )
                        if registered_client_id and registered_client_id in self._native_clients:
                            self._native_clients[registered_client_id].subscriptions.append(subscription)
                        matches = self._route_data_objects_for_subscription(subscription)
                        LOGGER.info(
                            "Routing(native): SubscribeDataObject link_id=%d type=%r recursive=%s members=%s",
                            req["link_id"],
                            bytes(req["data_type"]),
                            not req["exact_or_recursive"],
                            req["group_or_members"],
                        )
                        out_seq = await self._send_native_route_reply(
                            writer,
                            _build_mini_routing_read_data_object_reply(matches),
                            session_key,
                            out_seq,
                        )
                        if registered_client_id and registered_client_id in self._native_clients:
                            self._native_clients[registered_client_id].out_seq = out_seq
                        LOGGER.info(
                            "Routing(native): ReadDataObjectReply sent to %s:%s (%d objects)",
                            *peer,
                            len(matches),
                        )
                        continue

                    if service_type == MINI_ROUTING_SERVICE and message_type == ROUTING_CREATE_DATA_OBJECT:
                        req = _parse_mini_routing_create_data_object(clear)
                        key = self._route_data_key(int(req["link_id"]), bytes(req["data_type"]))
                        data_object = NativeRouteDataObject(
                            link_id=int(req["link_id"]),
                            owner_id=int(req["owner_id"]),
                            lifespan=int(req["lifespan"]),
                            data_type=bytes(req["data_type"]),
                            data=bytes(req["data"]),
                        )
                        self._touch_native_client(registered_client_id, "game_object")
                        existed = key in self._data_objects
                        self._data_objects[key] = data_object
                        LOGGER.info(
                            "Routing(native): CreateDataObject link_id=%d owner_id=%d lifespan=%d type=%r name=%r data_len=%d",
                            data_object.link_id,
                            data_object.owner_id,
                            data_object.lifespan,
                            data_object.data_type,
                            _decode_routing_data_type(data_object.data_type),
                            len(data_object.data),
                        )
                        out_seq = await self._send_native_route_reply(
                            writer,
                            _build_mini_routing_status_reply(0),
                            session_key,
                            out_seq,
                        )
                        if registered_client_id and registered_client_id in self._native_clients:
                            self._native_clients[registered_client_id].out_seq = out_seq
                        if existed:
                            delivered = await self._broadcast_native_route_data_object(
                                _build_mini_routing_replace_data_object(
                                    data_object.link_id,
                                    data_object.data_type,
                                    data_object.data,
                                ),
                                data_object,
                            )
                            LOGGER.info(
                                "Routing(native): ReplaceDataObject broadcast sent to %d subscribed clients",
                                delivered,
                            )
                        else:
                            delivered = await self._broadcast_native_route_data_object(
                                _build_mini_routing_create_data_object(
                                    data_object.link_id,
                                    data_object.owner_id,
                                    data_object.lifespan,
                                    data_object.data_type,
                                    data_object.data,
                                ),
                                data_object,
                            )
                            LOGGER.info(
                                "Routing(native): CreateDataObject broadcast sent to %d subscribed clients",
                                delivered,
                            )
                        continue

                    if service_type == MINI_ROUTING_SERVICE and message_type == ROUTING_REPLACE_DATA_OBJECT:
                        req = _parse_mini_routing_replace_data_object(clear)
                        key = self._route_data_key(int(req["link_id"]), bytes(req["data_type"]))
                        existing = self._data_objects.get(key)
                        owner_id = existing.owner_id if existing is not None else int(registered_client_id or 0)
                        lifespan = existing.lifespan if existing is not None else 0
                        data_object = NativeRouteDataObject(
                            link_id=int(req["link_id"]),
                            owner_id=owner_id,
                            lifespan=lifespan,
                            data_type=bytes(req["data_type"]),
                            data=bytes(req["data"]),
                        )
                        self._touch_native_client(registered_client_id, "game_object")
                        self._data_objects[key] = data_object
                        LOGGER.info(
                            "Routing(native): ReplaceDataObject link_id=%d owner_id=%d type=%r name=%r data_len=%d",
                            data_object.link_id,
                            data_object.owner_id,
                            data_object.data_type,
                            _decode_routing_data_type(data_object.data_type),
                            len(data_object.data),
                        )
                        out_seq = await self._send_native_route_reply(
                            writer,
                            _build_mini_routing_status_reply(0),
                            session_key,
                            out_seq,
                        )
                        if registered_client_id and registered_client_id in self._native_clients:
                            self._native_clients[registered_client_id].out_seq = out_seq
                        delivered = await self._broadcast_native_route_data_object(
                            _build_mini_routing_replace_data_object(
                                data_object.link_id,
                                data_object.data_type,
                                data_object.data,
                            ),
                            data_object,
                        )
                        LOGGER.info(
                            "Routing(native): ReplaceDataObject broadcast sent to %d subscribed clients",
                            delivered,
                        )
                        continue

                    if service_type == MINI_ROUTING_SERVICE and message_type == ROUTING_DELETE_DATA_OBJECT:
                        req = _parse_mini_routing_delete_data_object(clear)
                        key = self._route_data_key(int(req["link_id"]), bytes(req["data_type"]))
                        existing = self._data_objects.pop(key, None)
                        self._touch_native_client(registered_client_id, "game_object")
                        LOGGER.info(
                            "Routing(native): DeleteDataObject link_id=%d type=%r name=%r existed=%s",
                            req["link_id"],
                            bytes(req["data_type"]),
                            _decode_routing_data_type(bytes(req["data_type"])),
                            existing is not None,
                        )
                        out_seq = await self._send_native_route_reply(
                            writer,
                            _build_mini_routing_status_reply(0),
                            session_key,
                            out_seq,
                        )
                        if registered_client_id and registered_client_id in self._native_clients:
                            self._native_clients[registered_client_id].out_seq = out_seq
                        if existing is not None:
                            delivered = await self._broadcast_native_route_data_object(
                                _build_mini_routing_delete_data_object(
                                    existing.link_id,
                                    existing.data_type,
                                ),
                                existing,
                            )
                            LOGGER.info(
                                "Routing(native): DeleteDataObject broadcast sent to %d subscribed clients",
                                delivered,
                            )
                        continue

                    if service_type == MINI_ROUTING_SERVICE and message_type == ROUTING_RENEW_DATA_OBJECT:
                        req = _parse_mini_routing_renew_data_object(clear)
                        key = self._route_data_key(int(req["link_id"]), bytes(req["data_type"]))
                        existing = self._data_objects.get(key)
                        self._touch_native_client(registered_client_id, "game_object")
                        if existing is not None:
                            existing.lifespan = int(req["new_lifespan"])
                        LOGGER.info(
                            "Routing(native): RenewDataObject link_id=%d type=%r name=%r new_lifespan=%d existed=%s",
                            req["link_id"],
                            bytes(req["data_type"]),
                            _decode_routing_data_type(bytes(req["data_type"])),
                            req["new_lifespan"],
                            existing is not None,
                        )
                        out_seq = await self._send_native_route_reply(
                            writer,
                            _build_mini_routing_status_reply(0),
                            session_key,
                            out_seq,
                        )
                        if registered_client_id and registered_client_id in self._native_clients:
                            self._native_clients[registered_client_id].out_seq = out_seq
                        continue

                    if service_type == MINI_ROUTING_SERVICE and message_type == ROUTING_SEND_CHAT:
                        req = _parse_mini_routing_send_chat(clear)
                        sender_name = "unknown"
                        if registered_client_id and registered_client_id in self._native_clients:
                            sender_name = self._native_clients[registered_client_id].client_name
                        delivered = 0
                        if registered_client_id:
                            delivered = await self._broadcast_native_route_chat(
                                registered_client_id,
                                int(req["chat_type"]),
                                bytes(req["data"]),
                                list(req["addressees"]),
                                bool(req["include_exclude_flag"]),
                            )
                        client = self._touch_native_client(registered_client_id, "chat")
                        LOGGER.info(
                            "Routing(native): Chat from client_id=%d name=%r type=%d recipients=%d reply=%s sanitized=%s text=%r",
                            registered_client_id,
                            sender_name,
                            req["chat_type"],
                            delivered,
                            req["should_send_reply"],
                            req["raw_text"] != req["text"],
                            req["text"],
                        )
                        if self.gateway is not None and client is not None:
                            self.gateway.record_activity(
                                "chat",
                                room_port=self.listen_port,
                                room_name=self._room_display_name,
                                room_path=self._room_path,
                                player_id=client.client_id,
                                player_name=client.client_name,
                                player_ip=client.client_ip,
                                text=str(req["text"]),
                            )
                        if req["should_send_reply"]:
                            out_seq = await self._send_native_route_reply(
                                writer,
                                _build_mini_routing_status_reply(0),
                                session_key,
                                out_seq,
                            )
                            if registered_client_id and registered_client_id in self._native_clients:
                                self._native_clients[registered_client_id].out_seq = out_seq
                        continue

                    if service_type == MINI_ROUTING_SERVICE and message_type == ROUTING_SEND_DATA:
                        req = _parse_mini_routing_send_data(clear)
                        delivered = 0
                        self._touch_native_client(registered_client_id, "peer_data", len(bytes(req["data"])))
                        if registered_client_id:
                            delivered = await self._broadcast_native_route_peer_data(
                                registered_client_id,
                                bytes(req["data"]),
                                list(req["addressees"]),
                                bool(req["include_exclude_flag"]),
                            )
                        self._log_native_peer_data_event(
                            "SendData",
                            int(registered_client_id),
                            len(bytes(req["data"])),
                            delivered,
                            bool(req["should_send_reply"]),
                        )
                        if req["should_send_reply"]:
                            out_seq = await self._send_native_route_reply(
                                writer,
                                _build_mini_routing_status_reply(0),
                                session_key,
                                out_seq,
                            )
                            if registered_client_id and registered_client_id in self._native_clients:
                                self._native_clients[registered_client_id].out_seq = out_seq
                        continue

                    if service_type == MINI_ROUTING_SERVICE and message_type == ROUTING_SEND_DATA_BROADCAST:
                        req = _parse_mini_routing_send_data_broadcast(clear)
                        delivered = 0
                        self._touch_native_client(registered_client_id, "peer_data", len(bytes(req["data"])))
                        if registered_client_id:
                            delivered = await self._broadcast_native_route_peer_data(
                                registered_client_id,
                                bytes(req["data"]),
                                [],
                                False,
                            )
                        self._log_native_peer_data_event(
                            "SendDataBroadcast",
                            int(registered_client_id),
                            len(bytes(req["data"])),
                            delivered,
                            bool(req["should_send_reply"]),
                        )
                        if req["should_send_reply"]:
                            out_seq = await self._send_native_route_reply(
                                writer,
                                _build_mini_routing_status_reply(0),
                                session_key,
                                out_seq,
                            )
                            if registered_client_id and registered_client_id in self._native_clients:
                                self._native_clients[registered_client_id].out_seq = out_seq
                        continue

                    if service_type == MINI_ROUTING_SERVICE and message_type == ROUTING_KEEP_ALIVE:
                        self._touch_native_client(registered_client_id, "keepalive")
                        LOGGER.debug("Routing(native): KeepAlive from %s:%s", *peer)
                        continue

                    if service_type == MINI_ROUTING_SERVICE and message_type == ROUTING_RECONNECT_CLIENT:
                        req = _parse_mini_routing_reconnect_client(clear)
                        reconnect = await self._claim_pending_reconnect_by_id(
                            int(req["client_id"]),
                            client_ip,
                        )
                        if reconnect is None:
                            LOGGER.info(
                                "Routing(native): ReconnectClient failed from %s:%s for client_id=%d",
                                *peer,
                                int(req["client_id"]),
                            )
                            out_seq = await self._send_native_route_reply(
                                writer,
                                _build_mini_routing_status_reply(-1),
                                session_key,
                                out_seq,
                            )
                            continue

                        registered_client_id = reconnect.client_id
                        self._native_clients[registered_client_id] = NativeRouteClientState(
                            client_id=reconnect.client_id,
                            client_name_raw=bytes(reconnect.client_name_raw),
                            client_name=str(reconnect.client_name),
                            client_ip=str(reconnect.client_ip),
                            client_ip_u32=int(reconnect.client_ip_u32),
                            writer=writer,
                            session_key=session_key,
                            out_seq=out_seq,
                            connected_at=float(reconnect.connected_at),
                            last_activity_at=float(reconnect.last_activity_at),
                            last_activity_kind=str(reconnect.last_activity_kind),
                            chat_count=int(reconnect.chat_count),
                            peer_data_messages=int(reconnect.peer_data_messages),
                            peer_data_bytes=int(reconnect.peer_data_bytes),
                            subscriptions=[
                                NativeRouteSubscription(
                                    link_id=sub.link_id,
                                    data_type=bytes(sub.data_type),
                                    exact_or_recursive=bool(sub.exact_or_recursive),
                                    group_or_members=bool(sub.group_or_members),
                                )
                                for sub in reconnect.subscriptions
                            ],
                        )
                        self._touch_native_client(registered_client_id, "reconnect")
                        LOGGER.info(
                            "Routing(native): ReconnectClient success from %s:%s id=%d name=%r want_missed=%s",
                            *peer,
                            registered_client_id,
                            reconnect.client_name,
                            bool(req["want_missed_messages"]),
                        )
                        if self.gateway is not None:
                            self.gateway.record_activity(
                                "rejoin",
                                room_port=self.listen_port,
                                room_name=self._room_display_name,
                                room_path=self._room_path,
                                player_id=registered_client_id,
                                player_name=reconnect.client_name,
                                player_ip=client_ip,
                                details={"mode": "routing_reconnect"},
                            )
                        out_seq = await self._send_native_route_reply(
                            writer,
                            _build_mini_routing_status_reply(0),
                            session_key,
                            out_seq,
                        )
                        if registered_client_id in self._native_clients:
                            self._native_clients[registered_client_id].out_seq = out_seq
                        continue

                    if service_type == MINI_ROUTING_SERVICE and message_type == ROUTING_DISCONNECT_CLIENT:
                        disconnect_reason = "voluntary_disconnect"
                        if registered_client_id and registered_client_id in self._native_clients:
                            client = self._native_clients[registered_client_id]
                            LOGGER.info(
                                "Routing(native): DisconnectClient from %s:%s (id=%d name=%r)",
                                *peer, client.client_id, client.client_name,
                            )
                        else:
                            LOGGER.info("Routing(native): DisconnectClient from %s:%s", *peer)
                        return

                LOGGER.warning(
                    "Routing(native): unhandled clear msg header=0x%02x from %s:%s body=%s",
                    clear[0], *peer, clear[:64].hex(),
                )
                disconnect_reason = "protocol_error"
                return
        except asyncio.IncompleteReadError:
            disconnect_reason = "eof"
        except ConnectionResetError:
            disconnect_reason = "connection_reset"
        except (BrokenPipeError, ConnectionAbortedError):
            disconnect_reason = "transport_lost"
        except Exception:
            disconnect_reason = "handler_error"
            raise
        finally:
            if registered_client_id:
                self._flush_solo_peer_data_logs(registered_client_id)
                client = self._native_clients.pop(registered_client_id, None)
                if client is not None:
                    if self._should_offer_reconnect(client, disconnect_reason):
                        self._park_disconnected_client(client, disconnect_reason)
                    else:
                        await self._finalize_client_departure(
                            client.client_id,
                            client.client_name,
                            client.client_ip,
                            disconnect_reason=disconnect_reason,
                        )

    async def _handle_silencer_session(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        first_payload: bytes,
    ) -> None:
        peer = writer.get_extra_info("peername", ("?", 0))
        payload = first_payload
        while True:
            if payload[:2] != b"\x03\x02":
                LOGGER.warning(
                    "Routing: missing \\x03\\x02 header from %s:%s payload=%s",
                    *peer, payload[:32].hex(),
                )
                return

            msg_type = payload[2]
            data = payload[3:]

            if msg_type == self._INIT_ID:
                LOGGER.info("Routing: INIT from %s:%s", *peer)
                writer.write(_SILENCER_ROUTING_ACK)
                await writer.drain()
                await asyncio.sleep(0.05)
                writer.write(_SILENCER_ROUTING_USAGE)
                await writer.drain()

            elif msg_type == self._NEW_CONFLICT_ID:
                if len(data) == _SILENCER_CONFLICT_DATA_LEN:
                    LOGGER.info(
                        "Routing: NEW_CONFLICT from %s:%s (%d bytes)",
                        *peer, len(data),
                    )
                    tail = bytes(
                        _SILENCER_CONFLICT_TOTAL
                        - len(_SILENCER_CONFLICT_HDR)
                        - _SILENCER_CONFLICT_DATA_LEN
                    )
                    self._conflict_data = (
                        _SILENCER_CONFLICT_HDR + data[:_SILENCER_CONFLICT_DATA_LEN] + tail
                    )
                else:
                    LOGGER.warning(
                        "Routing: NEW_CONFLICT bad size %d (want %d) from %s:%s",
                        len(data), _SILENCER_CONFLICT_DATA_LEN, *peer,
                    )
                writer.write(self._conflict_data)
                await writer.drain()
                LOGGER.info("Routing: conflict listing sent to %s:%s", *peer)

            elif msg_type == self._CONFLICTQUERY_ID:
                LOGGER.info("Routing: CONFLICTQUERY from %s:%s", *peer)
                writer.write(self._conflict_data)
                await writer.drain()

            elif msg_type == self._CHATMESSAGE_ID:
                LOGGER.info(
                    "Routing: CHATMESSAGE (-> conflict listing) from %s:%s", *peer
                )
                writer.write(self._conflict_data)
                await writer.drain()

            elif msg_type == self._ABORT_CONFLICT:
                LOGGER.info("Routing: ABORT_CONFLICT from %s:%s", *peer)

            elif msg_type == self._USER_TERMINATION:
                LOGGER.info("Routing: USER_TERMINATION from %s:%s (keeping conn)", *peer)

            elif msg_type == self._CLIENTQUERY_ID:
                LOGGER.info("Routing: CLIENTQUERY (ignored) from %s:%s", *peer)

            else:
                LOGGER.warning(
                    "Routing: unknown msg_type=0x%02x len=%d from %s:%s",
                    msg_type, len(data), *peer,
                )

            payload = await _routing_recv(reader)

    async def handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername", ("?", 0))
        LOGGER.info("Routing-%s connection from %s:%s", self.listen_port, *peer)
        try:
            payload = await _routing_recv(reader)
            if self._is_native_auth_request(payload):
                await self._handle_native_client(reader, writer, payload)
            else:
                await self._handle_silencer_session(reader, writer, payload)
            return

        except asyncio.IncompleteReadError:
            LOGGER.debug("Routing: EOF from %s:%s", *peer)
        except Exception as exc:
            LOGGER.error("Routing: error from %s:%s: %s", *peer, exc)
        finally:
            writer.close()
            with contextlib.suppress(ConnectionResetError, BrokenPipeError, ConnectionAbortedError, OSError):
                await writer.wait_closed()


class RoutingServerManager:
    def __init__(
        self,
        host: str,
        public_host: str,
        base_port: int,
        max_port: Optional[int] = None,
        excluded_ports: Optional[set[int]] = None,
        gateway: Optional["BinaryGatewayServer"] = None,
    ) -> None:
        self.host = host
        self.public_host = public_host
        self.base_port = base_port
        self.max_port = max_port
        self.gateway = gateway
        self._excluded_ports = set(excluded_ports or set())
        self._listeners: Dict[int, asyncio.base_events.Server] = {}
        self._servers: Dict[int, SilencerRoutingServer] = {}
        self._next_port = base_port
        self._lock = asyncio.Lock()

    async def _start_listener_locked(
        self,
        port: int,
        publish_in_directory: bool,
    ) -> Tuple[SilencerRoutingServer, asyncio.base_events.Server]:
        existing = self._listeners.get(port)
        if existing is not None:
            return self._servers[port], existing

        routing_srv = SilencerRoutingServer(
            self.gateway,
            listen_port=port,
            publish_in_directory=publish_in_directory,
        )
        listener = await asyncio.start_server(routing_srv.handle_client, self.host, port)
        routing_srv.start_background_tasks()
        self._listeners[port] = listener
        self._servers[port] = routing_srv
        LOGGER.info(
            "Routing(manager): listener started on %s:%d (publish=%s)",
            self.host,
            port,
            publish_in_directory,
        )
        return routing_srv, listener

    async def start_listener(
        self,
        port: int,
        publish_in_directory: bool = True,
    ) -> Tuple[SilencerRoutingServer, asyncio.base_events.Server]:
        async with self._lock:
            return await self._start_listener_locked(port, publish_in_directory)

    async def allocate_server(self, publish_in_directory: bool = True) -> int:
        async with self._lock:
            for port in sorted(self._servers):
                server = self._servers[port]
                if server.can_host_room() and server._publish_in_directory == publish_in_directory:
                    server.mark_room_allocated()
                    return port

            port = self._next_port
            while port in self._listeners or port in self._excluded_ports:
                port += 1
            if self.max_port is not None and port > self.max_port:
                raise RuntimeError(
                    f"routing_port_range_exhausted:{self.base_port}-{self.max_port}"
                )
            self._next_port = port + 1
            server, _listener = await self._start_listener_locked(port, publish_in_directory)
            server.mark_room_allocated()
            return port

    def directory_entries(self) -> list[Dict[str, object]]:
        entries: list[Dict[str, object]] = []
        for port in sorted(self._servers):
            entry = self._servers[port].native_directory_entry(self.public_host)
            if entry is not None:
                entries.append(entry)
        return entries

    def dashboard_snapshot(self) -> Dict[str, object]:
        room_snapshots = [
            self._servers[port].dashboard_snapshot()
            for port in sorted(self._servers)
        ]
        players: list[Dict[str, object]] = []
        servers: list[Dict[str, object]] = []
        live_games: list[Dict[str, object]] = []
        current_ips: set[str] = set()

        for room in room_snapshots:
            room_players = []
            for client in room.get("clients", []):
                player_entry = {
                    "client_id": client.get("client_id"),
                    "client_name": client.get("client_name"),
                    "client_ip": client.get("client_ip"),
                    "chat_count": client.get("chat_count", 0),
                    "connected_seconds": client.get("connected_seconds", 0),
                    "idle_seconds": client.get("idle_seconds", 0),
                    "last_activity_kind": client.get("last_activity_kind", ""),
                    "subscription_count": client.get("subscription_count", 0),
                    "peer_data_messages": client.get("peer_data_messages", 0),
                    "peer_data_bytes": client.get("peer_data_bytes", 0),
                    "room_port": room.get("listen_port"),
                    "room_name": room.get("room_display_name"),
                    "room_path": room.get("room_path"),
                    "room_password_set": room.get("room_password_set", False),
                }
                room_players.append(player_entry)
                players.append(player_entry)
                if player_entry["client_ip"]:
                    current_ips.add(str(player_entry["client_ip"]))

            room_games = [
                {
                    **game,
                    "room_port": room.get("listen_port"),
                    "room_name": room.get("room_display_name"),
                }
                for game in room.get("games", [])
            ]
            live_games.extend(room_games)
            servers.append(
                {
                    "listen_port": room.get("listen_port"),
                    "room_name": room.get("room_display_name"),
                    "room_description": room.get("room_description"),
                    "room_path": room.get("room_path"),
                    "published": room.get("published", False),
                    "room_password_set": room.get("room_password_set", False),
                    "room_flags": room.get("room_flags", 0),
                    "player_count": len(room_players),
                    "players": room_players,
                    "game_count": len(room_games),
                    "games": room_games,
                }
            )

        players.sort(key=lambda item: (str(item["room_name"]), str(item["client_name"]), int(item["client_id"] or 0)))
        servers.sort(key=lambda item: (str(item["room_name"]), int(item["listen_port"] or 0)))
        live_games.sort(key=lambda item: (str(item["room_name"]), str(item["name"]), int(item["link_id"] or 0)))

        return {
            "host": self.host,
            "public_host": self.public_host,
            "base_port": self.base_port,
            "max_port": self.max_port,
            "next_port": self._next_port,
            "listener_ports": sorted(self._listeners),
            "room_count": len(room_snapshots),
            "published_room_count": sum(1 for room in room_snapshots if room.get("published")),
            "current_player_count": len(players),
            "current_unique_ip_count": len(current_ips),
            "current_game_count": len(live_games),
            "players": players,
            "servers": servers,
            "games": live_games,
            "rooms": room_snapshots,
        }

    def get_server(self, port: int) -> Optional[SilencerRoutingServer]:
        return self._servers.get(port)

    async def admin_kick_player(self, port: int, client_id: int) -> bool:
        server = self._servers.get(port)
        if server is None:
            return False
        return await server.admin_kick_client(client_id)

    async def admin_broadcast(self, message: str, room_port: Optional[int] = None) -> int:
        total = 0
        if room_port is not None:
            server = self._servers.get(room_port)
            if server is not None:
                total += await server.admin_broadcast_chat(message)
        else:
            for server in self._servers.values():
                total += await server.admin_broadcast_chat(message)
        return total

    async def close_all(self) -> None:
        listeners = list(self._listeners.values())
        for server in list(self._servers.values()):
            with contextlib.suppress(Exception):
                await server.stop_background_tasks()
        for listener in listeners:
            listener.close()
        for listener in listeners:
            with contextlib.suppress(Exception):
                await listener.wait_closed()


async def _handle_firewall_probe(reader: asyncio.StreamReader,
                                  writer: asyncio.StreamWriter) -> None:
    """Firewall probe listener (default port 2021).

    Homeworld 1 probes this port with TCP SYN to detect NAT/firewall mode.
    It retries ~4 times at ~0.5 s intervals.  Simply accepting the connection
    is sufficient — no data exchange is required.
    """
    peer = writer.get_extra_info("peername", ("?", 0))
    LOGGER.debug("Firewall probe accepted from %s:%s", *peer)
    with contextlib.suppress(Exception):
        writer.write(FIREWALL_PROBE_REPLY)
        await writer.drain()
    writer.close()
    await writer.wait_closed()


class AdminDashboardServer:
    """Local-only HTTP dashboard for live gateway state and backend DB inspection."""

    def __init__(
        self,
        gateway: BinaryGatewayServer,
        db_path: str,
        log_handler: DashboardLogHandler,
        admin_token: str = "",
        stats_token: str = "",
        repo_monitor: Optional[GitRepoMonitor] = None,
    ) -> None:
        self.gateway = gateway
        self.db_path = db_path
        self.log_handler = log_handler
        self.admin_token = admin_token.strip()
        self.stats_token = stats_token.strip()
        self.repo_monitor = repo_monitor or GitRepoMonitor(str(Path(__file__).resolve().parent))
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
        path = Path(self.db_path).resolve()
        if not path.exists():
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

    def snapshot(
        self,
        rows_per_table: int = 25,
        log_limit: int = 200,
        activity_limit: int = 150,
    ) -> Dict[str, object]:
        return {
            "generated_at": time.time(),
            "uptime_seconds": int(time.time() - self.started_at),
            "gateway": self.gateway.dashboard_snapshot(activity_limit=max(1, activity_limit)),
            "repo": self.repo_monitor.snapshot(),
            "db": self._db_snapshot(rows_per_table=max(1, rows_per_table)),
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
    function displayRoomName(snapshot,roomName,roomPort,gameCount=0){
      const gw=snapshot.gateway||{};
      const basePort=Number(gw.routing_port||0);
      const port=Number(roomPort||0);
      const name=String(roomName||"").trim();
      if((!name||name==="Homeworld Chat")&&port&&basePort&&port!==basePort){
        return gameCount>0?"Game Room":"Side Room";
      }
      return name||"Homeworld Chat";
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
      sidebarFooter.innerHTML=`<span class="status-dot ok"></span> Online ${age(up)}<br>${esc(gw.version_str||"")} &middot; ${esc(gw.public_host||"")}${extra}`;
    }

    function renderTopbar(snapshot){
      const p=pages.find(x=>x.id===activePage);
      pageTitle.textContent=p?p.label:"Dashboard";
      topbarMeta.textContent="Last refresh: "+new Date((snapshot.generated_at||0)*1000).toLocaleTimeString();
    }

    function renderOverview(snapshot){
      const gw=snapshot.gateway||{};const rt=gw.routing_manager||{};const am=gw.activity_metrics||{};const db=snapshot.db||{};const repo=snapshot.repo||{};
      const banned=gw.banned_ips||[];
      const peerBytes=(rt.players||[]).reduce((sum,p)=>sum+Number(p.peer_data_bytes||0),0);
      return `
        <div class="stat-grid">
          <div class="stat-card"><div class="label">Players Online</div><div class="value accent">${esc(rt.current_player_count||0)}</div></div>
          <div class="stat-card"><div class="label">Active Rooms</div><div class="value">${esc(rt.room_count||0)}</div></div>
          <div class="stat-card"><div class="label">Live Games</div><div class="value success">${esc(rt.current_game_count||0)}</div></div>
          <div class="stat-card"><div class="label">Unique IPs</div><div class="value">${esc(rt.current_unique_ip_count||0)}</div></div>
          <div class="stat-card"><div class="label">Peer Data</div><div class="value">${esc(peerBytes)}<span style="font-size:13px;color:var(--text-2);margin-left:6px;">bytes</span></div></div>
        </div>
        <div class="card-grid">
          <div class="card">
            <h2>Server Info</h2>
            <div class="kv">
              <div class="k">Public Host</div><div class="v">${esc(gw.public_host)}</div>
              <div class="k">Gateway Port</div><div class="v">${esc(gw.public_port)}</div>
              <div class="k">Routing Port</div><div class="v">${esc(gw.routing_port)}</div>
              <div class="k">Backend</div><div class="v">${esc(gw.backend_host)}:${esc(gw.backend_port)}</div>
              <div class="k">Version</div><div class="v">${esc(gw.version_str)}</div>
              <div class="k">Auth Keys</div><div class="v">${gw.auth_keys_loaded?'<span style="color:var(--success)">Loaded</span>':'<span style="color:var(--danger)">Not loaded</span>'}</div>
              <div class="k">Peer Sessions</div><div class="v">${esc(gw.peer_session_count)}</div>
              <div class="k">Uptime</div><div class="v">${age(snapshot.uptime_seconds)}</div>
              <div class="k">Valid Versions</div><div class="v">${(gw.valid_versions||[]).map(v=>`<span class="pill" style="margin-left:0;margin-right:4px;">${esc(v)}</span>`).join("")}</div>
            </div>
          </div>
          <div class="card">
            <h2>Activity Counters</h2>
            <div class="kv">
              <div class="k">Joins</div><div class="v">${esc(am.join_count||0)}</div>
              <div class="k">Leaves</div><div class="v">${esc(am.leave_count||0)}</div>
              <div class="k">Chat Messages</div><div class="v">${esc(am.chat_count||0)}</div>
              <div class="k">Rooms Opened</div><div class="v">${esc(am.room_open_count||0)}</div>
              <div class="k">IPs Seen (total)</div><div class="v">${esc(am.unique_ip_count||0)}</div>
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
      const rt=(snapshot.gateway||{}).routing_manager||{};const players=rt.players||[];
      if(!players.length)return '<div class="card"><h2>Players</h2><p class="muted">No live players connected.</p></div>';
      return `<div class="card"><h2>Players <span class="pill">${players.length}</span></h2>
        <div class="table-wrap"><table>
          <thead><tr><th>Player</th><th>IP</th><th>Room</th><th>Chat</th><th>Connected</th><th>Idle</th><th style="width:120px">Actions</th></tr></thead>
          <tbody>${players.map(p=>`<tr>
            <td>${hwMarkup(p.client_name)}</td>
            <td class="mono">${esc(p.client_ip)}</td>
            <td>${esc(displayRoomName(snapshot,p.room_name,p.room_port))} <span class="muted">:${esc(p.room_port)}</span></td>
            <td>${esc(p.chat_count)}</td>
            <td>${age(p.connected_seconds)}</td>
            <td>${age(p.idle_seconds)}</td>
            <td><button class="btn btn-danger btn-sm" data-action="kick" data-room-port="${esc(p.room_port)}" data-client-id="${esc(p.client_id)}">Kick</button> <button class="btn btn-danger btn-sm" data-action="ban-ip" data-ip="${esc(p.client_ip)}">Ban</button></td>
          </tr>`).join("")}</tbody>
        </table></div>
        ${players.map(p=>`<details><summary>${hwMarkup(p.client_name)} <span class="muted">${esc(p.client_ip)} &middot; ${esc(displayRoomName(snapshot,p.room_name,p.room_port))}:${esc(p.room_port)}</span></summary>
          <div class="kv" style="padding:8px 0;">
            <div class="k">Client ID</div><div class="v">${esc(p.client_id)}</div>
            <div class="k">Name</div><div class="v">${hwPlain(p.client_name)}</div>
            <div class="k">Subscriptions</div><div class="v">${esc(p.subscription_count)}</div>
            <div class="k">Peer Data Msgs</div><div class="v">${esc(p.peer_data_messages)}</div>
            <div class="k">Peer Data Bytes</div><div class="v">${esc(p.peer_data_bytes)}</div>
            <div class="k">Last Activity</div><div class="v">${esc(p.last_activity_kind)}</div>
          </div></details>`).join("")}
      </div>`;
    }

    function renderRooms(snapshot){
      const rt=(snapshot.gateway||{}).routing_manager||{};const servers=rt.servers||[];
      if(!servers.length)return '<div class="card"><h2>Rooms</h2><p class="muted">No routing rooms yet.</p></div>';
      return servers.map(room=>{
        const roomName=displayRoomName(snapshot,room.room_name,room.listen_port,room.game_count);
        const peerMsgs=(room.players||[]).reduce((sum,p)=>sum+Number(p.peer_data_messages||0),0);
        const peerBytes=(room.players||[]).reduce((sum,p)=>sum+Number(p.peer_data_bytes||0),0);
        const gameBytes=(room.games||[]).reduce((sum,g)=>sum+Number(g.data_len||0),0);
        return `<div class="card">
        <h2>${esc(roomName)} <span class="muted" style="font-weight:400;font-size:12px;">:${esc(room.listen_port)}</span> <span class="pill">${esc(room.player_count)} players</span> <span class="pill">${esc(room.game_count)} games</span></h2>
        <div class="kv">
          <div class="k">Description</div><div class="v">${esc(room.room_description)}</div>
          <div class="k">Path</div><div class="v">${esc(room.room_path)}</div>
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
        </table></div>`:'<p class="muted" style="margin-top:8px;">No published games.</p>'}
      </div>`;
      }).join("");
    }

    function renderActivity(snapshot){
      const gw=snapshot.gateway||{};const activity=gw.activity||[];const servers=(gw.routing_manager||{}).servers||[];
      const roomOpts=servers.map(r=>`<option value="${esc(r.listen_port)}">${esc(r.room_name)}:${esc(r.listen_port)}</option>`).join("");
      return `<div class="card">
        <h2>Activity Feed <span class="pill">${activity.length}</span></h2>
        <div class="action-bar">
          <input type="text" id="broadcast-msg" placeholder="Broadcast message...">
          <select id="broadcast-room"><option value="">All rooms</option>${roomOpts}</select>
          <button class="btn btn-accent" data-action="broadcast">Send</button>
          <button class="btn btn-danger" data-action="clear-activity">Clear</button>
        </div>
        ${activity.length?`<div class="table-wrap"><table>
          <thead><tr><th style="width:80px">Time</th><th style="width:70px">Event</th><th>Player</th><th>Room</th><th>IP</th><th>Detail</th></tr></thead>
          <tbody>${activity.map(e=>`<tr>
            <td class="mono">${esc(stamp(e.ts))}</td>
            <td>${kindBadge(e.kind)}</td>
            <td>${hwMarkup(e.player_name||"")}</td>
            <td>${esc(displayRoomName(snapshot,e.room_name,e.room_port))}${e.room_port?` <span class="muted">:${esc(e.room_port)}</span>`:""}</td>
            <td class="mono">${esc(e.player_ip||"")}</td>
            <td>${hwMarkup(activityDetail(snapshot,e))}</td>
          </tr>`).join("")}</tbody>
        </table></div>`:'<p class="muted">No activity recorded yet.</p>'}
      </div>`;
    }

    function renderIPs(snapshot){
      const gw=snapshot.gateway||{};const ips=gw.ip_metrics||[];
      return `<div class="card"><h2>IP Metrics <span class="pill">${ips.length}</span></h2>
        ${ips.length?`<div class="table-wrap"><table>
          <thead><tr><th>IP</th><th>Players Seen</th><th>Joins</th><th>Chats</th><th>Last Seen</th><th style="width:60px">Action</th></tr></thead>
          <tbody>${ips.map(e=>`<tr>
            <td class="mono">${esc(e.ip)}</td>
            <td>${nameList(e.player_names)}</td>
            <td>${esc(e.join_count)}</td>
            <td>${esc(e.chat_count)}</td>
            <td>${esc(stamp(e.last_seen))}</td>
            <td><button class="btn btn-danger btn-sm" data-action="ban-ip" data-ip="${esc(e.ip)}">Ban</button></td>
          </tr>`).join("")}</tbody>
        </table></div>`:'<p class="muted">No IP activity recorded yet.</p>'}
      </div>`;
    }

    function renderDatabase(snapshot){
      const db=snapshot.db||{};const tables=Object.entries(db.tables||{});
      if(!tables.length)return '<div class="card"><h2>Database</h2><p class="muted">No tables found.</p></div>';
      if(!activeDbTable||!db.tables[activeDbTable])activeDbTable=tables[0][0];
      const info=db.tables[activeDbTable]||{count:0,rows:[]};
      const rows=info.rows||[];
      const cols=rows.length?Object.keys(rows[0]):[];
      const isUsersTable=activeDbTable==="users";
      return `<div class="card">
        <h2>Database <span class="pill">${esc(db.table_count||0)} tables</span> <span class="pill">${esc(db.total_rows||0)} rows</span></h2>
        <div class="db-tabs">${tables.map(([name,info])=>`<button class="db-tab${name===activeDbTable?" active":""}" data-db-table="${esc(name)}">${esc(name)} <span class="muted">(${info.count})</span></button>`).join("")}</div>
        ${rows.length?`<div class="table-wrap"><table>
          <thead><tr>${cols.map(c=>`<th>${esc(c)}</th>`).join("")}${isUsersTable?'<th style="width:140px">Actions</th>':""}</tr></thead>
          <tbody>${rows.map(r=>`<tr>${cols.map(c=>{
            const v=r[c];
            if(v&&typeof v==="object")return '<td class="mono">'+esc(JSON.stringify(v))+"</td>";
            return "<td>"+esc(v)+"</td>";
          }).join("")}${isUsersTable?`<td><button class="btn btn-sm" data-action="reset-pw" data-username="${esc(r.username)}">Reset PW</button> <button class="btn btn-danger btn-sm" data-action="delete-user" data-username="${esc(r.username)}">Delete</button></td>`:""}</tr>`).join("")}</tbody>
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
      const colored=logs.map(e=>{
        const r=esc(e.rendered||"");
        if(e.level==="ERROR")return '<span class="log-error">'+r+"</span>";
        if(e.level==="WARNING")return '<span class="log-warn">'+r+"</span>";
        return '<span class="log-info">'+r+"</span>";
      }).join("\\n");
      return `<div class="card">
        <h2>Logs <span class="pill">${logs.length}</span></h2>
        <div class="action-bar"><button class="btn btn-danger" data-action="clear-logs">Clear Logs</button></div>
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
      content.querySelectorAll("[data-db-table]").forEach(btn=>{btn.addEventListener("click",()=>{activeDbTable=btn.dataset.dbTable;content.innerHTML=renderDatabase(lastSnapshot);bindDbTabs();});});
    }
    function bindDbTabs(){content.querySelectorAll("[data-db-table]").forEach(btn=>{btn.addEventListener("click",()=>{activeDbTable=btn.dataset.dbTable;content.innerHTML=renderDatabase(lastSnapshot);bindDbTabs();});});}

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
        showModal("Delete User",`<p>Permanently delete user <strong>${esc(u)}</strong>?</p>`,()=>adminAction("delete-user",{username:u}));
      }
      if(action==="reset-pw"){
        const u=btn.dataset.username;
        showModal("Reset Password",`<p>Reset password for <strong>${esc(u)}</strong>:</p><input type="password" id="new-pw" placeholder="New password">`,()=>{
          const pw=(document.getElementById("new-pw")||{}).value||"";
          if(!pw){showToast("Enter a password","error");return;}
          adminAction("reset-password",{username:u,new_password:pw});
        });
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
                if room_port is not None and hasattr(self.gateway.routing_manager, "get_server"):
                    server = self.gateway.routing_manager.get_server(room_port)
                    if server is not None:
                        room_name = str(getattr(server, "_room_display_name", "") or room_name)
                        room_path = str(getattr(server, "_room_path", "") or "")
                self.gateway.record_activity(
                    "broadcast",
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
                db_path = Path(self.db_path).resolve()
                if not db_path.exists():
                    return {"ok": False, "error": "database not found"}
                conn = sqlite3.connect(str(db_path))
                try:
                    cur = conn.execute("DELETE FROM users WHERE username=?", (username,))
                    conn.commit()
                    return {"ok": cur.rowcount > 0, "error": "" if cur.rowcount > 0 else "user not found"}
                finally:
                    conn.close()

            if path == "/api/admin/reset-password":
                username = str(body.get("username", "")).strip()
                new_password = str(body.get("new_password", ""))
                if not username or not new_password:
                    return {"ok": False, "error": "username and new_password required"}
                db_path = Path(self.db_path).resolve()
                if not db_path.exists():
                    return {"ok": False, "error": "database not found"}
                password_hash = hashlib.sha256(new_password.encode("utf-8")).hexdigest()
                conn = sqlite3.connect(str(db_path))
                try:
                    cur = conn.execute("UPDATE users SET password_hash=? WHERE username=?", (password_hash, username))
                    conn.commit()
                    return {"ok": cur.rowcount > 0, "error": "" if cur.rowcount > 0 else "user not found"}
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


class ConnState(str, Enum):
    CONNECTED = "CONNECTED"
    AUTHED = "AUTHED"
    PLAYER_READY = "PLAYER_READY"


@dataclass
class ConnectionContext:
    token: str | None = None
    player_id: str | None = None
    state: ConnState = ConnState.CONNECTED
    registered_lobbies: set[str] = field(default_factory=set)


@dataclass
class PeerSession:
    session_key: bytes
    session_id: int
    role: str
    sequenced: bool
    in_seq: int = 1
    out_seq: int = 1
    created_at: float = field(default_factory=time.time)
    last_used_at: float = field(default_factory=time.time)


class GatewayEventBus:
    """In-process pub/sub for pushing events to connected gateway clients."""

    def __init__(self) -> None:
        self._subs: Dict[str, list[asyncio.Queue]] = {}

    def subscribe(self, player_id: str, maxsize: int = 256) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self._subs.setdefault(player_id, []).append(q)
        return q

    def unsubscribe(self, player_id: str, q: asyncio.Queue) -> None:
        if player_id in self._subs:
            self._subs[player_id] = [x for x in self._subs[player_id] if x is not q]
            if not self._subs[player_id]:
                del self._subs[player_id]

    def publish(self, player_ids: list[str], event: Dict[str, object]) -> None:
        for pid in player_ids:
            for q in self._subs.get(pid, []):
                try:
                    q.put_nowait(event)
                except asyncio.QueueFull:
                    pass  # drop if client can't keep up

    @property
    def subscriber_count(self) -> int:
        return sum(len(qs) for qs in self._subs.values())


def _to_wire_map(payload: Dict[str, object]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in payload.items():
        if isinstance(v, bool):
            out[k] = "true" if v else "false"
        elif isinstance(v, (dict, list)):
            out[k] = json.dumps(v)
        else:
            out[k] = str(v)
    return out


def _from_wire_map(payload: Dict[str, str]) -> Dict[str, object]:
    out: Dict[str, object] = {}
    numeric_keys = {"after_seq", "max_players", "port"}
    for k, v in payload.items():
        vv = v.strip()
        if vv in ("true", "false"):
            out[k] = vv == "true"
        elif k in numeric_keys and vv.isdigit():
            out[k] = int(vv)
        elif (vv.startswith("{") and vv.endswith("}")) or (vv.startswith("[") and vv.endswith("]")):
            try:
                out[k] = json.loads(vv)
            except Exception:
                out[k] = v
        else:
            out[k] = v
    return out


def encode_frame(opcode: int, payload: Dict[str, object]) -> bytes:
    wm = _to_wire_map(payload)
    fields = []
    for k, v in wm.items():
        kb = k.encode("utf-8")
        vb = v.encode("utf-8")
        if len(kb) > 255:
            raise ValueError("key_too_long")
        fields.append(struct.pack(">B", len(kb)) + kb + struct.pack(">H", len(vb)) + vb)
    body = bytes([opcode]) + struct.pack(">H", len(fields)) + b"".join(fields)
    return struct.pack(">I", len(body)) + body


def decode_frame(data: bytes) -> Tuple[int, Dict[str, object]]:
    if len(data) < 3:
        raise ValueError("short_frame")
    opcode = data[0]
    nfields = struct.unpack(">H", data[1:3])[0]
    i = 3
    raw: Dict[str, str] = {}
    for _ in range(nfields):
        if i >= len(data):
            raise ValueError("truncated_keylen")
        klen = data[i]
        i += 1
        if i + klen > len(data):
            raise ValueError("truncated_key")
        key = data[i : i + klen].decode("utf-8")
        i += klen
        if i + 2 > len(data):
            raise ValueError("truncated_vallen")
        vlen = struct.unpack(">H", data[i : i + 2])[0]
        i += 2
        if i + vlen > len(data):
            raise ValueError("truncated_value")
        val = data[i : i + vlen].decode("utf-8")
        i += vlen
        raw[key] = val
    return opcode, _from_wire_map(raw)


def _invalid_action(error: str) -> Dict[str, object]:
    return {"action": "INVALID", "error": error}


def _required_payload_text(payload: Dict[str, object], key: str) -> Optional[str]:
    value = payload.get(key)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def opcode_to_action(opcode: int, payload: Dict[str, object], ctx: ConnectionContext) -> Dict[str, object]:
    if opcode == OP_PING:
        return {"action": "PING"}
    if opcode == OP_DIR_GET:
        return {"action": "TITAN_DIR_GET", "path": str(payload.get("path", "/TitanServers"))}
    if opcode == OP_AUTH_LOGIN:
        return {"action": "AUTH_LOGIN", "username": str(payload.get("username", "guest")), "password": str(payload.get("password", ""))}
    if opcode == OP_REGISTER_PLAYER:
        if ctx.state == ConnState.CONNECTED:
            return _invalid_action("auth_required")
        player_id = _required_payload_text(payload, "player_id")
        if player_id is None:
            return _invalid_action("missing_player_id")
        return {"action": "REGISTER_PLAYER", "player_id": player_id, "nickname": str(payload.get("nickname", player_id))}
    if opcode == OP_CREATE_LOBBY:
        if ctx.state != ConnState.PLAYER_READY or not ctx.token:
            return _invalid_action("player_not_ready")
        return {
            "action": "CREATE_LOBBY",
            "token": ctx.token,
            "owner_id": str(payload.get("owner_id", ctx.player_id or "")),
            "name": str(payload.get("name", "Lobby")),
            "map_name": str(payload.get("map_name", "Garden")),
            "region": str(payload.get("region", "global")),
            "max_players": int(payload.get("max_players", 4)),
        }
    if opcode == OP_JOIN_LOBBY:
        if ctx.state != ConnState.PLAYER_READY:
            return _invalid_action("player_not_ready")
        lobby_id = _required_payload_text(payload, "lobby_id")
        if lobby_id is None:
            return _invalid_action("missing_lobby_id")
        return {"action": "JOIN_LOBBY", "lobby_id": lobby_id, "player_id": str(payload.get("player_id", ctx.player_id or "")), "password": str(payload.get("password", ""))}
    if opcode == OP_ROUTE_REGISTER:
        if ctx.state != ConnState.PLAYER_READY:
            return _invalid_action("player_not_ready")
        lobby_id = _required_payload_text(payload, "lobby_id")
        if lobby_id is None:
            return _invalid_action("missing_lobby_id")
        return {"action": "TITAN_ROUTE_REGISTER", "lobby_id": lobby_id, "player_id": str(payload.get("player_id", ctx.player_id or ""))}
    if opcode == OP_ROUTE_CHAT:
        lid = _required_payload_text(payload, "lobby_id")
        if lid is None:
            return _invalid_action("missing_lobby_id")
        if lid not in ctx.registered_lobbies:
            return _invalid_action("route_not_registered")
        message = payload.get("message")
        if message is None:
            return _invalid_action("missing_message")
        return {"action": "TITAN_ROUTE_CHAT", "lobby_id": lid, "from_player": str(payload.get("from_player", ctx.player_id or "unknown")), "message": str(message)}
    if opcode == OP_START_GAME:
        if ctx.state != ConnState.PLAYER_READY:
            return _invalid_action("player_not_ready")
        lobby_id = _required_payload_text(payload, "lobby_id")
        if lobby_id is None:
            return _invalid_action("missing_lobby_id")
        return {"action": "TITAN_START_GAME", "lobby_id": lobby_id, "requester_id": str(payload.get("requester_id", ctx.player_id or "")), "port": payload.get("port")}
    if opcode == OP_POLL_EVENTS:
        if ctx.state == ConnState.CONNECTED:
            return _invalid_action("auth_required")
        return {"action": "ROUTE_POLL", "player_id": str(payload.get("player_id", ctx.player_id or "")), "after_seq": int(payload.get("after_seq", 0))}
    if opcode == OP_TITAN_MESSAGE:
        return {"action": "TITAN_MESSAGE", "packet_hex": str(payload.get("packet_hex", ""))}
    return {"action": "UNKNOWN_BINARY_OPCODE", "opcode": opcode}


def action_to_response_opcode(opcode: int) -> int:
    return opcode


async def call_backend(
    host: str,
    port: int,
    payload: Dict[str, object],
    *,
    shared_secret: str = "",
    timeout_s: float = BACKEND_RPC_TIMEOUT_SECONDS,
) -> Dict[str, object]:
    request_payload = dict(payload)
    if shared_secret:
        request_payload["_backend_secret"] = shared_secret

    reader: Optional[asyncio.StreamReader] = None
    writer: Optional[asyncio.StreamWriter] = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout_s)
        writer.write((json.dumps(request_payload) + "\n").encode("utf-8"))
        await asyncio.wait_for(writer.drain(), timeout=timeout_s)
        line = await asyncio.wait_for(reader.readline(), timeout=timeout_s)
        return json.loads(line.decode("utf-8")) if line else {"ok": False, "error": "backend_no_response"}
    except asyncio.TimeoutError:
        return {"ok": False, "error": "backend_timeout"}
    except OSError as exc:
        return {"ok": False, "error": f"backend_connect_failed:{exc}"}
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), timeout=max(1.0, timeout_s))


class BinaryGatewayServer:
    def __init__(self, backend_host: str, backend_port: int,
                 event_bus: Optional[GatewayEventBus] = None,
                 public_host: str = "127.0.0.1",
                 public_port: int = 15101,
                 routing_port: int = 15100,
                 version_str: str = "0110",
                 valid_versions: Optional[list[str]] = None,
                 keys_dir: Optional[str] = None,
                 backend_shared_secret: str = "",
                 backend_timeout_s: float = BACKEND_RPC_TIMEOUT_SECONDS):
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.backend_shared_secret = backend_shared_secret.strip()
        self.backend_timeout_s = max(1.0, float(backend_timeout_s))
        self.event_bus = event_bus or GatewayEventBus()
        self.public_host = public_host
        self.public_port = public_port
        self.routing_port = routing_port
        self.version_str = version_str
        self.valid_versions = tuple(valid_versions or [version_str])
        # Auth1 crypto state (loaded from keys_dir if provided)
        self._auth_keys_loaded = False
        self._key_block: bytes = b""
        self._auth_p = self._auth_q = self._auth_g = self._auth_y = self._auth_x = 0
        self._ver_p = self._ver_q = self._ver_g = 0
        self._next_user_id = 1000
        self._next_peer_session_id = 1
        self._peer_sessions: Dict[int, PeerSession] = {}
        self._activity: Deque[Dict[str, object]] = deque(maxlen=500)
        self._activity_counts: Dict[str, int] = {}
        self._ip_activity: Dict[str, Dict[str, object]] = {}
        self._banned_ips: Dict[str, str] = {}
        self.routing_manager: Optional[RoutingServerManager] = None
        self._maintenance_task: Optional[asyncio.Task] = None
        if keys_dir:
            self._load_keys(keys_dir)

    async def _call_backend(self, payload: Dict[str, object]) -> Dict[str, object]:
        return await call_backend(
            self.backend_host,
            self.backend_port,
            payload,
            shared_secret=self.backend_shared_secret,
            timeout_s=self.backend_timeout_s,
        )

    def start_background_tasks(self) -> None:
        if self._maintenance_task is None:
            self._maintenance_task = asyncio.create_task(self._peer_session_maintenance_loop())

    async def stop_background_tasks(self) -> None:
        task = self._maintenance_task
        self._maintenance_task = None
        if task is None:
            return
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    def _touch_peer_session(self, session: PeerSession) -> None:
        session.last_used_at = time.time()

    def _expire_peer_sessions(self) -> int:
        now = time.time()
        expired_ids = [
            session_id
            for session_id, session in list(self._peer_sessions.items())
            if now - session.last_used_at >= PEER_SESSION_TTL_SECONDS
        ]
        for session_id in expired_ids:
            session = self._peer_sessions.pop(session_id, None)
            if session is None:
                continue
            LOGGER.info(
                "Peer(session): expired session_id=%d role=%s idle_for=%.1fs",
                session.session_id,
                session.role,
                max(0.0, now - session.last_used_at),
            )
        return len(expired_ids)

    async def _peer_session_maintenance_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(PEER_SESSION_SWEEP_INTERVAL_SECONDS)
                self._expire_peer_sessions()
                self._prune_ip_activity()
        except asyncio.CancelledError:
            raise

    def _prune_ip_activity(self) -> int:
        now = time.time()
        removed = 0
        stale_ips = [
            ip
            for ip, raw in list(self._ip_activity.items())
            if now - float(raw.get("last_seen", 0.0)) >= IP_ACTIVITY_TTL_SECONDS
        ]
        for ip in stale_ips:
            self._ip_activity.pop(ip, None)
            removed += 1

        overflow = len(self._ip_activity) - MAX_IP_ACTIVITY_ROWS
        if overflow > 0:
            oldest = sorted(
                self._ip_activity.items(),
                key=lambda item: (float(item[1].get("last_seen", 0.0)), item[0]),
            )[:overflow]
            for ip, _raw in oldest:
                if ip in self._ip_activity:
                    self._ip_activity.pop(ip, None)
                    removed += 1
        return removed

    def record_activity(
        self,
        kind: str,
        *,
        room_port: Optional[int] = None,
        room_name: str = "",
        room_path: str = "",
        player_id: Optional[int] = None,
        player_name: str = "",
        player_ip: str = "",
        text: str = "",
        details: Optional[Dict[str, object]] = None,
    ) -> None:
        now = time.time()
        event = {
            "ts": now,
            "kind": kind,
            "room_port": room_port,
            "room_name": room_name,
            "room_path": room_path,
            "player_id": player_id,
            "player_name": player_name,
            "player_ip": player_ip,
            "text": text,
        }
        if details:
            event["details"] = dict(details)
        self._activity.append(event)
        self._activity_counts[kind] = self._activity_counts.get(kind, 0) + 1

        if player_ip:
            stats = self._ip_activity.setdefault(
                player_ip,
                {
                    "ip": player_ip,
                    "join_count": 0,
                    "leave_count": 0,
                    "chat_count": 0,
                    "last_seen": 0.0,
                    "player_names": set(),
                    "rooms": set(),
                },
            )
            stats["last_seen"] = now
            if player_name:
                cast_names = stats["player_names"]
                if isinstance(cast_names, set):
                    cast_names.add(player_name)
            if room_name:
                cast_rooms = stats["rooms"]
                if isinstance(cast_rooms, set):
                    cast_rooms.add(room_name)
            count_key = f"{kind}_count"
            if count_key in stats:
                stats[count_key] = int(stats[count_key]) + 1

    def _activity_snapshot(self, limit: int = 150) -> list[Dict[str, object]]:
        if limit <= 0:
            return []
        join_leave_chat = [
            entry for entry in self._activity
            if entry.get("kind") in {"join", "rejoin", "leave", "chat", "broadcast"}
        ]
        return list(join_leave_chat)[-limit:][::-1]

    def _ip_activity_snapshot(self, limit: int = 50) -> list[Dict[str, object]]:
        rows = []
        for ip, raw in self._ip_activity.items():
            player_names = raw.get("player_names", set())
            rooms = raw.get("rooms", set())
            rows.append(
                {
                    "ip": ip,
                    "join_count": int(raw.get("join_count", 0)),
                    "leave_count": int(raw.get("leave_count", 0)),
                    "chat_count": int(raw.get("chat_count", 0)),
                    "last_seen": float(raw.get("last_seen", 0.0)),
                    "player_names": sorted(player_names) if isinstance(player_names, set) else [],
                    "rooms": sorted(rooms) if isinstance(rooms, set) else [],
                }
            )
        rows.sort(key=lambda item: (-item["join_count"], -item["chat_count"], item["ip"]))
        return rows[:max(1, limit)]

    def ban_ip(self, ip: str, reason: str = "") -> None:
        self._banned_ips[ip.strip()] = reason

    def unban_ip(self, ip: str) -> bool:
        return self._banned_ips.pop(ip.strip(), None) is not None

    def clear_activity(self) -> None:
        self._activity.clear()
        self._activity_counts.clear()
        self._ip_activity.clear()

    def stats_snapshot(self) -> Dict[str, object]:
        routing_snapshot = (
            self.routing_manager.dashboard_snapshot()
            if self.routing_manager is not None
            else {}
        )
        if not isinstance(routing_snapshot, dict):
            routing_snapshot = {}

        rooms_raw = routing_snapshot.get("rooms", [])
        servers_raw = routing_snapshot.get("servers", [])
        players_raw = routing_snapshot.get("players", [])
        games_raw = routing_snapshot.get("games", [])

        room_has_games: Dict[int, bool] = {}
        room_reconnect_counts: Dict[int, int] = {}
        room_data_object_counts: Dict[int, int] = {}
        room_peer_data_messages: Dict[int, int] = {}
        room_peer_data_bytes: Dict[int, int] = {}
        room_game_data_bytes: Dict[int, int] = {}
        reconnecting_players: list[Dict[str, object]] = []

        for room in rooms_raw:
            if not isinstance(room, dict):
                continue
            port = int(room.get("listen_port") or 0)
            room_has_games[port] = bool(room.get("game_count", 0) or room.get("games"))
            room_data_object_counts[port] = int(
                room.get("data_object_count")
                or len(room.get("data_objects", []) or [])
            )
            pending_reconnects = room.get("pending_reconnects", []) or []
            room_reconnect_counts[port] = len(pending_reconnects)
            room_name = str(room.get("room_display_name") or room.get("room_name") or "")
            for reservation in pending_reconnects:
                if not isinstance(reservation, dict):
                    continue
                reconnecting_players.append(
                    {
                        "name": str(reservation.get("client_name") or ""),
                        "client_id": int(reservation.get("client_id") or 0),
                        "room_name": room_name,
                        "room_port": port,
                        "seconds_remaining": int(reservation.get("seconds_remaining") or 0),
                        "last_activity_kind": str(reservation.get("last_activity_kind") or ""),
                    }
                )

        players: list[Dict[str, object]] = []
        for player in players_raw:
            if not isinstance(player, dict):
                continue
            room_port = int(player.get("room_port") or 0)
            peer_data_messages = int(player.get("peer_data_messages") or 0)
            peer_data_bytes = int(player.get("peer_data_bytes") or 0)
            room_peer_data_messages[room_port] = room_peer_data_messages.get(room_port, 0) + peer_data_messages
            room_peer_data_bytes[room_port] = room_peer_data_bytes.get(room_port, 0) + peer_data_bytes
            players.append(
                {
                    "name": str(player.get("client_name") or ""),
                    "client_id": int(player.get("client_id") or 0),
                    "room_name": str(player.get("room_name") or ""),
                    "room_port": room_port,
                    # Retail routing does not expose a dedicated per-player presence
                    # flag, so we infer "game" from whether the room has live games.
                    "state": "game" if room_has_games.get(room_port, False) else "lobby",
                    "connected_seconds": int(player.get("connected_seconds") or 0),
                    "idle_seconds": int(player.get("idle_seconds") or 0),
                    "last_activity_kind": str(player.get("last_activity_kind") or ""),
                    "peer_data_messages": peer_data_messages,
                    "peer_data_bytes": peer_data_bytes,
                }
            )

        rooms: list[Dict[str, object]] = []
        for room in servers_raw:
            if not isinstance(room, dict):
                continue
            port = int(room.get("listen_port") or 0)
            rooms.append(
                {
                    "name": str(room.get("room_name") or ""),
                    "port": port,
                    "description": str(room.get("room_description") or ""),
                    "path": str(room.get("room_path") or ""),
                    "published": bool(room.get("published", False)),
                    "password_protected": bool(room.get("room_password_set", False)),
                    "player_count": int(room.get("player_count") or 0),
                    "game_count": int(room.get("game_count") or 0),
                    "reconnecting_count": int(room_reconnect_counts.get(port, 0)),
                    "peer_data_messages": int(room_peer_data_messages.get(port, 0)),
                    "peer_data_bytes": int(room_peer_data_bytes.get(port, 0)),
                    "game_data_bytes": int(room_game_data_bytes.get(port, 0)),
                    "data_object_count": int(room_data_object_counts.get(port, 0)),
                }
            )

        games: list[Dict[str, object]] = []
        for game in games_raw:
            if not isinstance(game, dict):
                continue
            room_port = int(game.get("room_port") or 0)
            data_len = int(game.get("data_len") or 0)
            room_game_data_bytes[room_port] = room_game_data_bytes.get(room_port, 0) + data_len
            games.append(
                {
                    "name": str(game.get("name") or ""),
                    "owner_name": str(game.get("owner_name") or ""),
                    "room_name": str(game.get("room_name") or ""),
                    "room_port": room_port,
                    "link_id": int(game.get("link_id") or 0),
                    "lifespan": int(game.get("lifespan") or 0),
                    "data_len": data_len,
                    "data_preview_hex": str(game.get("data_preview_hex") or ""),
                }
            )

        for room in rooms:
            port = int(room["port"])
            room["game_data_bytes"] = int(room_game_data_bytes.get(port, 0))

        traffic = {
            "peer_data_messages_total": sum(room_peer_data_messages.values()),
            "peer_data_bytes_total": sum(room_peer_data_bytes.values()),
            "game_object_count": len(games),
            "game_object_bytes_total": sum(int(game["data_len"]) for game in games),
        }

        return {
            "generated_at": time.time(),
            "server": {
                "public_host": self.public_host,
                "public_port": self.public_port,
                "routing_port": self.routing_port,
                "version": self.version_str,
                "valid_versions": list(self.valid_versions),
            },
            "counts": {
                "players_online": len(players),
                "rooms_open": len(rooms),
                "rooms_published": sum(1 for room in rooms if room["published"]),
                "games_live": len(games),
                "unique_ips": int(routing_snapshot.get("current_unique_ip_count") or 0),
                "players_reconnecting": len(reconnecting_players),
            },
            "traffic": traffic,
            "players": players,
            "reconnecting_players": reconnecting_players,
            "rooms": rooms,
            "games": games,
        }

    def dashboard_snapshot(self, activity_limit: int = 150) -> Dict[str, object]:
        self._prune_ip_activity()
        routing_snapshot = (
            self.routing_manager.dashboard_snapshot()
            if self.routing_manager is not None
            else None
        )
        return {
            "public_host": self.public_host,
            "public_port": self.public_port,
            "routing_port": self.routing_port,
            "backend_host": self.backend_host,
            "backend_port": self.backend_port,
            "version_str": self.version_str,
            "valid_versions": list(self.valid_versions),
            "auth_keys_loaded": self._auth_keys_loaded,
            "next_user_id": self._next_user_id,
            "peer_session_count": len(self._peer_sessions),
            "activity_metrics": {
                "join_count": self._activity_counts.get("join", 0),
                "leave_count": self._activity_counts.get("leave", 0),
                "chat_count": self._activity_counts.get("chat", 0),
                "room_open_count": self._activity_counts.get("room_open", 0),
                "unique_ip_count": len(self._ip_activity),
            },
            "activity": self._activity_snapshot(limit=activity_limit),
            "ip_metrics": self._ip_activity_snapshot(limit=50),
            "peer_sessions": {
                str(session_id): {
                    "role": session.role,
                    "session_id": session.session_id,
                    "sequenced": session.sequenced,
                    "in_seq": session.in_seq,
                    "out_seq": session.out_seq,
                    "created_at": session.created_at,
                    "last_used_at": session.last_used_at,
                    "session_key_len": len(session.session_key),
                }
                for session_id, session in sorted(self._peer_sessions.items())
            },
            "routing_manager": routing_snapshot,
            "banned_ips": [
                {"ip": ip, "reason": reason}
                for ip, reason in sorted(self._banned_ips.items())
            ],
        }

    def _load_keys(self, keys_dir: str) -> None:
        """Load verifier and auth server keypairs; build the signed key block."""
        from pathlib import Path
        kdir = Path(keys_dir)
        ver_priv_der = (kdir / "verifier_private.der").read_bytes()
        auth_priv_der = (kdir / "authserver_private.der").read_bytes()

        vp, vq, vg, vy, vx = won_crypto.decode_private_key(ver_priv_der)
        ap, aq, ag, ay, ax = won_crypto.decode_private_key(auth_priv_der)

        self._ver_p, self._ver_q, self._ver_g = vp, vq, vg
        self._auth_p, self._auth_q, self._auth_g = ap, aq, ag
        self._auth_y, self._auth_x = ay, ax

        self._key_block = won_crypto.build_auth1_pubkey_block(
            auth_p=ap, auth_q=aq, auth_g=ag, auth_y=ay,
            block_id=1,
            ver_p=vp, ver_q=vq, ver_g=vg, ver_x=vx,
        )
        self._auth_keys_loaded = True
        LOGGER.info("Auth1 keys loaded from %s (key_block=%d bytes)", keys_dir, len(self._key_block))

    def _build_user_cert(self, user_id: int) -> Tuple[bytes, int, int]:
        """Generate an ephemeral user keypair and build a signed Auth1Certificate.

        Returns (certificate_bytes, user_y, user_x).
        """
        p, q, g = self._auth_p, self._auth_q, self._auth_g
        # Generate ephemeral user private key
        q_bytes = (q.bit_length() + 7) // 8
        while True:
            ux = int.from_bytes(os.urandom(q_bytes + 4), 'big') % (q - 1) + 1
            uy = pow(g, ux, p)
            if uy > 1:
                break
        cert = won_crypto.build_auth1_certificate(
            user_id=user_id,
            community_id=1,
            trust_level=2,
            user_p=p, user_q=q, user_g=g, user_y=uy,
            auth_p=p, auth_q=q, auth_g=g, auth_x=self._auth_x,
        )
        return cert, uy, ux

    async def _handle_auth1_connection(self, reader: asyncio.StreamReader,
                                        writer: asyncio.StreamWriter,
                                        first_body: bytes) -> None:
        """Handle a stateful Auth1 handshake on a single connection.

        The client may start with either:
          - Auth1GetPubKeys (msg_type=1) — full 4-message flow
          - Auth1LoginRequestHW (msg_type=30) — client already has a cached key block

        Full flow:
          1. Client -> Auth1GetPubKeys       (msg_type=1)
          2. Server -> Auth1GetPubKeysReply   (msg_type=2)
          3. Client -> Auth1LoginRequestHW    (msg_type=30)
          4. Server -> Auth1LoginChallengeHW  (msg_type=32)
          5. Client -> Auth1LoginConfirmHW    (msg_type=33)
          6. Server -> Auth1LoginReply        (msg_type=4)

        Short flow (skips steps 1-2):
          1. Client -> Auth1LoginRequestHW    (msg_type=30)
          2. Server -> Auth1LoginChallengeHW  (msg_type=32)
          3. Client -> Auth1LoginConfirmHW    (msg_type=33)
          4. Server -> Auth1LoginReply        (msg_type=4)
        """
        peer = writer.get_extra_info("peername", ("?", 0))

        # Parse the first message to determine which step we're at
        svc, msg, first_msg_body = won_crypto.parse_tmessage(first_body)
        LOGGER.info("Auth1: first message from %s:%s (svc=%d msg=%d, %d bytes)",
                     *peer, svc, msg, len(first_msg_body))

        if msg == won_crypto.AUTH1_GET_PUB_KEYS:
            # Full flow: send GetPubKeysReply, then wait for LoginRequestHW
            reply = won_crypto.build_auth1_pubkeys_reply(self._key_block)
            writer.write(reply)
            await writer.drain()
            LOGGER.info("Auth1: GetPubKeysReply sent to %s:%s (%d bytes)", *peer, len(reply))

            # Read the next message (should be LoginRequestHW)
            body = await _titan_recv(reader)
            svc, msg, req_body = won_crypto.parse_tmessage(body)
            LOGGER.info("Auth1: next message from %s:%s (svc=%d msg=%d, %d bytes)",
                         *peer, svc, msg, len(req_body))
        elif msg == won_crypto.AUTH1_LOGIN_REQUEST_HW:
            # Short flow: client already has key block, jumped straight to login
            req_body = first_msg_body
            LOGGER.info("Auth1: client skipped GetPubKeys, starting at LoginRequestHW")
        else:
            LOGGER.warning("Auth1: unexpected msg_type=%d from %s:%s, closing", msg, *peer)
            return

        # --- LoginRequestHW processing ---
        login_req = won_crypto.parse_auth1_login_request(req_body)
        LOGGER.info("Auth1: LoginRequestHW block_id=%d eg_len=%d bf_len=%d",
                      login_req['block_id'], len(login_req['eg_ciphertext']), len(login_req['bf_data']))

        # Decrypt the session key from the ElGamal ciphertext
        try:
            session_key = won_crypto.eg_decrypt(
                login_req['eg_ciphertext'],
                self._auth_p, self._auth_g, self._auth_x,
            )
            LOGGER.info("Auth1: Session key decrypted (%d bytes)", len(session_key))
        except Exception as exc:
            LOGGER.error("Auth1: ElGamal decrypt failed: %s", exc)
            return

        client_ip = None
        if isinstance(peer, (tuple, list)) and peer:
            client_ip = str(peer[0])

        native_login = None
        try:
            native_login = won_crypto.parse_auth1_login_payload(login_req["bf_data"], session_key)
            LOGGER.info(
                "Auth1: native login user=%r community=%r create=%s need_key=%s cd_key=%s login_key=%s variant=%s",
                native_login["username"],
                native_login["community_name"],
                native_login["create_account"],
                native_login["need_key"],
                _mask_account_key(str(native_login["cd_key"])),
                _mask_account_key(str(native_login["login_key"])),
                native_login.get("ciphertext_variant", "direct"),
            )
        except Exception as exc:
            LOGGER.warning("Auth1: failed to parse native login payload from %s:%s: %s", *peer, exc)
            return

        backend = await self._call_backend(
            {
                "action": "AUTH_LOGIN_NATIVE",
                "username": str(native_login["username"]),
                "password": str(native_login["password"]),
                "new_password": str(native_login["new_password"]),
                "cd_key": str(native_login["cd_key"]),
                "login_key": str(native_login["login_key"]),
                "create_account": bool(native_login["create_account"]),
                "client_ip": client_ip,
            }
        )
        if not backend.get("ok"):
            error_code = str(backend.get("error", "native_auth_failed"))
            status = _native_auth_error_to_status(error_code)
            LOGGER.warning(
                "Auth1: native login rejected for user=%r from %s:%s error=%s status=%d",
                native_login["username"],
                *peer,
                error_code,
                status,
            )
            try:
                writer.write(won_crypto.build_auth1_login_failure_reply(status))
                await writer.drain()
            except Exception as exc:
                LOGGER.debug("Auth1: failed to send login failure reply to %s:%s: %s", *peer, exc)
            return
        native_result = backend.get("result", {})
        if isinstance(native_result, dict):
            LOGGER.info(
                "Auth1: native account accepted user=%r created=%s cd_key_bound=%s binding_changed=%s",
                native_result.get("username", native_login["username"]),
                bool(native_result.get("created", False)),
                bool(native_result.get("cd_key_bound", False)),
                bool(native_result.get("binding_changed", False)),
            )

        # --- Send LoginChallengeHW ---
        challenge_seed = os.urandom(16)
        challenge_reply = won_crypto.build_auth1_challenge(challenge_seed, session_key)
        writer.write(challenge_reply)
        await writer.drain()
        LOGGER.info("Auth1: ChallengeHW sent to %s:%s", *peer)

        # --- Receive LoginConfirmHW ---
        body = await _titan_recv(reader)
        svc, msg, confirm_body = won_crypto.parse_tmessage(body)
        LOGGER.info("Auth1: ConfirmHW received from %s:%s (svc=%d msg=%d, %d bytes)",
                     *peer, svc, msg, len(confirm_body))
        # We accept any confirm — we're not doing real file hash verification

        # --- Send LoginReply with certificate + client private key ---
        user_id = self._next_user_id
        self._next_user_id += 1
        cert, user_y, user_x = self._build_user_cert(user_id)

        login_reply = self._build_auth1_login_reply_with_key(cert, user_x, session_key)
        writer.write(login_reply)
        await writer.drain()
        LOGGER.info("Auth1: LoginReply sent to %s:%s (user_id=%d, cert=%d bytes)",
                     *peer, user_id, len(cert))

    def _build_auth1_login_reply_with_key(self, cert: bytes, user_x: int,
                                           session_key: bytes) -> bytes:
        """Build Auth1LoginReply containing certificate + encrypted private key.

        Wire layout (TMsgAuth1LoginReply::Pack + EncryptAndPack):
          [u16 LE status=0]
          [u8  error_count=0]
          [u8  num_clear_entries=1]
          [u8  type=1 (ALCertificate)]
          [u16 LE cert_len]
          [cert bytes]
          [BF_encrypt(session_key, [u8 num_crypt=1][u8 type=2][u16 LE key_len][key_der])]

        Clear entries: Certificate (type=1)
        Encrypted entries: ClientPrivateKey (type=2) — encrypted with session key
        """
        p, q, g = self._auth_p, self._auth_q, self._auth_g
        # Encode client private key as DER
        user_y = pow(g, user_x, p)
        priv_key_der = won_crypto.encode_private_key(p, q, g, user_y, user_x)

        body = struct.pack('<H', 0)   # status = Success
        body += bytes([0])            # error_count = 0

        # --- Clear section ---
        body += bytes([1])            # num_clear_entries = 1
        # Clear Entry: Certificate (type=1)
        body += bytes([1])
        body += struct.pack('<H', len(cert))
        body += cert

        # --- Encrypted section ---
        # Build plaintext buffer: [u8 num_crypt_entries][entries...]
        crypt_buf = bytes([1])        # num_crypt_entries = 1
        # Entry: ClientPrivateKey (type=2)
        crypt_buf += bytes([2])
        crypt_buf += struct.pack('<H', len(priv_key_der))
        crypt_buf += priv_key_der
        # Encrypt with session key (Blowfish CBC)
        encrypted = won_crypto.bf_encrypt(crypt_buf, session_key)
        body += encrypted

        return won_crypto.build_tmessage(
            won_crypto.AUTH1_SERVICE_TYPE,
            won_crypto.AUTH1_LOGIN_REPLY,
            body,
        )

    def _alloc_peer_session_id(self) -> int:
        for _ in range(MAX_PEER_SESSION_ID):
            session_id = self._next_peer_session_id
            self._next_peer_session_id = 1 if session_id >= MAX_PEER_SESSION_ID else session_id + 1
            if session_id not in self._peer_sessions:
                return session_id
        raise RuntimeError("peer_session_id_exhausted")

    async def _handle_auth1_peer_connection(self, reader: asyncio.StreamReader,
                                             writer: asyncio.StreamWriter,
                                             first_body: bytes) -> None:
        """Handle Auth1PeerToPeer for directory/factory server flows on port 15101."""
        peer = writer.get_extra_info("peername", ("?", 0))
        svc, msg, req_body = won_crypto.parse_tmessage(first_body)
        LOGGER.info(
            "Auth1Peer: first message from %s:%s (svc=%d msg=%d, %d bytes)",
            *peer, svc, msg, len(req_body),
        )
        if svc != AUTH1_PEER_SERVICE_TYPE or msg != AUTH1_PEER_REQUEST:
            LOGGER.warning("Auth1Peer: unexpected first message svc=%d msg=%d", svc, msg)
            return

        req = _parse_auth1_peer_request(req_body)
        client_cert = _parse_auth1_certificate(bytes(req["certificate"]))
        if client_cert["sig"] and not won_crypto.nr_md5_verify(
            bytes(client_cert["unsigned"]),
            bytes(client_cert["sig"]),
            self._auth_p,
            self._auth_q,
            self._auth_g,
            self._auth_y,
        ):
            LOGGER.warning("Auth1Peer: client certificate failed auth-key verification")
            return

        LOGGER.info(
            "Auth1Peer: request auth_mode=%d encrypt_mode=%d flags=0x%04x user_id=%d",
            req["auth_mode"], req["encrypt_mode"], req["encrypt_flags"], client_cert["user_id"],
        )

        server_user_id = self._next_user_id
        self._next_user_id += 1
        server_cert, _server_y, server_x = self._build_user_cert(server_user_id)
        secret_b = os.urandom(8)
        secret_b_plain = struct.pack("<H", len(secret_b)) + secret_b
        secret_b_cipher = won_crypto.eg_encrypt(
            secret_b_plain,
            int(client_cert["p"]),
            int(client_cert["g"]),
            int(client_cert["y"]),
        )

        challenge1 = _build_auth1_peer_challenge1(secret_b_cipher, server_cert)
        writer.write(challenge1)
        await writer.drain()
        LOGGER.info("Auth1Peer: Challenge1 sent to %s:%s", *peer)

        body = await _titan_recv(reader)
        svc, msg, challenge2_body = won_crypto.parse_tmessage(body)
        LOGGER.info(
            "Auth1Peer: next message from %s:%s (svc=%d msg=%d, %d bytes)",
            *peer, svc, msg, len(challenge2_body),
        )
        if svc != AUTH1_PEER_SERVICE_TYPE or msg != AUTH1_PEER_CHALLENGE2:
            LOGGER.warning("Auth1Peer: expected Challenge2, got svc=%d msg=%d", svc, msg)
            return

        challenge2_cipher = _parse_auth1_peer_challenge2(challenge2_body)
        challenge2_plain = won_crypto.eg_decrypt(
            challenge2_cipher,
            self._auth_p,
            self._auth_g,
            server_x,
        )
        if len(challenge2_plain) < 2:
            LOGGER.warning("Auth1Peer: Challenge2 plaintext too short")
            return
        secret_b_len, = struct.unpack("<H", challenge2_plain[:2])
        secret_b_echo = challenge2_plain[2:2 + secret_b_len]
        secret_a = challenge2_plain[2 + secret_b_len:]
        if secret_b_echo != secret_b:
            LOGGER.warning("Auth1Peer: SecretB mismatch from %s:%s", *peer)
            return
        if not secret_a:
            LOGGER.warning("Auth1Peer: empty SecretA from %s:%s", *peer)
            return

        self._expire_peer_sessions()
        session_id = self._alloc_peer_session_id() if req["auth_mode"] == 2 else 0
        secret_a_cipher = won_crypto.eg_encrypt(
            struct.pack("<H", len(secret_a)) + secret_a,
            int(client_cert["p"]),
            int(client_cert["g"]),
            int(client_cert["y"]),
        )
        complete = _build_auth1_peer_complete(secret_a_cipher, session_id)
        writer.write(complete)
        await writer.drain()
        LOGGER.info(
            "Auth1Peer: Complete sent to %s:%s (session_id=%d)",
            *peer, session_id,
        )

        if req["auth_mode"] == 2 and req["encrypt_mode"] == 1 and session_id != 0:
            role = PEER_ROLE_FACTORY if (int(req["encrypt_flags"]) & 0x0001) else PEER_ROLE_DIRECTORY
            sequenced = role == PEER_ROLE_DIRECTORY
            session = PeerSession(secret_b, session_id, role=role, sequenced=sequenced)
            self._peer_sessions[session_id] = session
            self._touch_peer_session(session)
            if role == PEER_ROLE_DIRECTORY:
                await self._handle_directory_session(reader, writer, session)
            elif role == PEER_ROLE_FACTORY:
                await self._handle_factory_session(reader, writer, session)

    async def _handle_directory_session(self, reader: asyncio.StreamReader,
                                         writer: asyncio.StreamWriter,
                                         session: PeerSession,
                                         first_body: Optional[bytes] = None) -> None:
        """Handle post-peer-auth encrypted directory traffic on the same socket."""
        peer = writer.get_extra_info("peername", ("?", 0))
        self._touch_peer_session(session)
        while True:
            if first_body is not None:
                body = first_body
                first_body = None
            else:
                try:
                    body = await _titan_recv(reader)
                except asyncio.IncompleteReadError:
                    return
            if not body:
                return

            if body[0] == 0x06:
                clear = _decrypt_small_session(
                    body,
                    session.session_key,
                    session.session_id,
                    session.in_seq if session.sequenced else None,
                )
                if session.sequenced:
                    session.in_seq += 1
            else:
                LOGGER.warning(
                    "Dir(session): unexpected header 0x%02x from %s:%s",
                    body[0], *peer,
                )
                return

            if len(clear) < 5:
                LOGGER.warning("Dir(session): clear message too short from %s:%s", *peer)
                return

            req = _decode_dir_get(clear)
            self._touch_peer_session(session)
            LOGGER.info(
                "Dir(session): path=%r svc_filter=%r",
                req["path"], req["service_name"],
            )
            reply_clear = await self._titan_dir_get_reply_body(req)
            reply_enc = _encrypt_small_session(
                reply_clear,
                session.session_key,
                session.session_id,
                session.out_seq if session.sequenced else None,
            )
            if session.sequenced:
                session.out_seq += 1
            writer.write(_titan_wrap(reply_enc))
            await writer.drain()
            # Homeworld tears down the dir pipe after handling the reply.
            return

    async def _handle_factory_session(self, reader: asyncio.StreamReader,
                                       writer: asyncio.StreamWriter,
                                       session: PeerSession,
                                       first_body: Optional[bytes] = None) -> None:
        """Handle post-peer-auth encrypted factory traffic on the same socket."""
        peer = writer.get_extra_info("peername", ("?", 0))
        self._touch_peer_session(session)
        if first_body is not None:
            body = first_body
        else:
            try:
                body = await _titan_recv(reader)
            except asyncio.IncompleteReadError:
                return
        if not body:
            return
        if body[0] != 0x06:
            LOGGER.warning(
                "Factory(session): unexpected header 0x%02x from %s:%s",
                body[0], *peer,
            )
            return

        clear = _decrypt_small_session(
            body,
            session.session_key,
            session.session_id,
            None,
        )
        req = _parse_fact_start_process(clear)
        self._touch_peer_session(session)
        LOGGER.info(
            "Factory(session): StartProcess process=%r display=%r register_dir=%r total_ports=%d",
            req["process_name"],
            req["display_name"],
            req["register_dir"],
            req["total_ports"],
        )

        selected_port = self.routing_port
        factory_id = "gateway_factory"
        process_name = str(req["process_name"])
        game_name = "homeworld" if process_name == "RoutingServHWGame" else "chat"
        room_password = _extract_factory_password(str(req["cmd_line"]))
        managed_locally = False

        if self.routing_manager is not None and process_name in {"RoutingServHWChat", "RoutingServHWGame"}:
            try:
                selected_port = await self.routing_manager.allocate_server(
                    publish_in_directory=(process_name == "RoutingServHWChat")
                )
                managed_locally = True
                routing_server = self.routing_manager._servers.get(selected_port)
                if routing_server is not None and process_name == "RoutingServHWChat":
                    routing_server._room_password = room_password
            except Exception as exc:
                LOGGER.warning("Factory(session): routing allocation failed: %s", exc)

        if room_password:
            LOGGER.info(
                "Factory(session): extracted room password for %r (len=%d)",
                process_name,
                len(room_password),
            )

        try:
            await self._call_backend(
                {
                    "action": "REGISTER_FACTORY",
                    "factory_id": factory_id,
                    "host": self.public_host,
                    "region": "global",
                    "max_processes": 4,
                }
            )
            if managed_locally:
                LOGGER.info(
                    "Factory(session): using local routing manager for %r on port=%d; "
                    "skipping backend FACTORY_START_PROCESS",
                    process_name,
                    selected_port,
                )
            else:
                backend = await self._call_backend(
                    {
                        "action": "FACTORY_START_PROCESS",
                        "factory_id": factory_id,
                        "process_name": process_name,
                        "game_name": game_name,
                        "port": selected_port,
                    }
                )
                if backend.get("ok"):
                    server = backend.get("server", {})
                    if isinstance(server, dict):
                        selected_port = int(server.get("port", selected_port))
                else:
                    LOGGER.warning(
                        "Factory(session): backend FACTORY_START_PROCESS failed: %s",
                        backend.get("error", "unknown_error"),
                    )
        except Exception as exc:
            LOGGER.warning("Factory(session): backend start-process bridge failed: %s", exc)

        reply_clear = _build_small_fact_status_reply(0, [selected_port])
        reply_enc = _encrypt_small_session(
            reply_clear,
            session.session_key,
            session.session_id,
            None,
        )
        writer.write(_titan_wrap(reply_enc))
        await writer.drain()
        LOGGER.info(
            "Factory(session): StatusReply sent to %s:%s (port=%d)",
            *peer, selected_port,
        )

    async def _handle_titan_packet(
        self,
        packet_hex: str,
        client_ip: Optional[str] = None,
    ) -> Dict[str, object]:
        try:
            packet = binascii.unhexlify(packet_hex.encode("ascii"))
        except Exception:
            return {"ok": False, "error": "invalid_packet_hex"}

        req = decode_request(packet)
        kind = req.get("kind")
        if kind == "auth_login":
            backend = await self._call_backend(
                {
                    "action": "AUTH_LOGIN",
                    "username": req["username"],
                    "password": req["password"],
                    "client_ip": client_ip,
                }
            )
            if backend.get("ok"):
                reply = AuthLoginReply(STATUS_OK, str(backend.get("token", ""))).encode()
            else:
                reply = AuthLoginReply(STATUS_FAIL, str(backend.get("error", "auth_failed"))).encode()
            return {"ok": True, "packet_hex": binascii.hexlify(reply).decode("ascii")}

        if kind == "dir_get":
            backend = await self._call_backend({"action": "TITAN_DIR_GET", "path": req["path"]})
            if backend.get("ok"):
                reply = DirGetReply(STATUS_OK, json.dumps(backend.get("entities", {}))).encode()
            else:
                reply = DirGetReply(STATUS_FAIL, json.dumps({"error": backend.get("error", "dir_failed")})).encode()
            return {"ok": True, "packet_hex": binascii.hexlify(reply).decode("ascii")}

        if kind == "route_register":
            backend = await self._call_backend({"action": "TITAN_ROUTE_REGISTER", "lobby_id": req["lobby_id"], "player_id": req["player_id"]})
            if backend.get("ok"):
                reply = RoutingStatusReply(STATUS_OK, "registered").encode()
            else:
                reply = RoutingStatusReply(STATUS_FAIL, str(backend.get("error", "route_register_failed"))).encode()
            return {"ok": True, "packet_hex": binascii.hexlify(reply).decode("ascii")}

        if kind == "route_join":
            backend = await self._call_backend({"action": "TITAN_ROUTE_JOIN", "lobby_id": req["lobby_id"], "player_id": req["player_id"]})
            if backend.get("ok"):
                reply = RoutingStatusReply(STATUS_OK, "joined").encode()
            else:
                reply = RoutingStatusReply(STATUS_FAIL, str(backend.get("error", "route_join_failed"))).encode()
            return {"ok": True, "packet_hex": binascii.hexlify(reply).decode("ascii")}

        if kind == "route_chat":
            backend = await self._call_backend({"action": "TITAN_ROUTE_CHAT", "lobby_id": req["lobby_id"], "from_player": req["player_id"], "message": req["message"]})
            if backend.get("ok"):
                reply = RoutingChatEvent(STATUS_OK, req["lobby_id"], req["player_id"], req["message"]).encode()
            else:
                reply = RoutingStatusReply(STATUS_FAIL, str(backend.get("error", "route_chat_failed"))).encode()
            return {"ok": True, "packet_hex": binascii.hexlify(reply).decode("ascii")}

        if kind == "route_data_set":
            backend = await self._call_backend({"action": "TITAN_ROUTE_SET_DATA_OBJECT", "lobby_id": req["lobby_id"], "key": req["key"], "value": req["value"]})
            if backend.get("ok"):
                backend2 = await self._call_backend({"action": "TITAN_ROUTE_GET_DATA_OBJECT", "lobby_id": req["lobby_id"], "key": req["key"]})
                if backend2.get("ok"):
                    reply = RoutingDataObjectReply(STATUS_OK, req["key"], str(backend2.get("value", ""))).encode()
                else:
                    reply = RoutingStatusReply(STATUS_FAIL, "data_object_read_failed").encode()
            else:
                reply = RoutingStatusReply(STATUS_FAIL, str(backend.get("error", "route_data_set_failed"))).encode()
            return {"ok": True, "packet_hex": binascii.hexlify(reply).decode("ascii")}

        reply = RoutingStatusReply(STATUS_FAIL, "unknown_message").encode()
        return {"ok": True, "packet_hex": binascii.hexlify(reply).decode("ascii")}

    async def _push_events_loop(self, queue: asyncio.Queue, writer: asyncio.StreamWriter) -> None:
        """Background task: read events from queue, encode as OP_SERVER_EVENT frames, push to client."""
        try:
            while True:
                event = await queue.get()
                try:
                    frame = encode_frame(OP_SERVER_EVENT, event)
                    writer.write(frame)
                    await writer.drain()
                except (ConnectionError, OSError):
                    break
        except asyncio.CancelledError:
            pass

    async def _publish_post_action_events(self, opcode: int, action: Dict[str, object], response: Dict[str, object]) -> None:
        """After event-generating actions, publish to all lobby members via the bus."""
        if not response.get("ok"):
            return

        lobby_id = str(action.get("lobby_id", ""))
        if not lobby_id:
            return

        event: Optional[Dict[str, object]] = None

        if opcode == OP_ROUTE_CHAT:
            event = {
                "type": "chat",
                "lobby_id": lobby_id,
                "from": str(action.get("from_player", "")),
                "message": str(action.get("message", "")),
            }
        elif opcode == OP_JOIN_LOBBY:
            event = {
                "type": "lobby_join",
                "lobby_id": lobby_id,
                "player_id": str(action.get("player_id", "")),
            }
        elif opcode == OP_START_GAME:
            launch = response.get("launch", {})
            if isinstance(launch, dict):
                event = {
                    "type": "game_launch",
                    "lobby_id": lobby_id,
                    "server": launch.get("server", {}),
                    "players": launch.get("players", []),
                    "map_name": launch.get("map_name", ""),
                }

        if event is None:
            return

        # Fetch lobby members from backend to know who to push to
        try:
            backend_resp = await self._call_backend({"action": "TITAN_DIR_GET", "path": "/Homeworld"})
            entities = backend_resp.get("entities", {})
            lobby_ent = entities.get(lobby_id)
            if isinstance(lobby_ent, dict):
                # Fall back to querying the lobby directly
                pass
        except Exception:
            pass

        # Simpler: query lobby player list directly
        try:
            lobby_resp = await self._call_backend({"action": "LIST_LOBBIES"})
            lobbies = lobby_resp.get("lobbies", [])
            for lob in lobbies:
                if isinstance(lob, dict) and lob.get("lobby_id") == lobby_id:
                    player_ids = lob.get("players", [])
                    if isinstance(player_ids, list):
                        self.event_bus.publish(player_ids, event)
                    return
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Titan native protocol path
    # ------------------------------------------------------------------

    async def _handle_titan_native(self, reader: asyncio.StreamReader,
                                    writer: asyncio.StreamWriter,
                                    first4: bytes) -> None:
        """Handle a connection that speaks the real Titan LE-framed protocol.

        Auth1 connections (ServiceType 0xC9 = 201) are stateful 4-message
        exchanges and are delegated to _handle_auth1_connection.

        Other connections (DirGet etc.) are ONE-SHOT: read one frame, send
        one reply, close.  This mirrors Silencer's ProcessClient15101.
        """
        peer = writer.get_extra_info("peername", ("?", 0))
        LOGGER.info("Titan native connection from %s:%s", *peer)
        try:
            body = await _titan_recv(reader, first4)
            if not body:
                return

            self._expire_peer_sessions()

            if len(body) >= 8:
                try:
                    service_type, message_type, _ = won_crypto.parse_tmessage(body)
                except Exception:
                    service_type = 0
                    message_type = 0
                if service_type == won_crypto.AUTH1_SERVICE_TYPE:
                    if not self._auth_keys_loaded:
                        LOGGER.error("Auth1 request received but no keys loaded (use --keys-dir)")
                        return
                    await self._handle_auth1_connection(reader, writer, body)
                    return
                if service_type == AUTH1_PEER_SERVICE_TYPE:
                    if not self._auth_keys_loaded:
                        LOGGER.error("Auth1Peer request received but no keys loaded (use --keys-dir)")
                        return
                    await self._handle_auth1_peer_connection(reader, writer, body)
                    return

            if len(body) >= 3 and body[0] == 0x06:
                session_id, = struct.unpack("<H", body[1:3])
                session = self._peer_sessions.get(session_id)
                if session is not None:
                    self._touch_peer_session(session)
                    LOGGER.info(
                        "Peer(session): resumed encrypted request from %s:%s (session_id=%d role=%s)",
                        *peer, session_id, session.role,
                    )
                    if session.role == PEER_ROLE_DIRECTORY:
                        await self._handle_directory_session(reader, writer, session, first_body=body)
                    elif session.role == PEER_ROLE_FACTORY:
                        await self._handle_factory_session(reader, writer, session, first_body=body)
                    return

            # Non-Auth1: one-shot dispatch (DirGet, etc.)
            version = body[0] if body else 0
            msg_type = body[1] if len(body) > 1 else 0
            LOGGER.debug(
                "Titan msg from %s:%s  ver=0x%02x type=0x%02x len=%d",
                peer[0], peer[1], version, msg_type, len(body),
            )
            reply_bytes = await self._dispatch_titan(version, msg_type, body)
            if reply_bytes:
                writer.write(reply_bytes)
                await writer.drain()
            await asyncio.sleep(1.0)   # mirror Silencer's sleep(1) before close
        except asyncio.IncompleteReadError:
            pass
        except Exception as exc:
            LOGGER.error("Titan native error from %s:%s: %s", *peer, exc)
        finally:
            writer.close()
            await writer.wait_closed()

    async def _dispatch_titan(self, version: int, msg_type: int,
                               body: bytes) -> Optional[bytes]:
        """Route an incoming Titan native message to the appropriate handler.

        Auth1 messages (ServiceType 0xC9) are handled by _handle_auth1_connection
        before reaching this method.  This only handles non-Auth1 one-shot messages.
        """
        if msg_type == 0x02:  # Dir Get Request (SmallMessage)
            try:
                req = _decode_dir_get(body)
                LOGGER.info(
                    "DirGet path=%r svc_filter=%r",
                    req["path"], req["service_name"],
                )
                return await self._titan_dir_get_reply(req)
            except Exception as exc:
                LOGGER.error("DirGet parse error: %s", exc)
                return None
        if (
            len(body) >= 8
            and body[0] == MINI_HEADER_TYPE
            and body[1] == MINI_COMMON_SERVICE
            and body[2] == MINI_COMM_PING
        ):
            try:
                ping = _parse_mini_ping(body)
                LOGGER.info(
                    "MiniPing: request start_tick=%d extended=%s",
                    ping["start_tick"], ping["extended"],
                )
                return _titan_wrap(_build_mini_ping_reply(int(ping["start_tick"])))
            except Exception as exc:
                LOGGER.error("MiniPing parse error: %s", exc)
                return None
        LOGGER.warning(
            "Unhandled Titan msg_type=0x%02x len=%d body=%s",
            msg_type, len(body), body[:64].hex(),
        )
        return None

    async def _titan_dir_get_reply_body(self, req: Dict[str, object]) -> bytes:
        """Build a clear SmallMessage Dir Get reply body.

        Discriminator (service_name / DataObject-type-filter substring matching):
          * "ValidVersions"     → COMBINED WON DirG2MultiEntityReply: service
                                  entries (AuthServer, TitanRoutingServer,
                                  TitanFactoryServer) with net_addr AND DataObjects.
          * "Auth"              → WON DirG2MultiEntityReply with AuthServer entry
          * "Routing"|"Factory" → WON DirG2MultiEntityReply with routing entries
          * anything else       → minimal DirG2MultiEntityReply (fallback)
        """
        path = str(req.get("path", "/TitanServers"))
        svc = str(req.get("service_name", ""))

        try:
            ip_raw = _socket.inet_aton(self.public_host)
        except Exception:
            ip_raw = b"\x7f\x00\x00\x01"
        auth_addr = struct.pack(">H", self.public_port) + ip_raw
        routing_addr = struct.pack(">H", self.routing_port) + ip_raw

        if path == "/Homeworld":
            LOGGER.info("DirGet: native /Homeworld query")
            flags = (
                DIR_GF_DECOMPSERVICES
                | DIR_GF_ADDTYPE
                | DIR_GF_DIRADDNAME
                | DIR_GF_ADDDISPLAYNAME
                | DIR_GF_SERVADDNAME
                | DIR_GF_SERVADDNETADDR
                | DIR_GF_ADDDATAOBJECTS
                | DIR_GF_ADDDOTYPE
                | DIR_GF_ADDDODATA
            )
            entries = []
            factory_entries = []
            if self.routing_manager is not None:
                entries.extend(self.routing_manager.directory_entries())
            if not entries:
                backend = await self._call_backend({"action": "TITAN_DIR_GET", "path": "/Homeworld"})
                if backend.get("ok"):
                    for entity_name, ent in dict(backend.get("entities", {})).items():
                        if not isinstance(ent, dict):
                            continue
                        payload = ent.get("payload", {})
                        if not isinstance(payload, dict):
                            payload = {}
                        if ent.get("entity_type") == "routing_room":
                            display_name = str(payload.get("Description", entity_name))
                            data_objects = []
                            for obj_name in ("Description", "RoomFlags", "__RSClientCount"):
                                if obj_name in payload:
                                    data_objects.append(_pack_directory_data_object(obj_name, payload[obj_name]))
                            entries.append({
                                "type": "S",
                                "name": "TitanRoutingServer",
                                "display_name": display_name,
                                "net_addr": routing_addr,
                                "data_objects": data_objects,
                            })

            titan_backend = await self._call_backend({"action": "TITAN_DIR_GET", "path": "/TitanServers"})
            if titan_backend.get("ok"):
                for entity_name, ent in dict(titan_backend.get("entities", {})).items():
                    if not isinstance(ent, dict):
                        continue
                    entity_name_s = str(entity_name)
                    is_factory = (
                        ent.get("entity_type") == "factory"
                        or entity_name_s.startswith("Factory:")
                        or entity_name_s == "TitanFactoryServer"
                    )
                    if not is_factory:
                        continue
                    payload = ent.get("payload", {})
                    if not isinstance(payload, dict):
                        payload = {}
                    display_name = str(payload.get("Description", entity_name_s.split(":", 1)[-1]))
                    data_objects = [
                        _pack_directory_data_object(
                            "Description",
                            payload.get("Description", display_name),
                        )
                    ]
                    for obj_name, default_value in (
                        ("__FactCur_RoutingServHWGame", 0),
                        ("__FactTotal_RoutingServHWGame", 0),
                        ("__ServerUptime", 0),
                    ):
                        data_objects.append(
                            _pack_directory_data_object(obj_name, payload.get(obj_name, default_value))
                        )
                    factory_entries.append({
                        "type": "S",
                        "name": "TitanFactoryServer",
                        "display_name": display_name,
                        "net_addr": auth_addr,
                        "data_objects": data_objects,
                    })

            if not factory_entries:
                factory_entries.append({
                    "type": "S",
                    "name": "TitanFactoryServer",
                    "display_name": "Melbourne",
                    "net_addr": auth_addr,
                    "data_objects": [
                        _pack_directory_data_object("Description", "Melbourne"),
                        _pack_directory_data_object("__FactCur_RoutingServHWGame", 0),
                        _pack_directory_data_object("__FactTotal_RoutingServHWGame", 0),
                        _pack_directory_data_object("__ServerUptime", 0),
                    ],
                })

            # Homeworld uses factory servers in two different passes:
            # 1. Before HWDS, it records FACTSERVER_ADDRESSES for actual
            #    StartRoutingServer requests.
            # 2. After an HWDS directory marker, it treats factory services as
            #    entries for the "Choose Server" picker UI.
            # So we intentionally publish the same factory set in both places.
            entries.extend(factory_entries)
            entries.append({
                "type": "D",
                "name": "HWDS",
                "display_name": "HWDS",
                "data_objects": [],
            })
            entries.extend(factory_entries)
            return _encode_dir_reply_body(flags, entries)

        if "ValidVersions" in svc:
            version_blob = "\r\n".join(self.valid_versions).encode("ascii")
            LOGGER.info(
                "DirGet: version check (combined)  svc_filter=%r  versions=%r",
                svc, list(self.valid_versions),
            )
            # Homeworld never makes separate Auth/Routing DirGet queries after
            # the version check — it discovers all server addresses from THIS
            # single /TitanServers reply.  GetServiceOp::Init() confirms the
            # standard WON flags are:
            #   DIR_GF_DECOMPSERVICES | DIR_GF_ADDDATAOBJECTS |
            #   DIR_GF_SERVADDNAME    | DIR_GF_SERVADDNETADDR
            # so service entries WITH addresses AND DataObjects come back
            # together in one packet.
            #
            # We return three service entries (AuthServer, TitanRoutingServer,
            # TitanFactoryServer), each carrying the version DataObject so the
            # existing GetVersionOp / GetServiceOp logic is satisfied.
            flags = (
                DIR_GF_DECOMPSERVICES
                | DIR_GF_ADDTYPE
                | DIR_GF_SERVADDNAME
                | DIR_GF_SERVADDNETADDR
                | DIR_GF_ADDDATAOBJECTS
                | DIR_GF_ADDDOTYPE
                | DIR_GF_ADDDODATA
            )
            ver_do = (svc.encode("ascii"), version_blob)
            entries = [
                {"type": "S", "name": "AuthServer",         "net_addr": auth_addr,    "data_objects": [ver_do]},
                {"type": "S", "name": "TitanRoutingServer", "net_addr": routing_addr, "data_objects": [ver_do]},
                {"type": "S", "name": "TitanFactoryServer", "net_addr": routing_addr, "data_objects": [ver_do]},
            ]
            return _encode_dir_reply_body(flags, entries)

        if "Auth" in svc:
            # Auth server lives on our Titan port (15101).  Homeworld opens a
            # fresh TCP connection there for the auth exchange.
            LOGGER.info(
                "DirGet: auth server query (svc=%r) → WON reply %s:%s",
                svc, self.public_host, self.public_port,
            )
            flags = (
                DIR_GF_DECOMPSERVICES
                | DIR_GF_ADDTYPE
                | DIR_GF_SERVADDNAME
                | DIR_GF_SERVADDNETADDR
            )
            entries = [{"type": "S", "name": "AuthServer", "net_addr": auth_addr}]
            return _encode_dir_reply_body(flags, entries)

        if "Routing" in svc or "Factory" in svc:
            # Routing/lobby server lives on port 15100 (SilencerRoutingServer).
            LOGGER.info(
                "DirGet: routing server query (svc=%r) → WON reply %s:%s",
                svc, self.public_host, self.routing_port,
            )
            flags = (
                DIR_GF_DECOMPSERVICES
                | DIR_GF_ADDTYPE
                | DIR_GF_SERVADDNAME
                | DIR_GF_SERVADDNETADDR
            )
            entries = [
                {"type": "S", "name": "TitanRoutingServer", "net_addr": routing_addr},
                {"type": "S", "name": "TitanFactoryServer", "net_addr": routing_addr},
            ]
            return _encode_dir_reply_body(flags, entries)

        # Fallback: minimal DirG2MultiEntityReply with a single service entry.
        name = svc or path.split("/")[-1] or "WONServer"
        # net_addr wire format: [u16 BE port][u32 BE IP]
        # IPAddr::SetSixByte memcpy's into &sin_port, so port comes first.
        net_addr = struct.pack(">H", self.public_port) + ip_raw
        fallback_flags = (
            DIR_GF_DECOMPROOT
            | DIR_GF_DECOMPSERVICES
            | DIR_GF_ADDTYPE
            | DIR_GF_SERVADDPATH
            | DIR_GF_SERVADDNAME
            | DIR_GF_SERVADDNETADDR
            | DIR_GF_ADDDISPLAYNAME
        )
        entries = [{
            "type": "S",
            "name": name,
            "path": path,
            "display_name": name,
            "net_addr": net_addr,
        }]
        LOGGER.info(
            "DirGet reply (fallback): path=%r filter=%r entries=%d addr=%s:%s",
            path, svc, len(entries), self.public_host, self.public_port,
        )
        return _encode_dir_reply_body(fallback_flags, entries)

    async def _titan_dir_get_reply(self, req: Dict[str, object]) -> bytes:
        return _titan_wrap(await self._titan_dir_get_reply_body(req))

    # ------------------------------------------------------------------
    # Custom binary protocol path  (our own framing, big-endian)
    # ------------------------------------------------------------------

    async def _handle_custom_protocol(self, reader: asyncio.StreamReader,
                                       writer: asyncio.StreamWriter,
                                       first4: bytes) -> None:
        ctx = ConnectionContext()
        push_task: Optional[asyncio.Task] = None
        event_queue: Optional[asyncio.Queue] = None
        try:
            hdr = first4
            peer = writer.get_extra_info("peername", ("?", 0))
            while True:
                length = struct.unpack(">I", hdr)[0]
                if length <= 0 or length > 10_000_000:
                    raise ValueError("invalid_frame_length")
                body = await reader.readexactly(length)
                opcode, payload = decode_frame(body)
                action = opcode_to_action(opcode, payload, ctx)
                if action.get("action") == "AUTH_LOGIN":
                    action["client_ip"] = str(peer[0])

                if action.get("action") == "INVALID":
                    response = {"ok": False, "error": action.get("error", "invalid")}
                elif action.get("action") == "UNKNOWN_BINARY_OPCODE":
                    response = {"ok": False, "error": "unknown_binary_opcode", "opcode": opcode}
                else:
                    try:
                        if action.get("action") == "TITAN_MESSAGE":
                            response = await self._handle_titan_packet(
                                str(action.get("packet_hex", "")),
                                client_ip=str(peer[0]),
                            )
                        else:
                            response = await self._call_backend(action)
                    except Exception as exc:
                        response = {"ok": False, "error": str(exc)}

                # State transitions
                if opcode == OP_AUTH_LOGIN and response.get("ok") and isinstance(response.get("token"), str):
                    ctx.token = str(response["token"])
                    ctx.state = ConnState.AUTHED
                if opcode == OP_REGISTER_PLAYER and response.get("ok"):
                    p = response.get("player", {})
                    if isinstance(p, dict) and isinstance(p.get("player_id"), str):
                        ctx.player_id = str(p["player_id"])
                        ctx.state = ConnState.PLAYER_READY
                        # Subscribe to push events once player is ready
                        if event_queue is None and ctx.player_id:
                            event_queue = self.event_bus.subscribe(ctx.player_id)
                            push_task = asyncio.create_task(
                                self._push_events_loop(event_queue, writer)
                            )
                if opcode == OP_ROUTE_REGISTER and response.get("ok"):
                    lid = str(action.get("lobby_id", ""))
                    if lid:
                        ctx.registered_lobbies.add(lid)

                # Send response frame
                writer.write(encode_frame(action_to_response_opcode(opcode), response))
                await writer.drain()

                # Publish events to other connected clients
                await self._publish_post_action_events(opcode, action, response)

                hdr = await reader.readexactly(4)

        except asyncio.IncompleteReadError:
            pass
        except Exception as exc:
            try:
                writer.write(encode_frame(0xFF, {"ok": False, "error": str(exc)}))
                await writer.drain()
            except Exception:
                pass
        finally:
            # Clean up push subscription
            if push_task is not None:
                push_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await push_task
            if event_queue is not None and ctx.player_id:
                self.event_bus.unsubscribe(ctx.player_id, event_queue)
            writer.close()
            await writer.wait_closed()

    # ------------------------------------------------------------------
    # Connection entry point — auto-detects protocol from first 4 bytes
    # ------------------------------------------------------------------

    async def handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter) -> None:
        """Dispatch incoming connections to Titan-native or custom handler."""
        try:
            first4 = await reader.readexactly(4)
        except asyncio.IncompleteReadError:
            return
        is_titan, _ = _is_titan_native(first4)
        if is_titan:
            await self._handle_titan_native(reader, writer, first4)
        else:
            await self._handle_custom_protocol(reader, writer, first4)


async def main_async(args: argparse.Namespace) -> None:
    event_bus = GatewayEventBus()
    if args.admin_port > 0 and not _is_loopback_host(args.admin_host) and not str(args.admin_token or "").strip():
        raise ValueError("Refusing to expose the admin dashboard on a non-loopback host without --admin-token.")
    valid_versions: list[str] = []
    if getattr(args, "valid_versions_file", None):
        raw = Path(args.valid_versions_file).read_text(encoding="utf-8")
        valid_versions.extend(_parse_valid_versions_text(raw))
    if getattr(args, "valid_version", None):
        for value in args.valid_version:
            valid_versions.extend(_parse_valid_versions_text(value))
    if not valid_versions:
        valid_versions.extend(_parse_valid_versions_text(args.version_str))
    srv = BinaryGatewayServer(
        args.backend_host, args.backend_port, event_bus,
        public_host=args.public_host,
        public_port=args.port,
        routing_port=args.routing_port,
        version_str=args.version_str,
        valid_versions=valid_versions,
        keys_dir=args.keys_dir,
        backend_shared_secret=args.backend_shared_secret,
        backend_timeout_s=args.backend_timeout,
    )
    LOGGER.info("ValidVersions configured: %r", list(srv.valid_versions))
    routing_manager = RoutingServerManager(
        args.host,
        args.public_host,
        args.routing_port,
        max_port=args.routing_max_port,
        excluded_ports={args.port, args.firewall_port},
        gateway=srv,
    )
    srv.routing_manager = routing_manager

    server = await asyncio.start_server(srv.handle_client, args.host, args.port)
    routing_srv, routing_server = await routing_manager.start_listener(
        args.routing_port,
        publish_in_directory=True,
    )
    firewall_server = await asyncio.start_server(
        _handle_firewall_probe, args.host, args.firewall_port
    )
    admin_dashboard = AdminDashboardServer(
        srv,
        args.db_path,
        DASHBOARD_LOG_HANDLER,
        admin_token=args.admin_token,
        stats_token=args.stats_token,
    )
    admin_server = None
    if args.admin_port > 0:
        admin_server = await asyncio.start_server(
            admin_dashboard.handle_client,
            args.admin_host,
            args.admin_port,
        )
        admin_dashboard.start_background_tasks()
    srv.start_background_tasks()

    addrs = ", ".join(str(s.getsockname()) for s in (server.sockets or []))
    r_addrs = ", ".join(str(s.getsockname()) for s in (routing_server.sockets or []))
    fw_addrs = ", ".join(str(s.getsockname()) for s in (firewall_server.sockets or []))
    admin_addrs = ", ".join(str(s.getsockname()) for s in (admin_server.sockets or [])) if admin_server else ""
    print(f"Titan binary gateway  listening on {addrs} -> {args.backend_host}:{args.backend_port}")
    print(f"Routing server        listening on {r_addrs}  (dynamic range ends at {args.routing_max_port})")
    print(f"Firewall probe        listening on {fw_addrs}")
    if admin_server:
        print(f"Admin dashboard       listening on {admin_addrs}")
    print(f"Public address reported to clients: {args.public_host}  "
          f"gateway:{args.port}  routing:{args.routing_port}")

    try:
        if admin_server:
            async with server, routing_server, firewall_server, admin_server:
                await asyncio.gather(
                    server.serve_forever(),
                    routing_server.serve_forever(),
                    firewall_server.serve_forever(),
                    admin_server.serve_forever(),
                )
        else:
            async with server, routing_server, firewall_server:
                await asyncio.gather(
                    server.serve_forever(),
                    routing_server.serve_forever(),
                    firewall_server.serve_forever(),
                )
    finally:
        await admin_dashboard.stop_background_tasks()
        await srv.stop_background_tasks()
        await routing_manager.close_all()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Binary Titan gateway with connection state machine")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=15101,
                   help="Port for Titan directory/version-check queries (Homeworld hardcodes 15101)")
    p.add_argument("--backend-host", default="127.0.0.1")
    p.add_argument("--backend-port", type=int, default=9100,
                   help="Port of the internal WON backend (won_server.py)")
    p.add_argument(
        "--backend-shared-secret",
        default=os.environ.get("BACKEND_SHARED_SECRET", ""),
        help="Optional shared secret sent to the internal backend JSON-RPC service.",
    )
    p.add_argument(
        "--backend-timeout",
        type=float,
        default=float(os.environ.get("BACKEND_RPC_TIMEOUT", BACKEND_RPC_TIMEOUT_SECONDS)),
        help="Timeout in seconds for backend JSON-RPC calls.",
    )
    p.add_argument("--public-host", default="127.0.0.1",
                   help="Public IP reported to Homeworld clients in directory replies")
    p.add_argument("--routing-port", type=int, default=15100,
                   help="Port for the Homeworld routing/lobby server (Homeworld connects here for chat and lobbies)")
    p.add_argument("--routing-max-port", type=int, default=15120,
                   help="Highest TCP port the gateway may allocate for extra room/game routing listeners")
    p.add_argument("--firewall-port", type=int, default=2021,
                   help="Port for WON firewall probe listener (Homeworld probes this to detect NAT)")
    p.add_argument("--admin-host", default="127.0.0.1",
                   help="Bind host for the local admin dashboard (127.0.0.1 keeps it local-only)")
    p.add_argument("--admin-port", type=int, default=8080,
                   help="Port for the local admin dashboard (set to 0 to disable)")
    p.add_argument(
        "--admin-token",
        default=os.environ.get("ADMIN_TOKEN", ""),
        help="Optional token for the admin dashboard. Required if --admin-host is not loopback.",
    )
    p.add_argument(
        "--stats-token",
        default=os.environ.get("STATS_TOKEN", ""),
        help="Optional token for the bot-friendly /api/stats endpoint. Falls back to --admin-token when unset.",
    )
    p.add_argument("--db-path", default=str(Path(__file__).with_name("won_server.db")),
                   help="Path to the SQLite backend DB shown in the admin dashboard")
    p.add_argument("--version-str", default="0110",
                   help="Legacy single ValidVersions value. Prefer --valid-version or --valid-versions-file for strict exact build strings.")
    p.add_argument("--valid-version", action="append", default=[],
                   help="Exact Homeworld versionString accepted by HomeworldValidVersions. Repeat for multiple allowed builds.")
    p.add_argument("--valid-versions-file", default=None,
                   help="Text file containing one exact allowed Homeworld versionString per line.")
    p.add_argument("--keys-dir", default=None,
                   help="Directory containing Auth1 keypairs (verifier_private.der, "
                        "authserver_private.der).  If not provided, Auth1 requests "
                        "will be rejected with an error log.")
    p.add_argument("--log", "--log-level", dest="log_level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                   help="Logging verbosity (DEBUG shows every raw packet event)")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )
    DASHBOARD_LOG_HANDLER.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")
    )
    logging.getLogger().addHandler(DASHBOARD_LOG_HANDLER)
    asyncio.run(main_async(args))
