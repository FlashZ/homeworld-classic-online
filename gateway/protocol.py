from __future__ import annotations

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
from pathlib import Path
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
ADMIN_BROADCAST_CLIENT_ID = 0xFFFE
ADMIN_BROADCAST_CLIENT_NAME = "[ADMIN]"
ADMIN_BROADCAST_CLIENT_NAME_RAW = ADMIN_BROADCAST_CLIENT_NAME.encode("utf-16-le")
ADMIN_BROADCAST_CLIENT_IP_U32 = 0
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


