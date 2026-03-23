#!/usr/bin/env python3
"""Minimal Titan-like message schemas and codecs (MVP).

Message envelope:
- msg_type: u16
- status:  u16
- payload_len: u32
- payload bytes

Payloads are length-prefixed UTF-8 fields for deterministic parsing.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, Tuple

# Message type IDs (MVP subset)
MSG_AUTH_LOGIN_REQ = 0x1001
MSG_AUTH_LOGIN_REPLY = 0x1002
MSG_DIR_GET_REQ = 0x2001
MSG_DIR_GET_REPLY = 0x2002
MSG_ROUTE_REGISTER_REQ = 0x3001
MSG_ROUTE_JOIN_REQ = 0x3003
MSG_ROUTE_CHAT_REQ = 0x3004
MSG_ROUTE_DATA_SET_REQ = 0x3005
MSG_ROUTING_STATUS_REPLY = 0x3002
MSG_ROUTING_CHAT_EVENT = 0x3006
MSG_ROUTING_DATA_OBJECT_REPLY = 0x3007

STATUS_OK = 0
STATUS_FAIL = 1


def _pack_fields(fields: Tuple[str, ...]) -> bytes:
    parts = []
    for f in fields:
        b = f.encode("utf-8")
        parts.append(struct.pack(">H", len(b)) + b)
    return b"".join(parts)


def _unpack_fields(payload: bytes, n: int) -> Tuple[str, ...]:
    out = []
    i = 0
    for _ in range(n):
        if i + 2 > len(payload):
            raise ValueError("truncated_field_len")
        ln = struct.unpack(">H", payload[i:i+2])[0]
        i += 2
        if i + ln > len(payload):
            raise ValueError("truncated_field")
        out.append(payload[i:i+ln].decode("utf-8"))
        i += ln
    return tuple(out)


def encode_titan_message(msg_type: int, status: int, payload: bytes) -> bytes:
    return struct.pack(">HHI", msg_type, status, len(payload)) + payload


def decode_titan_message(packet: bytes) -> Tuple[int, int, bytes]:
    if len(packet) < 8:
        raise ValueError("short_titan_packet")
    msg_type, status, ln = struct.unpack(">HHI", packet[:8])
    if len(packet) < 8 + ln:
        raise ValueError("truncated_titan_payload")
    return msg_type, status, packet[8:8+ln]


@dataclass
class AuthLoginReq:
    username: str
    password: str

    def encode(self) -> bytes:
        return encode_titan_message(MSG_AUTH_LOGIN_REQ, STATUS_OK, _pack_fields((self.username, self.password)))

    @staticmethod
    def decode(payload: bytes) -> "AuthLoginReq":
        u, p = _unpack_fields(payload, 2)
        return AuthLoginReq(u, p)


@dataclass
class AuthLoginReply:
    status: int
    token: str

    def encode(self) -> bytes:
        return encode_titan_message(MSG_AUTH_LOGIN_REPLY, self.status, _pack_fields((self.token,)))

    @staticmethod
    def decode(payload: bytes, status: int) -> "AuthLoginReply":
        (tok,) = _unpack_fields(payload, 1)
        return AuthLoginReply(status, tok)


@dataclass
class DirGetReq:
    path: str

    def encode(self) -> bytes:
        return encode_titan_message(MSG_DIR_GET_REQ, STATUS_OK, _pack_fields((self.path,)))

    @staticmethod
    def decode(payload: bytes) -> "DirGetReq":
        (path,) = _unpack_fields(payload, 1)
        return DirGetReq(path)


@dataclass
class DirGetReply:
    status: int
    entities_json: str

    def encode(self) -> bytes:
        return encode_titan_message(MSG_DIR_GET_REPLY, self.status, _pack_fields((self.entities_json,)))

    @staticmethod
    def decode(payload: bytes, status: int) -> "DirGetReply":
        (entities_json,) = _unpack_fields(payload, 1)
        return DirGetReply(status, entities_json)


@dataclass
class RouteRegisterReq:
    lobby_id: str
    player_id: str

    def encode(self) -> bytes:
        return encode_titan_message(MSG_ROUTE_REGISTER_REQ, STATUS_OK, _pack_fields((self.lobby_id, self.player_id)))

    @staticmethod
    def decode(payload: bytes) -> "RouteRegisterReq":
        lobby_id, player_id = _unpack_fields(payload, 2)
        return RouteRegisterReq(lobby_id, player_id)




@dataclass
class RouteJoinReq:
    lobby_id: str
    player_id: str

    def encode(self) -> bytes:
        return encode_titan_message(MSG_ROUTE_JOIN_REQ, STATUS_OK, _pack_fields((self.lobby_id, self.player_id)))

    @staticmethod
    def decode(payload: bytes) -> "RouteJoinReq":
        lobby_id, player_id = _unpack_fields(payload, 2)
        return RouteJoinReq(lobby_id, player_id)


@dataclass
class RouteChatReq:
    lobby_id: str
    player_id: str
    message: str

    def encode(self) -> bytes:
        return encode_titan_message(MSG_ROUTE_CHAT_REQ, STATUS_OK, _pack_fields((self.lobby_id, self.player_id, self.message)))

    @staticmethod
    def decode(payload: bytes) -> "RouteChatReq":
        lobby_id, player_id, message = _unpack_fields(payload, 3)
        return RouteChatReq(lobby_id, player_id, message)


@dataclass
class RouteDataSetReq:
    lobby_id: str
    key: str
    value: str

    def encode(self) -> bytes:
        return encode_titan_message(MSG_ROUTE_DATA_SET_REQ, STATUS_OK, _pack_fields((self.lobby_id, self.key, self.value)))

    @staticmethod
    def decode(payload: bytes) -> "RouteDataSetReq":
        lobby_id, key, value = _unpack_fields(payload, 3)
        return RouteDataSetReq(lobby_id, key, value)


@dataclass
class RoutingChatEvent:
    status: int
    lobby_id: str
    player_id: str
    message: str

    def encode(self) -> bytes:
        return encode_titan_message(MSG_ROUTING_CHAT_EVENT, self.status, _pack_fields((self.lobby_id, self.player_id, self.message)))


@dataclass
class RoutingDataObjectReply:
    status: int
    key: str
    value: str

    def encode(self) -> bytes:
        return encode_titan_message(MSG_ROUTING_DATA_OBJECT_REPLY, self.status, _pack_fields((self.key, self.value)))

    @staticmethod
    def decode(payload: bytes, status: int) -> "RoutingDataObjectReply":
        key, value = _unpack_fields(payload, 2)
        return RoutingDataObjectReply(status, key, value)


@dataclass
class RoutingStatusReply:
    status: int
    detail: str

    def encode(self) -> bytes:
        return encode_titan_message(MSG_ROUTING_STATUS_REPLY, self.status, _pack_fields((self.detail,)))

    @staticmethod
    def decode(payload: bytes, status: int) -> "RoutingStatusReply":
        (detail,) = _unpack_fields(payload, 1)
        return RoutingStatusReply(status, detail)


def decode_request(packet: bytes) -> Dict[str, object]:
    msg_type, _, payload = decode_titan_message(packet)
    if msg_type == MSG_AUTH_LOGIN_REQ:
        r = AuthLoginReq.decode(payload)
        return {"kind": "auth_login", "username": r.username, "password": r.password}
    if msg_type == MSG_DIR_GET_REQ:
        r = DirGetReq.decode(payload)
        return {"kind": "dir_get", "path": r.path}
    if msg_type == MSG_ROUTE_REGISTER_REQ:
        r = RouteRegisterReq.decode(payload)
        return {"kind": "route_register", "lobby_id": r.lobby_id, "player_id": r.player_id}
    if msg_type == MSG_ROUTE_JOIN_REQ:
        r = RouteJoinReq.decode(payload)
        return {"kind": "route_join", "lobby_id": r.lobby_id, "player_id": r.player_id}
    if msg_type == MSG_ROUTE_CHAT_REQ:
        r = RouteChatReq.decode(payload)
        return {"kind": "route_chat", "lobby_id": r.lobby_id, "player_id": r.player_id, "message": r.message}
    if msg_type == MSG_ROUTE_DATA_SET_REQ:
        r = RouteDataSetReq.decode(payload)
        return {"kind": "route_data_set", "lobby_id": r.lobby_id, "key": r.key, "value": r.value}
    return {"kind": "unknown", "msg_type": msg_type}
