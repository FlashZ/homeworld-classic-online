from __future__ import annotations

import asyncio
import json

from product_profile import HOMEWORLD_PRODUCT_PROFILE
import won_server


async def _send_request(
    writer: asyncio.StreamWriter,
    reader: asyncio.StreamReader,
    payload: dict[str, object],
) -> dict[str, object]:
    writer.write((json.dumps(payload) + "\n").encode("utf-8"))
    await writer.drain()
    raw = await reader.readline()
    assert raw, "expected JSON response line from backend"
    decoded = json.loads(raw.decode("utf-8"))
    assert isinstance(decoded, dict)
    return decoded


def test_backend_json_auth_and_lobby_flow_over_tcp(tmp_path) -> None:
    async def _run() -> None:
        db_path = tmp_path / "backend_integration.db"
        server, _state, store = await won_server.run_server(
            host="127.0.0.1",
            port=0,
            timeout_s=45,
            db_path=str(db_path),
            product_profile=HOMEWORLD_PRODUCT_PROFILE,
        )
        port = int(server.sockets[0].getsockname()[1])

        owner_writer: asyncio.StreamWriter | None = None
        owner_reader: asyncio.StreamReader | None = None
        guest_writer: asyncio.StreamWriter | None = None
        guest_reader: asyncio.StreamReader | None = None

        try:
            owner_reader, owner_writer = await asyncio.open_connection("127.0.0.1", port)
            guest_reader, guest_writer = await asyncio.open_connection("127.0.0.1", port)

            owner_auth = await _send_request(
                owner_writer,
                owner_reader,
                {
                    "action": "AUTH_LOGIN",
                    "username": "owner",
                    "password": "pw-owner",
                },
            )
            assert owner_auth["ok"] is True
            owner_token = str(owner_auth["token"])

            owner_player = await _send_request(
                owner_writer,
                owner_reader,
                {
                    "action": "REGISTER_PLAYER",
                    "player_id": "p1",
                    "nickname": "Owner",
                    "regions": ["na"],
                },
            )
            assert owner_player["ok"] is True
            assert owner_player["player"]["nickname"] == "Owner"

            create_lobby = await _send_request(
                owner_writer,
                owner_reader,
                {
                    "action": "CREATE_LOBBY",
                    "token": owner_token,
                    "owner_id": "p1",
                    "name": "Integration Lobby",
                    "map_name": "Garden",
                    "max_players": 4,
                    "region": "na",
                },
            )
            assert create_lobby["ok"] is True
            lobby = create_lobby["lobby"]
            assert lobby["name"] == "Integration Lobby"
            assert lobby["players"] == ["p1"]

            guest_auth = await _send_request(
                guest_writer,
                guest_reader,
                {
                    "action": "AUTH_LOGIN",
                    "username": "guest",
                    "password": "pw-guest",
                },
            )
            assert guest_auth["ok"] is True

            guest_player = await _send_request(
                guest_writer,
                guest_reader,
                {
                    "action": "REGISTER_PLAYER",
                    "player_id": "p2",
                    "nickname": "Guest",
                    "regions": ["na"],
                },
            )
            assert guest_player["ok"] is True

            join_lobby = await _send_request(
                guest_writer,
                guest_reader,
                {
                    "action": "JOIN_LOBBY",
                    "lobby_id": str(lobby["lobby_id"]),
                    "player_id": "p2",
                },
            )
            assert join_lobby["ok"] is True
            assert join_lobby["lobby"]["players"] == ["p1", "p2"]

            listed = await _send_request(
                owner_writer,
                owner_reader,
                {
                    "action": "LIST_LOBBIES",
                    "region": "na",
                },
            )
            assert listed["ok"] is True
            assert len(listed["lobbies"]) == 1
            assert listed["lobbies"][0]["lobby_id"] == lobby["lobby_id"]
            assert listed["lobbies"][0]["players"] == ["p1", "p2"]
        finally:
            for writer in (owner_writer, guest_writer):
                if writer is None:
                    continue
                writer.close()
                await writer.wait_closed()
            server.close()
            await server.wait_closed()
            store.close()

    asyncio.run(_run())
