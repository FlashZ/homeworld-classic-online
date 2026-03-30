import asyncio
from pathlib import Path
import struct

from cryptography.hazmat.primitives.asymmetric import dsa
from gateway.protocol import _parse_auth1_certificate
from product_profile import CATACLYSM_PRODUCT_PROFILE, HOMEWORLD_PRODUCT_PROFILE
import titan_binary_gateway
import won_crypto
import won_server


def _pack_pw_string(value: str) -> bytes:
    encoded = value.encode("utf-16-le")
    return struct.pack("<H", len(value)) + encoded


def _pack_raw_buf(data: bytes) -> bytes:
    payload = bytes(data or b"")
    return struct.pack("<H", len(payload)) + payload


def _write_test_keys(keys_dir: Path) -> Path:
    keys_dir.mkdir(parents=True, exist_ok=True)
    params = dsa.generate_parameters(key_size=1024)
    pn = params.parameter_numbers()
    p, q, g = pn.p, pn.q, pn.g

    verifier = params.generate_private_key().private_numbers()
    auth = params.generate_private_key().private_numbers()

    ver_y = verifier.public_numbers.y
    auth_y = auth.public_numbers.y

    ver_pub_der = won_crypto.encode_public_key(p, q, g, ver_y)
    ver_priv_der = won_crypto.encode_private_key(p, q, g, ver_y, verifier.x)
    auth_pub_der = won_crypto.encode_public_key(p, q, g, auth_y)
    auth_priv_der = won_crypto.encode_private_key(p, q, g, auth_y, auth.x)

    (keys_dir / "verifier_public.der").write_bytes(ver_pub_der)
    (keys_dir / "verifier_private.der").write_bytes(ver_priv_der)
    (keys_dir / "authserver_public.der").write_bytes(auth_pub_der)
    (keys_dir / "authserver_private.der").write_bytes(auth_priv_der)
    (keys_dir / "kver.kp").write_bytes(ver_pub_der)
    return keys_dir


def _build_auth1_login_request(
    runtime: titan_binary_gateway.BinaryGatewayServer,
    *,
    username: str,
    password: str,
    community_name: str,
    cd_key_raw: bytes,
    login_key_raw: bytes,
) -> tuple[bytes, bytes]:
    session_key = b"sekey123"
    clear = (
        struct.pack("<HBB", 1, 1, 1)
        + _pack_pw_string(username)
        + _pack_pw_string(community_name)
        + _pack_pw_string("")
        + _pack_pw_string(password)
        + _pack_pw_string("")
        + _pack_raw_buf(cd_key_raw)
        + _pack_raw_buf(login_key_raw)
    )
    eg_ciphertext = won_crypto.eg_encrypt(
        session_key,
        runtime._auth_p,
        runtime._auth_g,
        runtime._auth_y,
    )
    body = struct.pack("<H", 1)
    body += struct.pack("<H", len(eg_ciphertext))
    body += eg_ciphertext
    body += won_crypto.bf_encrypt(clear, session_key)
    return won_crypto.build_tmessage(
        won_crypto.AUTH1_SERVICE_TYPE,
        won_crypto.AUTH1_LOGIN_REQUEST_HW,
        body,
    ), session_key


async def _recv_tmessage(reader: asyncio.StreamReader) -> bytes:
    header = await reader.readexactly(4)
    total_len, = struct.unpack("<I", header)
    return await reader.readexactly(total_len - 4)


def _parse_login_reply_cert(reply_body: bytes) -> dict[str, object]:
    status, = struct.unpack("<H", reply_body[:2])
    assert status == 0
    assert reply_body[3] >= 1
    offset = 4
    entry_type = reply_body[offset]
    offset += 1
    assert entry_type == 1
    cert_len, = struct.unpack("<H", reply_body[offset:offset + 2])
    offset += 2
    cert = reply_body[offset:offset + cert_len]
    return _parse_auth1_certificate(cert)


async def _perform_native_login(
    runtime: titan_binary_gateway.BinaryGatewayServer,
    *,
    gateway_port: int,
    username: str,
    password: str,
    community_name: str,
    login_key_raw: bytes,
) -> int:
    cd_key_raw = won_crypto.generate_cd_key(community_name)["raw_key"]
    request, _session_key = _build_auth1_login_request(
        runtime,
        username=username,
        password=password,
        community_name=community_name,
        cd_key_raw=cd_key_raw,
        login_key_raw=login_key_raw,
    )
    reader, writer = await asyncio.open_connection("127.0.0.1", gateway_port)
    try:
        writer.write(request)
        await writer.drain()

        challenge = await _recv_tmessage(reader)
        challenge_service, challenge_type, _challenge_body = won_crypto.parse_tmessage(challenge)
        assert challenge_service == won_crypto.AUTH1_SERVICE_TYPE
        assert challenge_type == won_crypto.AUTH1_LOGIN_CHALLENGE_HW

        writer.write(
            won_crypto.build_tmessage(
                won_crypto.AUTH1_SERVICE_TYPE,
                won_crypto.AUTH1_LOGIN_CONFIRM_HW,
                b"",
            )
        )
        await writer.drain()

        reply = await _recv_tmessage(reader)
        reply_service, reply_type, reply_body = won_crypto.parse_tmessage(reply)
        assert reply_service == won_crypto.AUTH1_SERVICE_TYPE
        assert reply_type == won_crypto.AUTH1_LOGIN_REPLY
        cert = _parse_login_reply_cert(reply_body)
        return int(cert["user_id"])
    finally:
        writer.close()
        await writer.wait_closed()


def test_shared_edge_native_auth_routes_homeworld_and_cataclysm_over_one_gateway(
    tmp_path: Path,
) -> None:
    async def _run() -> None:
        keys_dir = _write_test_keys(tmp_path / "keys")
        home_backend, _home_state, home_store = await won_server.run_server(
            host="127.0.0.1",
            port=0,
            timeout_s=45,
            db_path=str(tmp_path / "homeworld.db"),
            product_profile=HOMEWORLD_PRODUCT_PROFILE,
        )
        cat_backend, _cat_state, cat_store = await won_server.run_server(
            host="127.0.0.1",
            port=0,
            timeout_s=45,
            db_path=str(tmp_path / "cataclysm.db"),
            product_profile=CATACLYSM_PRODUCT_PROFILE,
        )
        home_port = int(home_backend.sockets[0].getsockname()[1])
        cat_port = int(cat_backend.sockets[0].getsockname()[1])

        home_runtime = titan_binary_gateway.BinaryGatewayServer(
            "127.0.0.1",
            home_port,
            public_host="127.0.0.1",
            public_port=15101,
            routing_port=15100,
            routing_max_port=15109,
            keys_dir=str(keys_dir),
            product_profile=HOMEWORLD_PRODUCT_PROFILE,
            user_id_start=1000,
            peer_session_id_min=1,
            peer_session_id_max=32767,
        )
        cat_runtime = titan_binary_gateway.BinaryGatewayServer(
            "127.0.0.1",
            cat_port,
            public_host="127.0.0.1",
            public_port=15101,
            routing_port=15110,
            routing_max_port=15120,
            keys_dir=str(keys_dir),
            product_profile=CATACLYSM_PRODUCT_PROFILE,
            user_id_start=1_000_000,
            peer_session_id_min=32768,
            peer_session_id_max=titan_binary_gateway.MAX_PEER_SESSION_ID,
        )
        shared = titan_binary_gateway.SharedBinaryGatewayServer(
            {
                "homeworld": home_runtime,
                "cataclysm": cat_runtime,
            }
        )
        gateway_server = await asyncio.start_server(shared.handle_client, "127.0.0.1", 0)
        gateway_port = int(gateway_server.sockets[0].getsockname()[1])

        try:
            home_user_id = await _perform_native_login(
                home_runtime,
                gateway_port=gateway_port,
                username="HomeUser",
                password="pw-home",
                community_name="Homeworld",
                login_key_raw=b"hw-log01",
            )
            cat_user_id = await _perform_native_login(
                cat_runtime,
                gateway_port=gateway_port,
                username="CatUser",
                password="pw-cat",
                community_name="Cataclysm",
                login_key_raw=b"ct-log01",
            )

            assert home_user_id in home_runtime._issued_user_ids
            assert home_user_id not in cat_runtime._issued_user_ids
            assert cat_user_id in cat_runtime._issued_user_ids
            assert cat_user_id not in home_runtime._issued_user_ids
            assert home_user_id < 1_000_000
            assert cat_user_id >= 1_000_000
            assert shared._runtime_for_user_id(home_user_id) is home_runtime
            assert shared._runtime_for_user_id(cat_user_id) is cat_runtime
        finally:
            gateway_server.close()
            await gateway_server.wait_closed()
            home_backend.close()
            cat_backend.close()
            await home_backend.wait_closed()
            await cat_backend.wait_closed()
            home_store.close()
            cat_store.close()

    asyncio.run(_run())
