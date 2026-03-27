from __future__ import annotations

import struct

import pytest

import won_crypto


NR_P = 23
NR_Q = 11
NR_G = 4
NR_X = 3
NR_Y = pow(NR_G, NR_X, NR_P)

# 2**127 - 1 is a Mersenne prime, which keeps the ElGamal round-trip test fast
# while still exercising multi-byte block handling.
ELG_P = 170141183460469231731687303715884105727
ELG_G = 3
ELG_X = 123456789
ELG_Y = pow(ELG_G, ELG_X, ELG_P)

PUBLIC_KEY_PARAMS = (NR_P, NR_Q, NR_G, NR_Y)
PRIVATE_KEY_PARAMS = (NR_P, NR_Q, NR_G, NR_Y, NR_X)

KNOWN_HOMEWORLD_DISPLAY_KEY = "NYX7-ZEC9-FYZ6-GUX8-4253"
KNOWN_HOMEWORLD_ENCRYPTED_KEY = bytes(
    [0xFB, 0x0F, 0x77, 0xC4, 0x80, 0x3F, 0x65, 0xDB, 0xBB, 0xA6, 0x6A, 0x4D, 0x4E, 0x2C, 0xB6, 0x17]
)
KNOWN_CATACLYSM_DISPLAY_KEY = "GAF6-CAB4-SEX5-ZYL6-2622"
KNOWN_CATACLYSM_ENCRYPTED_KEY = bytes(
    [0x85, 0x05, 0xE4, 0x99, 0xD8, 0xC1, 0x80, 0x62, 0x31, 0x8D, 0xA4, 0x99, 0x90, 0xD8, 0x69, 0x8E]
)


def test_public_key_der_round_trip() -> None:
    key_der = won_crypto.encode_public_key(*PUBLIC_KEY_PARAMS)
    assert won_crypto.decode_public_key(key_der) == PUBLIC_KEY_PARAMS


def test_private_key_der_round_trip() -> None:
    key_der = won_crypto.encode_private_key(*PRIVATE_KEY_PARAMS)
    assert won_crypto.decode_private_key(key_der) == PRIVATE_KEY_PARAMS


def test_nr_md5_sign_and_verify_round_trip() -> None:
    message = b"homeworld-auth1-handshake"
    signature = won_crypto.nr_md5_sign(message, NR_P, NR_Q, NR_G, NR_X)
    assert won_crypto.nr_md5_verify(message, signature, NR_P, NR_Q, NR_G, NR_Y)


def test_nr_md5_verify_rejects_tampered_message_and_short_signature() -> None:
    message = b"routing-room-state"
    signature = won_crypto.nr_md5_sign(message, NR_P, NR_Q, NR_G, NR_X)
    assert not won_crypto.nr_md5_verify(message + b"!", signature, NR_P, NR_Q, NR_G, NR_Y)
    assert not won_crypto.nr_md5_verify(message, signature[:-1], NR_P, NR_Q, NR_G, NR_Y)


@pytest.mark.parametrize(
    "plaintext",
    [
        b"",
        b"HW1",
        b"A" * 320,
    ],
)
def test_elgamal_encrypt_decrypt_round_trip(plaintext: bytes) -> None:
    ciphertext = won_crypto.eg_encrypt(plaintext, ELG_P, ELG_G, ELG_Y)
    assert won_crypto.eg_decrypt(ciphertext, ELG_P, ELG_G, ELG_X) == plaintext


def test_tmessage_build_and_parse_round_trip() -> None:
    body = b"\x01\x02Titan\x00payload"
    frame = won_crypto.build_tmessage(201, won_crypto.AUTH1_LOGIN_REQUEST_HW, body)
    total_size, = struct.unpack("<I", frame[:4])
    assert total_size == len(frame)
    service_type, message_type, parsed_body = won_crypto.parse_tmessage(frame[4:])
    assert service_type == 201
    assert message_type == won_crypto.AUTH1_LOGIN_REQUEST_HW
    assert parsed_body == body


def test_parse_tmessage_rejects_short_body() -> None:
    with pytest.raises(ValueError, match="too short"):
        won_crypto.parse_tmessage(b"\x00" * 7)


def test_public_and_private_key_params_match() -> None:
    assert PRIVATE_KEY_PARAMS[:4] == PUBLIC_KEY_PARAMS


def test_parse_auth1_login_payload_round_trip() -> None:
    session_key = b"HWLOGIN!"

    def _pw(text: str) -> bytes:
        return struct.pack("<H", len(text)) + text.encode("utf-16-le")

    def _raw(text: str) -> bytes:
        encoded = text.encode("ascii")
        return struct.pack("<H", len(encoded)) + encoded

    clear = (
        struct.pack("<HBB", 7, 1, 1)
        + _pw("FleetCommand")
        + _pw("Sierra")
        + _pw("Pilot Nick")
        + _pw("secret")
        + _pw("new-secret")
        + _raw("GAF6CAB4SEX5ZYL62622")
        + _raw("native-login-token")
    )
    encrypted = won_crypto.bf_encrypt(clear, session_key)

    parsed = won_crypto.parse_auth1_login_payload(encrypted, session_key)

    assert parsed["block_id"] == 7
    assert parsed["need_key"] is True
    assert parsed["create_account"] is True
    assert parsed["username"] == "FleetCommand"
    assert parsed["community_name"] == "Sierra"
    assert parsed["nickname_key"] == "Pilot Nick"
    assert parsed["password"] == "secret"
    assert parsed["new_password"] == "new-secret"
    assert parsed["cd_key"] == "GAF6CAB4SEX5ZYL62622"
    assert parsed["login_key"] == "native-login-token"


def test_homeworld_cd_key_known_pair_round_trip() -> None:
    assert won_crypto.validate_cd_key(won_crypto.CDKEY_PRODUCT_HOMEWORLD, KNOWN_HOMEWORLD_DISPLAY_KEY)
    assert (
        won_crypto.encrypt_cd_key_for_registry(
            won_crypto.CDKEY_PRODUCT_HOMEWORLD,
            KNOWN_HOMEWORLD_DISPLAY_KEY,
        )
        == KNOWN_HOMEWORLD_ENCRYPTED_KEY
    )

    decoded = won_crypto.decrypt_cd_key_from_registry(
        won_crypto.CDKEY_PRODUCT_HOMEWORLD,
        KNOWN_HOMEWORLD_ENCRYPTED_KEY,
    )

    assert decoded["display_key"] == KNOWN_HOMEWORLD_DISPLAY_KEY
    assert decoded["plain_key"] == "NYX7ZEC9FYZ6GUX84253"
    assert decoded["valid"] is True


def test_cataclysm_cd_key_known_pair_round_trip() -> None:
    assert won_crypto.validate_cd_key(won_crypto.CDKEY_PRODUCT_CATACLYSM, KNOWN_CATACLYSM_DISPLAY_KEY)
    assert (
        won_crypto.encrypt_cd_key_for_registry(
            won_crypto.CDKEY_PRODUCT_CATACLYSM,
            KNOWN_CATACLYSM_DISPLAY_KEY,
        )
        == KNOWN_CATACLYSM_ENCRYPTED_KEY
    )

    decoded = won_crypto.decrypt_cd_key_from_registry(
        won_crypto.CDKEY_PRODUCT_CATACLYSM,
        KNOWN_CATACLYSM_ENCRYPTED_KEY,
    )

    assert decoded["display_key"] == KNOWN_CATACLYSM_DISPLAY_KEY
    assert decoded["plain_key"] == "GAF6CAB4SEX5ZYL62622"
    assert decoded["valid"] is True


@pytest.mark.parametrize(
    "product",
    [
        won_crypto.CDKEY_PRODUCT_HOMEWORLD,
        won_crypto.CDKEY_PRODUCT_CATACLYSM,
    ],
)
def test_generate_cd_key_round_trip(product: str) -> None:
    generated = won_crypto.generate_cd_key(product)

    assert won_crypto.validate_cd_key(product, generated["display_key"])
    assert generated["plain_key"] == generated["display_key"].replace("-", "")

    decoded = won_crypto.decrypt_cd_key_from_registry(product, generated["encrypted_key"])
    assert decoded["display_key"] == generated["display_key"]
    assert decoded["valid"] is True
