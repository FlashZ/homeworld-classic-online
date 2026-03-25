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
