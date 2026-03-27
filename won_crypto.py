#!/usr/bin/env python3
"""WON/Titan cryptographic primitives for the Homeworld 1 auth server.

Implements:
  - Standard DER ASN.1 encoding/decoding for DSA-style keys {p, q, g, y [,x]}
  - NR-MD5 (WON "BogusSign" / "BogusVerify") signature scheme
  - ElGamal public-key encryption in WON wire format
  - Auth1 public key block and certificate builders
  - Auth1 TMessage wire format helpers (ServiceType=201, framing, parsers)

All algorithms confirmed from WON open-source (wonapi/WONCrypt/ElGamal.cpp,
TitanApi/msg/Auth/TMsgAuth1LoginHW.cpp, TitanApi/msg/TMessage.h, etc.).

No external dependencies — pure Python stdlib only (hashlib, math, os, struct).
"""

from __future__ import annotations

import hashlib
import math
import os
import struct
import time
from typing import Tuple

MAX_K_ATTEMPTS = 1000


# ---------------------------------------------------------------------------
# DER ASN.1 helpers (standard DER, big-endian lengths)
# ---------------------------------------------------------------------------

def _der_length(n: int) -> bytes:
    """Encode a DER length value."""
    if n < 0x80:
        return bytes([n])
    elif n < 0x100:
        return bytes([0x81, n])
    elif n < 0x10000:
        return bytes([0x82, n >> 8, n & 0xFF])
    else:
        raise ValueError(f"DER length too large: {n}")


def _der_integer(value: int) -> bytes:
    """Encode a non-negative integer as a DER INTEGER (tag 0x02)."""
    if value < 0:
        raise ValueError("Negative integers not supported")
    if value == 0:
        raw = b'\x00'
    else:
        byte_len = (value.bit_length() + 7) // 8
        raw = value.to_bytes(byte_len, 'big')
        if raw[0] & 0x80:          # high bit set → prepend 0x00 to keep positive
            raw = b'\x00' + raw
    return b'\x02' + _der_length(len(raw)) + raw


def _der_sequence(contents: bytes) -> bytes:
    """Wrap bytes in a DER SEQUENCE (tag 0x30)."""
    return b'\x30' + _der_length(len(contents)) + contents


def _der_parse_length(data: bytes, offset: int) -> Tuple[int, int]:
    """Parse a DER length field at *offset*.  Returns (length, new_offset)."""
    if offset >= len(data):
        raise ValueError("truncated DER length")
    b = data[offset]
    offset += 1
    if b < 0x80:
        return b, offset
    elif b == 0x81:
        if offset >= len(data):
            raise ValueError("truncated DER length")
        return data[offset], offset + 1
    elif b == 0x82:
        if offset + 1 >= len(data):
            raise ValueError("truncated DER length")
        return (data[offset] << 8) | data[offset + 1], offset + 2
    else:
        raise ValueError(f"Unsupported DER length byte: 0x{b:02x}")


def _der_parse_sequence(data: bytes, offset: int) -> Tuple[int, int]:
    """Parse a DER SEQUENCE at *offset*. Returns (content_offset, end_offset)."""
    if offset >= len(data):
        raise ValueError("truncated DER sequence")
    if data[offset] != 0x30:
        raise ValueError(f"Expected DER SEQUENCE tag 0x30, got 0x{data[offset]:02x}")
    offset += 1
    length, offset = _der_parse_length(data, offset)
    end = offset + length
    if end > len(data):
        raise ValueError("truncated DER sequence")
    return offset, end


def _der_parse_integer(data: bytes, offset: int) -> Tuple[int, int]:
    """Parse a DER INTEGER at *offset*.  Returns (value, new_offset)."""
    if offset >= len(data):
        raise ValueError("truncated DER integer")
    if data[offset] != 0x02:
        raise ValueError(f"Expected DER INTEGER tag 0x02, got 0x{data[offset]:02x}")
    offset += 1
    length, offset = _der_parse_length(data, offset)
    if offset + length > len(data):
        raise ValueError("truncated DER integer")
    value = int.from_bytes(data[offset:offset + length], 'big')
    return value, offset + length


# ---------------------------------------------------------------------------
# Key encode / decode  (SEQUENCE { INTEGER p, q, g, y [, x] })
# ---------------------------------------------------------------------------

def encode_public_key(p: int, q: int, g: int, y: int) -> bytes:
    """Encode DSA-style public key as DER SEQUENCE { p, q, g, y }."""
    body = _der_integer(p) + _der_integer(q) + _der_integer(g) + _der_integer(y)
    return _der_sequence(body)


def encode_private_key(p: int, q: int, g: int, y: int, x: int) -> bytes:
    """Encode DSA-style private key as DER SEQUENCE { p, q, g, y, x }."""
    body = (
        _der_integer(p) + _der_integer(q) + _der_integer(g)
        + _der_integer(y) + _der_integer(x)
    )
    return _der_sequence(body)


def decode_public_key(der: bytes) -> Tuple[int, int, int, int]:
    """Decode DER SEQUENCE { p, q, g, y } into (p, q, g, y)."""
    offset, end = _der_parse_sequence(der, 0)
    p, offset = _der_parse_integer(der, offset)
    q, offset = _der_parse_integer(der, offset)
    g, offset = _der_parse_integer(der, offset)
    y, offset = _der_parse_integer(der, offset)
    if offset != end:
        raise ValueError("unexpected trailing data in DER public key")
    return p, q, g, y


def decode_private_key(der: bytes) -> Tuple[int, int, int, int, int]:
    """Decode DER SEQUENCE { p, q, g, y, x } into (p, q, g, y, x)."""
    offset, end = _der_parse_sequence(der, 0)
    p, offset = _der_parse_integer(der, offset)
    q, offset = _der_parse_integer(der, offset)
    g, offset = _der_parse_integer(der, offset)
    y, offset = _der_parse_integer(der, offset)
    x, offset = _der_parse_integer(der, offset)
    if offset != end:
        raise ValueError("unexpected trailing data in DER private key")
    return p, q, g, y, x


# ---------------------------------------------------------------------------
# NR-MD5  ("BogusSign" / "BogusVerify" from wonapi/WONCrypt/ElGamal.cpp)
#
# This is the Nyberg-Rueppel signature scheme with MD5 as the hash, matching
# Crypto++ NRSigner<MD5> / NRVerifier<MD5>.
#
# Sign:
#   m   = MD5(msg) interpreted as big-endian integer, reduced mod q
#   k   = random in [1, q-1]
#   r   = (pow(g, k, p) + m) % q
#   s   = (k - x*r) % q
#   sig = r_bytes || s_bytes   (each (q.bit_length()+7)//8 bytes wide)
#
# Verify:
#   m      = MD5(msg) mod q
#   result = (pow(g, s, p) * pow(y, r, p) % p + m) % q
#   valid  ⟺  result == r
# ---------------------------------------------------------------------------

def _nr_encode_hash(digest: bytes, q: int) -> int:
    """Convert a raw hash digest to an integer mod q (big-endian)."""
    return int.from_bytes(digest, 'big') % q


def nr_md5_sign(msg: bytes, p: int, q: int, g: int, x: int) -> bytes:
    """Sign *msg* with NR-MD5 (WON BogusSign).

    Returns a raw signature of 2 * q_bytes bytes: r_bytes || s_bytes.
    """
    q_bytes = (q.bit_length() + 7) // 8
    digest = hashlib.md5(msg).digest()
    m = _nr_encode_hash(digest, q)
    attempts = 0
    while True:
        attempts += 1
        if attempts > MAX_K_ATTEMPTS:
            raise RuntimeError("failed to find valid k")
        # k in [1, q-1]; retry on degenerate r or s
        k_raw = int.from_bytes(os.urandom(q_bytes + 4), 'big')
        k = k_raw % (q - 1) + 1
        r = (pow(g, k, p) + m) % q
        if r == 0:
            continue
        s = (k - x * r) % q
        if s == 0:
            continue
        return r.to_bytes(q_bytes, 'big') + s.to_bytes(q_bytes, 'big')


def nr_md5_verify(msg: bytes, sig: bytes, p: int, q: int, g: int, y: int) -> bool:
    """Verify an NR-MD5 signature (WON BogusVerify).

    *sig* must be 2 * q_bytes bytes: r_bytes || s_bytes.
    """
    q_bytes = (q.bit_length() + 7) // 8
    if len(sig) < 2 * q_bytes:
        return False
    r = int.from_bytes(sig[:q_bytes], 'big')
    s = int.from_bytes(sig[q_bytes:2 * q_bytes], 'big')
    digest = hashlib.md5(msg).digest()
    m = _nr_encode_hash(digest, q)
    result = (pow(g, s, p) * pow(y, r, p) % p + m) % q
    return r == result


# ---------------------------------------------------------------------------
# ElGamal encryption / decryption  (WON wire format from ElGamal.cpp)
#
# Wire format output:
#   [u32 LE num_blocks]
#   for each block:
#     a  (modulus_len bytes, big-endian)
#     b  (modulus_len bytes, big-endian)
#
# Message block layout inside M (modulus_len - 1 bytes, big-endian):
#   [zeros...][chunk (block_len bytes)][length_byte]
#   where block_len = modulus_len - 3, length_byte = actual chunk size
#
# k constraints: odd AND gcd(k, p-1) == 1
# a = g^k mod p
# b = y^k * M mod p
#
# Decrypt: m = b * inv(a^x mod p) mod p  (Fermat since p prime)
# ---------------------------------------------------------------------------

def eg_encrypt(plaintext: bytes, p: int, g: int, y: int) -> bytes:
    """Encrypt *plaintext* using WON ElGamal format.

    Output: [u32 LE num_blocks] + for each block: a || b (each modulus_len bytes).
    """
    modulus_len = (p.bit_length() + 7) // 8
    block_len = modulus_len - 3          # usable data bytes per block

    # Split plaintext into block_len-sized chunks
    if not plaintext:
        chunks: list[bytes] = [b'']
    else:
        chunks = [
            plaintext[i:i + block_len]
            for i in range(0, len(plaintext), block_len)
        ]

    out = bytearray(struct.pack('<I', len(chunks)))

    for chunk in chunks:
        this_len = len(chunk)

        # Build the M buffer: (modulus_len - 1) bytes
        #   layout: [zeros | chunk | length_byte]
        #   chunk lives at m_buf[-1-this_len : -1]
        #   length byte at m_buf[-1]
        m_buf = bytearray(modulus_len - 1)
        if this_len > 0:
            m_buf[-1 - this_len:-1] = chunk
        m_buf[-1] = this_len
        M = int.from_bytes(m_buf, 'big')

        # Generate k: odd AND gcd(k, p-1) == 1
        pm1 = p - 1
        attempts = 0
        while True:
            attempts += 1
            if attempts > MAX_K_ATTEMPTS:
                raise RuntimeError("failed to find valid k")
            k = int.from_bytes(os.urandom(modulus_len), 'big') % (p - 2) + 1
            k |= 1                         # force odd
            if math.gcd(k, pm1) == 1:
                break

        a = pow(g, k, p)
        b = pow(y, k, p) * M % p

        out += a.to_bytes(modulus_len, 'big')
        out += b.to_bytes(modulus_len, 'big')

    return bytes(out)


def eg_decrypt(ciphertext: bytes, p: int, g: int, x: int) -> bytes:
    """Decrypt a WON ElGamal ciphertext (produced by eg_encrypt or the game)."""
    modulus_len = (p.bit_length() + 7) // 8
    if len(ciphertext) < 4:
        raise ValueError("ElGamal ciphertext too short")
    num_blocks, = struct.unpack('<I', ciphertext[:4])
    offset = 4
    plaintext = bytearray()

    for _ in range(num_blocks):
        end = offset + 2 * modulus_len
        if end > len(ciphertext):
            raise ValueError("ElGamal ciphertext truncated")
        a = int.from_bytes(ciphertext[offset:offset + modulus_len], 'big')
        offset += modulus_len
        b = int.from_bytes(ciphertext[offset:offset + modulus_len], 'big')
        offset += modulus_len

        # m = b * inv(a^x mod p) mod p  — Fermat's little theorem since p is prime
        m = b * pow(pow(a, x, p), p - 2, p) % p

        m_bytes = m.to_bytes(modulus_len - 1, 'big')
        plain_len = m_bytes[-1]
        if plain_len > modulus_len - 2:
            raise ValueError(f"ElGamal decrypt: bad plain_len={plain_len}")
        plaintext += m_bytes[-1 - plain_len:-1]

    return bytes(plaintext)


# ---------------------------------------------------------------------------
# TMessage wire format helpers
#
# TMessage framing (confirmed from TMessage.h / TMessage.cpp):
#   [u32 LE total_size]           ← total_size includes these 4 bytes
#   [u32 LE service_type]         ← Auth1Login = 201 = 0xC9
#   [u32 LE message_type]
#   [body bytes...]
#
# Auth1Login ServiceType = 201 = 0xC9  (from HeaderTypes.h: Auth1Login = 201)
#
# Auth1 message type numbers (from TMsgTypesAuth.h):
#   Auth1GetPubKeys       =  1
#   Auth1GetPubKeysReply  =  2
#   Auth1LoginReply       =  4
#   Auth1LoginRequestHW   = 30
#   Auth1LoginChallengeHW = 32
#   Auth1LoginConfirmHW   = 33
# ---------------------------------------------------------------------------

AUTH1_SERVICE_TYPE        = 201   # 0xC9

AUTH1_GET_PUB_KEYS        = 1
AUTH1_GET_PUB_KEYS_REPLY  = 2
AUTH1_LOGIN_REPLY         = 4
AUTH1_LOGIN_REQUEST_HW    = 30
AUTH1_LOGIN_CHALLENGE_HW  = 32
AUTH1_LOGIN_CONFIRM_HW    = 33


def build_tmessage(service_type: int, msg_type: int, body: bytes) -> bytes:
    """Build a complete TMessage frame.

    Wire layout: [u32 LE total][u32 LE svc][u32 LE msg][body]
    total = 4 (size field) + 4 (svc) + 4 (msg) + len(body)
    """
    header = struct.pack('<II', service_type, msg_type)
    payload = header + body
    return struct.pack('<I', len(payload) + 4) + payload


def parse_tmessage(data: bytes) -> Tuple[int, int, bytes]:
    """Parse a TMessage body (the 4-byte size prefix already stripped by _titan_recv).

    Returns (service_type, msg_type, remaining_body).
    """
    if len(data) < 8:
        raise ValueError(f"TMessage body too short: {len(data)} bytes")
    service_type, msg_type = struct.unpack('<II', data[:8])
    return service_type, msg_type, data[8:]


def _pack_raw_buf(data: bytes) -> bytes:
    """PackRawBuf: [u16 LE len][data]  (TMsgAuthRawBufferBase::PackRawBuf)."""
    return struct.pack('<H', len(data)) + data


# ---------------------------------------------------------------------------
# Auth1 public key block
#
# Wire layout (unsigned portion, then NR-MD5 signature):
#   [u16 LE family=1]
#   [u32 LE issue_time]
#   [u32 LE expire_time]
#   [u16 LE block_id]
#   [u16 LE num_keys=1]
#   [u16 LE key_len]
#   [key_len bytes: DER-encoded auth server public key]
#   [2*q_bytes: NR-MD5 signature with VERIFIER private key]
# ---------------------------------------------------------------------------

def build_auth1_pubkey_block(
    auth_p: int, auth_q: int, auth_g: int, auth_y: int,
    block_id: int,
    ver_p: int, ver_q: int, ver_g: int, ver_x: int,
    issue_time: int = 0,
    expire_time: int = 0,
) -> bytes:
    """Build a signed Auth1PublicKeyBlock.

    Contains the auth server's public key signed with the verifier private key.
    The game verifies this block against kver.kp (the verifier public key file).
    """
    if issue_time == 0:
        issue_time = int(time.time())
    if expire_time == 0:
        expire_time = issue_time + 365 * 24 * 3600   # 1 year

    key_der = encode_public_key(auth_p, auth_q, auth_g, auth_y)
    # family(H) + issue_time(I) + expire_time(I) + block_id(H) + num_keys(H) + key_len(H)
    header = struct.pack('<HIIHHH', 1, issue_time, expire_time, block_id, 1, len(key_der))
    unsigned_block = header + key_der

    sig = nr_md5_sign(unsigned_block, ver_p, ver_q, ver_g, ver_x)
    return unsigned_block + sig


# ---------------------------------------------------------------------------
# Auth1 certificate
#
# Wire layout (unsigned portion, then NR-MD5 signature):
#   [u16 LE family=1]
#   [u32 LE issue_time]
#   [u32 LE expire_time]
#   [u32 LE user_id]
#   [u32 LE community_id]
#   [u16 LE trust_level]
#   [u16 LE pub_key_len]
#   [pub_key_len bytes: DER-encoded user (session) public key]
#   [2*q_bytes: NR-MD5 signature with AUTH SERVER private key]
# ---------------------------------------------------------------------------

def build_auth1_certificate(
    user_id: int,
    community_id: int,
    trust_level: int,
    user_p: int, user_q: int, user_g: int, user_y: int,
    auth_p: int, auth_q: int, auth_g: int, auth_x: int,
    issue_time: int = 0,
    expire_time: int = 0,
) -> bytes:
    """Build a signed Auth1Certificate.

    Contains an ephemeral user public key, signed with the auth server private key.
    The game verifies this certificate against the auth server's public key from
    the key block received earlier in the handshake.
    """
    if issue_time == 0:
        issue_time = int(time.time())
    if expire_time == 0:
        expire_time = issue_time + 365 * 24 * 3600

    user_key_der = encode_public_key(user_p, user_q, user_g, user_y)
    # family(H) + issue_time(I) + expire_time(I) + user_id(I) + community_id(I)
    # + trust_level(H) + key_len(H)  →  2+4+4+4+4+2+2 = 22 bytes
    header = struct.pack(
        '<HIIIIHH',
        1, issue_time, expire_time, user_id, community_id, trust_level,
        len(user_key_der),
    )
    unsigned_cert = header + user_key_der

    sig = nr_md5_sign(unsigned_cert, auth_p, auth_q, auth_g, auth_x)
    return unsigned_cert + sig


# ---------------------------------------------------------------------------
# Blowfish CBC encrypt/decrypt (WON BFSymmetricKey format)
# ---------------------------------------------------------------------------

def _get_blowfish():
    """Import Blowfish cipher from pycryptodome."""
    try:
        from Crypto.Cipher import Blowfish
        return Blowfish
    except ImportError:
        from Cryptodome.Cipher import Blowfish
        return Blowfish


def bf_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt using WON's BFSymmetricKey format.

    Wire format: Blowfish-CBC(IV=0xFF*8, [u32 LE len][plaintext][PKCS7 pad])
    """
    Blowfish = _get_blowfish()
    iv = b'\xff' * 8
    # Prepend 4-byte LE length
    data = struct.pack('<I', len(plaintext)) + plaintext
    # PKCS7 pad to Blowfish block size (8)
    pad_len = 8 - (len(data) % 8)
    if pad_len == 0:
        pad_len = 8
    data += bytes([pad_len] * pad_len)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    return cipher.encrypt(data)


def bf_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt using WON's BFSymmetricKey format.

    Returns the original plaintext (strips length prefix and padding).
    """
    Blowfish = _get_blowfish()
    iv = b'\xff' * 8
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    # First 4 bytes = LE u32 original length
    if len(decrypted) < 4:
        raise ValueError("BF decrypt: too short")
    orig_len = struct.unpack('<I', decrypted[:4])[0]
    if orig_len > len(decrypted) - 4:
        raise ValueError(f"BF decrypt: length {orig_len} exceeds data")
    return decrypted[4:4 + orig_len]


# ---------------------------------------------------------------------------
# Retail client CD-key encode/decode helpers
#
# Ported from Homeworld's ClientCDKey.cpp and CRC16.cpp. This is the actual
# retail key format used for both the human-readable 20-character key and the
# 16-byte WON registry value.
# ---------------------------------------------------------------------------

CDKEY_PRODUCT_HOMEWORLD = "Homeworld"
CDKEY_PRODUCT_CATACLYSM = "Cataclysm"

_CDKEY_STRING_MAP = "CVCNCVCNCVCNCVCNNNNN"
_CDKEY_C_CHARS = "BCDFGJLMNPRSTWXZ"
_CDKEY_V_CHARS = "AEUY"
_CDKEY_SKIP_CHARS = {"-", " ", "\t", "\r", "\n", "\0"}
_CDKEY_BINARY_LEN = 16

_CRC16_TABLE = (
    0x0000, 0x8005, 0x800F, 0x000A, 0x801B, 0x001E, 0x0014, 0x8011,
    0x8033, 0x0036, 0x003C, 0x8039, 0x0028, 0x802D, 0x8027, 0x0022,
    0x8063, 0x0066, 0x006C, 0x8069, 0x0078, 0x807D, 0x8077, 0x0072,
    0x0050, 0x8055, 0x805F, 0x005A, 0x804B, 0x004E, 0x0044, 0x8041,
    0x80C3, 0x00C6, 0x00CC, 0x80C9, 0x00D8, 0x80DD, 0x80D7, 0x00D2,
    0x00F0, 0x80F5, 0x80FF, 0x00FA, 0x80EB, 0x00EE, 0x00E4, 0x80E1,
    0x00A0, 0x80A5, 0x80AF, 0x00AA, 0x80BB, 0x00BE, 0x00B4, 0x80B1,
    0x8093, 0x0096, 0x009C, 0x8099, 0x0088, 0x808D, 0x8087, 0x0082,
    0x8183, 0x0186, 0x018C, 0x8189, 0x0198, 0x819D, 0x8197, 0x0192,
    0x01B0, 0x81B5, 0x81BF, 0x01BA, 0x81AB, 0x01AE, 0x01A4, 0x81A1,
    0x01E0, 0x81E5, 0x81EF, 0x01EA, 0x81FB, 0x01FE, 0x01F4, 0x81F1,
    0x81D3, 0x01D6, 0x01DC, 0x81D9, 0x01C8, 0x81CD, 0x81C7, 0x01C2,
    0x0140, 0x8145, 0x814F, 0x014A, 0x815B, 0x015E, 0x0154, 0x8151,
    0x8173, 0x0176, 0x017C, 0x8179, 0x0168, 0x816D, 0x8167, 0x0162,
    0x8123, 0x0126, 0x012C, 0x8129, 0x0138, 0x813D, 0x8137, 0x0132,
    0x0110, 0x8115, 0x811F, 0x011A, 0x810B, 0x010E, 0x0104, 0x8101,
    0x8303, 0x0306, 0x030C, 0x8309, 0x0318, 0x831D, 0x8317, 0x0312,
    0x0330, 0x8335, 0x833F, 0x033A, 0x832B, 0x032E, 0x0324, 0x8321,
    0x0360, 0x8365, 0x836F, 0x036A, 0x837B, 0x037E, 0x0374, 0x8371,
    0x8353, 0x0356, 0x035C, 0x8359, 0x0348, 0x834D, 0x8347, 0x0342,
    0x03C0, 0x83C5, 0x83CF, 0x03CA, 0x83DB, 0x03DE, 0x03D4, 0x83D1,
    0x83F3, 0x03F6, 0x03FC, 0x83F9, 0x03E8, 0x83ED, 0x83E7, 0x03E2,
    0x83A3, 0x03A6, 0x03AC, 0x83A9, 0x03B8, 0x83BD, 0x83B7, 0x03B2,
    0x0390, 0x8395, 0x839F, 0x039A, 0x838B, 0x038E, 0x0384, 0x8381,
    0x0280, 0x8285, 0x828F, 0x028A, 0x829B, 0x029E, 0x0294, 0x8291,
    0x82B3, 0x02B6, 0x02BC, 0x82B9, 0x02A8, 0x82AD, 0x82A7, 0x02A2,
    0x82E3, 0x02E6, 0x02EC, 0x82E9, 0x02F8, 0x82FD, 0x82F7, 0x02F2,
    0x02D0, 0x82D5, 0x82DF, 0x02DA, 0x82CB, 0x02CE, 0x02C4, 0x82C1,
    0x8243, 0x0246, 0x024C, 0x8249, 0x0258, 0x825D, 0x8257, 0x0252,
    0x0270, 0x8275, 0x827F, 0x027A, 0x826B, 0x026E, 0x0264, 0x8261,
    0x0220, 0x8225, 0x822F, 0x022A, 0x823B, 0x023E, 0x0234, 0x8231,
    0x8213, 0x0216, 0x021C, 0x8219, 0x0208, 0x820D, 0x8207, 0x0202,
)


def crc16_won(data: bytes, init_value: int = 0, xor_out_value: int = 0) -> int:
    """Compute the WON CRC16 used by retail CD-key code."""
    register = init_value & 0xFFFF
    for byte in data:
        register = _CRC16_TABLE[((register >> 8) ^ byte) & 0xFF] ^ ((register << 8) & 0xFFFF)
    return (register ^ xor_out_value) & 0xFFFF


def _normalize_cd_key_text(value: str) -> str:
    return "".join(ch for ch in value.upper() if ch not in _CDKEY_SKIP_CHARS)


def _derive_cd_key_symmetric_key(product: str) -> bytes:
    """Match ClientCDKey::CreateSymmetricKey."""
    product_bytes = product.encode("ascii")
    rolling = product_bytes
    checksums = [crc16_won(rolling)]
    for byte in product_bytes[:3]:
        rolling += bytes([byte])
        checksums.append(crc16_won(rolling))
    return b"".join(struct.pack("<H", checksum) for checksum in checksums)


def _light_validity_check(product: str, key_bytes: bytes) -> int:
    checksum = crc16_won(product.encode("ascii") + key_bytes)
    return (checksum & 0x0FFF) >> 4


def _pack_cd_key_raw(key_bytes: bytes, light_check: int) -> bytes:
    if len(key_bytes) != 7:
        raise ValueError("cd_key_key_bytes_len")
    return key_bytes[:3] + bytes([light_check & 0xFF]) + key_bytes[3:]


def _unpack_cd_key_raw(raw: bytes) -> Tuple[bytes, int]:
    if len(raw) != 8:
        raise ValueError("cd_key_raw_len")
    return raw[:3] + raw[4:], raw[3]


def cd_key_to_display(raw: bytes) -> str:
    """Convert an 8-byte raw retail CD-key buffer to display form."""
    if len(raw) != 8:
        raise ValueError("cd_key_raw_len")
    buf = int.from_bytes(raw, "little")
    offset = 0
    chars = []

    for token in _CDKEY_STRING_MAP:
        if token == "C":
            chars.append(_CDKEY_C_CHARS[(buf >> offset) & 0x0F])
            offset += 4
        elif token == "V":
            chars.append(_CDKEY_V_CHARS[(buf >> offset) & 0x03])
            offset += 2
        elif token == "N":
            chars.append(chr(((buf >> offset) & 0x07) + ord("2")))
            offset += 3
        else:
            raise ValueError("cd_key_unknown_map_token")

    return "-".join("".join(chars[i:i + 4]) for i in range(0, len(chars), 4))


def cd_key_from_display(display_key: str) -> bytes:
    """Parse a retail display/plain CD-key into the raw 8-byte buffer."""
    normalized = _normalize_cd_key_text(display_key)
    if len(normalized) != len(_CDKEY_STRING_MAP):
        raise ValueError("cd_key_length")

    buf = 0
    offset = 0
    for token, char in zip(_CDKEY_STRING_MAP, normalized):
        if token == "C":
            value = _CDKEY_C_CHARS.find(char)
            if value < 0:
                raise ValueError("cd_key_invalid_c")
            buf |= value << offset
            offset += 4
        elif token == "V":
            value = _CDKEY_V_CHARS.find(char)
            if value < 0:
                raise ValueError("cd_key_invalid_v")
            buf |= value << offset
            offset += 2
        elif token == "N":
            if char < "2" or char > "9":
                raise ValueError("cd_key_invalid_n")
            buf |= (ord(char) - ord("2")) << offset
            offset += 3
        else:
            raise ValueError("cd_key_unknown_map_token")

    return buf.to_bytes(8, "little")


def validate_cd_key(product: str, display_key: str) -> bool:
    """Check whether a retail Homeworld-family CD key passes the client checksum."""
    try:
        raw = cd_key_from_display(display_key)
    except ValueError:
        return False
    key_bytes, light_check = _unpack_cd_key_raw(raw)
    return _light_validity_check(product, key_bytes) == light_check


def encrypt_cd_key_for_registry(product: str, display_key: str) -> bytes:
    """Convert a retail display/plain CD key to the 16-byte WON registry blob."""
    raw = cd_key_from_display(display_key)
    key_bytes, light_check = _unpack_cd_key_raw(raw)
    if _light_validity_check(product, key_bytes) != light_check:
        raise ValueError("invalid_cd_key")
    return bf_encrypt(raw, _derive_cd_key_symmetric_key(product))


def decrypt_cd_key_from_registry(product: str, encrypted_key: bytes) -> dict:
    """Decode a WON registry CD-key value back to display/plain form."""
    if len(encrypted_key) != _CDKEY_BINARY_LEN:
        raise ValueError("cd_key_encrypted_len")
    raw = bf_decrypt(encrypted_key, _derive_cd_key_symmetric_key(product))
    if len(raw) != 8:
        raise ValueError("cd_key_decrypted_raw_len")
    key_bytes, light_check = _unpack_cd_key_raw(raw)
    display_key = cd_key_to_display(raw)
    return {
        "display_key": display_key,
        "plain_key": _normalize_cd_key_text(display_key),
        "raw_key": raw,
        "key_bytes": key_bytes,
        "light_check": light_check,
        "valid": _light_validity_check(product, key_bytes) == light_check,
    }


def generate_cd_key(product: str, *, beta: bool = False) -> dict:
    """Generate a new retail-compatible Homeworld-family CD key."""
    key_bytes = bytearray(os.urandom(7))
    if beta:
        key_bytes[0] |= 0x01
    else:
        key_bytes[0] &= 0xFE

    light_check = _light_validity_check(product, bytes(key_bytes))
    raw = _pack_cd_key_raw(bytes(key_bytes), light_check)
    display_key = cd_key_to_display(raw)
    return {
        "display_key": display_key,
        "plain_key": _normalize_cd_key_text(display_key),
        "encrypted_key": bf_encrypt(raw, _derive_cd_key_symmetric_key(product)),
        "raw_key": raw,
        "beta": bool(key_bytes[0] & 0x01),
    }


# ---------------------------------------------------------------------------
# Auth1 TMessage builders (complete framed packets ready to send)
# ---------------------------------------------------------------------------

def build_auth1_pubkeys_reply(key_block: bytes) -> bytes:
    """Build Auth1GetPubKeysReply TMessage.

    Body: [u16 LE status=0][u16 LE raw_len][key_block bytes]
    (TMsgAuth1GetPubKeys::Pack)
    """
    body = struct.pack('<HH', 0, len(key_block)) + key_block
    return build_tmessage(AUTH1_SERVICE_TYPE, AUTH1_GET_PUB_KEYS_REPLY, body)


def build_auth1_challenge(challenge_seed: bytes, session_key: bytes) -> bytes:
    """Build Auth1LoginChallengeHW TMessage.

    The 16-byte challenge seed is encrypted with the session key (Blowfish CBC)
    before being packed into the message.

    Body: PackRawBuf(bf_encrypt(challenge_seed, session_key))
    """
    encrypted = bf_encrypt(challenge_seed, session_key)
    body = _pack_raw_buf(encrypted)
    return build_tmessage(AUTH1_SERVICE_TYPE, AUTH1_LOGIN_CHALLENGE_HW, body)


def build_auth1_login_reply(cert: bytes) -> bytes:
    """Build Auth1LoginReply TMessage.

    Body layout (from TMsgAuth1LoginBase::Pack):
      [u16 LE status=0]
      [u8  error_count=0]
      [u8  num_clear_entries=1]
      [u8  entry_type=1  (ALCertificate)]
      [u16 LE cert_len]
      [cert bytes]
    """
    body = (
        struct.pack('<H', 0)               # status = Success
        + bytes([0, 1, 1])                 # error_count=0, num_clear=1, type=ALCert=1
        + struct.pack('<H', len(cert))
        + cert
    )
    return build_tmessage(AUTH1_SERVICE_TYPE, AUTH1_LOGIN_REPLY, body)


# ---------------------------------------------------------------------------
# Auth1 LoginRequestHW parser
# ---------------------------------------------------------------------------

def parse_auth1_login_request(body: bytes) -> dict:
    """Parse the body of an Auth1LoginRequestHW message (after 8-byte TMessage header).

    Returns a dict with:
      block_id        – u16: which key block was used to encrypt the session key
      eg_ciphertext   – bytes: ElGamal-encrypted session key (WON format)
      bf_data         – bytes: Blowfish-encrypted login data (may be empty)

    Login data (after Blowfish decrypt with session key):
      [u16 blockId][u8 needKeyFlg][u8 createAcctFlg]
      [wstr userName][wstr communityName][wstr nicknameKey]
      [wstr password][wstr newPassword]
      [u16 cdKeyLen][cdKey][u16 loginKeyLen][loginKey]
    """
    offset = 0
    if len(body) < 4:
        return {'block_id': 0, 'eg_ciphertext': b'', 'bf_data': b''}

    block_id, = struct.unpack('<H', body[offset:offset + 2])
    offset += 2

    # PackRawBuf: [u16 LE len][data] for ElGamal-encrypted session key
    eg_len, = struct.unpack('<H', body[offset:offset + 2])
    offset += 2
    eg_ciphertext = body[offset:offset + eg_len]
    offset += eg_len

    # PackRawBuf: [u16 LE len][data] for Blowfish-encrypted login data
    bf_data = b''
    if offset + 2 <= len(body):
        bf_len, = struct.unpack('<H', body[offset:offset + 2])
        offset += 2
        bf_data = body[offset:offset + bf_len]

    return {
        'block_id': block_id,
        'eg_ciphertext': eg_ciphertext,
        'bf_data': bf_data,
    }


def _read_pw_string_le(data: bytes, offset: int) -> Tuple[str, int]:
    """Read a WON PW_STRING ([u16 LE chars][utf-16-le bytes])."""
    if offset + 2 > len(data):
        raise ValueError("auth1_login_pw_string_truncated_len")
    nchar, = struct.unpack('<H', data[offset:offset + 2])
    offset += 2
    byte_len = nchar * 2
    if offset + byte_len > len(data):
        raise ValueError("auth1_login_pw_string_truncated_data")
    value = data[offset:offset + byte_len].decode("utf-16-le", errors="replace") if nchar else ""
    return value, offset + byte_len


def _read_raw_buf_le(data: bytes, offset: int) -> Tuple[bytes, int]:
    """Read a WON PackRawBuf ([u16 LE len][raw bytes])."""
    if offset + 2 > len(data):
        raise ValueError("auth1_login_raw_buf_truncated_len")
    raw_len, = struct.unpack('<H', data[offset:offset + 2])
    offset += 2
    if offset + raw_len > len(data):
        raise ValueError("auth1_login_raw_buf_truncated_data")
    return data[offset:offset + raw_len], offset + raw_len


def _decode_login_raw_text(raw: bytes) -> str:
    """Best-effort decode for CD/login key buffers."""
    if not raw:
        return ""
    try:
        return raw.decode("ascii").rstrip("\x00")
    except UnicodeDecodeError:
        pass
    if len(raw) % 2 == 0:
        try:
            return raw.decode("utf-16-le").rstrip("\x00")
        except UnicodeDecodeError:
            pass
    return raw.hex()


def parse_auth1_login_payload(bf_data: bytes, session_key: bytes) -> dict:
    """Decrypt and parse the Auth1LoginRequestHW login payload.

    Returned fields mirror the native WON/Homeworld login blob:
      block_id, need_key, create_account, username, community_name,
      nickname_key, password, new_password, cd_key, login_key.
    """
    if not bf_data:
        return {
            "block_id": 0,
            "need_key": False,
            "create_account": False,
            "username": "",
            "community_name": "",
            "nickname_key": "",
            "password": "",
            "new_password": "",
            "cd_key": "",
            "login_key": "",
            "raw_cd_key": b"",
            "raw_login_key": b"",
        }

    clear = bf_decrypt(bf_data, session_key)
    offset = 0
    if len(clear) < 4:
        raise ValueError("auth1_login_payload_too_short")

    block_id, = struct.unpack('<H', clear[offset:offset + 2])
    offset += 2
    need_key = clear[offset] != 0
    offset += 1
    create_account = clear[offset] != 0
    offset += 1

    username, offset = _read_pw_string_le(clear, offset)
    community_name, offset = _read_pw_string_le(clear, offset)
    nickname_key, offset = _read_pw_string_le(clear, offset)
    password, offset = _read_pw_string_le(clear, offset)
    new_password, offset = _read_pw_string_le(clear, offset)
    raw_cd_key, offset = _read_raw_buf_le(clear, offset)
    raw_login_key, offset = _read_raw_buf_le(clear, offset)

    return {
        "block_id": block_id,
        "need_key": need_key,
        "create_account": create_account,
        "username": username,
        "community_name": community_name,
        "nickname_key": nickname_key,
        "password": password,
        "new_password": new_password,
        "cd_key": _decode_login_raw_text(raw_cd_key),
        "login_key": _decode_login_raw_text(raw_login_key),
        "raw_cd_key": raw_cd_key,
        "raw_login_key": raw_login_key,
    }
