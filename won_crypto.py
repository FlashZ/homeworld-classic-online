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
