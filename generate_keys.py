#!/usr/bin/env python3
"""One-time key generation for the WON OSS Auth1 server.

Generates two DSA-style keypairs sharing the same (p, q, g) parameters:
  1. Verifier keypair — signs the Auth1PublicKeyBlock; game verifies against kver.kp
  2. Auth server keypair — decrypts ElGamal session keys; signs Auth1Certificates

Output files (in --keys-dir):
  verifier_public.der   — copy to Homeworld game dir as "kver.kp"
  verifier_private.der
  authserver_public.der
  authserver_private.der

Usage:
  python won_oss_server/generate_keys.py [--keys-dir won_oss_server/keys]
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Allow direct execution from either:
# - the standalone repo layout: <root>/won_oss_server/*.py
# - the older nested layout:    <root>/tools/won_oss_server/*.py
_package_parent = Path(__file__).resolve().parent.parent
if str(_package_parent) not in sys.path:
    sys.path.insert(0, str(_package_parent))

from cryptography.hazmat.primitives.asymmetric import dsa

from won_oss_server.won_crypto import encode_private_key, encode_public_key


def generate_keys(keys_dir: str) -> None:
    out = Path(keys_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Generate shared DSA parameters (1024-bit, matching WON's key size)
    print("Generating 1024-bit DSA parameters (this may take a moment)...")
    params = dsa.generate_parameters(key_size=1024)
    pn = params.parameter_numbers()
    p, q, g = pn.p, pn.q, pn.g

    # Generate verifier keypair
    ver_priv = params.generate_private_key()
    ver_nums = ver_priv.private_numbers()
    ver_x = ver_nums.x
    ver_y = ver_nums.public_numbers.y

    # Generate auth server keypair (same p, q, g)
    auth_priv = params.generate_private_key()
    auth_nums = auth_priv.private_numbers()
    auth_x = auth_nums.x
    auth_y = auth_nums.public_numbers.y

    # Save verifier keys
    ver_pub_der = encode_public_key(p, q, g, ver_y)
    ver_priv_der = encode_private_key(p, q, g, ver_y, ver_x)
    (out / "verifier_public.der").write_bytes(ver_pub_der)
    (out / "verifier_private.der").write_bytes(ver_priv_der)

    # Save auth server keys
    auth_pub_der = encode_public_key(p, q, g, auth_y)
    auth_priv_der = encode_private_key(p, q, g, auth_y, auth_x)
    (out / "authserver_public.der").write_bytes(auth_pub_der)
    (out / "authserver_private.der").write_bytes(auth_priv_der)

    # Copy verifier public key as kver.kp (what the game loads)
    kver_path = out / "kver.kp"
    kver_path.write_bytes(ver_pub_der)

    print(f"Keys written to {out.resolve()}/")
    print(f"  verifier_public.der  ({len(ver_pub_der)} bytes)")
    print(f"  verifier_private.der ({len(ver_priv_der)} bytes)")
    print(f"  authserver_public.der ({len(auth_pub_der)} bytes)")
    print(f"  authserver_private.der ({len(auth_priv_der)} bytes)")
    print(f"  kver.kp              ({len(ver_pub_der)} bytes) = verifier_public.der")
    print()
    print("Next steps:")
    print(f"  1. Copy {kver_path.resolve()} to your Homeworld game directory")
    print(f"  2. Start the gateway with --keys-dir {out}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate WON Auth1 keypairs")
    parser.add_argument(
        "--keys-dir",
        default=str(Path(__file__).resolve().parent / "keys"),
        help="Directory to write key files (default: sibling keys directory)",
    )
    args = parser.parse_args()
    generate_keys(args.keys_dir)


if __name__ == "__main__":
    main()
