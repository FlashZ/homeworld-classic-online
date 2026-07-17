#!/usr/bin/env python3
"""Generate retail-compatible Homeworld-family CD keys."""

from __future__ import annotations

import argparse
import json
from typing import Iterable

import won_crypto


PRODUCT_CHOICES = (
    won_crypto.CDKEY_PRODUCT_HOMEWORLD,
    won_crypto.CDKEY_PRODUCT_CATACLYSM,
)


def _format_csharp_byte_array(data: bytes) -> str:
    return ", ".join(f"0x{byte:02X}" for byte in data)


def _generate_pairs(product: str, count: int, beta: bool) -> list[dict]:
    return [won_crypto.generate_cd_key(product, beta=beta) for _ in range(count)]


def _emit_text(product: str, pairs: Iterable[dict]) -> None:
    for index, pair in enumerate(pairs, start=1):
        print(f"[{index}] {product}")
        print(f"  display:   {pair['display_key']}")
        print(f"  plain:     {pair['plain_key']}")
        print(f"  encrypted: {pair['encrypted_key'].hex().upper()}")


def _emit_json(pairs: Iterable[dict]) -> None:
    payload = []
    for pair in pairs:
        payload.append(
            {
                "display_key": pair["display_key"],
                "plain_key": pair["plain_key"],
                "encrypted_key_hex": pair["encrypted_key"].hex().upper(),
                "beta": pair["beta"],
            }
        )
    print(json.dumps(payload, indent=2))


def _emit_csharp(pairs: Iterable[dict]) -> None:
    for pair in pairs:
        print(
            f'new RegistryCdKeyOption("{pair["display_key"]}", '
            f"new byte[] {{ {_format_csharp_byte_array(pair['encrypted_key'])} }}),"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--product",
        default=won_crypto.CDKEY_PRODUCT_HOMEWORLD,
        choices=PRODUCT_CHOICES,
        help="Retail product name used for checksum and registry encryption.",
    )
    parser.add_argument("--count", type=int, default=1, help="How many keys to generate.")
    parser.add_argument(
        "--format",
        choices=("text", "json", "csharp"),
        default="text",
        help="Output format. 'csharp' emits RegistryCdKeyOption lines for the installer pool.",
    )
    parser.add_argument("--beta", action="store_true", help="Generate beta-flagged keys.")
    args = parser.parse_args()

    if args.count <= 0:
        raise SystemExit("--count must be positive")

    pairs = _generate_pairs(args.product, args.count, args.beta)
    if args.format == "json":
        _emit_json(pairs)
    elif args.format == "csharp":
        _emit_csharp(pairs)
    else:
        _emit_text(args.product, pairs)


if __name__ == "__main__":
    main()
