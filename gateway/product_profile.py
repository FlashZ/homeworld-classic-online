"""Compatibility shim for shared product profiles."""

from product_profile import (
    CATACLYSM_PRODUCT_PROFILE,
    HOMEWORLD_PRODUCT_PROFILE,
    PRODUCT_PROFILES,
    ProductProfile,
    product_profile_from_name,
)

__all__ = [
    "CATACLYSM_PRODUCT_PROFILE",
    "HOMEWORLD_PRODUCT_PROFILE",
    "PRODUCT_PROFILES",
    "ProductProfile",
    "product_profile_from_name",
]
