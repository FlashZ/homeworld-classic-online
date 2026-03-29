from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProductProfile:
    key: str
    community_name: str
    directory_root: str
    lobby_room_name: str
    lobby_room_description: str
    valid_versions_service: str
    auth_service_name: str = "AuthServer"
    routing_service_name: str = "TitanRoutingServer"
    factory_service_name: str = "TitanFactoryServer"
    titan_servers_path: str = "/TitanServers"
    factory_directory_marker: str = "HWDS"
    default_factory_display_name: str = "Melbourne"
    factory_current_object_name: str = "__FactCur_RoutingServHWGame"
    factory_total_object_name: str = "__FactTotal_RoutingServHWGame"
    routing_chat_process_name: str = "RoutingServHWChat"
    routing_game_process_name: str = "RoutingServHWGame"

    def matches_valid_versions_filter(self, service_name: str) -> bool:
        svc = str(service_name or "")
        return bool(svc) and (
            svc == self.valid_versions_service or svc.endswith("ValidVersions")
        )

    def matches_auth_filter(self, service_name: str) -> bool:
        svc = str(service_name or "")
        return bool(svc) and (svc == self.auth_service_name or "Auth" in svc)

    def matches_routing_or_factory_filter(self, service_name: str) -> bool:
        svc = str(service_name or "")
        return bool(svc) and (
            svc == self.routing_service_name
            or svc == self.factory_service_name
            or "Routing" in svc
            or "Factory" in svc
        )


HOMEWORLD_PRODUCT_PROFILE = ProductProfile(
    key="homeworld",
    community_name="Homeworld",
    directory_root="/Homeworld",
    lobby_room_name="Homeworld Chat",
    lobby_room_description="Homeworld Chat",
    valid_versions_service="HomeworldValidVersions",
)

CATACLYSM_PRODUCT_PROFILE = ProductProfile(
    key="cataclysm",
    community_name="Cataclysm",
    directory_root="/Cataclysm",
    lobby_room_name="Cataclysm Chat",
    lobby_room_description="Cataclysm Chat",
    valid_versions_service="CataclysmValidVersions",
)

PRODUCT_PROFILES: dict[str, ProductProfile] = {
    HOMEWORLD_PRODUCT_PROFILE.key: HOMEWORLD_PRODUCT_PROFILE,
    CATACLYSM_PRODUCT_PROFILE.key: CATACLYSM_PRODUCT_PROFILE,
}


def product_profile_from_name(name: str) -> ProductProfile:
    return PRODUCT_PROFILES.get(str(name or "").strip().lower(), HOMEWORLD_PRODUCT_PROFILE)
