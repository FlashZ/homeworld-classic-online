# Cataclysm Bootstrap Notes

This repo now carries the Cataclysm research that used to live in the
separate `cataclysm_won_server` workspace.

## Current State

- Product profile exists in [product_profile.py](../product_profile.py).
- The backend and gateway can run the Cataclysm profile with
  `--product cataclysm`.
- The unified Windows installer can now detect and configure Cataclysm
  installs without a separate Cataclysm-only installer.
- The remaining unmerged step is the shared-IP dual-product edge in
  [docs/unified-edge-two-backend-architecture.md](unified-edge-two-backend-architecture.md).

## Confirmed Retail Bootstrap Details

- Directory/auth bootstrap port: `15101/tcp`
- Version lookup path: `/TitanServers`
- Valid-versions service name: `CataclysmValidVersions`
- Directory root: `/Cataclysm`
- Known WON hostnames:
  - `cataclysm.central.won.net`
  - `cataclysm.east.won.net`
  - `cataclysm.west.won.net`
  - `www.won.net`
- Working client build under test: `1.0.0.1`
- Bootstrap files required in the game root:
  - `NetTweak.script`
  - `kver.kp`

## Cataclysm Installer Notes

The merged installer now knows the Cataclysm-specific differences:

- default host: `cataclysm.kerrbell.dev`
- backup suffix: `.cataclysm_oss.bak`
- retail product name for CD-key generation: `Cataclysm`
- Sierra registry path: `SOFTWARE\\Sierra On-Line\\Cataclysm`
- Sierra version subkey: `1.0.0.0`
- VirtualStore path:
  `SOFTWARE\\Classes\\VirtualStore\\MACHINE\\SOFTWARE\\WOW6432Node\\Sierra On-Line\\Cataclysm`
- supported executables:
  - `Cataclysm.exe`
  - `HomeworldCataclysm.exe`
  - `Homeworld.exe`

The installer still writes the same two bootstrap files to the game root and
optionally writes a matching Cataclysm Sierra/WON registry key pair.

## Networking Notes Still Worth Remembering

- Confirmed LAN local-IP probe: `UDP 48357`
- Confirmed LAN advertisement port: `UDP 6038`
- Likely gameplay/direct port: `6037`

Those match the existing NetTweak defaults, but broader field testing is still
useful.

## Open Questions

- Whether every Cataclysm retail install really needs registry values, or if
  some machines can live entirely on file bootstrap
- Whether any post-login behavior differs enough from Homeworld to justify
  extra product hooks in routing or firewall handling
- When the unified edge is built, whether Cataclysm needs any protocol-based
  classification hints beyond valid-versions and directory-root detection
