# Retail WON OSS Server

[![Tests](https://github.com/FlashZ/won_oss_server/actions/workflows/tests.yml/badge.svg)](https://github.com/FlashZ/won_oss_server/actions/workflows/tests.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![Homeworld 1.05](https://img.shields.io/badge/Homeworld-1.05-orange)](https://en.wikipedia.org/wiki/Homeworld)
[![Cataclysm 1.0.0.1](https://img.shields.io/badge/Cataclysm-1.0.0.1-teal)](https://en.wikipedia.org/wiki/Homeworld:_Cataclysm)

Open-source online bootstrap for the original retail **Homeworld** and **Homeworld: Cataclysm** clients.

This project gives players a simple Windows installer and a Linux/Wine helper that point the retail games at a working WON-compatible server, install the required verifier key, and can write a matching retail-format CD key for online login.

Homeworld Remastered Classic is not supported.

## Note

This repo has also been a genuine test for me of how far AI can help with reverse engineering.

I was not trying to reproduce or copy the original server code. The idea was to work from retail clients, packet behavior, public assets, and live testing, and use AI to help piece together compatible server behavior from the outside in.

So alongside getting retail Homeworld and Cataclysm working online again, this project has also been me pushing on AI-assisted reverse engineering in a real practical setting.

This is also an unofficial fan project. It is not affiliated with, endorsed by, sponsored by, or connected to Relic Entertainment, Sierra, Gearbox Entertainment or Blackbird Interactive.

## For Players

Download the latest installer from [GitHub Releases](https://github.com/FlashZ/won_oss_server/releases).

### Windows quick install

1. Download `RetailWONSetup.exe`.
2. Right-click it and choose `Run as administrator`.
3. Let it detect your Homeworld and/or Cataclysm install.
4. If you have both games installed, you can configure both in one run.
5. Confirm the detected install folder for each game.
6. Keep the detected CD key, or replace it with a generated one.
7. Optionally install the community map pack.
8. Finish the setup, then launch the game normally.

The installer can:

- auto-detect retail Homeworld and Cataclysm installs
- show the folder it found before it changes anything
- let you change that folder if it found the wrong copy
- update `NetTweak.script` to point at your server
- install the matching `kver.kp` verifier key
- show detected CD keys and let you keep or replace them
- optionally write a randomized retail CD key for the selected game
- optionally download community multiplayer maps from `FlashZ/Homeworld_Map_Collection`

No Python is required for the Windows installer.

### Linux / Wine / Proton

Linux players hosting or running the retail Windows games under Wine or Proton can use the release Linux helper bundle.

1. Download `RetailWONSetup-linux-....zip` from GitHub Releases.
2. Extract it.
3. Run the helper from the extracted folder:

```bash
bash installer/install-linux.sh \
  --game homeworld \
  --game-dir "$HOME/Games/Homeworld" \
  --wine-prefix "$HOME/.wine" \
  --install-maps
```

Use `--game cataclysm` for Homeworld: Cataclysm/Emergence. Pass `--server your.host.name` for a private server, `--skip-registry` to avoid Wine registry writes, or `--force-new-key` to replace a detected CD key. The helper writes a generated retail CD key by default when no existing key is found; if it detects one, interactive runs ask before replacing it and `--non-interactive` keeps it unless `--force-new-key` is set.

The Linux helper needs `bash`, `python3`, and either `curl` or `wget` when `--install-maps` downloads the map archive.

### In Game (Homeworld)

1. Click Internet.
2. Click New Account
3. Enter desired username and password
4. Click Create New Account
5. Launch WON

### In Game (Cataclysm/Emergence)

1. Click Internet.
2. Click New Account
3. Enter desired username and password
4. Cancel on the details screen (it will ask for email, country, and zip code)
5. Click Create New Account
6. Launch WON

### Notable Bug Fix

- Fixes the classic Homeworld desync bug caused by shooting dust clouds with ion cannons

### What the installer changes

The installer only touches the files and registry values needed for online play:

- `NetTweak.script`
- `kver.kp`
- the Sierra/WON CD key registry values for the selected game, if you leave CD key install enabled
- community map folders under `MultiPlayer`, if you select the map pack

If an older shared installer key is detected, the current installer now refreshes it to a new random key by default.

### SmartScreen and hash checking

GitHub releases include:

- `RetailWONSetup-....exe`
- `RetailWONSetup-....exe.sha256`
- `RetailWONSetup-....exe.VERIFY.txt`
- `RetailWONSetup-linux-....zip`

If Windows SmartScreen appears, check the file hash first:

```powershell
Get-FileHash .\RetailWONSetup-....exe -Algorithm SHA256
```

The SHA-256 value printed by PowerShell must match the release `.sha256` file and the bundled `VERIFY.txt`.

### Troubleshooting

`The installer found the wrong folder`

Use `Change...` on the install screen and point it at the exact game folder you actually launch from.

`I have both games installed`

Run the latest installer and choose `Configure both detected games`.

`Homeworld works, but Cataclysm does not`

Run the installer again and make sure Cataclysm was selected and patched too. The two games use different product settings and different CD key families.

`I updated my CD key and now login fails`

Ask the server operator to clear your CD key binding for that game, then log in again so the account can bind to the new key.

`Can I use this with Remastered Classic?`

No. This project is for the original retail Homeworld family only, as Remastered Classic had the online option removed.

## For Server Hosts

If you are trying to run the server, Docker stack, shared-edge setup, admin dashboard, or rebuild the installer from source, use the server guide:

- [Server Setup Guide](docs/server-setup.md)

Additional technical docs:

- [Cataclysm Bootstrap Notes](docs/cataclysm-bootstrap-notes.md)
- [Unified Edge / Two Backend Architecture Notes](docs/unified-edge-two-backend-architecture.md)

## What This Project Supports

- retail Homeworld 1.05 bootstrap/install flow
- retail Homeworld: Cataclysm 1.0.0.1 bootstrap/install flow
- randomized retail-format CD key generation per game
- optional community multiplayer map installation
- Linux/Wine/Proton helper setup
- WON-style Auth1, directory, routing, factory, and firewall services
- an admin dashboard for live server monitoring

## Support

If you want to support the project:

<a href="https://buymeacoffee.com/nickkb" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="41" width="174"></a>

## License

AGPL-3.0. See [LICENSE](LICENSE) if present in your checkout, or the badge link above.
