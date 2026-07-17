# Retail WON OSS Server

[![Tests](https://github.com/FlashZ/homeworld-classic-online/actions/workflows/tests.yml/badge.svg)](https://github.com/FlashZ/homeworld-classic-online/actions/workflows/tests.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![Homeworld 1.05](https://img.shields.io/badge/Homeworld-1.05-orange)](https://en.wikipedia.org/wiki/Homeworld)
[![Cataclysm 1.0.0.1](https://img.shields.io/badge/Cataclysm-1.0.0.1-teal)](https://en.wikipedia.org/wiki/Homeworld:_Cataclysm)

An open-source WON-compatible online service for the original retail **Homeworld** and **Homeworld: Cataclysm** clients.

It includes a Windows installer and a Linux/Wine/Proton helper that configure the game, install the matching verifier key, and set up a retail-format CD key when needed.

## Play online

### Before you start

- You need an installed copy of the original retail game: **Homeworld 1.05** or **Homeworld: Cataclysm 1.0.0.1**.
- Homeworld Remastered Classic is not supported.
- If you are playing on Windows, use the Windows installer below. You do not need Python or to run the server yourself.

### Windows (recommended)

1. Go to [GitHub Releases](https://github.com/FlashZ/homeworld-classic-online/releases) and download the latest `RetailWONSetup-...exe` file.
2. Right-click the file and choose **Run as administrator**.
3. Select Homeworld, Cataclysm, or both, then confirm the game folder the installer found. Use **Change...** if it selected the wrong copy.
4. Leave the default server selected to play on the community service. Only enter a custom server address when a private-server host has given you one.
5. At the CD-key step, keep your detected key if you want to retain it. If no key is found, accept the generated key. Older shared installer keys are offered a fresh unique replacement.
6. Choose whether to install the optional community multiplayer map pack, then finish and launch the game normally.

The installer configures both games in one run when they are installed. It backs up an existing `NetTweak.script` before changing it.

### Create an in-game account

Do this from the game's **Internet** screen after installing.

**Homeworld**

1. Select **New Account**.
2. Enter a username and password.
3. Select **Create New Account**, then **Launch WON**.

**Cataclysm / Emergence**

1. Select **New Account**.
2. Enter a username and password.
3. When the optional details screen asks for email, country, and ZIP code, select **Cancel**.
4. Select **Create New Account**, then **Launch WON**.

### Linux, Wine, or Proton

Check [GitHub Releases](https://github.com/FlashZ/homeworld-classic-online/releases) for a `RetailWONSetup-linux-...zip` bundle first. If the latest release does not include one, use the Linux/Wine/Proton helper from the source repository:

```bash
git clone https://github.com/FlashZ/homeworld-classic-online.git
cd homeworld-classic-online
```

Then run this from the repository folder, changing the two paths for your installation:

```bash
bash installer/install-linux.sh \
  --game homeworld \
  --game-dir "$HOME/Games/Homeworld" \
  --wine-prefix "$HOME/.wine" \
  --install-maps
```

Use `--game cataclysm` for Cataclysm/Emergence. The helper uses the community server by default; add `--server your.host.name` only for a private server. It requires `bash`, `python3`, and Wine (unless you pass `--skip-registry`). `curl` or `wget` is needed only when downloading the map pack.

## If something goes wrong

**The installer found the wrong folder**

Select **Change...** and choose the folder containing the game executable you actually launch.

**I want to switch from Homeworld to Cataclysm, or configure both**

Run the installer again and select the game or **Configure both**. Each game has separate online settings and CD-key formats.

**I changed my CD key**

Log in normally with your username and password. The server updates that account's CD-key binding after a successful login.

**Windows SmartScreen warned about the download**

Verify the download before running it. Each release includes a matching `.sha256` file and `VERIFY.txt`. In PowerShell, run the following with the actual installer filename and compare the result with the release checksum:

```powershell
Get-FileHash .\RetailWONSetup-...exe -Algorithm SHA256
```

**I need to undo the setup**

Open an elevated Command Prompt in the download folder and run the installer with `--uninstall` (for example, `RetailWONSetup-...exe --uninstall`). This removes the installed `NetTweak.script`, `kver.kp`, and installer-managed CD-key values. The saved `NetTweak.script` backup remains in the game folder if one was created.

## What the installer changes

For each selected game, it changes only the files and registry values required for online play:

- `NetTweak.script` (with an existing file saved as a game-specific `.bak` file)
- `kver.kp`
- Sierra and WON CD-key registry values, if you choose to write a generated key
- multiplayer map folders under `MultiPlayer`, if you choose the map pack

## For server hosts

The server supports a single Homeworld or Cataclysm service, or a shared public gateway with separate product backends. It includes Docker deployment, a live admin dashboard, and the WON-style Auth1, directory, routing, factory, and firewall services.

For Docker setup, self-hosting, shared-edge deployment, installer builds, and testing, see the [Server Setup Guide](docs/server-setup.md). Maintainers preparing a release should also read [Release Maintenance](docs/release-maintenance.md).

## Project status and background

This is an unofficial fan project. It is not affiliated with, endorsed by, sponsored by, or connected to Relic Entertainment, Sierra, Gearbox Entertainment, or Blackbird Interactive.

The compatibility work is implemented from retail-client behaviour, packet observations, public assets, and live testing; it does not reproduce the original server code. The longer account of the AI-assisted reverse-engineering work is in [Rebuilding Retail WON with AI](docs/rebuilding-retail-won-with-ai.md).

## Support

If you want to support the project:

<a href="https://buymeacoffee.com/nickkb" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="41" width="174"></a>

## License

AGPL-3.0. See [LICENSE](LICENSE).
