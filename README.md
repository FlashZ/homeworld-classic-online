# Retail WON OSS Server

[![Tests](https://github.com/FlashZ/won_oss_server/actions/workflows/tests.yml/badge.svg)](https://github.com/FlashZ/won_oss_server/actions/workflows/tests.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![Homeworld 1.05](https://img.shields.io/badge/Homeworld-1.05-orange)](https://en.wikipedia.org/wiki/Homeworld)
[![Cataclysm 1.0.0.1](https://img.shields.io/badge/Cataclysm-1.0.0.1-teal)](https://en.wikipedia.org/wiki/Homeworld:_Cataclysm)

Open-source online bootstrap for the original retail **Homeworld** and **Homeworld: Cataclysm** clients.

This project gives players a simple Windows installer that points the retail games at a working WON-compatible server, installs the required verifier key, and can write a matching retail-format CD key for online login.

Homeworld Remastered Classic is not supported.

## Note

This repo has also been a genuine test for me of how far AI can help with reverse engineering.

I was not trying to reproduce or copy the original server code. The idea was to work from retail clients, packet behavior, public assets, and live testing, and use AI to help piece together compatible server behavior from the outside in.

So alongside getting retail Homeworld and Cataclysm working online again, this project has also been me pushing on AI-assisted reverse engineering in a real practical setting.

This is also an unofficial fan project. It is not affiliated with, endorsed by, sponsored by, or connected to Relic Entertainment, Sierra, or any current or former owners of the Homeworld intellectual property.

## For Players

Download the latest installer from [GitHub Releases](https://github.com/FlashZ/won_oss_server/releases).

### Quick install

1. Download `RetailWONSetup.exe`.
2. Right-click it and choose `Run as administrator`.
3. Let it detect your Homeworld and/or Cataclysm install.
4. If you have both games installed, you can configure both in one run.
5. Confirm the detected install folder for each game.
6. Finish the setup, then launch the game normally.

The installer can:

- auto-detect retail Homeworld and Cataclysm installs
- show the folder it found before it changes anything
- let you change that folder if it found the wrong copy
- update `NetTweak.script` to point at your server
- install the matching `kver.kp` verifier key
- optionally write a randomized retail CD key for the selected game

No Python is required on the client machine.

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

If an older shared installer key is detected, the current installer now refreshes it to a new random key by default.

### SmartScreen and hash checking

GitHub releases include:

- `RetailWONSetup-....exe`
- `RetailWONSetup-....exe.sha256`
- `RetailWONSetup-....exe.VERIFY.txt`

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
- WON-style Auth1, directory, routing, factory, and firewall services
- an admin dashboard for live server monitoring

## Support

If you want to support the project:

<script type="text/javascript" src="https://cdnjs.buymeacoffee.com/1.0.0/button.prod.min.js" data-name="bmc-button" data-slug="nickkb" data-color="#5F7FFF" data-emoji="" data-font="Cookie" data-text="Buy me a coffee" data-outline-color="#000000" data-font-color="#ffffff" data-coffee-color="#FFDD00"></script>

[Buy me a coffee](https://www.buymeacoffee.com/nickkb)

## License

AGPL-3.0. See [LICENSE](LICENSE) if present in your checkout, or the badge link above.
