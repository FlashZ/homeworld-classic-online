# Server Setup Guide

This guide is for people hosting or developing the server. If you are just trying to play, go back to the main [README](../README.md).

## Overview

This repo supports two server layouts:

- `single-product` mode for either Homeworld or Cataclysm
- `shared-edge` mode for one public gateway serving both products with separate internal backends

Shared-edge mode is working, but it should still be treated as active validation work rather than a final "retail-perfect" claim.

## Docker Quick Start

Copy `.env.example` to `.env`, then set at least:

- `PUBLIC_HOST`
- `BACKEND_SHARED_SECRET`
- `ADMIN_TOKEN`

For a normal single-product stack, also set:

- `PRODUCT=homeworld` or `PRODUCT=cataclysm`
- `SHARED_EDGE=0`

If you want to enable the browser-based WON auth bridge for Homeworld Stats, also set:

- `WEB_AUTH_SHARED_SECRET`
- `WEB_AUTH_PUBLIC_BASE_URL`

The `WEB_AUTH_PUBLIC_BASE_URL` value should be the public Homeworld Stats base URL, because the gateway validates browser return targets against it.

Then start it:

```bash
docker compose up -d --build
```

The admin dashboard is available on the host at:

- `http://127.0.0.1:8080/?token=YOUR_ADMIN_TOKEN`

Health probes are also available on the admin port:

- `/health`
- `/ready`

### Ports to expose

| Port | Purpose |
|------|---------|
| `15101/tcp` | Auth1 and directory |
| `15100-15120/tcp` | Routing, chat, game rooms |
| `2021/tcp` | Firewall/NAT probe |

## Shared-Edge Mode

Set these in `.env`:

- `SHARED_EDGE=1`
- `EDGE_DEFAULT_PRODUCT=homeworld` or `EDGE_DEFAULT_PRODUCT=cataclysm`
- `BACKEND_PORT=9100`
- `CATACLYSM_BACKEND_PORT=9101`

Then launch normally:

```bash
docker compose up -d --build
docker compose logs -f gateway
```

On startup you should see lines like:

- `Shared-edge runtime: homeworld ...`
- `Shared-edge runtime: cataclysm ...`
- `Titan binary gateway listening on (...) -> shared edge`

With the default routing range:

- Homeworld uses `15100-15109`
- Cataclysm uses `15110-15120`

State is stored separately under:

- `data/homeworld/`
- `data/cataclysm/`

## Two Separate Stacks Instead

If you do not want shared-edge yet, run two ordinary single-product stacks on separate public IPs or separate machines.

Typical one-host/two-IP layout:

1. Create `homeworld.env`:
   - `PRODUCT=homeworld`
   - `SHARED_EDGE=0`
   - `PORT_BIND_IP=<homeworld-public-ip>`
   - `PUBLIC_HOST=homeworld.example.com`
2. Create `cataclysm.env`:
   - `PRODUCT=cataclysm`
   - `SHARED_EDGE=0`
   - `PORT_BIND_IP=<cataclysm-public-ip>`
   - `PUBLIC_HOST=cataclysm.example.com`
3. Launch each stack separately:

```bash
docker compose --env-file homeworld.env -p won-homeworld up -d --build
docker compose --env-file cataclysm.env -p won-cataclysm up -d --build
```

Use this when you want the cleanest operational separation.

## Manual Python Setup

Install server dependencies:

```powershell
python -m pip install -r requirements-server.txt
```

Optionally generate a fresh server key set:

```powershell
python generate_keys.py --keys-dir keys
```

Generate retail-compatible keys for installer pools or testing:

```powershell
python generate_cdkeys.py --product Homeworld --count 10
python generate_cdkeys.py --product Cataclysm --count 25 --format csharp
```

### Start a single-product stack

```powershell
# Terminal 1 - backend
python won_server.py --product homeworld --host 127.0.0.1 --port 9100 --db-path data/homeworld/won_server.db

# Terminal 2 - gateway
python titan_binary_gateway.py `
  --product homeworld `
  --host 0.0.0.0 --port 15101 `
  --backend-host 127.0.0.1 --backend-port 9100 `
  --public-host 192.168.x.x `
  --routing-port 15100 `
  --admin-host 127.0.0.1 --admin-port 8080 `
  --keys-dir keys --log-level INFO
```

Swap `homeworld` for `cataclysm` to run the Cataclysm profile instead.

### Security defaults

- The backend defaults to `127.0.0.1`.
- Non-loopback backend access should use `--shared-secret` on `won_server.py` and a matching `--backend-shared-secret` on `titan_binary_gateway.py`.
- The dashboard defaults to `127.0.0.1`.
- If you bind the dashboard to a non-loopback address, set `--admin-token` and use `?token=...`.

## Rebuilding the Windows Installer

Build the installer from source with:

```powershell
installer\build_installer.bat
```

Output:

- `installer\RetailWONSetup.exe`

You can override the output filename with `INSTALLER_OUTPUT_NAME=...`.

## Self-Hosting with Your Own Keys

The network identity is defined by the verifier/auth key material under `keys/`.

To run an independent network:

1. Generate a fresh key set:
   - `python generate_keys.py --keys-dir keys`
2. Use a fresh hostname/IP and database.
3. If using Docker, place your key files in `./data/<product>/keys/` before first startup.
4. Rebuild the installer with your host and matching `kver.kp`.
5. Distribute that installer, or manually distribute `kver.kp` plus a matching `NetTweak.script`.

Rules to keep straight:

- `kver.kp` must match the verifier keypair the server uses
- every client on your network needs the matching `kver.kp`
- clients using another network's installer or `kver.kp` will not trust your server
- reusing somebody else's private keys joins their trust domain instead of creating your own

## Testing

Run the Python suite from the repo root:

```bash
python -m pip install -r requirements-server.txt
python -m pip install pytest
python -m pytest
```

## More Technical Docs

- [Cataclysm Bootstrap Notes](cataclysm-bootstrap-notes.md)
- [Unified Edge / Two Backend Architecture Notes](unified-edge-two-backend-architecture.md)
