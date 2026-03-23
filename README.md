# WON OSS Server (Homeworld-oriented)

Open-source replacement for the Sierra WON (World Opponent Network) backend services, targeting Homeworld 1 multiplayer. Implements the real WON/Titan wire protocol — including Auth1 key exchange, NR-MD5 signatures, and ElGamal encryption — so the original Homeworld 1 client can connect without executable patching.

## Architecture

```
┌──────────────┐  Titan binary  ┌───────────────────────────┐     ┌────────────────┐
│  Homeworld   │───────────────▶│      Binary Gateway        │────▶│  JSON Backend   │
│   Client     │◀───────────────│   (titan_binary_gateway.py)│◀────│  (won_server.py)│
│              │  :15101 auth   │                            │     │                │
│              │  :15100 lobby  │  ┌─────────────────────┐  │     │  SQLite WAL    │
└──────────────┘                │  │   GatewayEventBus   │  │     │  persistence   │
                                │  │  (in-process pub/sub)│  │     └────────────────┘
                                │  └─────────────────────┘  │
                                │                            │
                                │  Titan framing / codecs:   │
                                │  ┌─────────────────────┐  │
                                │  │   titan_messages.py  │  │
                                │  │   won_crypto.py      │  │
                                │  └─────────────────────┘  │
                                └───────────────────────────┘
```

### Components

| Component | File | Port (default) | Purpose |
|---|---|---|---|
| JSON Backend | `won_server.py` | 9100 | Core state: auth, lobbies, matchmaking, routing, events, persistence |
| Binary Gateway | `titan_binary_gateway.py` | 15101 | Titan-native protocol: Auth1 handshake, DirGet, Auth1Peer, Factory, native routing |
| Routing/Lobby | (built into gateway) | 15100-15120 | Native Homeworld chat rooms and game routing |
| Firewall Probe | (built into gateway) | 2021 | Accepts connections for NAT detection |
| Admin Dashboard | (built into gateway) | 8080 | Live web dashboard showing rooms, players, logs, DB snapshot |
| Titan Codecs | `titan_messages.py` | — | Titan-like message encode/decode (auth, dir, route, chat, data objects) |
| Crypto Primitives | `won_crypto.py` | — | NR-MD5, ElGamal, Auth1 key blocks, certificates, TMessage framing |
| Key Generator | `generate_keys.py` | — | One-time DSA key pair generation; produces `kver.kp` for game directory |
| Client Installer | `installer/HWOnlineSetup.exe` | — | Standalone Windows installer (no Python needed) |

## Features

### Implemented

- **Real Auth1 crypto** (`won_crypto.py`): NR-MD5 signatures (WON "BogusSign/BogusVerify"), ElGamal public-key encryption (WON wire format), DER key encoding, Auth1PublicKeyBlock and Auth1Certificate builders — all confirmed byte-for-byte against WON open-source (`wonapi/WONCrypt/ElGamal.cpp`)
- **Auth1 handshake** (port 15101): Full 4-message HW handshake — GetPubKeys → GetPubKeysReply → LoginRequestHW → ChallengeHW → ConfirmHW → LoginReply with signed certificate. Keys loaded from `keys/` at startup.
- **Auth1Peer sessions**: Encrypted persistent sessions for directory queries and factory requests, using the same ElGamal + Blowfish key exchange
- **Directory service**: `DirGet` SmallMessage protocol; returns AuthServer, TitanRoutingServer, TitanFactoryServer entries with addresses and `ValidVersions` data objects
- **Native Homeworld routing** (port 15100-15120): Full MiniRouting protocol — RegisterClient, GetClientList, SendChat, SendData, SendDataBroadcast, SubscribeDataObject, Create/Replace/Delete/Renew DataObject, KeepAlive, DisconnectClient. Supports multiple concurrent rooms via dynamic port allocation.
- **Silencer routing server** (port 15100): Legacy Homeworld lobby/conflict protocol — INIT, NEW_CONFLICT, CONFLICTQUERY, CHATMESSAGE, ABORT_CONFLICT, USER_TERMINATION
- **Factory service**: Allocates routing server ports for chat and game rooms on demand
- **Firewall probe** (port 2021): Accepts and closes connections used for NAT detection
- **Admin dashboard** (port 8080): Live web UI showing rooms, connected players, chat feed, routing data objects, IP metrics, gateway logs, and a read-only snapshot of `won_server.db`
- **Backend state**: Auth, lobbies, matchmaking, routing, game-launch lifecycle via JSON backend (`won_server.py`)
- **Push-based event delivery**: `GatewayEventBus` pushes chat, join, and game-launch events over persistent TCP
- **Persistence**: SQLite WAL — users, lobbies, sessions survive restarts
- **Docker deployment**: Single-container setup with `docker-compose.yml`, automatic data seeding on first start
- **Windows client installer**: Standalone `.exe` (no Python needed) that auto-detects the game, installs CD key, `kver.kp`, and `NetTweak.script`

### Known gaps

- **Credential validation**: Server issues a certificate to any connecting client without checking username/password (fine for public play — the goal is to let people play)
- **NAT/firewall detection**: The gateway now returns a 16-byte probe stub, but strict-NAT behaviour still needs broader field testing on real networks
- **Reconnect-to-match**: Routing now keeps a short reconnect grace window, but it currently matches by the same player name and IP and still needs wider real-world validation
- **Game process model**: Routing rooms are managed in-gateway rather than spawning external `RoutingServHWGame` binaries; this works but means game rooms share the gateway process

---

## Quick start

Run each command in a **separate terminal** from the repo root.

### 0. Generate keys for a new trust domain (optional)

If you are creating an independent fork instead of using the bundled key set, generate a fresh verifier/auth pair first:

```powershell
python generate_keys.py `
  --keys-dir keys
```

This writes:

- `verifier_public.der`
- `verifier_private.der`
- `authserver_public.der`
- `authserver_private.der`
- `kver.kp`

If you are using the existing bundled trust domain, skip this step.

### 1. Start the JSON backend (terminal 1)

```powershell
python won_server.py `
  --host 127.0.0.1 --port 9100 `
  --db-path won_server.db
```

The backend persists all state to `won_server.db`. Delete the file to start fresh.

### 2. Start the binary gateway (terminal 2)

```powershell
python titan_binary_gateway.py `
  --host 0.0.0.0 --port 15101 `
  --backend-host 127.0.0.1 --backend-port 9100 `
  --public-host 192.168.x.x `
  --routing-port 15100 `
  --admin-host 127.0.0.1 --admin-port 8080 `
  --keys-dir keys `
  --log-level INFO
```

Replace `192.168.x.x` with your LAN IP (or public VPS IP). Homeworld connects to **port 15101** for Auth1 and directory queries, and to **port 15100+** for routing/lobby.

Open [http://127.0.0.1:8080/](http://127.0.0.1:8080/) on the host machine to view the admin dashboard.

### 3. Bootstrap clients (Windows installer)

Build the installer once on a Windows machine:

```powershell
installer\build_installer.bat
```

Then distribute `HWOnlineSetup.exe` to each player and run it as Administrator:

```powershell
HWOnlineSetup.exe 192.168.x.x
```

The installer:

- auto-detects the Homeworld install directory (registry + common paths), prompts if not found
- installs a valid WON Homeworld CD key in the registry
- writes `NetTweak.script` so `hosts`-file edits are not needed
- installs `kver.kp` into the game folder

No Python required on client machines. Players just double-click the exe, then launch Homeworld normally.

You can also pass a hostname if you have DNS set up:

```powershell
HWOnlineSetup.exe hw1.example.com
```

---

## Self-hosting with your own keys

This project can be published openly without giving away control of the main network. The source code is public, but trust is defined by the key material in `keys/`.

### What defines a network

These files define a Homeworld network identity:

- `keys/authserver_private.der`
- `keys/authserver_public.der`
- `keys/verifier_private.der`
- `keys/verifier_public.der`
- `keys/kver.kp`

The two private `.der` files are the sensitive part. Do not publish them if you want to remain the operator of your own official network.

### What a self-hosted fork must change

If someone wants to run an independent network instead of joining yours, they should replace the entire `keys/` set with their own matching files before first launch.

Important rules:

- `kver.kp` must match the verifier keypair used by the server
- every client on that fork must receive the matching `kver.kp`
- clients using your public installer or your public `kver.kp` will not automatically trust a different fork
- reusing someone else's private keys means reusing their trust domain, not creating an independent one

### Client bootstrap for a fork

The standalone installer embeds both a default server host and a verifier blob. A fork operator should rebuild the installer after updating:

- `installer/hwclient_setup.cs`

In practice that means:

- set the default host to the fork's own domain or IP
- replace the embedded `kver.kp` bytes with the fork's matching verifier blob
- rebuild `HWOnlineSetup.exe`

If the installer is not rebuilt, the fork operator must at least distribute their own `kver.kp` and a matching `NetTweak.script` manually.

### First-start checklist for an independent fork

1. Replace `keys/` with the fork's own matching verifier/auth files.
2. Use a fresh hostname, public IP, and database.
3. If using Docker, place the fork's key files in `./data/keys/` before the first `docker compose up`.
4. Rebuild the Windows installer so it embeds the fork's host and `kver.kp`.
5. Distribute that rebuilt installer, or manually distribute the matching `kver.kp` and `NetTweak.script`.

---

## Lean server install

If you want a smaller VPS/runtime copy, you do not need to ship the whole development folder.

### Minimum files for a plain Python server

```text
won_oss_server/
  __init__.py
  won_server.py
  titan_binary_gateway.py
  titan_messages.py
  won_crypto.py
  requirements-server.txt
  keys/
    verifier_private.der
    authserver_private.der
```

### Minimum files for Docker deployment

```text
won_oss_server/
  __init__.py
  won_server.py
  titan_binary_gateway.py
  titan_messages.py
  won_crypto.py
  requirements-server.txt
  Dockerfile
  docker-entrypoint.sh
  docker_supervisor.py
  docker-compose.yml
  .env             # create from .env.example
  keys/
    verifier_private.der
    authserver_private.der
```

### Safe to remove from a server-only copy

- `installer/` — only needed if distributing the Windows client installer from the VPS
- `generate_keys.py` — only needed if your keypair is not yet generated
- `SERVER_CODE_WALKTHROUGH.md`
- `README.md`
- `__pycache__/`
- `.gitignore`
- `.dockerignore` — if you are not using Docker
- `.env.example` — after you have created your real `.env`

### Key files actually required at runtime

For the current server runtime, only these private keys are required:

- `keys/verifier_private.der`
- `keys/authserver_private.der`

Useful but not strictly required on the server at runtime:

- `keys/verifier_public.der`
- `keys/authserver_public.der`
- `keys/kver.kp`

Keep `kver.kp` backed up somewhere safe even if you remove it from the VPS copy. Clients and the Windows installer still need it, and it must match the server's active keypair.

---

## Docker deployment

### What it does

- Builds one image containing `won_server.py` and `titan_binary_gateway.py`
- Starts both processes inside one container
- Persists the SQLite database and key material under `./data`
- Seeds `./data/won_server.db` and `./data/keys/` from the bundled repo copy on first start only

Your existing clients will keep working as long as the container is seeded with the same keys they already trust.

### Files

- `Dockerfile`
- `docker-entrypoint.sh`
- `docker-compose.yml`
- `.env.example`

### First-time VPS setup

From inside the `won_oss_server` directory on the VPS:

```bash
cp .env.example .env
```

Edit `.env` and set:

```text
PUBLIC_HOST=207.211.142.136
```

Use the server's public IPv4 here. Keep using the same verifier/auth key set your clients already have.

### Build and start

```bash
docker compose up -d --build
```

### View logs

```bash
docker compose logs -f
```

### Stop

```bash
docker compose down
```

### Ports to open

- `15101/tcp` — Titan gateway + Auth1
- `15100-15120/tcp` — routing/chat/game rooms
- `2021/tcp` — firewall probe

The compose file also binds the admin dashboard to `127.0.0.1:8080` on the VPS host only.

### Data persistence

The compose file mounts:

```text
./data:/data
```

Important notes:

- On first start, the container copies `won_server.db` and `keys/*` into `/data` only if those files do not already exist.
- After that, the container keeps using the persisted `/data` copy.
- If you are migrating an existing live server, make sure `./data/keys/` contains your current `authserver_private.der`, `verifier_private.der`, and `kver.kp` before letting clients connect.

This is the recommended VPS deployment path because it avoids the "gateway is up but backend on 9100 died with the shell" failure mode.

---

## Auth1 Protocol Details

The Auth1 handshake uses a 4-message exchange over a single TCP connection on port 15101.

### Handshake Flow

```
Client                                          Server (port 15101)
  │                                                │
  │── Auth1GetPubKeys (TMessage svc=201, msg=1) ──▶│
  │◀── Auth1GetPubKeysReply (msg=2) ───────────────│  [status=0][keyBlockLen][Auth1PublicKeyBlock]
  │                                                │
  │── Auth1LoginRequestHW (msg=30) ───────────────▶│  [blockId][EG(session_key)][BF(login_data)]
  │◀── Auth1LoginChallengeHW (msg=32) ─────────────│  [raw_len][16 random bytes]
  │                                                │
  │── Auth1LoginConfirmHW (msg=33) ───────────────▶│  [raw_len][confirm_bytes]
  │◀── Auth1LoginReply (msg=4) ────────────────────│  [status=0][0][1][1][certLen][Auth1Certificate]
  │                                                │
  │  (connection closes)                           │
  │                                                │
  │── connects to port 15100 (routing/lobby) ─────▶│
```

### Key Block and Certificate

- **Auth1PublicKeyBlock**: contains the auth server's public key (p, q, g, y), signed with the verifier private key. The game verifies this against `kver.kp`.
- **Auth1Certificate**: contains an ephemeral user session public key, signed with the auth server private key. Issued on successful login; carried by the client to authenticate to routing servers.

### TMessage Wire Format

```
[u32 LE total_size]      ← includes these 4 bytes
[u32 LE service_type]    ← 201 (Auth1Login)
[u32 LE msg_type]
[body...]
```

Detection: `body[0] == 0xC9` (low byte of service_type 201 in LE).

---

## Roadmap

1. ✅ **Reverse-engineer Auth1 wire format** — Confirmed from WON open-source.
2. ✅ **Implement crypto primitives** — `won_crypto.py`: NR-MD5, ElGamal, key blocks, certificates.
3. ✅ **Wire up Auth1 in gateway** — Keys loaded at startup, full handshake working end-to-end.
4. ✅ **End-to-end client test** — Game reaches lobby screen, chat works, rooms visible.
5. ✅ **Internet multiplayer** — Two clients tested over the public internet: lobby, chat, game hosting, joining, and full gameplay confirmed working.
6. ✅ **Firewall probe response** — Gateway now sends a 16-byte probe response instead of only accepting and closing.
7. ✅ **Server keepalive** — Gateway now sends periodic routing keepalives and reaps stale peer sessions.
