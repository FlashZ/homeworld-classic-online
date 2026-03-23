# WON OSS Server Code Walkthrough

This document is a code-first explanation of how the Homeworld WON OSS stack works today.

It is written for someone who did not author the system and wants to understand:

- what each process is responsible for
- how a Homeworld client moves through login, directory, lobby, and game launch
- which file owns which part of the behavior
- where to look when something goes wrong

This guide follows the current code in:

- `won_server.py`
- `titan_binary_gateway.py`
- `won_crypto.py`
- `titan_messages.py`
- `installer/hwclient_setup.cs`
- `generate_keys.py`
- `packet_sniffer_framework.py`
- `titan_bridge.py`

It is more specific than `README.md`, and it is meant to be the "how this actually works" companion for the codebase.

## 1. The Short Version

The system is split into two main runtime pieces:

1. `won_server.py`
   This is the internal state and persistence backend.
   It stores users, lobbies, sessions, factories, game servers, directory entities, and queued events in SQLite.
   It speaks newline-delimited JSON over TCP and is not meant to be spoken to directly by the original Homeworld client.

2. `titan_binary_gateway.py`
   This is the Homeworld-facing server.
   It speaks the real Titan/WON wire protocol that the original game expects on:
   - `15101` for directory/auth/factory entry
   - `15100` and up for routing/lobby/game traffic
   - `2021` for the firewall probe

In other words:

- the backend owns truth
- the gateway owns compatibility

The Homeworld client never talks to `won_server.py` directly.
It always talks to the gateway, and the gateway translates that traffic into backend actions where needed.

## 2. Runtime Topology

At runtime, the system looks like this:

```text
Homeworld client
    |
    |  Titan/WON TCP
    v
titan_binary_gateway.py
    |
    |  internal JSON actions over TCP
    v
won_server.py
    |
    |  SQLite WAL
    v
won_server.db
```

There are also supporting pieces:

- `installer/hwclient_setup.cs`
  Configures the Windows client so Homeworld points at your server.

- `generate_keys.py`
  Generates the verifier/auth key material used by Auth1.

- `packet_sniffer_framework.py`
  A TCP MITM capture proxy for protocol debugging.

- `titan_bridge.py`
  A human-readable bridge for manual testing against the backend.

## 3. The Ports and What They Mean

These are the ports that matter for the real Homeworld path:

- `15101/TCP`
  Main Titan gateway.
  Homeworld uses this for version checks, directory lookups, Auth1 login, and Auth1Peer directory/factory sessions.

- `15100/TCP`
  Base routing/lobby server.
  This is the default chat/lobby port.

- `15100-15120/TCP`
  Dynamic routing server range.
  Additional room/game listeners can be created here.

- `2021/TCP`
  Firewall probe port.
  Homeworld uses a TCP probe here for NAT/firewall detection.

- `9100/TCP`
  Internal backend port.
  Only the gateway and test tools should talk to this.

- `8080/TCP`
  Optional local admin dashboard.

Important: in the current Python OSS stack, the externally exposed Homeworld ports are TCP, not UDP.

## 4. The Startup Sequence

### 4.1 Backend startup: `won_server.py`

When you launch `won_server.py`, it does the following:

1. Builds a `StateStore`
   - opens SQLite
   - enables WAL mode
   - creates the schema if it does not exist

2. Builds a `WONLikeState`
   - loads players, lobbies, servers, factories, sessions, directory entities, and queued events from the database
   - bootstraps default `/Homeworld` and `/TitanServers` directory entries if needed

3. Builds a `WONLikeProtocolServer`
   - this is the JSON action dispatcher

4. Starts an `asyncio` TCP server
   - default bind: `0.0.0.0:9100`

5. Starts `prune_loop`
   - periodically removes stale registered game servers

### 4.2 Gateway startup: `titan_binary_gateway.py`

When you launch `titan_binary_gateway.py`, it does the following:

1. Builds a `GatewayEventBus`
   - only used for the custom binary protocol path, not the original Homeworld native flow

2. Loads accepted `ValidVersions`
   - from `--version-str`, `--valid-version`, or `--valid-versions-file`

3. Builds a `BinaryGatewayServer`
   - stores the public host/port configuration
   - optionally loads Auth1 keys from `--keys-dir`

4. Builds a `RoutingServerManager`
   - owns the base routing listener and any extra dynamic routing listeners

5. Starts listeners for:
   - `15101` gateway
   - `15100` routing
   - `2021` firewall probe
   - optional admin dashboard

The gateway is the public face of the system.
If the gateway is down, the original game cannot connect, even if `won_server.py` is healthy.

## 5. Client Bootstrap: How the Game Is Pointed at the Server

The client bootstrap path is now the standalone installer in `installer/hwclient_setup.cs`.
`prepare_homeworld_client.bat` is the earlier batch-based version and is useful as historical context, but the installer is the supported friend-distribution path.

Its job is to make an unmodified Homeworld install trust and find your server.

It does three things:

1. Installs a valid WON Homeworld CD key
   - writes the WON registry key directly
   - also mirrors the plain Sierra key if needed

2. Writes `NetTweak.script`
   - sets `DIRSERVER_IPSTRINGS`
   - sets `DIRSERVER_PORTS`
   - sets `PATCHSERVER_IPSTRINGS`
   - sets `PATCHSERVER_PORTS`

3. Installs `kver.kp`
   - either from a sibling `keys\\kver.kp`
   - or from the embedded fallback payload in the batch file

This means the client no longer needs:

- a Python installer
- a `hosts` file hack

The critical idea is:

- `NetTweak.script` tells Homeworld where to connect
- `kver.kp` tells Homeworld which verifier public key to trust

If those two do not match the server you are actually running, login will fail.

## 6. End-to-End Request Flow

This is the most important mental model in the whole system.

### 6.1 Step 1: Homeworld checks `/TitanServers`

The client first connects to `15101` and issues a Titan directory query for `/TitanServers`, usually asking for `HomeworldValidVersions`.

Code path:

- gateway accepts TCP in `BinaryGatewayServer.handle_client`
- auto-detects Titan native framing in `_is_titan_native`
- enters `_handle_titan_native`
- routes a directory get request through `_dispatch_titan`
- parses it with `_decode_dir_get`
- builds the reply with `_titan_dir_get_reply_body`

Why this matters:

- this is how the client learns the auth server address
- this is how it learns the routing/factory server addresses
- this is where version gating happens

When you see logs like:

```text
DirGet path='/TitanServers' svc_filter='HomeworldValidVersions'
```

you are in this phase.

### 6.2 Step 2: Homeworld performs Auth1 login

After version discovery, the client opens another connection to `15101` and starts the Auth1 login handshake.

Code path:

- `_handle_titan_native`
- `won_crypto.parse_tmessage`
- `_handle_auth1_connection`

There are two supported client behaviors:

1. Full flow
   - `GetPubKeys`
   - `GetPubKeysReply`
   - `LoginRequestHW`
   - `ChallengeHW`
   - `ConfirmHW`
   - `LoginReply`

2. Cached-key short flow
   - client skips `GetPubKeys`
   - starts directly at `LoginRequestHW`

Inside `_handle_auth1_connection`, the gateway:

- parses the login request
- decrypts the session key with ElGamal
- sends a challenge encrypted with that session key
- accepts the confirm packet
- generates a user certificate
- sends `LoginReply` with:
  - the signed certificate
  - the encrypted user private key

This is where the cryptography in `won_crypto.py` is used.

### 6.3 Step 3: Homeworld performs Auth1Peer

After basic Auth1 login, the client performs an Auth1Peer handshake for an encrypted session to either:

- the directory role
- the factory role

Code path:

- `_handle_auth1_peer_connection`

This method:

- verifies the presented client certificate
- creates a temporary server certificate
- exchanges `SecretA` / `SecretB`
- derives the session context
- creates a `PeerSession`

The `PeerSession` stores:

- `session_key`
- `session_id`
- `role`
- `sequenced`
- `in_seq`
- `out_seq`

Why this matters:

- directory sessions become encrypted follow-up directory queries
- factory sessions become encrypted start-process requests

### 6.4 Step 4: Encrypted directory session

If the Auth1Peer role is directory, the gateway enters `_handle_directory_session`.

This is a short encrypted follow-up exchange:

- read one encrypted directory request
- decrypt it
- build a normal directory reply
- encrypt the reply
- send it back
- close

This is how later directory lookups, such as `/Homeworld`, are served after peer auth.

### 6.5 Step 5: `/Homeworld` directory lookup

The client queries `/Homeworld` to discover visible rooms and factory entries.

Code path:

- `_titan_dir_get_reply_body`
- if `path == "/Homeworld"`

The gateway builds the room list from:

- in-process routing listeners owned by `RoutingServerManager`
- and, if needed, fallback entities from the backend directory

For each visible room, the reply can include data objects like:

- `Description`
- `RoomFlags`
- `__RSClientCount`

Factory entries are also surfaced here so Homeworld can:

- populate its server chooser
- know where to send launch requests

### 6.6 Step 6: Lobby and routing traffic on port 15100+

Once the client moves into the routing/lobby world, it stops using `15101` for most room activity and moves to routing server ports.

That logic is owned by:

- `SilencerRoutingServer`
- `RoutingServerManager`

`SilencerRoutingServer` has two personalities:

1. Legacy "Silencer" room behavior
   - handled by `_handle_silencer_session`
   - keeps compatibility with older conflict-listing behavior

2. Native Homeworld routing behavior
   - handled by `_handle_native_client`
   - this is the real peer-authenticated routing flow used by the original game

In the native path, the server handles:

- `RegisterClient`
- `GetClientList`
- `SubscribeDataObject`
- `CreateDataObject`
- `ReplaceDataObject`
- `RenewDataObject`
- `DeleteDataObject`
- `SendData`
- `SendDataBroadcast`
- chat and group change notifications

Internally, `SilencerRoutingServer` keeps room state in memory:

- native client list
- subscriptions
- data objects
- room metadata
- room password

This is why a lot of routing behavior is in the gateway, not in the backend.
The backend is authoritative for long-lived state, but live packet fanout happens in the routing server object itself.

### 6.7 Step 7: Starting a game

When the host launches a game, the Homeworld client sends a factory start-process request.

Code path:

- Auth1Peer factory role
- `_handle_factory_session`

Inside `_handle_factory_session`, the gateway:

1. decrypts the factory request
2. parses the desired process name
3. decides which routing port to use
4. asks `RoutingServerManager` for a room/game listener if needed
5. calls the backend with:
   - `REGISTER_FACTORY`
   - `FACTORY_START_PROCESS`
6. sends a factory status reply containing the selected routing port

Important nuance:

The current Python stack does not launch an external dedicated game binary.
Instead, it allocates or reuses an in-process routing listener and reports that port back to Homeworld.

That is why you can see logs like:

```text
Factory(session): backend FACTORY_START_PROCESS failed: backend_no_response
```

and still have the actual game routing work.

The in-process routing manager is doing the real heavy lifting.

### 6.8 Step 8: Players join the game routing port

After the factory reply, both clients connect to the returned routing port, such as `15102`.

From that point on:

- the same `SilencerRoutingServer` native routing logic relays peer data
- Homeworld game traffic is carried as routing peer data packets
- data objects represent room/game metadata

This is the point where map transfer, lobby state, and in-game exchange become visible in routing logs.

### 6.9 Step 9: Event push and tooling-only paths

The gateway also supports a custom big-endian binary protocol for testing and tooling.

That path is not used by the original Homeworld client.

It exists so helper tools can:

- log in
- register players
- create or join lobbies
- poll or receive events

The relevant pieces are:

- `ConnectionContext`
- `GatewayEventBus`
- `encode_frame`
- `decode_frame`
- `_handle_custom_protocol`
- `_push_events_loop`
- `_publish_post_action_events`

This is useful for test clients and experiments, but it is not the main production path for original Homeworld traffic.

## 7. File-by-File Code Walkthrough

This section is the "block by block" tour.

## 7.1 `won_server.py`

This file is the internal backend.

### Block A: Constants and dataclasses

At the top of the file are:

- directory object name constants
- `Player`
- `Lobby`
- `GameServer`
- `Factory`

These are the core in-memory models.

They are intentionally small and plain.
The backend keeps its complexity in the state manager, not in fancy model classes.

### Block B: `StateStore`

`StateStore` owns SQLite setup and schema creation.

Key responsibilities:

- open the DB
- enable WAL
- create tables
- expose a connection to the higher-level state manager

The schema includes:

- `users`
- `players`
- `lobbies`
- `lobby_players`
- `game_servers`
- `factories`
- `directory_entities`
- `sessions`
- `events`

This tells you what the backend considers durable state.

### Block C: `WONLikeState`

`WONLikeState` is the real backend brain.

Think of it as:

- in-memory cache
- business rules layer
- persistence coordinator

Its responsibilities break down into a few groups.

#### C1. Load and bootstrap

- `_load_from_db`
- `_bootstrap_directory`

These reconstruct runtime state from SQLite and ensure the directory tree starts with the expected roots.

#### C2. Persistence helpers

- `_persist_table_replace`
- `_persist_players`
- `_persist_lobbies`
- `_persist_servers`
- `_persist_factories`
- `_persist_directory`
- `_persist_sessions`
- `_persist_events`

These methods are very literal: they push the current in-memory view back into the DB.

This backend prefers simple full-table replacement in several places instead of trying to be clever with partial updates.

#### C3. Directory/data-object shaping

- `_room_data_objects`
- `_factory_data_objects`

These convert live lobby/factory state into the data object payloads that the gateway later exposes in directory replies.

#### C4. Event creation

- `_emit_event`

This is the backend's event queue writer.
It increments `event_seq`, appends events per player, and persists them.

#### C5. Auth/session helpers

- `create_user`
- `login`
- `require_token`

This is only for the backend JSON/custom protocol world.
It is not the same thing as the native Homeworld Auth1 certificate flow.

That distinction is important:

- backend login creates app-level sessions and tokens
- native Auth1 creates WON-style cryptographic identity material for the original client

#### C6. Player and lobby operations

- `upsert_player`
- `create_lobby`
- `join_lobby`
- `leave_lobby`
- `list_lobbies`

These are straightforward state transitions:

- update the lobby
- update directory exposure
- update routing membership
- persist
- emit events

#### C7. Factory and server operations

- `register_server`
- `register_factory`
- `factory_start_process`
- `factory_process_stopped`
- `prune_stale_servers`

These model available game capacity.
They do not themselves speak Titan; they just record the state that the gateway or test tools care about.

#### C8. Matchmaking and game launch

- `matchmaking`
- `start_game_from_lobby`

`start_game_from_lobby` is especially important.
It decides:

- whether an existing game server can be reused
- whether a factory should be used
- which players are included in the launch payload

It then emits a `game_launch` event.

#### C9. Titan-friendly directory/routing helpers

- `dir_upsert`
- `dir_list`
- `route_join`
- `route_set_data_object`
- `route_get_data_object`
- `register_route_client`
- `route_send_chat`
- `poll_events`

These are the narrow backend hooks the gateway uses.

### Block D: `serialize_lobby` and `serialize_server`

These convert internal dataclasses into plain dictionaries suitable for:

- backend JSON replies
- launch payloads
- testing tools

### Block E: `WONLikeProtocolServer`

This is the JSON command server that sits on port `9100`.

It has two key methods:

- `handle_client`
- `handle_request`

`handle_client`:

- reads one JSON object per line
- calls `handle_request`
- writes one JSON reply per line

`handle_request` is a large action dispatcher.
It maps action strings like:

- `AUTH_LOGIN`
- `REGISTER_PLAYER`
- `CREATE_LOBBY`
- `JOIN_LOBBY`
- `REGISTER_FACTORY`
- `FACTORY_START_PROCESS`
- `TITAN_DIR_GET`
- `TITAN_START_GAME`

to the state methods described above.

### Block F: Background loop and CLI

- `prune_loop`
- `run_server`
- `main_async`
- `build_parser`

This is the process bootstrap layer.

## 7.2 `titan_binary_gateway.py`

This is the biggest file and the most important one for understanding real Homeworld compatibility.

### Block A: Direct-execution import bootstrap

At the top, the file adjusts `sys.path` so it can be run either from:

- the repo layout
- a standalone VPS layout

This is there so the same file works both locally and after deployment as `won_oss_server/...`.

### Block B: `DashboardLogHandler`

This is a simple in-memory ring buffer of logs used by the admin dashboard.

It is not part of the game protocol.
It only exists to make local inspection easier.

### Block C: Protocol constants and low-level helpers

This large section defines:

- message IDs
- routing constants
- factory constants
- directory flag constants

and helpers such as:

- `_is_titan_native`
- `_titan_recv`
- `_titan_wrap`
- `_routing_recv`
- `_routing_wrap`
- `_parse_*`
- `_build_*`

This block is the wire-format toolbox.

If you want to know:

- how a packet is framed
- how a packet is parsed
- how a packet is rebuilt

this is where you look.

### Block D: `SilencerRoutingServer`

This class is the heart of the lobby/game routing side.

It owns:

- room-local client state
- room-local data objects
- room-local subscriptions
- room-local room metadata

Its methods break down into three groups.

#### D1. Room bookkeeping and snapshots

- `_touch_native_client`
- `_alloc_native_client_id`
- `can_host_room`
- `is_directory_visible`
- `native_directory_entry`
- `dashboard_snapshot`

These support routing management and dashboard visibility.

#### D2. Delivery helpers

- `_send_native_route_reply`
- `_send_native_route_client_reply`
- `_broadcast_native_route_chat`
- `_broadcast_native_route_peer_data`
- `_broadcast_native_route_group_change`
- `_broadcast_native_route_data_object`

These methods actually fan packets out to connected clients.
This is where live packet relay happens.

#### D3. Session handlers

- `_handle_native_client`
- `_handle_silencer_session`
- `handle_client`

`handle_client` first decides whether the incoming routing connection is:

- a native Auth1Peer Homeworld routing client
- or a simpler legacy Silencer-style conflict-list client

Then it dispatches accordingly.

`_handle_native_client` is the important one for real multiplayer.
That is where routing registration, data objects, chat, peer data, and disconnect handling live.

### Block E: `RoutingServerManager`

This class owns the set of routing listeners.

Responsibilities:

- start the base routing listener
- allocate new routing listeners in a port range
- reuse listeners that can host a room
- build directory-visible routing entries
- aggregate dashboard snapshots across all rooms

The key idea is:

the system does not have a single monolithic routing server object.
It has a manager plus one `SilencerRoutingServer` per routing listener.

That is how game rooms can move onto dynamic ports like `15102`.

### Block F: Firewall probe and admin dashboard

This part includes:

- `_handle_firewall_probe`
- `AdminDashboardServer`

The firewall probe is deliberately simple:

- accept TCP
- close immediately

The admin dashboard is HTTP-only and local by default.
It shows:

- gateway state
- routing room snapshots
- activity summaries
- database snapshots
- recent logs

### Block G: Connection context and in-process event bus

This block defines:

- `ConnState`
- `ConnectionContext`
- `PeerSession`
- `GatewayEventBus`

These are support structures:

- `ConnectionContext` is for the custom binary client path
- `PeerSession` is for native Auth1Peer encrypted sessions
- `GatewayEventBus` is an in-process pub/sub helper

### Block H: Custom binary protocol helpers

This includes:

- `_to_wire_map`
- `_from_wire_map`
- `encode_frame`
- `decode_frame`
- `opcode_to_action`
- `action_to_response_opcode`

This is not Homeworld-native.
It exists so tooling can talk to the gateway in a simpler binary framing.

### Block I: Backend bridge

- `call_backend`

This is the main bridge from gateway to backend.

It:

- opens a TCP connection to `won_server.py`
- sends one JSON action
- reads one JSON response
- closes

That is the core architectural seam between compatibility logic and state logic.

### Block J: `BinaryGatewayServer`

This class is the public gateway brain.

Think of it as the top-level coordinator for all public Titan-facing behavior.

Its major responsibilities are:

#### J1. Process-level state

Stored in `__init__`:

- backend address
- public host/port
- accepted versions
- auth key state
- peer session table
- activity logs
- routing manager reference

#### J2. Visibility and dashboard state

- `record_activity`
- `_activity_snapshot`
- `_ip_activity_snapshot`
- `dashboard_snapshot`

#### J3. Key loading and certificate construction

- `_load_keys`
- `_build_user_cert`

This is where verifier/auth DER keys are loaded and converted into a signed public key block and Auth1 certificates.

#### J4. Auth1 server flow

- `_handle_auth1_connection`
- `_build_auth1_login_reply_with_key`

This is the main Homeworld login path.

#### J5. Auth1Peer flow

- `_alloc_peer_session_id`
- `_handle_auth1_peer_connection`
- `_handle_directory_session`
- `_handle_factory_session`

This is the encrypted follow-up session layer after Auth1 login.

#### J6. Tooling protocol translation

- `_handle_titan_packet`
- `_push_events_loop`
- `_publish_post_action_events`

These are for the custom binary/testing path.

#### J7. Titan native connection handling

- `_handle_titan_native`
- `_dispatch_titan`
- `_titan_dir_get_reply_body`
- `_titan_dir_get_reply`

This is where:

- the real Homeworld client lands
- directory replies are built
- version checks are answered
- one-shot native Titan packets are dispatched

`_titan_dir_get_reply_body` is one of the most important methods in the whole codebase because it decides what world the client believes exists.

#### J8. Entry point multiplexer

- `_handle_custom_protocol`
- `handle_client`

`handle_client` is the first public entry point after accept.
It chooses:

- Titan native path
- or custom protocol path

based on the first four bytes.

### Block K: Process bootstrap

- `main_async`
- `build_parser`

This is where the gateway process:

- loads config
- loads keys
- creates the routing manager
- starts all listeners
- prints the public addresses

## 7.3 `won_crypto.py`

This file is the cryptographic implementation layer.

You can think of it in four chunks.

### Chunk A: DER encoding/decoding

- `_der_length`
- `_der_integer`
- `_der_sequence`
- parse helpers
- `encode_public_key`
- `encode_private_key`
- `decode_public_key`
- `decode_private_key`

This gives the project a stable way to read and write the key material stored on disk.

### Chunk B: NR-MD5 signatures

- `_nr_encode_hash`
- `nr_md5_sign`
- `nr_md5_verify`

This is used for:

- signing the Auth1 public key block
- verifying certificates in peer-auth flows

### Chunk C: ElGamal

- `eg_encrypt`
- `eg_decrypt`

This is used for:

- session key exchange
- SecretA / SecretB exchange in Auth1Peer

### Chunk D: WON/Titan message builders

- `build_tmessage`
- `parse_tmessage`
- `build_auth1_pubkey_block`
- `build_auth1_certificate`
- `build_auth1_pubkeys_reply`
- `build_auth1_challenge`
- `build_auth1_login_reply`
- `parse_auth1_login_request`

This is the part that turns raw crypto primitives into actual on-wire WON Auth1 structures.

### Chunk E: Blowfish helpers

- `_get_blowfish`
- `bf_encrypt`
- `bf_decrypt`

These are used for the symmetric encrypted parts of the Auth1 flow.

## 7.4 `titan_messages.py`

This is a small codec file for the custom binary/testing protocol.

It is not the real Homeworld native Titan implementation.

Its role is to provide simple structured messages for:

- auth login
- directory get
- route register
- route join
- route chat
- route data object replies

It exists so tests and tools do not need to manually build bytes every time.

## 7.5 `installer/hwclient_setup.cs`

This is the friend-distribution client bootstrap installer.

Its important blocks are:

1. argument and path handling
2. admin check
3. game directory discovery
4. bundled CD key install
5. existing `NetTweak.script` backup
6. new `NetTweak.script` write
7. `kver.kp` install
   - sibling file if available
   - embedded fallback otherwise

The script is designed so a friend can:

- drop it beside `Homeworld.exe`
- run as Administrator
- pass your server host

and be done.

## 7.6 `generate_keys.py`

This is a one-time utility script.

It:

1. generates shared DSA parameters
2. generates a verifier keypair
3. generates an auth server keypair
4. writes DER files
5. writes `kver.kp` as a copy of the verifier public key

Important rule:

the server's keys and the client's `kver.kp` must stay in sync.

If you regenerate keys, clients need the matching `kver.kp`.

## 7.7 `packet_sniffer_framework.py`

This is a utility, but a very useful one.

It provides:

- `proxy`
  a TCP MITM proxy that logs both directions as NDJSON

- `summary`
  a quick summarizer for the NDJSON capture

Use this when:

- reverse-engineering a missing message type
- confirming packet ordering
- comparing Homeworld behavior against your gateway

## 7.8 `titan_bridge.py`

This is a text-oriented bridge into the backend.

It is useful for:

- quick manual testing
- smoke-testing backend actions without launching Homeworld

It translates simple text commands into backend JSON actions.

This is a developer convenience tool, not part of the production Homeworld path.

## 8. Read the Code in This Order

If you are tired or new to the codebase, read it in this order:

1. `installer/hwclient_setup.cs`
   Understand how the client is pointed at the server.

2. `generate_keys.py`
   Understand where `kver.kp` and the private keys come from.

3. `won_crypto.py`
   Skim the names so Auth1 logs stop feeling magical.

4. `won_server.py`
   Understand the backend state model and action vocabulary.

5. `titan_binary_gateway.py`
   Read this in layers:
   - constants and helpers
   - `BinaryGatewayServer`
   - `SilencerRoutingServer`
   - `RoutingServerManager`
   - `main_async`

6. `packet_sniffer_framework.py`
   Keep this in mind for debugging unknown packet flows.

## 9. How to Map Log Lines Back to Code

When you see a log prefix, it usually maps cleanly to a code block.

- `Auth1:`
  `BinaryGatewayServer._handle_auth1_connection`

- `Auth1Peer:`
  `BinaryGatewayServer._handle_auth1_peer_connection`

- `DirGet:`
  `BinaryGatewayServer._dispatch_titan` and `_titan_dir_get_reply_body`

- `Dir(session):`
  `BinaryGatewayServer._handle_directory_session`

- `Factory(session):`
  `BinaryGatewayServer._handle_factory_session`

- `Routing(native):`
  `SilencerRoutingServer._handle_native_client` and the routing broadcast helpers

- `Routing(manager):`
  `RoutingServerManager`

- `Firewall probe`
  `_handle_firewall_probe`

This mapping is worth memorizing because it makes debugging much faster.

## 10. Important Design Choices

These are the non-obvious architectural decisions that explain why the code looks the way it does.

### 10.1 Compatibility is concentrated in the gateway

The backend is intentionally simple and JSON-based.
All ugly protocol compatibility work is pushed into the gateway.

That is why `titan_binary_gateway.py` is large and `won_server.py` is comparatively clean.

### 10.2 Live room behavior is mostly in-memory

The backend persists durable state, but live routing fanout is owned by the routing server objects in memory.

That is why:

- chat
- data object broadcasts
- peer data broadcasts
- dynamic room listeners

are handled in `SilencerRoutingServer`, not in SQLite.

### 10.3 The factory path is partly simulated

The current system models dedicated server launching well enough for the client protocol, but it does not launch an external original WON routing executable.

Instead:

- the gateway allocates a routing listener
- the backend records that a process/server exists
- the client is told which port to use

This is why the system can already host real games even though "managed process spawning" is still a placeholder.

### 10.4 There are two worlds in the same repo

There are really two protocol worlds here:

1. The real Homeworld-native Titan/WON path
2. The internal JSON/custom-tooling path

They overlap, but they are not the same.

When debugging original Homeworld multiplayer, focus on the native path first.

## 11. Current Limitations and Caveats

These are important for setting expectations.

- Native Auth1 currently issues certificates without a full real account system behind them.
  It is compatibility-first, not a secure public identity platform.

- `WONLikeProtocolServer._spawn_managed_process` is still a placeholder supervisor.

- Some backend warnings about factory start-process behavior are non-fatal if the routing manager already allocated the needed port.

- The admin dashboard is an operational aid, not an authoritative source of protocol truth.

- `README.md` contains some older notes that do not always match the newest code.
  When in doubt, trust the code and this walkthrough.

## 12. Practical Debugging Checklist

When something breaks, ask these questions in order.

### 12.1 Did the client point at the right server?

Check:

- `NetTweak.script`
- Wireshark destination IP and port
- `kver.kp` matches the server keys

### 12.2 Did the gateway receive the connection?

Check gateway logs for:

- `Titan native connection`
- `Auth1`
- `DirGet`

If you do not see them, the problem is before the gateway.

### 12.3 Did the request fail before or after backend bridging?

If the gateway logs show:

- packet parse messages but no backend call results, inspect gateway logic
- backend errors, inspect `won_server.py`

### 12.4 Is the failure in directory, auth, or routing?

Break it into layers:

1. `/TitanServers` version lookup
2. Auth1 login
3. Auth1Peer directory/factory
4. `/Homeworld` room listing
5. routing connect
6. game launch
7. peer data flow

That layering matches the code and keeps debugging sane.

## 13. Final Mental Model

If you remember nothing else, remember this:

- `won_server.py` is the state machine
- `titan_binary_gateway.py` is the language interpreter
- `SilencerRoutingServer` is the live room relay
- `RoutingServerManager` is the room/game port allocator
- `won_crypto.py` is the trust and handshake machinery
- `installer/hwclient_setup.cs` is what makes stock Homeworld trust your server

Everything else is support structure around those pieces.
