# SEMP Reference Client

A SEMP client (CLI + desktop GUI) that demonstrates the full protocol lifecycle: key generation, handshake, encrypted envelope composition, submission, fetching, decryption, key requests, session rekeying, and `.semp` file import/export.

Built on the [semp-go](https://github.com/semp-dev/semp-go) library and designed to work with the [semp-reference-server](https://github.com/semp-dev/semp-reference-server).

Two binaries:
- **`semp-client`** -- command-line interface
- **`semp-gui`** -- desktop GUI (Fyne-based)

## Quick Start (Local)

This walkthrough starts a local reference server and two clients (Alice and Bob) on the same machine.

### 1. Build the server

```bash
git clone https://github.com/semp-dev/semp-reference-server.git
cd semp-reference-server
go build -o semp-server ./cmd/semp-server
```

### 2. Configure and start the server

Create `semp.toml`:

```toml
domain = "example.com"
listen_addr = ":8443"

[database]
path = "semp.db"

[[users]]
address = "alice@example.com"

[[users]]
address = "bob@example.com"

[policy]
session_ttl = 300
permissions = ["send", "receive"]

[logging]
level = "info"
```

Start the server:

```bash
./semp-server -config semp.toml
```

The server generates domain keys and user keys automatically on first run and stores them in `semp.db`. You should see output like:

```
level=INFO msg="generated new domain keys" domain=example.com ...
level=INFO msg="generated user keys" address=alice@example.com ...
level=INFO msg="generated user keys" address=bob@example.com ...
level=INFO msg="listening" addr=:8443
```

### 3. Build the client

```bash
git clone https://github.com/semp-dev/semp-reference-client.git
cd semp-reference-client
go build -o semp-client ./cmd/semp-client
go build -o semp-gui ./cmd/semp-gui
```

### 4. Create client configs

```bash
cp config.example.toml alice.toml
cp config.example.toml bob.toml
```

**alice.toml:**
```toml
identity = "alice@example.com"
server = "ws://localhost:8443/v1/ws"
domain = "example.com"

[database]
path = "alice.db"

[tls]
insecure = true
```

**bob.toml:**
```toml
identity = "bob@example.com"
server = "ws://localhost:8443/v1/ws"
domain = "example.com"

[database]
path = "bob.db"

[tls]
insecure = true
```

### 5. Generate client keys

```bash
./semp-client -config alice.toml init
./semp-client -config bob.toml init
```

> **Note:** The server and client generate keys independently using the same algorithm suite (`SuiteBaseline`). The server recognises users listed in its config and maintains its own key store. The client maintains a separate local key store for decryption.

### 6. Send and receive

```bash
# Alice sends a message to Bob
./semp-client -config alice.toml send \
  -to bob@example.com \
  -subject "Hello SEMP" \
  -body "This is an end-to-end encrypted message."

# Bob fetches his messages
./semp-client -config bob.toml fetch

# Bob reads the message
./semp-client -config bob.toml inbox
./semp-client -config bob.toml read <message-id>
```

## Connecting to a Remote Server

To use the client against a deployed reference server (e.g. `semp.example.com`), adjust the client config:

```toml
identity = "alice@example.com"
server = "wss://semp.example.com/v1/ws"
domain = "example.com"

[database]
path = "alice.db"

[tls]
insecure = false
```

Key differences from local setup:
- **`server`** uses `wss://` (TLS) and points to the deployed server's hostname
- **`tls.insecure`** is `false` (enforces TLS -- the default for production)
- **`domain`** is the email domain (e.g. `example.com`), which may differ from the server hostname (`semp.example.com`)

The server must have TLS configured (directly or via a reverse proxy like Caddy) and the user must be listed in the server's `[[users]]` config.

## Cross-Domain Federation

Two servers on different domains can exchange messages via federation. For example, Alice on `alpha.com` can send to Bob on `beta.com`.

### Server setup

Each server needs to know about its federation peer. Add to **Server-Alpha** (`alpha.com`):

```toml
[[federation.peers]]
domain             = "beta.com"
endpoint           = "wss://semp.beta.com/v1/federate"
domain_signing_key = "<beta.com's Ed25519 signing public key, base64>"
```

And the reverse on **Server-Beta** (`beta.com`):

```toml
[[federation.peers]]
domain             = "alpha.com"
endpoint           = "wss://semp.alpha.com/v1/federate"
domain_signing_key = "<alpha.com's Ed25519 signing public key, base64>"
```

You can extract a server's domain signing key from its database:

```bash
sqlite3 semp.db "SELECT hex(public_key) FROM domain_keys WHERE key_type = 'signing';"
```

Or from its well-known endpoint:

```bash
curl https://semp.alpha.com/.well-known/semp/configuration
```

Alternatively, if DNS SRV/TXT records are configured per the [SEMP Discovery spec](https://github.com/semp-dev/semp-spec/blob/main/DISCOVERY.md), static peer configuration can be skipped -- the servers discover each other automatically.

### Client usage

From the client's perspective, cross-domain is transparent. Alice's client connects to her home server, and the server handles federation:

```bash
# Alice on alpha.com sends to Bob on beta.com
./semp-client -config alice.toml send \
  -to bob@beta.com \
  -subject "Cross-domain test" \
  -body "Federated delivery via SEMP."

# Bob on beta.com fetches from his server
./semp-client -config bob.toml fetch
```

The flow is:
1. Alice's client connects to Server-Alpha, requests Bob's keys (routed over federation)
2. Client encrypts and submits the envelope to Server-Alpha
3. Server-Alpha opens a federation session to Server-Beta and forwards the envelope
4. Bob's client connects to Server-Beta and fetches the message

## CLI Commands

| Command | Description |
|---------|-------------|
| `init` | Generate identity (Ed25519) and encryption (X25519) key pairs |
| `send` | Compose, encrypt, and submit an envelope |
| `fetch` | Fetch and decrypt all pending envelopes from the home server |
| `inbox` | List received messages |
| `sent` | List sent messages |
| `read <id>` | Display a decrypted message |
| `keys -address <addr>` | Request recipient keys via the in-session SEMP_KEYS protocol |
| `export <id> [-o file]` | Export a stored envelope as a `.semp` file |
| `import <file>` | Import, verify, and decrypt a `.semp` file |
| `status` | Show identity, key fingerprints, and server info |

### Send with attachments

```bash
./semp-client -config alice.toml send \
  -to bob@example.com \
  -subject "See attached" \
  -body "Report is attached." \
  -attach report.pdf,notes.txt
```

### Export / Import `.semp` files

```bash
./semp-client -config bob.toml export <message-id> -o message.semp
./semp-client -config alice.toml import message.semp
```

## Desktop GUI

Launch the GUI with the same TOML config:

```bash
./semp-gui -config alice.toml
```

The GUI provides a familiar email client layout:
- **Left sidebar** -- Inbox/Sent folder navigation + New Message button
- **Center panel** -- Message list with sender, subject, and date
- **Right panel** -- Full message detail with headers, body, and attachment info
- **Status bar** -- Identity, connection state, key fingerprints
- **Menu bar:**
  - File: Import/Export `.semp` files
  - Tools: Generate Keys, Lookup Keys, Connect, Fetch Messages
  - Help: Status, About

All network operations (connect, handshake, send, fetch, key lookup) run in background goroutines to keep the UI responsive. The client connects lazily on the first network operation.

## Architecture

```
cmd/semp-client/main.go        CLI entry point and subcommand dispatch
cmd/semp-gui/main.go           Desktop GUI entry point (Fyne)
internal/config/config.go       TOML configuration
internal/store/schema.go        SQLite schema
internal/store/sqlite.go        keys.PrivateStore implementation + message storage
internal/keygen/keygen.go       Key generation (Ed25519 + KEM)
internal/client/client.go       Core client: connect, handshake, session
internal/client/sender.go       Envelope composition and submission
internal/client/receiver.go     Envelope fetch and decryption
internal/client/rekey.go        Background session rekeying at 80% TTL
internal/gui/app.go             GUI shared state and bindings
internal/gui/layout.go          Window assembly and menu bar
internal/gui/sidebar.go         Folder navigation
internal/gui/messagelist.go     Message list (widget.List)
internal/gui/messagedetail.go   Message detail view
internal/gui/compose.go         Compose window
internal/gui/statusbar.go       Status bar
internal/gui/dialogs.go         Menu action handlers (import, export, keys, status)
internal/gui/background.go      Goroutine helpers for network operations
```

### Protocol Flow

```
Client                                      Server
  |                                           |
  |-- WebSocket upgrade (semp.v1) ---------> |
  |-- SEMP_HANDSHAKE (4-message exchange) -->|
  |<-- Session established (ID, TTL) --------|
  |                                           |
  |-- SEMP_KEYS (request recipient keys) --->|
  |<-- SEMP_KEYS (response) ----------------|
  |                                           |
  |-- SEMP_ENVELOPE (encrypted) ------------>|
  |<-- SEMP_SUBMISSION (per-recipient status)|
  |                                           |
  |-- SEMP_FETCH (request) ----------------->|
  |<-- SEMP_FETCH (response with envelopes) -|
  |                                           |
  |-- SEMP_REKEY (at 80% TTL) ------------->|
  |<-- SEMP_REKEY (accepted, new session) ---|
  |                                           |
  |-- close -------------------------------->|
```

### Cryptography

- **Suite:** `x25519-chacha20-poly1305` (SuiteBaseline)
- **Identity keys:** Ed25519
- **Encryption keys:** X25519 (KEM)
- **Envelope encryption:** ChaCha20-Poly1305 with fresh per-envelope keys
- **Key wrapping:** Per-recipient KEM encapsulation
- **Session keys:** Five derived keys (K_enc_c2s, K_enc_s2c, K_mac_c2s, K_mac_s2c, K_env_mac)

### Storage

Local SQLite database (pure-Go, no CGO) with tables for:
- `user_keys` / `domain_keys` -- key material (implements `keys.PrivateStore`)
- `messages` -- decrypted message metadata and raw envelopes
- `contacts` -- cached recipient encryption keys
- `device_certificates` -- scoped delegation certificates

## Dependencies

| Package | Purpose |
|---------|---------|
| `semp.dev/semp-go` | SEMP protocol library |
| `github.com/BurntSushi/toml` | Configuration parsing |
| `modernc.org/sqlite` | Pure-Go SQLite driver |
| `fyne.io/fyne/v2` | Desktop GUI framework (for semp-gui) |

## License

See [LICENSE](LICENSE).
