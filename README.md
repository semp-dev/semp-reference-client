# SEMP Reference Client

A SEMP client (CLI + desktop GUI) that demonstrates the full protocol lifecycle: key registration, handshake, encrypted envelope composition, submission, fetching, decryption, key requests, session rekeying, and `.semp` file import/export.

Built on the [semp-go](https://github.com/semp-dev/semp-go) library and designed to work with the [semp-reference-server](https://github.com/semp-dev/semp-reference-server).

Two binaries:
- **`semp-client`** -- command-line interface
- **`semp-gui`** -- desktop GUI (Fyne-based)

## Quick Start (Local)

This walkthrough starts a local reference server and two clients on the same machine.

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
address  = "alice@example.com"
password = "changeme"

[[users]]
address  = "bob@example.com"
password = "changeme"

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

The server generates its domain keys on first run. User keys are registered by clients.

### 3. Build the client

```bash
git clone https://github.com/semp-dev/semp-reference-client.git
cd semp-reference-client
go build -o semp-client ./cmd/semp-client
go build -o semp-gui ./cmd/semp-gui
```

### 4. Create client configs

**alice.toml:**
```toml
identity = "alice@example.com"
server = "ws://localhost:8443/v1/ws"

[database]
path = "alice.db"

[tls]
insecure = true
```

**bob.toml:**
```toml
identity = "bob@example.com"
server = "ws://localhost:8443/v1/ws"

[database]
path = "bob.db"

[tls]
insecure = true
```

### 5. Register

Each user generates keys locally and registers with the server:

```bash
./semp-client -config alice.toml register -password changeme
./semp-client -config bob.toml register -password changeme
```

This generates Ed25519 identity and X25519 encryption key pairs on the client device, pushes only the public keys to the server, and caches the server's domain keys locally. **Private keys never leave the client device.**

### 6. Send and receive

```bash
# Alice sends a message to Bob
./semp-client -config alice.toml send \
  -to bob@example.com \
  -subject "Hello" \
  -body 'Just SEMPing real quick'

# Bob fetches his messages
./semp-client -config bob.toml fetch

# Bob reads the message
./semp-client -config bob.toml inbox
./semp-client -config bob.toml read <message-id>
```

### Example output

Real output from a live deployment:

**Alice sends:**
```
$ ./semp-client -config alice.toml send -to bob@example.com -subject "Hello" -body 'Just SEMPing real quick'
level=INFO msg=connected server=wss://semp.example.com/v1/ws
level=INFO msg="session established" session_id=06ERA4E8HSKAK83ZJQN5NBNXTC ttl=5m0s
level=INFO msg="envelope sent" message_id=alice@example.com-1776054028518410000 to=[bob@example.com]
Envelope submitted: alice@example.com-1776054028518410000
  bob@example.com: delivered
```

**Bob fetches:**
```
$ ./semp-client -config bob.toml fetch
level=INFO msg=connected server=wss://semp.example.com/v1/ws
level=INFO msg="session established" session_id=06ERA4P18PF4HPGEHAQX8HKNJM ttl=5m0s
level=INFO msg="fetched envelopes" count=1 drained=true

--- Message alice@example.com-1776054028518410000 ---
From:    alice@example.com
To:      bob@example.com
Subject: Hello
Body:
Just SEMPing real quick

1 message(s) fetched.
```

## Connecting to a Remote Server

```toml
identity = "alice@example.com"
server = "wss://semp.example.com/v1/ws"

[database]
path = "alice.db"

[tls]
insecure = false
```

Key differences from local setup:
- **`server`** uses `wss://` (TLS) and points to the deployed server's hostname
- **`tls.insecure`** is `false` (enforces TLS)
- The email domain (e.g. `example.com`) may differ from the server hostname (`semp.example.com`)

Register before first use:

```bash
./semp-client -config alice.toml register -password changeme
```

## Cross-Domain Federation

Two servers on different domains can exchange messages via federation. From the client's perspective, cross-domain messaging is transparent:

```bash
# Alice on alpha.com sends to Bob on beta.com
./semp-client -config alice.toml send \
  -to bob@beta.com \
  -subject "Cross-domain test" \
  -body "Federated delivery via SEMP."

# Bob on beta.com fetches from his server
./semp-client -config bob.toml fetch
```

Federation is automatic when both servers have DNS SRV/TXT records configured. The servers discover each other, exchange domain signing keys via well-known endpoints, and establish federation sessions on demand. No manual peer configuration required.

The flow:
1. Alice's client connects to Server-Alpha, requests Bob's keys (routed over federation)
2. Client encrypts and submits the envelope to Server-Alpha
3. Server-Alpha discovers Server-Beta via DNS SRV, fetches its domain key, opens a federation session, and forwards the envelope
4. Bob's client connects to Server-Beta and fetches the message

## CLI Commands

| Command | Description |
|---------|-------------|
| `register -password <pw>` | Generate keys locally and register public keys with the server |
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
  - Tools: Register, Lookup Keys, Connect, Fetch Messages
  - Help: Status, About

All network operations run in background goroutines to keep the UI responsive. The client connects lazily on the first network operation.

## Architecture

```
cmd/semp-client/main.go        CLI entry point and subcommand dispatch
cmd/semp-gui/main.go           Desktop GUI entry point (Fyne)
internal/config/config.go       TOML configuration
internal/store/schema.go        SQLite schema
internal/store/sqlite.go        keys.PrivateStore implementation + message storage
internal/keygen/keygen.go       Key generation (Ed25519 + KEM)
internal/client/client.go       Core client: connect, register, handshake, session
internal/client/sender.go       Envelope composition and submission
internal/client/receiver.go     Envelope fetch and decryption
internal/client/rekey.go        Background session rekeying at 80% TTL
internal/gui/                   Desktop GUI (Fyne widgets, dialogs, background ops)
```

### Key Provisioning

```
Client                                       Server
  |                                            |
  |  1. Generate Ed25519 + X25519 keys         |
  |     (private keys stay on device)           |
  |                                            |
  |  2. POST /v1/register ------------------>  |
  |     { address, password, public keys }     |
  |                                            |
  |  <-- 200 OK  ----------------------------- |
  |     { domain signing key,                  |
  |       domain encryption key }              |
  |                                            |
  |  3. Cache domain keys locally              |
  |  4. Ready to handshake and send            |
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
| `semp.dev/semp-go` v0.2.0 | SEMP protocol library |
| `github.com/BurntSushi/toml` | Configuration parsing |
| `modernc.org/sqlite` | Pure-Go SQLite driver |
| `fyne.io/fyne/v2` | Desktop GUI framework (for semp-gui) |

## License

See [LICENSE](LICENSE).
