# SEMP Reference Client

A command-line SEMP client that demonstrates the full protocol lifecycle: key generation, handshake, encrypted envelope composition, submission, fetching, decryption, key requests, session rekeying, and `.semp` file import/export.

Built on the [semp-go](https://github.com/semp-dev/semp-go) library and designed to work with the [semp-reference-server](https://github.com/semp-dev/semp-reference-server).

## Quick Start

### Prerequisites

- Go 1.24+ (uses `semp.dev/semp-go`)
- A running [semp-reference-server](https://github.com/semp-dev/semp-reference-server)

### Build

```bash
GONOSUMDB=semp.dev GOPROXY=direct go build -o semp-client ./cmd/semp-client
```

### Configure

Copy the example config for each user:

```bash
cp config.example.toml alice.toml
cp config.example.toml bob.toml
```

Edit each file:

```toml
# alice.toml
identity = "alice@example.com"
server = "ws://localhost:8443/v1/ws"
domain = "example.com"

[database]
path = "alice.db"

[tls]
insecure = true
```

```toml
# bob.toml
identity = "bob@example.com"
server = "ws://localhost:8443/v1/ws"
domain = "example.com"

[database]
path = "bob.db"

[tls]
insecure = true
```

### Generate Keys

```bash
./semp-client -config alice.toml init
./semp-client -config bob.toml init
```

> **Note:** The reference server also generates keys for configured users on startup. Both client and server use the same keygen logic (`crypto.SuiteBaseline`), but they maintain separate key stores. For the reference demo, ensure the server's config includes your users so the server recognises them during handshake.

### Send a Message

```bash
./semp-client -config alice.toml send \
  -to bob@example.com \
  -subject "Hello SEMP" \
  -body "This is an end-to-end encrypted message."
```

With attachments:

```bash
./semp-client -config alice.toml send \
  -to bob@example.com \
  -subject "See attached" \
  -body "Report is attached." \
  -attach report.pdf,notes.txt
```

### Fetch Messages

```bash
./semp-client -config bob.toml fetch
```

### List and Read Messages

```bash
./semp-client -config bob.toml inbox
./semp-client -config bob.toml read <message-id>
```

### Request Recipient Keys

```bash
./semp-client -config alice.toml keys -address bob@example.com
```

### Export / Import `.semp` Files

```bash
./semp-client -config bob.toml export <message-id> -o message.semp
./semp-client -config alice.toml import message.semp
```

### Check Status

```bash
./semp-client -config alice.toml status
```

## Commands

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

## Architecture

```
cmd/semp-client/main.go        CLI entry point and subcommand dispatch
internal/config/config.go       TOML configuration
internal/store/schema.go        SQLite schema
internal/store/sqlite.go        keys.PrivateStore implementation + message storage
internal/keygen/keygen.go       Key generation (Ed25519 + KEM)
internal/client/client.go       Core client: connect, handshake, session
internal/client/sender.go       Envelope composition and submission
internal/client/receiver.go     Envelope fetch and decryption
internal/client/rekey.go        Background session rekeying at 80% TTL
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

## License

See [LICENSE](LICENSE).
