# impl/go

Go implementation of the reference SEMP client. Built on `semp.dev/semp-go`.

## Build

    go build -o semp-client ./cmd/semp-client

## Run

    ./semp-client -config ../../shared/config/config.example.toml status

## Test

    go test ./...

## Subcommands

`register`, `send`, `fetch`, `inbox`, `sent`, `read`, `keys`, `export`,
`import`, `block`, `unblock`, `blocklist`, `status`. See `cmd/semp-client/main.go`
for flags.

## Module layout

- `cmd/semp-client/`: CLI entry point.
- `internal/client/`: protocol-driving client library. `Connect`,
  `Handshake`, `Register`, `Send`, `Fetch`, background rekey at 80% TTL.
- `internal/config/`: TOML config loader.
- `internal/store/`: SQLite-backed `keys.PrivateStore` impl + message storage.
- `internal/keygen/`: key-generation helpers (test fixtures).
