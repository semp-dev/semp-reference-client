# semp-reference-client

Reference SEMP client implementations. Demonstrates the full client-side protocol lifecycle: key registration, handshake, encrypted envelope composition, submission, fetching, decryption, key requests, session rekeying, and `.semp` import/export.

This repo is **CLI-only**. Reference implementations exist to demonstrate protocol behavior, not user experience; build your own GUI on top of these libraries.

## Layout

```
shared/        # language-neutral assets (config schema, SQL DDL, docs, scripts)
impl/
  go/          # Go implementation (built on semp.dev/semp-go)
  ts/          # TypeScript implementation (built on @sempdev/semp)
docker/        # multi-stage Dockerfiles + docker-compose.yml
```

Each implementation reads the same TOML config shape (`shared/config/`), the same SQLite schema (`shared/schema/`), and produces byte-identical wire output. Cross-impl interop is exercised by `shared/scripts/test-federation.sh`.

## Quick start

### Go

    cd impl/go
    go build -o semp-client ./cmd/semp-client
    ./semp-client -config ../../shared/config/config.example.toml status

### TypeScript

    cd impl/ts
    npm install
    npm run build
    node dist/cli.js -c ../../shared/config/config.example.toml status

### Federation smoke test

Drives a four-direction (same-domain × cross-domain × A→B + B→A) test against a live two-server federation:

    IMPL=go ALICE_PASSWORD=... BOB_PASSWORD=... shared/scripts/test-federation.sh
    IMPL=ts ALICE_PASSWORD=... BOB_PASSWORD=... shared/scripts/test-federation.sh

Both implementations MUST pass identically.

## Subcommands

`register`, `send`, `fetch`, `inbox`, `sent`, `read`, `keys`, `export`, `import`, `block`, `unblock`, `blocklist`, `status`. Both impls expose the same flags.

## Related repos

- [`semp-go`](https://github.com/semp-dev/semp-go): Go protocol library.
- [`semp-ts`](https://github.com/semp-dev/semp-ts): TypeScript protocol library.
- [`semp-spec`](https://github.com/semp-dev/semp-spec): protocol specification.
- [`semp-reference-server`](https://github.com/semp-dev/semp-reference-server): reference server (also polyglot).

## License

MIT.
