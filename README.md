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

## Cross-language interop verified

The Go and TS client implementations are wire-compatible with each other and with both server impls. Tested locally end-to-end (not yet in CI) with this matrix:

| Scenario | Verdict |
|---|---|
| Go client against Go server (same-impl loop) | ✅ |
| TS client against TS server (same-impl loop) | ✅ |
| TS client against Go server | ✅ |
| Go client against TS server | ✅ |
| TS-signed envelope decoded by Go reader | ✅ (`sender_signature` verifies cross-impl) |
| Go-signed envelope decoded by TS reader | ✅ (reverse direction also passes) |

**Versions** (the four pieces that have to agree byte-for-byte): `semp-go v0.5.1`, `semp-ts v0.5.2`, `semp-reference-server master`, `semp-reference-client` (this repo) `master`. Each impl reads the same TOML, the same SQLite schema, and the same cross-language test vectors at `semp-spec/vectors/v1.0.0/`.

**Reproduce**: bring up a Go+TS federation pair via `docker compose -f ../semp-reference-server/shared/deploy/docker-compose.federation.yml up -d --build`. Then drive `register` / `send` / `fetch` from either client impl against `domain-a.local` (Go) and `domain-b.local` (TS).

## Subcommands

`register`, `send`, `fetch`, `inbox`, `sent`, `read`, `keys`, `export`, `import`, `block`, `unblock`, `blocklist`, `status`. Both impls expose the same flags.

## Related repos

- [`semp-go`](https://github.com/semp-dev/semp-go): Go protocol library.
- [`semp-ts`](https://github.com/semp-dev/semp-ts): TypeScript protocol library.
- [`semp-spec`](https://github.com/semp-dev/semp-spec): protocol specification.
- [`semp-reference-server`](https://github.com/semp-dev/semp-reference-server): reference server (also polyglot).

## License

MIT.
