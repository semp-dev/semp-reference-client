# semp-client (TypeScript)

TypeScript reference port of `impl/go`. CLI-only. Same config schema,
same SQLite schema, same per-command stdout shape as the Go reference.

## Requirements

- Node.js 22+
- npm (or compatible) to install dependencies. `better-sqlite3` builds
  a native module on install.

## Install

```sh
cd impl/ts
npm install
```

## Build

```sh
npm run build
```

Produces `dist/cli.js` (the executable bundle) and copies the shared
SQL schema into `dist/shared/schema/` so `dist/` is self-contained.

## Run

```sh
./bin/semp-client --config semp.toml status
# or after npm link:
semp-client --config semp.toml status
```

The federation harness uses single-dash long flags (`-config`,
`-password`, `-to`, etc.) to match the Go `flag` package convention.
The TS CLI accepts both `-foo` and `--foo` for the same options so
the same harness drives both impls.

## Test

```sh
npm test
```

Smoke test only. Cross-impl interop is covered by
`shared/scripts/test-federation.sh`.
