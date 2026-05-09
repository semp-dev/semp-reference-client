# shared/

Language-neutral assets consumed by every implementation under `impl/`.
If you need to change the database schema, the TOML config shape, or the
federation test harness, change it here; both `impl/go` and `impl/ts`
read from this directory (or carry a tracked-in-sync copy when language
constraints prevent direct reads).

## Contents

- **`config/`**: example TOML configuration file. Both impls' parsers
  consume this same shape; the `config-schema.md` doc in `docs/` is the
  authoritative field reference.
- **`schema/`**: SQLite DDL for the client store. The TS impl loads
  these files directly. The Go impl carries an inline copy because
  Go's `go:embed` cannot reach outside its module; the inline copy
  in `impl/go/internal/store/schema.go` MUST stay byte-identical to
  `0001_init.sql` here.
- **`docs/`**: cross-impl contracts that both implementations honor:
  - `config-schema.md`: TOML field reference.
  - `store-contract.md`: SQLite WAL settings, busy-timeout, single-process expectation.
  - `semp-file-format.md`: `.semp` export/import format (per ENVELOPE.md §11).
- **`scripts/`**: integration scripts. `test-federation.sh` accepts
  `IMPL=go|ts` to drive either implementation through the same scenario.
