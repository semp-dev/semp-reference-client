# shared/schema/

Numbered SQLite migration files applied in lexicographic order.

## Files

- `0001_init.sql`: initial schema. Five tables: `domain_keys`,
  `user_keys`, `device_certificates`, `messages`, `contacts`.

## Migration tracking

Both impls create a `schema_migrations(version INTEGER PRIMARY KEY,
applied_at TEXT)` table on first init and record one row per applied
file (`version` = the leading integer in the filename).

## Cross-impl sync

The TS impl loads files from this directory directly. The Go impl
carries an inline string-literal copy in
`impl/go/internal/store/schema.go` because `go:embed` cannot reach
outside its module. **The inline Go copy MUST stay byte-identical to
`0001_init.sql` here.** When you change the schema, update both files
in the same commit.

A future improvement: a CI check that diffs the embedded Go const
against the file in this directory.
