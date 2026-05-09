# SQLite store contract

Pinned settings every impl applies on `InitDB`-equivalent:

| Pragma | Value | Reason |
|---|---|---|
| `journal_mode` | `WAL` | Concurrent reads while a write is in progress. |
| `foreign_keys` | `ON` | Enforce key-record / device-cert references. |
| `busy_timeout` | `5000` (ms) | Wait up to 5s for a competing writer to release the lock before failing. |

## Concurrency expectations

The client-side database is **single-process**. WAL allows concurrent
reads, but only one writer at a time. If two processes attempt to write
the same DB simultaneously, the second one waits up to `busy_timeout`
ms then returns a `database is locked` error.

Operators running multiple `semp-client` instances against the same
SQLite file will hit this. The reference impl does not coordinate
multi-process access; users wanting that should run a server tier in
front of the database.

## Driver semantics differ

- `impl/go` uses `modernc.org/sqlite` (pure-Go, async via `database/sql`).
- `impl/ts` uses `better-sqlite3` (native bindings, fully synchronous).

Both honor WAL and `busy_timeout` identically. The synchronous-vs-async
difference is internal to each impl and does not affect on-disk behavior
or wire output.

## Master-key encryption (server side)

When the server's TOML config sets `database.master_key`, private key
material is encrypted at rest with AES-256-GCM keyed by Argon2id over
the master_key. The encryption envelope MUST be byte-identical across
implementations so a database written by one impl is readable by the
other (relevant for the server repo only; the client does not currently
encrypt at rest with a master key).
