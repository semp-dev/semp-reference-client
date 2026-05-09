# impl/

Language implementations of the reference client. Each impl reads the
same config schema (`shared/config/`), the same SQLite schema
(`shared/schema/`), and produces byte-identical wire output.

## Parity matrix

| Feature | `impl/go` | `impl/ts` |
|---|---|---|
| CLI subcommands | ✅ 13 (register, send, fetch, inbox, sent, read, keys, export, import, block, unblock, blocklist, status) | ✅ 13 |
| Transport: WebSocket (ws/wss) | ✅ | ✅ |
| Transport: HTTP/2 (http/https) | ✅ | ✅ |
| Crypto suite: x25519-chacha20-poly1305 | ✅ | ✅ |
| Crypto suite: pq-kyber768-x25519 | ✅ | ✅ |
| SQLite store | ✅ (modernc.org/sqlite) | ✅ (better-sqlite3) |
| `.semp` export/import | ✅ | ✅ |
| Background session rekey | ✅ | ✅ |

Both impls are CLI-only. There is no GUI in either implementation;
reference impls demonstrate protocol behavior, not UX.
