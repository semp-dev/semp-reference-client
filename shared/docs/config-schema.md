# Config schema

TOML reference for both `impl/go` and `impl/ts`.

| Field | Type | Default | Description |
|---|---|---|---|
| `identity` | string | (required) | The user's SEMP address, e.g. `alice@example.com`. |
| `domain` | string | derived from `identity` | The user's home domain. |
| `server` | string | (required) | Home-server endpoint URL. `ws://` or `wss://` for the WebSocket binding; `http://` or `https://` for the HTTP/2 binding. |
| `suite` | string | `pq-kyber768-x25519` | Cryptographic algorithm suite. Either `pq-kyber768-x25519` (post-quantum hybrid) or `x25519-chacha20-poly1305` (baseline). |
| `database.path` | string | `semp-client.db` | Path to the SQLite database file. |
| `tls.insecure` | bool | `false` | Allow plaintext `ws://` / `http://` connections. Production deployments MUST leave this `false`. |

## Validation rules

- `identity` MUST contain exactly one `@`. The right-hand side is the
  domain.
- If `domain` is omitted, it is derived from `identity`.
- If `domain` is set, it MUST match the domain portion of `identity`.
- `server` MUST be a valid URL with one of the supported schemes.
- `suite` MUST be one of the two listed values; case-sensitive.

Both impl parsers MUST surface validation errors with byte-identical
messages so error output matches across implementations.
