# shared/config/

`config.example.toml` is the starting point for any deployment. Copy it
and adjust for your user:

    cp config.example.toml alice.toml

Both implementations parse this same shape:

- `impl/go` uses `github.com/BurntSushi/toml`.
- `impl/ts` uses `smol-toml`.

The authoritative field reference is `../docs/config-schema.md`. If you
add a new field, document it there and update both impl parsers in the
same change.
