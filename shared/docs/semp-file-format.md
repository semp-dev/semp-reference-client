# `.semp` file format

Both impls' `semp-client export` and `semp-client import` subcommands
produce and consume identical bytes for a given message.

## Format

A `.semp` file is a JSON-encoded `Envelope` value, exactly as it traveled
on the wire. The encoding follows ENVELOPE.md §11 (canonical wire form):
sorted keys, no insignificant whitespace, UTF-8.

## Producer / consumer

- Producer: `semp-client export <message-id> -o <path>` writes the
  raw envelope bytes from the local store to `<path>`. The bytes are
  whatever was received from the server (sender-signed, server-MAC'd).
- Consumer: `semp-client import <path>` reads the file, decrypts using
  the local user's private keys, verifies signatures, and stores the
  resulting message record.

## Cross-impl interop test

Build both `impl/go` and `impl/ts` clients, then:

    IMPL=go semp-client export <id> -o /tmp/m.semp
    IMPL=ts semp-client import /tmp/m.semp

This exercises the format contract. The reverse direction
(`IMPL=ts ... export` / `IMPL=go ... import`) MUST also succeed.

## Why no separate format spec

The format is just "one wire-form Envelope per file". The wire form
is pinned by ENVELOPE.md upstream. Don't write a separate spec here;
lean on the upstream document plus the cross-impl test.
