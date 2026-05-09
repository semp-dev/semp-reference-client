/**
 * Smoke test. Exercises the public surface end-to-end without an
 * actual SEMP server: validates that
 *
 *   1. `loadConfig` parses a TOML config and applies defaults.
 *   2. `initDB` materializes the schema; `SQLitePrivateStore`
 *      satisfies the `PrivateKeyStore` interface and round-trips
 *      key + message rows.
 *   3. `Client` constructs cleanly.
 *   4. The transport `newMemoryPair` import path works (sanity
 *      check that @sempdev/semp/transport is reachable).
 *
 * The federation harness is the cross-impl interop check; this file
 * only guarantees the local TS pieces fit together.
 *
 * @module
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { newMemoryPair } from "@sempdev/semp/transport";

import { describe, expect, it } from "vitest";

import { Client } from "../src/client/client.js";
import { generateEncryptionKeyPair, generateIdentityKeyPair, resolveSuite } from "../src/client/keygen.js";
import { loadConfig } from "../src/config/config.js";
import { newLogger } from "../src/logger.js";
import { SQLitePrivateStore, initDB } from "../src/store/sqlite.js";

function makeTempConfig(dir: string, override: Partial<{ identity: string; suite: string }> = {}): string {
  const dbPath = join(dir, "client.db");
  const cfgPath = join(dir, "client.toml");
  const identity = override.identity ?? "alice@example.test";
  const suite = override.suite ?? "x25519-chacha20-poly1305";
  const toml = [
    `identity = "${identity}"`,
    `domain = "example.test"`,
    `server = "wss://server.example.test/v1/ws"`,
    `suite = "${suite}"`,
    "",
    "[database]",
    `path = "${dbPath}"`,
    "",
    "[tls]",
    "insecure = false",
    "",
  ].join("\n");
  writeFileSync(cfgPath, toml, "utf8");
  return cfgPath;
}

describe("smoke", () => {
  it("loadConfig applies defaults and validates required fields", () => {
    const dir = mkdtempSync(join(tmpdir(), "semp-smoke-"));
    try {
      const cfgPath = makeTempConfig(dir);
      const cfg = loadConfig(cfgPath);
      expect(cfg.identity).toBe("alice@example.test");
      expect(cfg.domain).toBe("example.test");
      expect(cfg.server).toBe("wss://server.example.test/v1/ws");
      expect(cfg.tls.insecure).toBe(false);
      expect(cfg.database.path.endsWith("client.db")).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("loadConfig defaults the database path when omitted", () => {
    const dir = mkdtempSync(join(tmpdir(), "semp-smoke-"));
    try {
      const cfgPath = join(dir, "client.toml");
      writeFileSync(
        cfgPath,
        [
          'identity = "bob@example.test"',
          'server = "wss://srv.example.test/v1/ws"',
          "",
        ].join("\n"),
        "utf8",
      );
      const cfg = loadConfig(cfgPath);
      expect(cfg.database.path).toBe("semp-client.db");
      expect(cfg.suite).toBe("pq-kyber768-x25519");
      expect(cfg.domain).toBe("example.test");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("loadConfig rejects missing identity", () => {
    const dir = mkdtempSync(join(tmpdir(), "semp-smoke-"));
    try {
      const cfgPath = join(dir, "client.toml");
      writeFileSync(cfgPath, 'server = "wss://srv.example.test/v1/ws"\n', "utf8");
      expect(() => loadConfig(cfgPath)).toThrow(/identity is required/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("SQLitePrivateStore round-trips user keys and messages", () => {
    const dir = mkdtempSync(join(tmpdir(), "semp-smoke-"));
    try {
      const dbPath = join(dir, "store.db");
      const handle = initDB(dbPath);
      const store = new SQLitePrivateStore(handle.db);

      // User key insert + lookup.
      const id = generateIdentityKeyPair();
      const idFP = store.putUserKeyPair(
        "alice@example.test",
        "identity",
        "ed25519",
        id.publicKey,
        id.privateKey,
      );
      expect(idFP).toMatch(/^[0-9a-f]{64}$/);

      const enc = generateEncryptionKeyPair("x25519-chacha20-poly1305");
      const encFP = store.putUserKeyPair(
        "alice@example.test",
        "encryption",
        "x25519-chacha20-poly1305",
        enc.publicKey,
        enc.privateKey,
      );
      expect(encFP).not.toBe(idFP);

      const loadedPriv = store.loadUserPrivateKey("alice@example.test", "encryption");
      expect(loadedPriv).not.toBeNull();
      expect(loadedPriv?.privateKey.length).toBe(32);

      // PrivateKeyStore interface methods.
      const pk = store.loadPrivateKey(idFP);
      expect(pk.length).toBe(32);

      // Message round-trip.
      store.storeMessage({
        messageId: "m1",
        direction: "received",
        from: "bob@example.test",
        to: ["alice@example.test"],
        cc: [],
        subject: "hello",
        bodyText: "world",
        rawEnvelope: new Uint8Array([1, 2, 3]),
      });
      const got = store.getMessage("m1");
      expect(got).not.toBeNull();
      expect(got?.subject).toBe("hello");
      expect(got?.bodyText).toBe("world");
      expect(Array.from(got?.rawEnvelope ?? [])).toEqual([1, 2, 3]);

      const inbox = store.listMessages("received");
      expect(inbox.length).toBe(1);
      expect(store.listMessages("sent").length).toBe(0);

      handle.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("Client constructs and resolves the suite without crashing", () => {
    const dir = mkdtempSync(join(tmpdir(), "semp-smoke-"));
    try {
      const cfgPath = makeTempConfig(dir, { suite: "pq-kyber768-x25519" });
      const cfg = loadConfig(cfgPath);
      const handle = initDB(cfg.database.path);
      try {
        const store = new SQLitePrivateStore(handle.db);
        const logger = newLogger();
        const client = new Client(cfg, store, logger);
        expect(client.cfg.identity).toBe("alice@example.test");
        expect(client.suite).toBe("pq-kyber768-x25519");
        expect(client.session).toBeNull();
        expect(client.transport).toBeNull();
      } finally {
        handle.close();
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("resolveSuite picks the configured suite or falls back to baseline", () => {
    expect(resolveSuite("pq-kyber768-x25519")).toBe("pq-kyber768-x25519");
    expect(resolveSuite("x25519-chacha20-poly1305")).toBe("x25519-chacha20-poly1305");
    expect(resolveSuite("bogus")).toBe("x25519-chacha20-poly1305");
  });

  it("@sempdev/semp/transport newMemoryPair is reachable", async () => {
    const [a, b] = newMemoryPair();
    const msg = new TextEncoder().encode("ping");
    await a.send(msg);
    const received = await b.receive();
    expect(received).not.toBeNull();
    expect(new TextDecoder().decode(received as Uint8Array)).toBe("ping");
    await a.close();
    await b.close();
  });
});
