/**
 * SQLite-backed `PrivateKeyStore` plus message and contact tables.
 *
 * Mirrors `impl/go/internal/store/sqlite.go`. Same column names, same
 * value formats (ISO 8601 timestamps; raw bytes for public/private
 * keys; lowercase-hex fingerprints in `key_id`). Same `INSERT OR
 * REPLACE` semantics so re-registering a user overwrites the previous
 * record in place.
 *
 * better-sqlite3 is synchronous, matching the synchronous shape of
 * `PrivateKeyStore` in @sempdev/semp/keys.
 *
 * @module
 */

import BetterSqlite3 from "better-sqlite3";
import type { Database } from "better-sqlite3";

import type { DeviceCertificate } from "@sempdev/semp/keys";
import {
  type KeyStoreRecord,
  type KeyType,
  type PrivateKeyStore,
  type Revocation,
  fingerprint,
} from "@sempdev/semp/keys";

import { applySchema } from "./schema.js";

/** Convenience handle wrapping the open database. */
export interface SQLiteHandle {
  db: Database;
  close(): void;
}

/**
 * Open or create the SQLite file at `path`, apply pragmas + schema,
 * and return the underlying handle.
 */
export function initDB(path: string): SQLiteHandle {
  const db = new BetterSqlite3(path);
  applySchema(db);
  return {
    db,
    close: () => {
      db.close();
    },
  };
}

/** ISO 8601 UTC timestamp matching the Go impl's `time.RFC3339` format. */
function isoNow(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** Default user-key validity per impl/go (1 year). */
const UserKeyTTLMs = 365 * 24 * 60 * 60 * 1000;

/** Default domain-key validity per impl/go (2 years). */
const DomainKeyTTLMs = 2 * 365 * 24 * 60 * 60 * 1000;

/** Stored message row. */
export interface Message {
  messageId: string;
  direction: "sent" | "received";
  from: string;
  to: string[];
  cc: string[];
  subject: string;
  bodyText: string;
  rawEnvelope: Uint8Array;
  storedAt: string;
}

/** Cached contact row. */
export interface Contact {
  address: string;
  domain: string;
  encKeyId: string;
  encPubKey: string;
}

interface DomainKeyRow {
  algorithm: string;
  public_key: Buffer;
  key_id: string;
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
  revocation_reason: string | null;
  replacement_key_id: string | null;
}

interface UserKeyRow extends DomainKeyRow {
  key_type: string;
}

interface MessageRow {
  message_id: string;
  direction: string;
  from_addr: string;
  to_addrs: string;
  cc_addrs: string | null;
  subject: string | null;
  body_text: string | null;
  raw_envelope: Buffer | null;
  stored_at: string;
}

interface ContactRow {
  address: string;
  domain: string;
  enc_key_id: string;
  enc_pub_key: string;
  updated_at: string;
}

interface DeviceCertRow {
  user_id: string;
  device_id: string;
  device_public_key: string;
  issuing_device_key_id: string;
  scope_json: string;
  issued_at: string;
  expires_at: string | null;
  signature_json: string;
}

/**
 * SQLite-backed implementation of `PrivateKeyStore` plus the
 * reference-client local message / contact tables.
 */
export class SQLitePrivateStore implements PrivateKeyStore {
  readonly db: Database;

  constructor(db: Database) {
    this.db = db;
  }

  // -------------------------------------------------------------------------
  // KeyStore ; domain keys

  lookupDomainKey(domain: string): KeyStoreRecord | null {
    const row = this.db
      .prepare(
        `SELECT algorithm, public_key, key_id, created_at, expires_at,
                revoked_at, revocation_reason, replacement_key_id
           FROM domain_keys
          WHERE domain = ? AND key_type = 'signing'`,
      )
      .get(domain) as DomainKeyRow | undefined;
    if (row === undefined) {
      return null;
    }
    return mapDomainRow(row, "domain");
  }

  /** Mirror of impl/go's LookupDomainEncryptionKey. Not in the @sempdev/semp KeyStore interface. */
  lookupDomainEncryptionKey(domain: string): KeyStoreRecord | null {
    const row = this.db
      .prepare(
        `SELECT algorithm, public_key, key_id, created_at, expires_at,
                revoked_at, revocation_reason, replacement_key_id
           FROM domain_keys
          WHERE domain = ? AND key_type = 'encryption'`,
      )
      .get(domain) as DomainKeyRow | undefined;
    if (row === undefined) {
      return null;
    }
    return mapDomainRow(row, "domain");
  }

  // -------------------------------------------------------------------------
  // KeyStore ; user keys

  lookupUserKeys(address: string, keyTypes?: KeyType[]): KeyStoreRecord[] {
    const params: unknown[] = [address];
    let sql = `SELECT key_type, algorithm, public_key, key_id, created_at, expires_at,
                      revoked_at, revocation_reason, replacement_key_id
                 FROM user_keys WHERE address = ? AND revoked_at IS NULL`;
    if (keyTypes !== undefined && keyTypes.length > 0) {
      const placeholders = keyTypes.map(() => "?").join(",");
      sql += ` AND key_type IN (${placeholders})`;
      for (const t of keyTypes) {
        params.push(t);
      }
    }
    const rows = this.db.prepare(sql).all(...params) as UserKeyRow[];
    return rows.map((r) => {
      const rec = mapDomainRow(r, r.key_type as KeyType);
      rec.address = address;
      return rec;
    });
  }

  putRecord(rec: KeyStoreRecord): void {
    if (rec.key_type === "domain") {
      // Domain records arrive via putDomainPublic; mirror impl/go.
      return;
    }
    if (rec.address === undefined || rec.address === "") {
      throw new Error("store: putRecord on user key requires address");
    }
    const pubBytes = Buffer.from(rec.public_key, "base64");
    this.db
      .prepare(
        `INSERT OR REPLACE INTO user_keys
         (address, key_type, algorithm, public_key, key_id, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        rec.address,
        rec.key_type,
        rec.algorithm,
        pubBytes,
        rec.key_id,
        rec.created,
        rec.expires ?? "",
      );
  }

  putRevocation(keyId: string, rev: Revocation): void {
    this.db
      .prepare(
        `UPDATE user_keys SET revoked_at = ?, revocation_reason = ?, replacement_key_id = ? WHERE key_id = ?`,
      )
      .run(rev.revoked_at, rev.reason, rev.replacement_key_id ?? "", keyId);
    this.db
      .prepare(
        `UPDATE domain_keys SET revoked_at = ?, revocation_reason = ?, replacement_key_id = ? WHERE key_id = ?`,
      )
      .run(rev.revoked_at, rev.reason, rev.replacement_key_id ?? "", keyId);
  }

  // -------------------------------------------------------------------------
  // KeyStore ; device certificates

  lookupDeviceCertificate(deviceKeyId: string): DeviceCertificate | null {
    const row = this.db
      .prepare(
        `SELECT user_id, device_id, device_public_key, issuing_device_key_id, scope_json,
                issued_at, expires_at, signature_json
           FROM device_certificates WHERE device_key_id = ?`,
      )
      .get(deviceKeyId) as DeviceCertRow | undefined;
    if (row === undefined) {
      return null;
    }
    const cert: DeviceCertificate = {
      type: "SEMP_DEVICE_CERTIFICATE",
      version: "1.0.0",
      account: row.user_id,
      device_id: row.device_id,
      device_public_key: row.device_public_key,
      issued_by: row.issuing_device_key_id,
      scope: JSON.parse(row.scope_json) as DeviceCertificate["scope"],
      issued_at: row.issued_at,
      expires_at: row.expires_at ?? "",
      signature: JSON.parse(row.signature_json) as DeviceCertificate["signature"],
    };
    return cert;
  }

  putDeviceCertificate(cert: DeviceCertificate): void {
    const pubBytes = Buffer.from(cert.device_public_key, "base64");
    const deviceKeyId = fingerprint(new Uint8Array(pubBytes.buffer, pubBytes.byteOffset, pubBytes.byteLength));
    this.db
      .prepare(
        `INSERT OR REPLACE INTO device_certificates
         (device_key_id, user_id, device_id, device_public_key, issuing_device_key_id,
          scope_json, issued_at, expires_at, signature_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        deviceKeyId,
        cert.account,
        cert.device_id,
        cert.device_public_key,
        cert.issued_by,
        JSON.stringify(cert.scope),
        cert.issued_at,
        cert.expires_at,
        JSON.stringify(cert.signature),
      );
  }

  // -------------------------------------------------------------------------
  // PrivateKeyStore

  loadPrivateKey(keyId: string): Uint8Array {
    const row = this.db
      .prepare(
        `SELECT private_key FROM user_keys WHERE key_id = ? AND private_key IS NOT NULL`,
      )
      .get(keyId) as { private_key: Buffer } | undefined;
    if (row !== undefined) {
      return new Uint8Array(row.private_key);
    }
    const dom = this.db
      .prepare(
        `SELECT private_key FROM domain_keys WHERE key_id = ? AND private_key IS NOT NULL`,
      )
      .get(keyId) as { private_key: Buffer } | undefined;
    if (dom !== undefined) {
      return new Uint8Array(dom.private_key);
    }
    throw new Error(`store: private key not found for ${keyId}`);
  }

  storePrivateKey(keyId: string, privateKey: Uint8Array): void {
    const buf = Buffer.from(privateKey);
    const res = this.db
      .prepare(`UPDATE user_keys SET private_key = ? WHERE key_id = ?`)
      .run(buf, keyId);
    if (res.changes === 0) {
      this.db
        .prepare(`UPDATE domain_keys SET private_key = ? WHERE key_id = ?`)
        .run(buf, keyId);
    }
  }

  // -------------------------------------------------------------------------
  // Reference-client helpers (mirror of impl/go's SQLiteStore methods)

  /** True if any keys are present for `address`. */
  hasUserKeys(address: string): boolean {
    const row = this.db
      .prepare(`SELECT COUNT(*) AS n FROM user_keys WHERE address = ?`)
      .get(address) as { n: number };
    return row.n > 0;
  }

  /**
   * Persist a user key pair. Returns the SHA-256 fingerprint of the
   * public key, used as `key_id` everywhere.
   */
  putUserKeyPair(
    address: string,
    keyType: KeyType,
    algorithm: string,
    pub: Uint8Array,
    priv: Uint8Array,
  ): string {
    const fp = fingerprint(pub);
    const created = isoNow();
    const expires = new Date(Date.now() + UserKeyTTLMs).toISOString().replace(/\.\d{3}Z$/, "Z");
    this.db
      .prepare(
        `INSERT OR REPLACE INTO user_keys
         (address, key_type, algorithm, public_key, private_key, key_id, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        address,
        keyType,
        algorithm,
        Buffer.from(pub),
        Buffer.from(priv),
        fp,
        created,
        expires,
      );
    return fp;
  }

  /**
   * Evict the cached domain key for `(domain, keyType)`. Used by the
   * verify-time self-heal path: when openAndVerify rejects an envelope
   * because the cached sender-domain signing key does not match the
   * key id on the wire, the receiver evicts the stale row and retries
   * with a force-refresh resolver. Returns the number of rows deleted.
   */
  evictDomainKey(domain: string, keyType: "signing" | "encryption"): number {
    const result = this.db
      .prepare(`DELETE FROM domain_keys WHERE domain = ? AND key_type = ?`)
      .run(domain, keyType);
    return Number(result.changes);
  }

  /** Persist a domain public key (private optional). Mirrors impl/go. */
  putDomainKey(
    domain: string,
    keyType: "signing" | "encryption",
    algorithm: string,
    pub: Uint8Array,
    priv?: Uint8Array,
  ): string {
    const fp = fingerprint(pub);
    const created = isoNow();
    const expires = new Date(Date.now() + DomainKeyTTLMs).toISOString().replace(/\.\d{3}Z$/, "Z");
    this.db
      .prepare(
        `INSERT OR REPLACE INTO domain_keys
         (domain, key_type, algorithm, public_key, private_key, key_id, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        domain,
        keyType,
        algorithm,
        Buffer.from(pub),
        priv === undefined ? null : Buffer.from(priv),
        fp,
        created,
        expires,
      );
    return fp;
  }

  /**
   * Load private + fingerprint for a user key by (address, key_type).
   * Returns null on miss.
   */
  loadUserPrivateKey(
    address: string,
    keyType: KeyType,
  ): { privateKey: Uint8Array; keyId: string } | null {
    const row = this.db
      .prepare(
        `SELECT private_key, key_id FROM user_keys
          WHERE address = ? AND key_type = ? AND revoked_at IS NULL`,
      )
      .get(address, keyType) as { private_key: Buffer | null; key_id: string } | undefined;
    if (row === undefined || row.private_key === null) {
      return null;
    }
    return { privateKey: new Uint8Array(row.private_key), keyId: row.key_id };
  }

  /**
   * Load public + fingerprint for a user key by (address, key_type).
   * Returns null on miss.
   */
  loadUserPublicKey(
    address: string,
    keyType: KeyType,
  ): { publicKey: Uint8Array; keyId: string } | null {
    const row = this.db
      .prepare(
        `SELECT public_key, key_id FROM user_keys
          WHERE address = ? AND key_type = ? AND revoked_at IS NULL`,
      )
      .get(address, keyType) as { public_key: Buffer; key_id: string } | undefined;
    if (row === undefined) {
      return null;
    }
    return { publicKey: new Uint8Array(row.public_key), keyId: row.key_id };
  }

  // -------------------------------------------------------------------------
  // Messages

  /** Persist a decrypted message row. */
  storeMessage(msg: {
    messageId: string;
    direction: "sent" | "received";
    from: string;
    to: string[];
    cc: string[];
    subject: string;
    bodyText: string;
    rawEnvelope: Uint8Array;
  }): void {
    this.db
      .prepare(
        `INSERT OR REPLACE INTO messages
         (message_id, direction, from_addr, to_addrs, cc_addrs, subject, body_text,
          raw_envelope, stored_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        msg.messageId,
        msg.direction,
        msg.from,
        JSON.stringify(msg.to),
        JSON.stringify(msg.cc),
        msg.subject,
        msg.bodyText,
        Buffer.from(msg.rawEnvelope),
        isoNow(),
      );
  }

  listMessages(direction: "sent" | "received"): Message[] {
    const rows = this.db
      .prepare(
        `SELECT message_id, direction, from_addr, to_addrs, cc_addrs, subject, body_text,
                raw_envelope, stored_at
           FROM messages WHERE direction = ? ORDER BY stored_at DESC`,
      )
      .all(direction) as MessageRow[];
    return rows.map(rowToMessage);
  }

  getMessage(messageId: string): Message | null {
    const row = this.db
      .prepare(
        `SELECT message_id, direction, from_addr, to_addrs, cc_addrs, subject, body_text,
                raw_envelope, stored_at
           FROM messages WHERE message_id = ?`,
      )
      .get(messageId) as MessageRow | undefined;
    if (row === undefined) {
      return null;
    }
    return rowToMessage(row);
  }

  // -------------------------------------------------------------------------
  // Contacts

  putContact(address: string, domain: string, encKeyId: string, encPubKey: string): void {
    this.db
      .prepare(
        `INSERT OR REPLACE INTO contacts (address, domain, enc_key_id, enc_pub_key, updated_at)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(address, domain, encKeyId, encPubKey, isoNow());
  }

  getContact(address: string): Contact | null {
    const row = this.db
      .prepare(
        `SELECT address, domain, enc_key_id, enc_pub_key, updated_at FROM contacts WHERE address = ?`,
      )
      .get(address) as ContactRow | undefined;
    if (row === undefined) {
      return null;
    }
    return {
      address: row.address,
      domain: row.domain,
      encKeyId: row.enc_key_id,
      encPubKey: row.enc_pub_key,
    };
  }
}

// ---------------------------------------------------------------------------
// Helpers

function mapDomainRow(row: DomainKeyRow, keyType: KeyType): KeyStoreRecord {
  const rec: KeyStoreRecord = {
    key_type: keyType,
    algorithm: row.algorithm,
    public_key: Buffer.from(row.public_key).toString("base64"),
    key_id: row.key_id,
    created: row.created_at,
  };
  if (row.expires_at !== null && row.expires_at !== "") {
    rec.expires = row.expires_at;
  }
  if (row.revoked_at !== null && row.revoked_at !== "") {
    const revocation: Revocation = {
      reason: (row.revocation_reason ?? "") as Revocation["reason"],
      revoked_at: row.revoked_at,
    };
    if (row.replacement_key_id !== null && row.replacement_key_id !== "") {
      revocation.replacement_key_id = row.replacement_key_id;
    }
    rec.revocation = revocation;
  }
  return rec;
}

function rowToMessage(row: MessageRow): Message {
  return {
    messageId: row.message_id,
    direction: row.direction as "sent" | "received",
    from: row.from_addr,
    to: parseJSONArray(row.to_addrs),
    cc: parseJSONArray(row.cc_addrs ?? "[]"),
    subject: row.subject ?? "",
    bodyText: row.body_text ?? "",
    rawEnvelope:
      row.raw_envelope === null ? new Uint8Array(0) : new Uint8Array(row.raw_envelope),
    storedAt: row.stored_at,
  };
}

function parseJSONArray(s: string): string[] {
  if (s === "" || s === "null") {
    return [];
  }
  try {
    const parsed = JSON.parse(s) as unknown;
    if (Array.isArray(parsed)) {
      return parsed.filter((x): x is string => typeof x === "string");
    }
    return [];
  } catch {
    return [];
  }
}
