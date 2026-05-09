/**
 * SQLite schema bootstrap.
 *
 * Loads `shared/schema/0001_init.sql` and applies it once per database.
 * Mirrors `impl/go/internal/store/schema.go` byte-for-byte: same
 * pragma sequence (WAL, foreign_keys, busy_timeout) and the same
 * `schema_migrations(version, applied_at)` ledger.
 *
 * @module
 */

import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import type { Database } from "better-sqlite3";

/** Resolve `shared/schema/0001_init.sql` from both dev and built layouts. */
function resolveSchemaPath(): string {
  // import.meta.url points to the running .js (dist) or .ts (tsx) file.
  const here = dirname(fileURLToPath(import.meta.url));

  // Built layout: <pkg>/dist/store/schema.js -> <pkg>/dist/shared/schema/0001_init.sql
  const builtCopy = resolve(here, "..", "shared", "schema", "0001_init.sql");
  if (existsSync(builtCopy)) {
    return builtCopy;
  }

  // Dev layout (tsx): <pkg>/src/store/schema.ts -> <pkg>/../../shared/schema/0001_init.sql
  const devSource = resolve(here, "..", "..", "..", "..", "shared", "schema", "0001_init.sql");
  if (existsSync(devSource)) {
    return devSource;
  }

  // Last-resort fallback: walk upward from `here` until we find shared/schema/0001_init.sql.
  let dir = here;
  for (let i = 0; i < 8; i++) {
    const candidate = resolve(dir, "shared", "schema", "0001_init.sql");
    if (existsSync(candidate)) {
      return candidate;
    }
    const parent = dirname(dir);
    if (parent === dir) {
      break;
    }
    dir = parent;
  }
  throw new Error("store: cannot locate shared/schema/0001_init.sql relative to the package");
}

/**
 * Apply pragmas, the schema, and post-schema migrations on a fresh
 * better-sqlite3 handle. Idempotent: repeat invocations are no-ops.
 */
export function applySchema(db: Database): void {
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.pragma("busy_timeout = 5000");

  // Migration ledger.
  db.exec(
    "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT)",
  );
  const row = db
    .prepare("SELECT version FROM schema_migrations WHERE version = ?")
    .get(1);

  if (row === undefined) {
    const sql = readFileSync(resolveSchemaPath(), "utf8");
    db.exec(sql);
    db.prepare(
      "INSERT INTO schema_migrations (version, applied_at) VALUES (?, datetime('now'))",
    ).run(1);
  }

  // Post-schema migrations. ALTER TABLE ADD COLUMN raises "duplicate
  // column name" when the column already exists; swallow that case.
  const migrations: string[] = [
    "ALTER TABLE device_certificates ADD COLUMN device_public_key TEXT NOT NULL DEFAULT ''",
  ];
  for (const stmt of migrations) {
    try {
      db.exec(stmt);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("duplicate column name") || msg.includes("already exists")) {
        continue;
      }
      throw err;
    }
  }
}
