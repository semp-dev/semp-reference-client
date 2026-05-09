/**
 * TOML configuration loader for the SEMP reference client.
 *
 * Mirrors `impl/go/internal/config/config.go`: same field names, same
 * defaults, same validation. The TS variant adds an optional
 * `[logging]` section so the CLI's pino logger can be tuned without
 * recompiling; the Go impl wires this through `slog`.
 *
 * @module
 */

import { readFileSync } from "node:fs";

import { parse as parseToml } from "smol-toml";

/** Database settings. */
export interface DatabaseConfig {
  /** Filesystem path of the SQLite file. Default: "semp-client.db". */
  path: string;
}

/** TLS settings. */
export interface TLSConfig {
  /** Allow plain ws://. Default: false. */
  insecure: boolean;
}

/** Optional logging settings. */
export interface LoggingConfig {
  /** pino level: "trace" | "debug" | "info" | "warn" | "error" | "fatal". Default "info". */
  level?: string;
  /** "json" or "pretty". Default "pretty". */
  format?: "json" | "pretty";
}

/** Top-level client configuration shape. */
export interface Config {
  /** SEMP address ("user@domain"). Required. */
  identity: string;
  /** Home domain. Defaults to the suffix of `identity`. */
  domain: string;
  /** WebSocket or HTTP/2 server endpoint. Required. */
  server: string;
  /** Crypto suite identifier. Default: "pq-kyber768-x25519". */
  suite: string;
  database: DatabaseConfig;
  tls: TLSConfig;
  logging?: LoggingConfig;
}

/** Default suite mirrors impl/go. */
const DefaultSuite = "pq-kyber768-x25519";

/** Default SQLite filename mirrors impl/go. */
const DefaultDatabasePath = "semp-client.db";

/**
 * Load and validate a TOML config file. Throws on read error, parse
 * error, or missing required fields.
 */
export function loadConfig(path: string): Config {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    throw new Error(
      `config: read ${path}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  let parsed: unknown;
  try {
    parsed = parseToml(raw);
  } catch (err) {
    throw new Error(
      `config: parse ${path}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error(`config: parse ${path}: top-level value is not a table`);
  }
  const obj = parsed as Record<string, unknown>;

  const identity = stringField(obj, "identity") ?? "";
  if (identity === "") {
    throw new Error("config: identity is required");
  }
  if (!identity.includes("@")) {
    throw new Error("config: identity must be a valid address (user@domain)");
  }

  let domain = stringField(obj, "domain") ?? "";
  if (domain === "") {
    const at = identity.indexOf("@");
    domain = identity.slice(at + 1);
  }

  const server = stringField(obj, "server") ?? "";
  if (server === "") {
    throw new Error("config: server endpoint is required");
  }

  const suite = stringField(obj, "suite") ?? DefaultSuite;

  const databaseSection = recordField(obj, "database");
  const dbPath =
    stringField(databaseSection, "path") ?? DefaultDatabasePath;

  const tlsSection = recordField(obj, "tls");
  const insecureRaw = tlsSection["insecure"];
  const insecure = typeof insecureRaw === "boolean" ? insecureRaw : false;

  const config: Config = {
    identity,
    domain,
    server,
    suite,
    database: { path: dbPath },
    tls: { insecure },
  };

  const loggingSection = obj["logging"];
  if (typeof loggingSection === "object" && loggingSection !== null && !Array.isArray(loggingSection)) {
    const lg = loggingSection as Record<string, unknown>;
    const logging: LoggingConfig = {};
    const level = stringField(lg, "level");
    if (level !== undefined) {
      logging.level = level;
    }
    const format = stringField(lg, "format");
    if (format === "json" || format === "pretty") {
      logging.format = format;
    }
    if (Object.keys(logging).length > 0) {
      config.logging = logging;
    }
  }
  return config;
}

function stringField(rec: Record<string, unknown>, key: string): string | undefined {
  const v = rec[key];
  return typeof v === "string" ? v : undefined;
}

function recordField(
  rec: Record<string, unknown>,
  key: string,
): Record<string, unknown> {
  const v = rec[key];
  if (typeof v === "object" && v !== null && !Array.isArray(v)) {
    return v as Record<string, unknown>;
  }
  return {};
}
