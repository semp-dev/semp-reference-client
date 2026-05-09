/**
 * `keys` subcommand. Mirrors runKeys: connect+handshake, send a
 * SEMP_KEYS request, print every record returned in the response.
 *
 * @module
 */

import { fetchKeys, newKeysRequest } from "@sempdev/semp/keys";

import type { Logger } from "pino";

import { Client } from "../client/client.js";
import type { Config } from "../config/config.js";
import { SQLitePrivateStore } from "../store/sqlite.js";

export interface KeysOptions {
  address: string;
}

export async function runKeys(
  cfg: Config,
  store: SQLitePrivateStore,
  logger: Logger,
  opts: KeysOptions,
): Promise<void> {
  if (opts.address === "") {
    process.stderr.write("error: --address is required\n");
    process.exit(1);
  }
  const client = new Client(cfg, store, logger);
  try {
    await client.connectAndHandshake();
    if (client.session === null) {
      throw new Error("client: no session");
    }
    const reqId = `kr-${Date.now()}`;
    const req = newKeysRequest(reqId, [opts.address]);
    const resp = await fetchKeys(client.session.transport, req);
    for (const r of resp.results) {
      process.stdout.write(
        `Address: ${r.address}  Status: ${r.status}  Domain: ${r.domain}\n`,
      );
      if (r.domain_key !== undefined) {
        const dk = r.domain_key;
        process.stdout.write(
          `  Domain signing key: ${dk.key_id} (algo: ${dk.algorithm}, expires: ${dk.expires ?? ""})\n`,
        );
      }
      if (r.domain_enc_key !== undefined) {
        const dek = r.domain_enc_key;
        process.stdout.write(
          `  Domain encryption key: ${dek.key_id} (algo: ${dek.algorithm}, expires: ${dek.expires ?? ""})\n`,
        );
      }
      for (const uk of r.user_keys) {
        process.stdout.write(
          `  User key [${uk.key_type ?? ""}]: ${uk.key_id} (algo: ${uk.algorithm}, expires: ${uk.expires ?? ""})\n`,
        );
        if (uk.revocation !== undefined) {
          process.stdout.write(
            `    REVOKED at ${uk.revocation.revoked_at}: ${uk.revocation.reason}\n`,
          );
        }
      }
      if (r.error_reason !== undefined && r.error_reason !== "") {
        process.stdout.write(`  Error: ${r.error_reason}\n`);
      }
    }
  } finally {
    await client.close();
  }
}
