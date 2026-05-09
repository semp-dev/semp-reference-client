/**
 * `register` subcommand. Mirrors `impl/go/cmd/semp-client/main.go`'s
 * runRegister: requires `-password`, runs Client.register, then
 * prints the just-registered identity + key fingerprints.
 *
 * @module
 */

import type { Logger } from "pino";

import { Client } from "../client/client.js";
import type { Config } from "../config/config.js";
import { SQLitePrivateStore } from "../store/sqlite.js";

export interface RegisterOptions {
  password: string;
}

export async function runRegister(
  cfg: Config,
  store: SQLitePrivateStore,
  logger: Logger,
  opts: RegisterOptions,
): Promise<void> {
  if (opts.password === "") {
    process.stderr.write("error: --password is required\n");
    process.stderr.write("usage: semp-client register --password <password>\n");
    process.exit(1);
  }

  const client = new Client(cfg, store, logger);
  await client.register(opts.password);

  const idPub = store.loadUserPublicKey(cfg.identity, "identity");
  const encPub = store.loadUserPublicKey(cfg.identity, "encryption");
  process.stdout.write(`Registered: ${cfg.identity}\n`);
  process.stdout.write(`Identity key:   ${idPub === null ? "" : idPub.keyId}\n`);
  process.stdout.write(`Encryption key: ${encPub === null ? "" : encPub.keyId}\n`);
}
