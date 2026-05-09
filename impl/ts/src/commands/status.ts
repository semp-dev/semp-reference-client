/**
 * `status` subcommand. Mirrors runStatus: prints config, identity,
 * fingerprints, and inbox / sent counts.
 *
 * @module
 */

import type { Config } from "../config/config.js";
import type { SQLitePrivateStore } from "../store/sqlite.js";

export function runStatus(cfg: Config, store: SQLitePrivateStore): void {
  process.stdout.write(`Identity:   ${cfg.identity}\n`);
  process.stdout.write(`Domain:     ${cfg.domain}\n`);
  process.stdout.write(`Server:     ${cfg.server}\n`);
  process.stdout.write(`Database:   ${cfg.database.path}\n`);

  const id = store.loadUserPrivateKey(cfg.identity, "identity");
  const enc = store.loadUserPrivateKey(cfg.identity, "encryption");
  if (id !== null) {
    process.stdout.write(`Identity key:   ${id.keyId}\n`);
  } else {
    process.stdout.write("Identity key:   not registered (run 'register')\n");
  }
  if (enc !== null) {
    process.stdout.write(`Encryption key: ${enc.keyId}\n`);
  } else {
    process.stdout.write("Encryption key: not registered (run 'register')\n");
  }

  const inbox = store.listMessages("received");
  const sent = store.listMessages("sent");
  process.stdout.write(`Inbox:      ${inbox.length} message(s)\n`);
  process.stdout.write(`Sent:       ${sent.length} message(s)\n`);
}
