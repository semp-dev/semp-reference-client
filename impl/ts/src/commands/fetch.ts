/**
 * `fetch` subcommand. Mirrors `impl/go/cmd/semp-client/main.go`'s
 * runFetch: pulls + decrypts pending envelopes, prints them in the
 * same format the Go impl uses.
 *
 * The federation harness greps for "Subject: <subject>" ; that line
 * MUST be present byte-identically to the Go impl.
 *
 * @module
 */

import type { Logger } from "pino";

import { Client } from "../client/client.js";
import { fetchInbox } from "../client/receiver.js";
import type { Config } from "../config/config.js";
import { SQLitePrivateStore } from "../store/sqlite.js";

export async function runFetch(
  cfg: Config,
  store: SQLitePrivateStore,
  logger: Logger,
): Promise<void> {
  const client = new Client(cfg, store, logger);
  try {
    await client.connectAndHandshake();
    const messages = await fetchInbox(client);

    if (messages.length === 0) {
      process.stdout.write("No new messages.\n");
      return;
    }

    for (const m of messages) {
      process.stdout.write(`\n--- Message ${m.messageId} ---\n`);
      process.stdout.write(`From:    ${m.from}\n`);
      process.stdout.write(`To:      ${m.to.join(", ")}\n`);
      if (m.cc.length > 0) {
        process.stdout.write(`CC:      ${m.cc.join(", ")}\n`);
      }
      process.stdout.write(`Subject: ${m.subject}\n`);
      process.stdout.write(`Body:\n${m.body}\n`);
      if (m.attachments.length > 0) {
        process.stdout.write("Attachments:\n");
        for (const a of m.attachments) {
          process.stdout.write(`  - ${a.filename} (${a.mimeType}, ${a.size} bytes)\n`);
        }
      }
    }
    process.stdout.write(`\n${messages.length} message(s) fetched.\n`);
  } finally {
    await client.close();
  }
}
