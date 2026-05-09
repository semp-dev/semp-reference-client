/**
 * `read` subcommand. Mirrors runRead: prints one stored message in
 * full.
 *
 * @module
 */

import type { SQLitePrivateStore } from "../store/sqlite.js";

export function runRead(store: SQLitePrivateStore, messageId: string): void {
  if (messageId === "") {
    process.stderr.write("usage: semp-client read <message-id>\n");
    process.exit(1);
  }
  const m = store.getMessage(messageId);
  if (m === null) {
    process.stderr.write(`message not found: ${messageId}\n`);
    process.exit(1);
  }
  process.stdout.write(`Message ID: ${m.messageId}\n`);
  process.stdout.write(`Direction:  ${m.direction}\n`);
  process.stdout.write(`From:       ${m.from}\n`);
  process.stdout.write(`To:         ${m.to.join(", ")}\n`);
  if (m.cc.length > 0) {
    process.stdout.write(`CC:         ${m.cc.join(", ")}\n`);
  }
  process.stdout.write(`Subject:    ${m.subject}\n`);
  process.stdout.write(`Date:       ${m.storedAt}\n`);
  process.stdout.write(`\n${m.bodyText}\n`);
}
