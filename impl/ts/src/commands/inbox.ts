/**
 * `inbox` and `sent` listing subcommands. Mirrors runInbox / runSent.
 *
 * @module
 */

import type { Message, SQLitePrivateStore } from "../store/sqlite.js";

export function runInbox(store: SQLitePrivateStore): void {
  const msgs = store.listMessages("received");
  if (msgs.length === 0) {
    process.stdout.write("Inbox is empty.\n");
    return;
  }
  printMessageList(msgs);
}

export function runSent(store: SQLitePrivateStore): void {
  const msgs = store.listMessages("sent");
  if (msgs.length === 0) {
    process.stdout.write("No sent messages.\n");
    return;
  }
  printMessageList(msgs);
}

function pad(s: string, width: number): string {
  if (s.length >= width) {
    return s;
  }
  return s + " ".repeat(width - s.length);
}

function printMessageList(msgs: Message[]): void {
  process.stdout.write(
    `${pad("MESSAGE ID", 36)}  ${pad("DIR", 8)}  ${pad("FROM", 25)}  SUBJECT\n`,
  );
  process.stdout.write(`${"-".repeat(100)}\n`);
  for (const m of msgs) {
    let subj = m.subject;
    if (subj.length > 40) {
      subj = `${subj.slice(0, 37)}...`;
    }
    process.stdout.write(
      `${pad(m.messageId, 36)}  ${pad(m.direction, 8)}  ${pad(m.from, 25)}  ${subj}\n`,
    );
  }
  process.stdout.write(`\n${msgs.length} message(s)\n`);
}
