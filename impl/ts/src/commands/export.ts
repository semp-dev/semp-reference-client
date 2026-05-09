/**
 * `export` subcommand. Mirrors runExport: looks up a stored message,
 * decodes its raw envelope, re-encodes via encodeEnvelopeFile, writes
 * to a `.semp` file (or stdout target).
 *
 * @module
 */

import { writeFileSync } from "node:fs";

import { decodeEnvelope, encodeEnvelopeFile } from "@sempdev/semp/envelope";

import type { SQLitePrivateStore } from "../store/sqlite.js";

export interface ExportOptions {
  messageId: string;
  output: string;
}

export function runExport(store: SQLitePrivateStore, opts: ExportOptions): void {
  if (opts.messageId === "") {
    process.stderr.write("usage: semp-client export <message-id> [-o file.semp]\n");
    process.exit(1);
  }
  const m = store.getMessage(opts.messageId);
  if (m === null) {
    process.stderr.write(`message not found: ${opts.messageId}\n`);
    process.exit(1);
  }
  if (m.rawEnvelope.length === 0) {
    process.stderr.write(`no raw envelope stored for message ${opts.messageId}\n`);
    process.exit(1);
  }
  let env;
  try {
    env = decodeEnvelope(m.rawEnvelope);
  } catch (err) {
    process.stderr.write(
      `error decoding stored envelope: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    process.exit(1);
  }
  const data = encodeEnvelopeFile(env);
  const outPath = opts.output === "" ? `${opts.messageId}.semp` : opts.output;
  try {
    writeFileSync(outPath, Buffer.from(data));
  } catch (err) {
    process.stderr.write(
      `error writing ${outPath}: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    process.exit(1);
  }
  process.stdout.write(`Exported to ${outPath}\n`);
}
