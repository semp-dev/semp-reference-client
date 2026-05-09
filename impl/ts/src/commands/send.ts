/**
 * `send` subcommand. Mirrors `impl/go/cmd/semp-client/main.go`'s
 * runSend: builds + submits an envelope, prints "Envelope submitted:
 * <id>" plus one "  <recipient>: <status>" line per recipient.
 *
 * The federation harness greps for "<recipient>: delivered" ; we
 * MUST emit the recipient/status pair byte-identically to the Go
 * impl.
 *
 * @module
 */

import type { Logger } from "pino";

import { Client } from "../client/client.js";
import { send } from "../client/sender.js";
import type { Config } from "../config/config.js";
import { SQLitePrivateStore } from "../store/sqlite.js";

export interface SendOptions {
  to: string;
  cc: string;
  subject: string;
  body: string;
  attach: string;
}

export async function runSend(
  cfg: Config,
  store: SQLitePrivateStore,
  logger: Logger,
  opts: SendOptions,
): Promise<void> {
  if (opts.to === "") {
    process.stderr.write("error: --to is required\n");
    process.exit(1);
  }
  const to = opts.to.split(",").map((s) => s.trim()).filter((s) => s !== "");
  const cc = opts.cc === "" ? [] : opts.cc.split(",").map((s) => s.trim()).filter((s) => s !== "");
  const attach = opts.attach === "" ? [] : opts.attach.split(",").map((s) => s.trim()).filter((s) => s !== "");

  const client = new Client(cfg, store, logger);
  try {
    await client.connectAndHandshake();
    const result = await send(client, {
      to,
      cc,
      subject: opts.subject,
      body: opts.body,
      attachments: attach,
    });

    process.stdout.write(`Envelope submitted: ${result.envelopeId}\n`);
    for (const r of result.results) {
      let line = `  ${r.recipient}: ${r.status}`;
      if (typeof r.reason === "string" && r.reason !== "") {
        line += ` (${r.reason})`;
      }
      process.stdout.write(`${line}\n`);
    }
  } finally {
    await client.close();
  }
}
