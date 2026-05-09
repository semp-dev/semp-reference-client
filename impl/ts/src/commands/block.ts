/**
 * `block`, `unblock`, `blocklist` subcommands. All three use the
 * server's REST endpoint at /v1/blocklist; mirrors runBlock /
 * runUnblock / runBlockList.
 *
 * @module
 */

import type { Config } from "../config/config.js";

function serverHTTPBase(server: string): string {
  let url = server;
  url = url.replace(/^wss:\/\//, "https://");
  url = url.replace(/^ws:\/\//, "http://");
  const idx = url.indexOf("/v1/");
  if (idx > 0) {
    url = url.slice(0, idx);
  }
  return url;
}

export interface BlockOptions {
  type: string;
  entity: string;
  reason: string;
  scope: string;
}

export async function runBlock(cfg: Config, opts: BlockOptions): Promise<void> {
  if (opts.entity === "") {
    process.stderr.write("error: --entity is required\n");
    process.exit(1);
  }
  const body = {
    user_id: cfg.identity,
    entity_type: opts.type,
    entity_value: opts.entity,
    acknowledgment: "rejected",
    reason: opts.reason,
    scope: opts.scope,
  };
  const url = serverHTTPBase(cfg.server) + "/v1/blocklist";
  let resp: Response;
  try {
    resp = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch (err) {
    process.stderr.write(
      `error: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    process.exit(1);
  }
  let id = "";
  try {
    const obj = (await resp.json()) as Record<string, unknown>;
    if (typeof obj["id"] === "string") {
      id = obj["id"] as string;
    }
  } catch {
    // ignore body parse failures; mirrors Go behavior.
  }
  process.stdout.write(`Blocked ${opts.type} ${opts.entity} (id: ${id})\n`);
}

export async function runUnblock(cfg: Config, entryId: string): Promise<void> {
  if (entryId === "") {
    process.stderr.write("usage: semp-client unblock <entry-id>\n");
    process.exit(1);
  }
  const url = serverHTTPBase(cfg.server) + "/v1/blocklist/" + entryId;
  try {
    await fetch(url, { method: "DELETE" });
  } catch (err) {
    process.stderr.write(
      `error: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    process.exit(1);
  }
  process.stdout.write(`Unblocked entry ${entryId}\n`);
}

interface BlockEntryWire {
  id?: string;
  entity?: {
    type?: string;
    address?: string;
    domain?: string;
    hostname?: string;
  };
  acknowledgment?: string;
  scope?: string;
}

export async function runBlockList(cfg: Config): Promise<void> {
  const url =
    serverHTTPBase(cfg.server) + "/v1/blocklist?address=" + encodeURIComponent(cfg.identity);
  let resp: Response;
  try {
    resp = await fetch(url);
  } catch (err) {
    process.stderr.write(
      `error: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    process.exit(1);
  }
  let entries: BlockEntryWire[] = [];
  try {
    const parsed = (await resp.json()) as unknown;
    if (Array.isArray(parsed)) {
      entries = parsed as BlockEntryWire[];
    }
  } catch {
    // ignore body parse failures.
  }
  if (entries.length === 0) {
    process.stdout.write("No block list entries.\n");
    return;
  }
  for (const entry of entries) {
    const ent = entry.entity ?? {};
    let value = ent.address ?? "";
    if (value === "") {
      value = ent.domain ?? "";
    }
    if (value === "") {
      value = ent.hostname ?? "";
    }
    process.stdout.write(
      `  ${entry.id ?? ""}  ${ent.type ?? ""} ${value}  (scope: ${entry.scope ?? ""}, ack: ${entry.acknowledgment ?? ""})\n`,
    );
  }
  process.stdout.write(`\n${entries.length} entry(s)\n`);
}
