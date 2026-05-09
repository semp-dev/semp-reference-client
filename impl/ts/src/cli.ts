/**
 * CLI entry point. Mirrors `impl/go/cmd/semp-client/main.go`'s
 * dispatch surface and stdout formatting.
 *
 * Argv quirk: the federation harness invokes the client with
 * single-dash long flags ("-config", "-password", "-to", ...). Go's
 * `flag` package accepts both `-foo` and `--foo`; commander.js does
 * not. We rewrite single-dash long flags to double-dash before handing
 * off to commander.
 *
 * @module
 */

import { Command, Option } from "commander";

import { runBlock, runBlockList, runUnblock } from "./commands/block.js";
import { runExport } from "./commands/export.js";
import { runFetch } from "./commands/fetch.js";
import { runImport } from "./commands/import.js";
import { runInbox, runSent } from "./commands/inbox.js";
import { runKeys } from "./commands/keys.js";
import { runRead } from "./commands/read.js";
import { runRegister } from "./commands/register.js";
import { runSend } from "./commands/send.js";
import { runStatus } from "./commands/status.js";
import { type Config, loadConfig } from "./config/config.js";
import { newLogger } from "./logger.js";
import { initDB, SQLitePrivateStore } from "./store/sqlite.js";

interface Bootstrap {
  cfg: Config;
  store: SQLitePrivateStore;
  closeStore: () => void;
}

/**
 * Convert `-foo` (single-dash long-name) tokens to `--foo` so
 * commander accepts the federation harness's argv convention. Leaves
 * `-c` (single-letter short flag) and `--foo` (already long-form) and
 * `-` and `--` and pure values alone.
 */
function normalizeLongFlags(argv: string[]): string[] {
  const out: string[] = [];
  for (const tok of argv) {
    if (tok === "-" || tok === "--") {
      out.push(tok);
      continue;
    }
    if (tok.startsWith("--")) {
      out.push(tok);
      continue;
    }
    if (tok.startsWith("-") && tok.length > 2 && !tok.startsWith("--")) {
      // Honor `-foo=bar` -> `--foo=bar` and `-foo` -> `--foo`.
      // Skip negative numbers ("-5").
      const after = tok.slice(1);
      if (/^-?\d/.test(after)) {
        out.push(tok);
        continue;
      }
      out.push(`--${after}`);
      continue;
    }
    out.push(tok);
  }
  return out;
}

let bootstrap: Bootstrap | null = null;

function setupBootstrap(configPath: string): Bootstrap {
  if (bootstrap !== null) {
    return bootstrap;
  }
  const cfg = loadConfig(configPath);
  const handle = initDB(cfg.database.path);
  const store = new SQLitePrivateStore(handle.db);
  bootstrap = {
    cfg,
    store,
    closeStore: () => {
      try {
        handle.close();
      } catch {
        // ignore
      }
    },
  };
  return bootstrap;
}

function teardown(): void {
  if (bootstrap !== null) {
    bootstrap.closeStore();
    bootstrap = null;
  }
}

async function main(): Promise<void> {
  const argv = normalizeLongFlags(process.argv.slice(2));

  const program = new Command();
  program
    .name("semp-client")
    .description("SEMP reference client (TypeScript port)")
    .option("-c, --config <path>", "path to TOML config file", "semp.toml")
    .allowExcessArguments(true);

  // Per-subcommand bootstrap: load config + open the store after the
  // root option parser has assigned `--config`.
  const withBoot = (fn: (boot: Bootstrap) => Promise<void> | void) => {
    return async () => {
      const opts = program.opts<{ config: string }>();
      const boot = setupBootstrap(opts.config);
      try {
        await fn(boot);
      } finally {
        teardown();
      }
    };
  };

  program
    .command("register")
    .description("Generate keys and register with the home server")
    .requiredOption("--password <pw>", "account password")
    .action(async (cmdOpts: { password: string }) => {
      await withBoot(async ({ cfg, store }) => {
        const logger = newLogger(cfg);
        await runRegister(cfg, store, logger, { password: cmdOpts.password });
      })();
    });

  program
    .command("send")
    .description("Compose, encrypt, and submit an envelope")
    .requiredOption("--to <addresses>", "recipient address(es), comma-separated")
    .option("--cc <addresses>", "CC recipients, comma-separated", "")
    .option("--subject <subject>", "message subject", "")
    .option("--body <body>", "message body (text/plain)", "")
    .option("--attach <paths>", "file paths to attach, comma-separated", "")
    .action(async (cmdOpts: { to: string; cc: string; subject: string; body: string; attach: string }) => {
      await withBoot(async ({ cfg, store }) => {
        const logger = newLogger(cfg);
        await runSend(cfg, store, logger, {
          to: cmdOpts.to,
          cc: cmdOpts.cc,
          subject: cmdOpts.subject,
          body: cmdOpts.body,
          attach: cmdOpts.attach,
        });
      })();
    });

  program
    .command("fetch")
    .description("Fetch and decrypt pending envelopes")
    .action(async () => {
      await withBoot(async ({ cfg, store }) => {
        const logger = newLogger(cfg);
        await runFetch(cfg, store, logger);
      })();
    });

  program
    .command("inbox")
    .description("List received messages")
    .action(async () => {
      await withBoot(async ({ store }) => {
        runInbox(store);
      })();
    });

  program
    .command("sent")
    .description("List sent messages")
    .action(async () => {
      await withBoot(async ({ store }) => {
        runSent(store);
      })();
    });

  program
    .command("read <messageId>")
    .description("Display a decrypted message")
    .action(async (messageId: string) => {
      await withBoot(async ({ store }) => {
        runRead(store, messageId);
      })();
    });

  program
    .command("keys")
    .description("Request recipient keys from the server")
    .requiredOption("--address <addr>", "address to look up")
    .action(async (cmdOpts: { address: string }) => {
      await withBoot(async ({ cfg, store }) => {
        const logger = newLogger(cfg);
        await runKeys(cfg, store, logger, { address: cmdOpts.address });
      })();
    });

  program
    .command("export <messageId>")
    .description("Export a message as a .semp file")
    .option("-o, --output <path>", "output file path (default: <message-id>.semp)", "")
    .action(async (messageId: string, cmdOpts: { output: string }) => {
      await withBoot(async ({ store }) => {
        runExport(store, { messageId, output: cmdOpts.output });
      })();
    });

  program
    .command("import <file>")
    .description("Import and decrypt a .semp file")
    .action(async (file: string) => {
      await withBoot(async ({ cfg, store }) => {
        const logger = newLogger(cfg);
        runImport(cfg, store, logger, file);
      })();
    });

  program
    .command("block")
    .description("Add a block list entry on the server")
    .addOption(
      new Option("--type <type>", "entity type")
        .choices(["user", "domain", "server"])
        .default("user"),
    )
    .requiredOption("--entity <value>", "address, domain, or hostname to block")
    .option("--reason <reason>", "reason for blocking", "")
    .addOption(
      new Option("--scope <scope>", "scope")
        .choices(["all", "direct", "group"])
        .default("all"),
    )
    .action(async (cmdOpts: { type: string; entity: string; reason: string; scope: string }) => {
      await withBoot(async ({ cfg }) => {
        await runBlock(cfg, {
          type: cmdOpts.type,
          entity: cmdOpts.entity,
          reason: cmdOpts.reason,
          scope: cmdOpts.scope,
        });
      })();
    });

  program
    .command("unblock <entryId>")
    .description("Remove a block list entry")
    .action(async (entryId: string) => {
      await withBoot(async ({ cfg }) => {
        await runUnblock(cfg, entryId);
      })();
    });

  program
    .command("blocklist")
    .description("List block entries for your address")
    .action(async () => {
      await withBoot(async ({ cfg }) => {
        await runBlockList(cfg);
      })();
    });

  program
    .command("status")
    .description("Show identity, keys, and server info")
    .action(async () => {
      await withBoot(async ({ cfg, store }) => {
        runStatus(cfg, store);
      })();
    });

  await program.parseAsync(argv, { from: "user" });
}

main().catch((err) => {
  const msg = err instanceof Error ? err.message : String(err);
  process.stderr.write(`error: ${msg}\n`);
  teardown();
  process.exit(1);
});
