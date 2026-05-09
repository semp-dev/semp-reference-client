/**
 * pino logger factory. Mirrors impl/go's `slog` setup: structured
 * info-level logging emitted to stderr, leaving stdout clean for
 * user-facing output.
 *
 * @module
 */

import { pino, destination, type Logger } from "pino";

import type { Config } from "./config/config.js";

/**
 * Build a logger for the CLI process. Honors `cfg.logging` when the
 * caller has parsed a config; falls back to defaults so commands that
 * run before config load still produce useful output.
 */
export function newLogger(cfg?: Pick<Config, "logging"> | undefined): Logger {
  const level = cfg?.logging?.level ?? "info";
  const format = cfg?.logging?.format ?? "pretty";
  if (format === "json") {
    return pino(
      {
        level,
        formatters: {
          level: (label) => ({ level: label }),
        },
      },
      destination(2),
    );
  }
  return pino(
    {
      level,
      transport: {
        target: "pino-pretty",
        options: {
          destination: 2,
          colorize: true,
          translateTime: "SYS:HH:MM:ss",
          ignore: "pid,hostname",
        },
      },
    },
  );
}
