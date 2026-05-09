/**
 * Background rekey driver. Mirrors `impl/go/internal/client/rekey.go`:
 * fires once at 80% of the session TTL, then exits.
 *
 * @module
 */

import { rekeyClient } from "@sempdev/semp/session";

import type { Client } from "./client.js";

/** Threshold matching impl/go's `session.RekeyThreshold` constant (0.8). */
const RekeyThreshold = 0.8;

/**
 * Schedule a single rekey at 80% of the session TTL. Returns a
 * cancel function that clears the pending timer; safe to invoke any
 * number of times.
 */
export function autoRekey(client: Client): () => void {
  if (client.session === null) {
    return () => undefined;
  }
  const ttlMs = client.session.sessionTTL * 1000;
  const delay = Math.max(1000, Math.floor(ttlMs * RekeyThreshold));

  let cancelled = false;
  const handle = setTimeout(() => {
    void runRekey(client).catch((err) => {
      client.logger.warn(
        { err: err instanceof Error ? err.message : String(err) },
        "rekey failed",
      );
    });
  }, delay);

  return () => {
    if (cancelled) {
      return;
    }
    cancelled = true;
    clearTimeout(handle);
  };
}

async function runRekey(client: Client): Promise<void> {
  const session = client.session;
  if (session === null) {
    return;
  }
  if (session.isExpired()) {
    client.logger.warn("session expired before rekey");
    return;
  }
  const newId = await rekeyClient(session);
  client.logger.info(
    {
      newSessionId: newId,
      expiresAt: session.expiresAt().toISOString(),
    },
    "session rekeyed",
  );
}
