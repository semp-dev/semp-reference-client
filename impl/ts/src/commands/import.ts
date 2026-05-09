/**
 * `import` subcommand. Mirrors runImport: decodes a .semp file,
 * verifies the seal signature against the cached domain key, opens
 * the brief + enclosure with the user's encryption private key, and
 * persists the decrypted message.
 *
 * @module
 */

import { readFileSync } from "node:fs";

import {
  decodeEnvelopeFile,
  openBriefAny,
  openEnclosureAny,
  verifySealSignature,
} from "@sempdev/semp/envelope";

import type { Logger } from "pino";

import { resolveSuite } from "../client/keygen.js";
import type { Config } from "../config/config.js";
import { SQLitePrivateStore } from "../store/sqlite.js";

export function runImport(
  cfg: Config,
  store: SQLitePrivateStore,
  logger: Logger,
  filePath: string,
): void {
  if (filePath === "") {
    process.stderr.write("usage: semp-client import <file.semp>\n");
    process.exit(1);
  }
  let data: Buffer;
  try {
    data = readFileSync(filePath);
  } catch (err) {
    process.stderr.write(
      `error reading ${filePath}: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    process.exit(1);
  }
  let env;
  try {
    env = decodeEnvelopeFile(data);
  } catch (err) {
    process.stderr.write(
      `error decoding .semp file: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    process.exit(1);
  }
  process.stdout.write(`Envelope ID:   ${env.postmark.id}\n`);
  process.stdout.write(`From domain:   ${env.postmark.from_domain}\n`);
  process.stdout.write(`To domain:     ${env.postmark.to_domain}\n`);

  // Verify seal signature against the cached domain key (if any).
  const domainRec = store.lookupDomainKey(env.postmark.from_domain);
  if (domainRec !== null) {
    const domainPub = new Uint8Array(Buffer.from(domainRec.public_key, "base64"));
    if (verifySealSignature(env, domainPub)) {
      process.stdout.write("Signature:     valid\n");
    } else {
      process.stdout.write("Signature:     INVALID (signature did not verify)\n");
    }
  } else {
    process.stdout.write("Signature:     not verified (domain key not cached)\n");
  }

  const priv = store.loadUserPrivateKey(cfg.identity, "encryption");
  const pub = store.loadUserPublicKey(cfg.identity, "encryption");
  if (priv === null || pub === null) {
    process.stdout.write("\nCannot decrypt: no encryption key available.\n");
    return;
  }

  const candidates = [
    { keyId: priv.keyId, privateKey: priv.privateKey, publicKey: pub.publicKey },
  ];

  const suite = resolveSuite(cfg.suite);
  let brief;
  try {
    brief = openBriefAny(suite, env, candidates).brief as Record<string, unknown>;
  } catch (err) {
    process.stdout.write(
      `\nBrief decryption failed: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    return;
  }
  let enc;
  try {
    enc = openEnclosureAny(suite, env, candidates).enclosure as Record<string, unknown>;
  } catch (err) {
    process.stdout.write(
      `\nEnclosure decryption failed: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    return;
  }

  const messageId = typeof brief["message_id"] === "string" ? (brief["message_id"] as string) : "";
  const from = typeof brief["from"] === "string" ? (brief["from"] as string) : "";
  const to = Array.isArray(brief["to"])
    ? (brief["to"] as unknown[]).filter((x): x is string => typeof x === "string")
    : [];
  const cc = Array.isArray(brief["cc"])
    ? (brief["cc"] as unknown[]).filter((x): x is string => typeof x === "string")
    : [];
  const subject = typeof enc["subject"] === "string" ? (enc["subject"] as string) : "";
  const bodyMap = enc["body"];
  const body =
    typeof bodyMap === "object" && bodyMap !== null && !Array.isArray(bodyMap)
      ? typeof (bodyMap as Record<string, unknown>)["text/plain"] === "string"
        ? ((bodyMap as Record<string, unknown>)["text/plain"] as string)
        : ""
      : "";

  process.stdout.write("\n--- Decrypted Message ---\n");
  process.stdout.write(`Message ID: ${messageId}\n`);
  process.stdout.write(`From:       ${from}\n`);
  process.stdout.write(`To:         ${to.join(", ")}\n`);
  if (cc.length > 0) {
    process.stdout.write(`CC:         ${cc.join(", ")}\n`);
  }
  process.stdout.write(`Subject:    ${subject}\n`);
  process.stdout.write(`\n${body}\n`);

  store.storeMessage({
    messageId,
    direction: "received",
    from,
    to,
    cc,
    subject,
    bodyText: body,
    rawEnvelope: data,
  });
  logger.info({ messageId }, "imported message");
}
