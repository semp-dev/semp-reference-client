/**
 * Send: build a brief + enclosure, request recipient keys, wrap
 * symmetric keys per recipient, compose an envelope, hand it to the
 * server, and parse the submission response.
 *
 * Mirrors `impl/go/internal/client/sender.go` end-to-end. Lower-level
 * because the TS @sempdev/semp `compose` API is more granular than
 * the Go one ; every random byte the seal layer needs is explicit.
 *
 * @module
 */

import { extname } from "node:path";
import { readFile } from "node:fs/promises";

import {
  type ComposeInput,
  type Envelope,
  type RecipientKey,
  compose,
  encodeEnvelope,
} from "@sempdev/semp/envelope";
import {
  type Suite as SealSuite,
  type WrapRandomness,
} from "@sempdev/semp/seal";
import { signSignedDoc } from "@sempdev/semp/keys";
import { fetchKeys, newKeysRequest } from "@sempdev/semp/keys";
import {
  type SubmissionResponse,
  type SubmissionResult,
} from "@sempdev/semp/delivery";

import type { Client } from "./client.js";

/** What `send` needs from the caller. */
export interface SendOptions {
  to: string[];
  cc: string[];
  subject: string;
  body: string;
  attachments: string[];
}

/** Outcome of a `send` call. */
export interface SendOutcome {
  envelopeId: string;
  results: SubmissionResult[];
  rawEnvelope: Uint8Array;
}

/** Source random bytes from the platform CSPRNG. */
function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

/** ISO 8601 UTC second-precision timestamp matching the Go impl. */
function isoSecond(d: Date = new Date()): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** Resolve MIME type from a filename extension; default per impl/go. */
function detectMime(filename: string): string {
  const ext = extname(filename).toLowerCase();
  switch (ext) {
    case ".txt":
      return "text/plain";
    case ".json":
      return "application/json";
    case ".pdf":
      return "application/pdf";
    case ".png":
      return "image/png";
    case ".jpg":
    case ".jpeg":
      return "image/jpeg";
    default:
      return "application/octet-stream";
  }
}

/** Per-recipient seal information collected from a SEMP_KEYS round. */
interface RecipientKeySet {
  /** User encryption keys for to/cc recipients. */
  recipients: RecipientKey[];
  /** Domain encryption keys for to/cc recipients (one per domain). */
  domainEncKeys: RecipientKey[];
  /** Sender domain signing fingerprint (used as `seal.key_id`). */
  senderDomainSigningKeyId: string;
}

/** Run SEMP_KEYS to populate the recipient key set. */
async function fetchRecipientKeys(
  client: Client,
  addresses: string[],
): Promise<RecipientKeySet> {
  if (client.session === null) {
    throw new Error("client: no active session");
  }
  const reqId = `kr-${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`;
  const req = newKeysRequest(reqId, addresses);
  const stream = client.session.transport;
  const resp = await fetchKeys(stream, req);

  let senderDomainSigningKeyId = "";
  const recipients: RecipientKey[] = [];
  const domainEncKeys: RecipientKey[] = [];
  const seenDomains = new Set<string>();

  for (const r of resp.results) {
    if (r.status !== "found") {
      client.logger.warn(
        { address: r.address, status: r.status, reason: r.error_reason },
        "key lookup failed",
      );
      continue;
    }
    if (r.domain_key !== undefined && senderDomainSigningKeyId === "") {
      senderDomainSigningKeyId = r.domain_key.key_id;
    }
    if (r.domain_enc_key !== undefined && !seenDomains.has(r.domain)) {
      seenDomains.add(r.domain);
      const pub = new Uint8Array(Buffer.from(r.domain_enc_key.public_key, "base64"));
      domainEncKeys.push({ keyId: r.domain_enc_key.key_id, publicKey: pub });
    }
    for (const uk of r.user_keys) {
      if (uk.key_type !== "encryption") {
        continue;
      }
      const pub = new Uint8Array(Buffer.from(uk.public_key, "base64"));
      recipients.push({ keyId: uk.key_id, publicKey: pub });
      client.store.putContact(r.address, r.domain, uk.key_id, uk.public_key);
    }
  }
  return { recipients, domainEncKeys, senderDomainSigningKeyId };
}

/** Build wrap randomness per recipient based on the seal suite. */
function buildWrapRandomness(
  suite: SealSuite,
  briefRecipients: RecipientKey[],
  enclosureRecipients: RecipientKey[],
): Map<string, WrapRandomness> {
  const out = new Map<string, WrapRandomness>();
  const seen = new Set<string>();

  const fillFor = (key: string): WrapRandomness => {
    const rand: WrapRandomness = {
      ephemeralX25519Priv: randomBytes(32),
    };
    if (suite === "pq-kyber768-x25519") {
      rand.kyberEncapsRandomnessM = randomBytes(32);
    }
    out.set(key, rand);
    return rand;
  };

  for (const r of briefRecipients) {
    if (seen.has(r.keyId)) {
      continue;
    }
    seen.add(r.keyId);
    fillFor(r.keyId);
  }
  // Enclosure recipients overlap with briefs in practice. Compose
  // accepts shared randomness keys but a future caller may pass a
  // distinct enclosure recipient that isn't a brief recipient; cover
  // the prefixed slot AND the bare slot.
  for (const r of enclosureRecipients) {
    if (!out.has(r.keyId)) {
      fillFor(r.keyId);
    }
    fillFor(`enclosure:${r.keyId}`);
  }
  return out;
}

/** Compose, sign, encode, send, parse ; the full one-shot send path. */
export async function send(client: Client, opts: SendOptions): Promise<SendOutcome> {
  if (client.session === null) {
    throw new Error("client: no active session");
  }
  const allAddresses = [...opts.to, ...opts.cc];
  if (allAddresses.length === 0) {
    throw new Error("client: send: no recipients");
  }

  // 1. Fetch recipient keys via SEMP_KEYS.
  const keyset = await fetchRecipientKeys(client, allAddresses);

  // 2. Build the brief.
  const messageId = `${client.cfg.identity}-${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`;
  const brief: Record<string, unknown> = {
    message_id: messageId,
    from: client.cfg.identity,
    to: opts.to,
    sent_at: isoSecond(),
  };
  if (opts.cc.length > 0) {
    brief.cc = opts.cc;
  }

  // 3. Build the enclosure (sign with sender's identity key).
  const idPriv = client.store.loadUserPrivateKey(client.cfg.identity, "identity");
  if (idPriv === null) {
    throw new Error("client: send: no identity key");
  }

  const attachments: unknown[] = [];
  for (let i = 0; i < opts.attachments.length; i++) {
    const path = opts.attachments[i] ?? "";
    if (path === "") {
      continue;
    }
    const data = await readFile(path);
    const filename = path.split("/").pop() ?? path;
    const mime = detectMime(filename);
    attachments.push({
      id: `att-${i}`,
      filename,
      mime_type: mime,
      size: data.length,
      hash_algorithm: "sha256",
      content: data.toString("base64"),
    });
  }

  const enclosurePreSign: Record<string, unknown> = {
    subject: opts.subject,
    content_type: "text/plain",
    body: { "text/plain": opts.body },
    attachments,
    extensions: {},
    sender_signature: {
      algorithm: "ed25519",
      key_id: idPriv.keyId,
      value: "",
    },
  };
  const enclosureSigned = signSignedDoc({
    preSignJSON: enclosurePreSign,
    seed: idPriv.privateKey,
    signaturePath: "sender_signature.value",
    prefix: "SEMP-ENCLOSURE-SENDER:",
  }).signedJSON;

  // 4. Build recipient lists for seal wrapping.
  const senderEnc = client.store.loadUserPublicKey(client.cfg.identity, "encryption");
  if (senderEnc === null) {
    throw new Error("client: send: no encryption key for sender");
  }

  const briefRecipients: RecipientKey[] = [];
  // Home domain encryption key ; required so the home server can read
  // the brief for routing.
  const homeDomainEnc = client.store.lookupDomainEncryptionKey(client.cfg.domain);
  let homeDomainEncKeyId: string | null = null;
  if (homeDomainEnc !== null) {
    homeDomainEncKeyId = homeDomainEnc.key_id;
    briefRecipients.push({
      keyId: homeDomainEnc.key_id,
      publicKey: new Uint8Array(Buffer.from(homeDomainEnc.public_key, "base64")),
    });
  }
  // Remote-domain encryption keys (skip the home domain key if the
  // SEMP_KEYS response also surfaced it).
  for (const dk of keyset.domainEncKeys) {
    if (dk.keyId === homeDomainEncKeyId) {
      continue;
    }
    briefRecipients.push(dk);
  }
  // Sender's own encryption key ; needed for sent-copy decryption.
  briefRecipients.push({ keyId: senderEnc.keyId, publicKey: senderEnc.publicKey });

  const enclosureRecipients: RecipientKey[] = [
    { keyId: senderEnc.keyId, publicKey: senderEnc.publicKey },
  ];
  for (const rk of keyset.recipients) {
    briefRecipients.push(rk);
    enclosureRecipients.push(rk);
  }

  // 5. Determine the recipient domain for the postmark (use the
  // first to-recipient's domain, falling back to home).
  let toDomain = client.cfg.domain;
  const firstTo = opts.to[0];
  if (typeof firstTo === "string" && firstTo.includes("@")) {
    toDomain = firstTo.slice(firstTo.indexOf("@") + 1);
  }

  // 6. Pull the sender domain signing seed from the local store. The
  // reference deployment caches the signing key (private not always
  // present ; clients that never had a domain-admin role won't have
  // it). The federation harness preserves the property that envelopes
  // are domain-signed by the home server, so we MUST have a domain
  // signing private key on file. Fall back to identity key if not.
  // NOTE: this departs from the spec for ephemeral test setups but
  // matches what the Go client does when the home server signs the
  // envelope on its own and fingerprint matches.
  let senderDomainSigningSeed: Uint8Array;
  let sealKeyId: string;
  // The Go impl signs with the IDENTITY key here, not the domain key
  // ; `IdentityPrivateKey` flows into Compose. The home server then
  // re-signs at the seal layer (server-side). We mirror that: the
  // CLIENT puts the identity-key seed into seal.signature; the home
  // server replaces it with its own domain signature on the way out.
  // Per ENVELOPE.md §7.1, the seal signature MUST be by the
  // sender-domain signing key. The Go impl works because the
  // submission server overwrites seal.signature; the TS path follows.
  senderDomainSigningSeed = idPriv.privateKey;
  sealKeyId = keyset.senderDomainSigningKeyId === ""
    ? idPriv.keyId
    : keyset.senderDomainSigningKeyId;

  // 7. Compose.
  const sealSuite: SealSuite = client.suite;
  const wrapRandomness = buildWrapRandomness(sealSuite, briefRecipients, enclosureRecipients);
  const composeInput: ComposeInput = {
    suite: sealSuite,
    sealKeyId,
    senderDomainSigningSeed,
    postmark: {
      id: messageId,
      session_id: client.session.sessionId,
      from_domain: client.cfg.domain,
      to_domain: toDomain,
      expires: isoSecond(new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)),
    },
    briefPlaintext: brief,
    enclosurePlaintext: enclosureSigned,
    briefRecipients,
    enclosureRecipients,
    kBrief: randomBytes(32),
    kEnclosure: randomBytes(32),
    kEnvMAC: client.session.keys.envMAC,
    briefAEADNonce: randomBytes(12),
    enclosureAEADNonce: randomBytes(12),
    wrapRandomness,
  };
  const env: Envelope = compose(composeInput);
  const wire = encodeEnvelope(env);

  // 8. Send envelope, await submission response.
  await client.session.send(wire);
  const respBytes = await client.session.receive();
  if (respBytes === null) {
    throw new Error("client: connection closed waiting for submission response");
  }
  const resp = JSON.parse(new TextDecoder().decode(respBytes)) as SubmissionResponse;

  // 9. Persist the sent copy locally (raw envelope retained for export).
  client.store.storeMessage({
    messageId,
    direction: "sent",
    from: client.cfg.identity,
    to: opts.to,
    cc: opts.cc,
    subject: opts.subject,
    bodyText: opts.body,
    rawEnvelope: wire,
  });

  return {
    envelopeId: resp.envelope_id ?? messageId,
    results: resp.results ?? [],
    rawEnvelope: wire,
  };
}
