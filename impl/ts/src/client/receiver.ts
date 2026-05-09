/**
 * Fetch: pull pending envelopes from the home server, decrypt + verify,
 * persist locally. Mirrors `impl/go/internal/client/receiver.go`.
 *
 * @module
 */

import {
  type RecipientCandidate,
  type SenderKeyResolverFunc,
  decodeEnvelope,
  openAndVerify,
} from "@sempdev/semp/envelope";
import {
  type FetchResponse,
  newFetchRequest,
} from "@sempdev/semp/delivery";
import { fetchKeys, newKeysRequest } from "@sempdev/semp/keys";

import type { Client } from "./client.js";

/** Decrypted view of one fetched message. */
export interface DecryptedMessage {
  messageId: string;
  from: string;
  to: string[];
  cc: string[];
  subject: string;
  body: string;
  attachments: AttachmentInfo[];
  rawEnvelope: Uint8Array;
}

/** Lightweight summary of an attachment in a decrypted enclosure. */
export interface AttachmentInfo {
  id: string;
  filename: string;
  mimeType: string;
  size: number;
}

/**
 * Build a {@link SenderKeyResolverFunc} bound to this client's
 * session. The resolver looks up the sender DOMAIN signing key (the
 * one that signs `seal.signature`) by checking the local cache and
 * falling back to SEMP_KEYS via the home server.
 *
 * `skipCache` forces a network fetch and bypasses the local row.
 * The receive loop calls this with `false` first; on a verify
 * failure it evicts the cached row and retries with `true`.
 */
function buildSenderKeyResolver(
  client: Client,
  skipCache = false,
): SenderKeyResolverFunc {
  return async (fromDomain: string, keyId: string) => {
    // 1. Local cache. Cross-domain SEMP_KEYS responses cached during
    //    earlier outbound sends populate this; the receiver verifies
    //    without a network round trip. Skipped on the self-heal retry.
    if (!skipCache) {
      const local = client.store.lookupDomainKey(fromDomain);
      if (local !== null && local.key_id === keyId) {
        return new Uint8Array(Buffer.from(local.public_key, "base64"));
      }
    }
    // 2. SEMP_KEYS via the home server. This works only for sender
    //    domains the server already knows about; an address probe
    //    (e.g. _resolver@<fromDomain>) only carries `domain_key` in
    //    the SEMP_KEYS result when the probe matches a known user.
    if (client.session === null) {
      return null;
    }
    const probeAddress = `_resolver@${fromDomain}`;
    const reqId = `vr-${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`;
    const req = newKeysRequest(reqId, [probeAddress]);
    let resp;
    try {
      resp = await fetchKeys(client.session.transport, req);
    } catch (err) {
      client.logger.warn(
        { err: err instanceof Error ? err.message : String(err) },
        "verify-resolver: fetchKeys failed",
      );
      return null;
    }
    for (const r of resp.results) {
      if (r.domain !== fromDomain) {
        continue;
      }
      if (r.domain_key !== undefined && r.domain_key.key_id === keyId) {
        const pub = new Uint8Array(Buffer.from(r.domain_key.public_key, "base64"));
        client.store.putDomainKey(fromDomain, "signing", r.domain_key.algorithm, pub);
        return pub;
      }
    }
    return null;
  };
}

/**
 * Detect the openAndVerify error path that suggests a stale cached
 * sender-domain key: either the resolver returned `null` (cache
 * confidently said "no key for this id, here's the cached one") or
 * verifySealSignature rejected the seal. Both warrant a single
 * force-refresh retry; an opaque error (decode, candidate mismatch)
 * does not.
 */
function isStaleSenderKeyError(err: unknown): boolean {
  if (!(err instanceof Error)) {
    return false;
  }
  return (
    err.message.includes("seal.signature did not verify") ||
    err.message.includes("resolver returned null")
  );
}

/** Build the recipient candidate list from the local encryption key. */
function buildRecipientCandidates(client: Client): RecipientCandidate[] {
  const priv = client.store.loadUserPrivateKey(client.cfg.identity, "encryption");
  const pub = client.store.loadUserPublicKey(client.cfg.identity, "encryption");
  if (priv === null || pub === null) {
    throw new Error(`client: no encryption key for ${client.cfg.identity}`);
  }
  return [{ keyId: priv.keyId, privateKey: priv.privateKey, publicKey: pub.publicKey }];
}

/** Fetch + decrypt + persist. Returns the decrypted view of each message. */
export async function fetchInbox(client: Client): Promise<DecryptedMessage[]> {
  if (client.session === null) {
    throw new Error("client: no active session");
  }

  // 1. Send fetch request.
  const req = newFetchRequest();
  await client.session.send(new TextEncoder().encode(JSON.stringify(req)));

  // 2. Receive response.
  const respBytes = await client.session.receive();
  if (respBytes === null) {
    throw new Error("client: connection closed waiting for fetch response");
  }
  const resp = JSON.parse(new TextDecoder().decode(respBytes)) as FetchResponse;
  client.logger.info(
    { count: resp.envelopes.length, drained: resp.drained },
    "fetched envelopes",
  );

  if (resp.envelopes.length === 0) {
    return [];
  }

  const candidates = buildRecipientCandidates(client);
  const cachingResolver = buildSenderKeyResolver(client, false);
  const refreshResolver = buildSenderKeyResolver(client, true);

  const out: DecryptedMessage[] = [];
  for (const b64 of resp.envelopes) {
    let raw: Uint8Array;
    try {
      raw = new Uint8Array(Buffer.from(b64, "base64"));
    } catch (err) {
      client.logger.warn(
        { err: err instanceof Error ? err.message : String(err) },
        "skip envelope: bad base64",
      );
      continue;
    }
    let env;
    try {
      env = decodeEnvelope(raw);
    } catch (err) {
      client.logger.warn(
        { err: err instanceof Error ? err.message : String(err) },
        "skip envelope: decode failed",
      );
      continue;
    }
    let opened;
    try {
      opened = await openAndVerify({
        suite: client.suite,
        envelope: env,
        candidates,
        resolver: cachingResolver,
      });
    } catch (err) {
      // Self-heal: a stale cached sender-domain key (e.g. the sender
      // re-registered with a fresh identity since we last cached it)
      // produces "seal.signature did not verify" or
      // "resolver returned null". Evict the cached row and retry once
      // with a force-refresh resolver before giving up. Any other
      // error path falls straight through to "skip envelope".
      if (isStaleSenderKeyError(err)) {
        client.store.evictDomainKey(env.postmark.from_domain, "signing");
        try {
          opened = await openAndVerify({
            suite: client.suite,
            envelope: env,
            candidates,
            resolver: refreshResolver,
          });
          client.logger.info(
            { fromDomain: env.postmark.from_domain, postmarkId: env.postmark.id },
            "verify-resolver: self-heal retry succeeded after force-refresh",
          );
        } catch (retryErr) {
          client.logger.warn(
            {
              err: retryErr instanceof Error ? retryErr.message : String(retryErr),
              postmarkId: env.postmark.id,
            },
            "skip envelope: open+verify failed after force-refresh retry",
          );
          continue;
        }
      } else {
        client.logger.warn(
          { err: err instanceof Error ? err.message : String(err), postmarkId: env.postmark.id },
          "skip envelope: open+verify failed",
        );
        continue;
      }
    }

    const brief = opened.brief as Record<string, unknown>;
    const enclosure = opened.enclosure as Record<string, unknown>;

    const messageId = stringField(brief, "message_id");
    const from = stringField(brief, "from");
    const to = stringArrayField(brief, "to");
    const cc = stringArrayField(brief, "cc");
    const subject = stringField(enclosure, "subject");
    const body = stringInBody(enclosure, "text/plain");
    const attachments = parseAttachments(enclosure);

    out.push({
      messageId,
      from,
      to,
      cc,
      subject,
      body,
      attachments,
      rawEnvelope: raw,
    });

    client.store.storeMessage({
      messageId,
      direction: "received",
      from,
      to,
      cc,
      subject,
      bodyText: body,
      rawEnvelope: raw,
    });
  }

  return out;
}

function stringField(rec: Record<string, unknown>, key: string): string {
  const v = rec[key];
  return typeof v === "string" ? v : "";
}

function stringArrayField(rec: Record<string, unknown>, key: string): string[] {
  const v = rec[key];
  if (!Array.isArray(v)) {
    return [];
  }
  return v.filter((x): x is string => typeof x === "string");
}

function stringInBody(rec: Record<string, unknown>, contentType: string): string {
  const body = rec["body"];
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return "";
  }
  const v = (body as Record<string, unknown>)[contentType];
  return typeof v === "string" ? v : "";
}

function parseAttachments(rec: Record<string, unknown>): AttachmentInfo[] {
  const list = rec["attachments"];
  if (!Array.isArray(list)) {
    return [];
  }
  const out: AttachmentInfo[] = [];
  for (const item of list) {
    if (typeof item !== "object" || item === null || Array.isArray(item)) {
      continue;
    }
    const a = item as Record<string, unknown>;
    const id = typeof a["id"] === "string" ? (a["id"] as string) : "";
    const filename = typeof a["filename"] === "string" ? (a["filename"] as string) : "";
    const mimeType = typeof a["mime_type"] === "string" ? (a["mime_type"] as string) : "";
    const size = typeof a["size"] === "number" ? (a["size"] as number) : 0;
    out.push({ id, filename, mimeType, size });
  }
  return out;
}
