/**
 * Core client: connect, handshake, register, close. Mirrors
 * `impl/go/internal/client/client.go` and uses the @sempdev/semp
 * primitives directly.
 *
 * @module
 */

import {
  type ClientConfig as HandshakeClientConfig,
  type Capabilities,
  defaultClientCapabilities,
  runClient as runClientHandshake,
} from "@sempdev/semp/handshake";
import { type Session } from "@sempdev/semp/session";
import {
  type Transport,
  dialH2Session,
  dialWS,
} from "@sempdev/semp/transport";

import type { Logger } from "pino";

import type { Config } from "../config/config.js";
import { SQLitePrivateStore } from "../store/sqlite.js";
import {
  type SuiteId,
  generateEncryptionKeyPair,
  generateIdentityKeyPair,
  resolveSuite,
} from "./keygen.js";


/** HTTPS / HTTP base URL derived from the configured server URL. */
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

/** Outcome of a client-side register call. */
export interface RegisterResult {
  identityKeyId: string;
  encryptionKeyId: string;
  domainSigningKeyId?: string;
  domainEncryptionKeyId?: string;
}

interface RegisterRequestBody {
  address: string;
  password: string;
  identity_key: { algorithm: string; public_key: string };
  encryption_key: { algorithm: string; public_key: string };
}

interface RegisterKeyEntry {
  algorithm: string;
  public_key: string;
  key_id: string;
}

interface RegisterResponseBody {
  status?: string;
  domain_signing_key?: RegisterKeyEntry | null;
  domain_encryption_key?: RegisterKeyEntry | null;
}

/** Manages a single SEMP session with the home server. */
export class Client {
  readonly cfg: Config;
  readonly store: SQLitePrivateStore;
  readonly suite: SuiteId;
  readonly logger: Logger;
  /** Transport opened by `connect`. Becomes owned by `session` on success. */
  transport: Transport | null = null;
  session: Session | null = null;

  constructor(cfg: Config, store: SQLitePrivateStore, logger: Logger) {
    this.cfg = cfg;
    this.store = store;
    this.suite = resolveSuite(cfg.suite);
    this.logger = logger;
  }

  // -------------------------------------------------------------------------
  // Register

  /**
   * Generate keys locally if missing, POST them to /v1/register, and
   * cache the server's domain keys. Returns the public-key
   * fingerprints for the just-registered identity.
   */
  async register(password: string): Promise<RegisterResult> {
    if (!this.store.hasUserKeys(this.cfg.identity)) {
      const id = generateIdentityKeyPair();
      this.store.putUserKeyPair(
        this.cfg.identity,
        "identity",
        "ed25519",
        id.publicKey,
        id.privateKey,
      );
      const enc = generateEncryptionKeyPair(this.suite);
      this.store.putUserKeyPair(
        this.cfg.identity,
        "encryption",
        this.suite,
        enc.publicKey,
        enc.privateKey,
      );
      this.logger.info({ address: this.cfg.identity }, "generated keys locally");
    }

    const idPub = this.store.loadUserPublicKey(this.cfg.identity, "identity");
    if (idPub === null) {
      throw new Error("client: no identity key present after generation");
    }
    const encPub = this.store.loadUserPublicKey(this.cfg.identity, "encryption");
    if (encPub === null) {
      throw new Error("client: no encryption key present after generation");
    }

    const body: RegisterRequestBody = {
      address: this.cfg.identity,
      password,
      identity_key: {
        algorithm: "ed25519",
        public_key: Buffer.from(idPub.publicKey).toString("base64"),
      },
      encryption_key: {
        algorithm: this.suite,
        public_key: Buffer.from(encPub.publicKey).toString("base64"),
      },
    };

    const url = serverHTTPBase(this.cfg.server) + "/v1/register";
    let resp: Response;
    try {
      resp = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
    } catch (err) {
      throw new Error(
        `client: register: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    if (!resp.ok) {
      throw new Error(`client: register: server returned ${resp.status}`);
    }
    const reg = (await resp.json()) as RegisterResponseBody;

    let domainSigningKeyId: string | undefined;
    let domainEncryptionKeyId: string | undefined;
    if (reg.domain_signing_key !== undefined && reg.domain_signing_key !== null) {
      const dk = reg.domain_signing_key;
      const pub = new Uint8Array(Buffer.from(dk.public_key, "base64"));
      domainSigningKeyId = this.store.putDomainKey(
        this.cfg.domain,
        "signing",
        dk.algorithm,
        pub,
      );
      this.logger.info({ fingerprint: domainSigningKeyId }, "cached domain signing key");
    }
    if (reg.domain_encryption_key !== undefined && reg.domain_encryption_key !== null) {
      const dk = reg.domain_encryption_key;
      const pub = new Uint8Array(Buffer.from(dk.public_key, "base64"));
      domainEncryptionKeyId = this.store.putDomainKey(
        this.cfg.domain,
        "encryption",
        dk.algorithm,
        pub,
      );
      this.logger.info(
        { fingerprint: domainEncryptionKeyId },
        "cached domain encryption key",
      );
    }

    this.logger.info(
      {
        address: this.cfg.identity,
        identityFingerprint: idPub.keyId,
        encryptionFingerprint: encPub.keyId,
      },
      "registered with server",
    );

    const out: RegisterResult = {
      identityKeyId: idPub.keyId,
      encryptionKeyId: encPub.keyId,
    };
    if (domainSigningKeyId !== undefined) {
      out.domainSigningKeyId = domainSigningKeyId;
    }
    if (domainEncryptionKeyId !== undefined) {
      out.domainEncryptionKeyId = domainEncryptionKeyId;
    }
    return out;
  }

  // -------------------------------------------------------------------------
  // Connect / handshake

  /** Open a transport based on the configured server URL. */
  async connect(): Promise<void> {
    const server = this.cfg.server;
    const allowInsecure = this.cfg.tls.insecure;
    if (server.startsWith("ws://") || server.startsWith("wss://")) {
      this.transport = await dialWS(server, { allowInsecure });
    } else if (server.startsWith("http://") || server.startsWith("https://")) {
      // The h2 transport runs over a long-lived POST to a per-session
      // URL; the caller wires that URL itself in opts.sessionUrl.
      this.transport = await dialH2Session({ sessionUrl: server });
    } else {
      throw new Error(`client: unsupported server URL scheme: ${server}`);
    }
    this.logger.info({ server: this.cfg.server }, "connected");
  }

  /** Run the handshake; on success owns the transport via the returned Session. */
  async handshake(): Promise<void> {
    if (this.transport === null) {
      throw new Error("client: not connected");
    }

    const idPriv = this.store.loadUserPrivateKey(this.cfg.identity, "identity");
    if (idPriv === null) {
      throw new Error(`client: no identity key for ${this.cfg.identity}; run 'register' first`);
    }
    const domainSigning = this.store.lookupDomainKey(this.cfg.domain);
    if (domainSigning === null) {
      throw new Error(
        `client: no domain signing key cached for ${this.cfg.domain}; re-run 'register' first`,
      );
    }
    const serverDomainPub = new Uint8Array(
      Buffer.from(domainSigning.public_key, "base64"),
    );

    const transportId = this.cfg.server.startsWith("ws") ? "ws" : "h2";

    const capabilities: Capabilities = defaultClientCapabilities();

    const cfg: HandshakeClientConfig = {
      suite: this.suite,
      capabilities,
      transport: transportId,
      serverDomainPub,
      identity: {
        clientId: this.cfg.identity,
        clientIdentity: this.cfg.identity,
        longTermSeed: idPriv.privateKey,
        longTermKeyId: idPriv.keyId,
      },
    };

    const session = await runClientHandshake(this.transport, cfg);
    this.session = session;
    this.logger.info(
      {
        sessionId: session.sessionId,
        ttl: session.sessionTTL,
        expiresAt: session.expiresAt().toISOString(),
      },
      "session established",
    );
  }

  /** Convenience: dial then handshake. */
  async connectAndHandshake(): Promise<void> {
    await this.connect();
    await this.handshake();
  }

  /** Close the session (and underlying transport). */
  async close(): Promise<void> {
    if (this.session !== null) {
      await this.session.erase();
      this.session = null;
      this.transport = null;
      return;
    }
    if (this.transport !== null) {
      try {
        await this.transport.close();
      } catch {
        // already closed
      }
      this.transport = null;
    }
  }
}
