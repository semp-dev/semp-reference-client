/**
 * User key-pair generation. Mirrors `impl/go/internal/keygen/keygen.go`
 * but expressed against the @sempdev/semp primitives.
 *
 * - Identity keys: Ed25519 32-byte seed.
 * - Encryption keys: depends on suite.
 *     baseline ("x25519-chacha20-poly1305")  -> X25519 32-byte priv, 32-byte pub.
 *     hybrid   ("pq-kyber768-x25519")        -> kyberPriv (2400) || x25519Priv (32)
 *                                               kyberPub  (1184) || x25519Pub  (32)
 *
 * The encryption key layout matches `seal/wrap.ts` so wrap/unwrap
 * accept the bytes without further unpacking.
 *
 * @module
 */

import {
  HybridPrivateKeySize,
  HybridPublicKeySize,
  Kyber768PublicKeySize,
  X25519Size,
  kyber768KeyPairFromSeed,
  x25519PublicKey,
} from "@sempdev/semp/crypto";
import { SeedSize, publicKeyFromSeed } from "@sempdev/semp/keys";

/** Suites this client supports. */
export type SuiteId = "x25519-chacha20-poly1305" | "pq-kyber768-x25519";

/** Resolve a configured suite string; defaults to baseline if unknown. */
export function resolveSuite(s: string): SuiteId {
  if (s === "pq-kyber768-x25519" || s === "x25519-chacha20-poly1305") {
    return s;
  }
  return "x25519-chacha20-poly1305";
}

/** Random byte block sourced from the platform CSPRNG. */
function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

/** Identity key pair (Ed25519). */
export function generateIdentityKeyPair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const seed = randomBytes(SeedSize);
  const pub = publicKeyFromSeed(seed);
  return { publicKey: pub, privateKey: seed };
}

/** Encryption key pair, sized for the chosen suite. */
export function generateEncryptionKeyPair(
  suite: SuiteId,
): { publicKey: Uint8Array; privateKey: Uint8Array } {
  if (suite === "x25519-chacha20-poly1305") {
    const priv = randomBytes(X25519Size);
    const pub = x25519PublicKey(priv);
    return { publicKey: pub, privateKey: priv };
  }
  // Hybrid: Kyber half (deterministic from a fresh 64-byte seed,
  // which is cryptographically equivalent to a uniform keygen) plus
  // a fresh X25519 keypair.
  const kyberSeed = randomBytes(64);
  const kyber = kyber768KeyPairFromSeed(kyberSeed);
  const xPriv = randomBytes(X25519Size);
  const xPub = x25519PublicKey(xPriv);

  const pub = new Uint8Array(HybridPublicKeySize);
  pub.set(kyber.publicKey, 0);
  pub.set(xPub, Kyber768PublicKeySize);

  const priv = new Uint8Array(HybridPrivateKeySize);
  priv.set(kyber.secretKey, 0);
  priv.set(xPriv, kyber.secretKey.length);

  return { publicKey: pub, privateKey: priv };
}
