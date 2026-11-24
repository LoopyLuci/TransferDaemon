import { blake3 } from "@noble/hashes/blake3.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { gcm } from "@noble/ciphers/aes.js";
import { utf8 } from "./bytes.js";
import { TransferdError } from "./errors.js";

export { randomBytes };

/** The Ed25519 group order L. Scalars at or above it are non-canonical. */
export const ED25519_ORDER = 2n ** 252n + 27742317777372353535851937790883648493n;

/** The context the ML-DSA half of a hybrid signature is bound to. */
export const ML_DSA_SIGN_CONTEXT = utf8("TransferDaemon-v1-hybrid-sign");

// --- BLAKE3 ---------------------------------------------------------------------------------------

export function blake3Hash(data: Uint8Array): Uint8Array {
  return blake3(data);
}

export function blake3Keyed(key: Uint8Array, data: Uint8Array): Uint8Array {
  if (key.length !== 32) {
    throw new TransferdError("a BLAKE3 key is 32 bytes");
  }
  return blake3(data, { key });
}

export function blake3DeriveKey(context: string, material: Uint8Array): Uint8Array {
  return blake3(material, { context: utf8(context) });
}

// --- X25519 ---------------------------------------------------------------------------------------

/** A fresh 32-byte X25519 private key. */
export function x25519Generate(): Uint8Array {
  return randomBytes(32);
}

export function x25519Public(privateKey: Uint8Array): Uint8Array {
  return x25519.getPublicKey(privateKey);
}

export function x25519Exchange(privateKey: Uint8Array, peerPublic: Uint8Array): Uint8Array {
  try {
    return x25519.getSharedSecret(privateKey, peerPublic);
  } catch {
    throw new TransferdError("X25519 exchange failed: the peer key is of low order");
  }
}

// --- Ed25519 --------------------------------------------------------------------------------------

export function ed25519Public(seed: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(seed);
}

export function ed25519Sign(seed: Uint8Array, message: Uint8Array): Uint8Array {
  return ed25519.sign(message, seed);
}

/** The ordinary Ed25519 check. Used for the Ed25519 half of hybrid signatures. */
export function ed25519Verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  try {
    return ed25519.verify(signature, message, publicKey, { zip215: false });
  } catch {
    return false;
  }
}

/**
 * The strict check used for invites: a canonical S, and neither the key nor R of small order.
 * Matches the Python implementation's `ed25519_verify_strict`.
 */
export function ed25519VerifyStrict(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) {
    return false;
  }
  if (littleEndianToBigInt(signature.subarray(32)) >= ED25519_ORDER) {
    return false;
  }
  if (hasSmallOrder(publicKey) || hasSmallOrder(signature.subarray(0, 32))) {
    return false;
  }
  return ed25519Verify(publicKey, message, signature);
}

function hasSmallOrder(encoding: Uint8Array): boolean {
  try {
    return ed25519.Point.fromBytes(encoding, false).isSmallOrder();
  } catch {
    // An encoding that does not decode is refused by the ordinary check that follows.
    return false;
  }
}

function littleEndianToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    value = (value << 8n) | BigInt(bytes[i]);
  }
  return value;
}

// --- ML-KEM-768 (FIPS 203) ------------------------------------------------------------------------

export interface MlKemKeypair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

/** A decapsulation key from its 64-byte seed, and its 1184-byte encapsulation key. */
export function mlkemKeypair(seed: Uint8Array): MlKemKeypair {
  return ml_kem768.keygen(seed);
}

/** Returns the shared secret and the ciphertext. `m` pins the randomness; leave it out in normal use. */
export function mlkemEncapsulate(publicKey: Uint8Array, m?: Uint8Array): { sharedSecret: Uint8Array; ciphertext: Uint8Array } {
  const out = m === undefined ? ml_kem768.encapsulate(publicKey) : ml_kem768.encapsulate(publicKey, m);
  return { sharedSecret: out.sharedSecret, ciphertext: out.cipherText };
}

export function mlkemDecapsulate(secretKey: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  return ml_kem768.decapsulate(ciphertext, secretKey);
}

// --- ML-DSA-87 (FIPS 204) -------------------------------------------------------------------------

export interface MlDsaKeypair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

/** An ML-DSA-87 key pair from its 32-byte seed (xi). */
export function mldsaFromSeed(xi: Uint8Array): MlDsaKeypair {
  return ml_dsa87.keygen(xi);
}

export function mldsaSign(secretKey: Uint8Array, message: Uint8Array, context: Uint8Array): Uint8Array {
  return ml_dsa87.sign(message, secretKey, { context });
}

export function mldsaVerify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array, context: Uint8Array): boolean {
  try {
    return ml_dsa87.verify(signature, message, publicKey, { context });
  } catch {
    return false;
  }
}

// --- AES-256-GCM ----------------------------------------------------------------------------------

/** Ciphertext followed by the 16-byte tag. */
export function aesGcmSeal(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
  return gcm(key, nonce, aad).encrypt(plaintext);
}

export function aesGcmOpen(key: Uint8Array, nonce: Uint8Array, sealed: Uint8Array, aad: Uint8Array): Uint8Array {
  try {
    return gcm(key, nonce, aad).decrypt(sealed);
  } catch {
    throw new TransferdError("AES-GCM authentication failed");
  }
}
