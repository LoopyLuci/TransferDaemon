import { bytesToHex, concatBytes, utf8 } from "./bytes.js";
import {
  ML_DSA_SIGN_CONTEXT,
  blake3DeriveKey,
  ed25519Public,
  ed25519Sign,
  ed25519Verify,
  mldsaFromSeed,
  mldsaSign,
  mldsaVerify,
  randomBytes,
} from "./crypto.js";
import { TransferdError } from "./errors.js";

export const ED25519_PK_LEN = 32;
export const ML_DSA_87_PK_LEN = 2592;
export const HYBRID_PK_LEN = ED25519_PK_LEN + ML_DSA_87_PK_LEN; // 2624
export const ED25519_SIG_LEN = 64;
export const ML_DSA_87_SIG_LEN = 4627;
export const HYBRID_SIG_LEN = ED25519_SIG_LEN + ML_DSA_87_SIG_LEN; // 4691

export const MLDSA_SEED_CONTEXT = "TransferDaemon-v1-mldsa87-seed";
export const RELAY_TOKEN_CONTEXT = "transferd-overlay-relay-token-v1";
export const FINGERPRINT_CONTEXT = "TransferDaemon-overlay-key-fingerprint-v1";

const NODE_ID = /^[0-9a-f]{64}$/;

/** A node's signing identity. Keep the seed secret: it is the identity. */
export class HybridIdentity {
  readonly seed: Uint8Array;
  readonly name: string;
  readonly ed25519PublicKey: Uint8Array;
  /** `ed25519_pk (32) || ml_dsa_87_pk (2592)`. */
  readonly publicKey: Uint8Array;
  readonly nodeId: string;
  private readonly mldsaSecretKey: Uint8Array;

  constructor(seed: Uint8Array, name = "") {
    if (seed.length !== 64) {
      throw new TransferdError("an identity seed is 64 bytes");
    }
    this.seed = Uint8Array.from(seed);
    this.name = name;
    this.ed25519PublicKey = ed25519Public(this.seed.subarray(0, 32));
    const mldsa = mldsaFromSeed(blake3DeriveKey(MLDSA_SEED_CONTEXT, this.seed));
    this.mldsaSecretKey = mldsa.secretKey;
    this.publicKey = concatBytes(this.ed25519PublicKey, mldsa.publicKey);
    this.nodeId = bytesToHex(this.ed25519PublicKey);
  }

  static generate(name = ""): HybridIdentity {
    return new HybridIdentity(randomBytes(64), name);
  }

  /** A hybrid signature over `message`: Ed25519 (64) followed by ML-DSA-87 (4627). */
  sign(message: Uint8Array): Uint8Array {
    return concatBytes(
      ed25519Sign(this.seed.subarray(0, 32), message),
      mldsaSign(this.mldsaSecretKey, message, ML_DSA_SIGN_CONTEXT),
    );
  }

  /** The Ed25519 half alone. Anyone can check it against the node id. */
  signEd25519(message: Uint8Array): Uint8Array {
    return ed25519Sign(this.seed.subarray(0, 32), message);
  }

  relayToken(): Uint8Array {
    return relayTokenFor(this.nodeId);
  }
}

/** The 32-byte token a node registers with a relay, derived from the node id's text. */
export function relayTokenFor(nodeId: string): Uint8Array {
  return blake3DeriveKey(RELAY_TOKEN_CONTEXT, utf8(nodeId));
}

/** What an invite carries in place of the 2624-byte key. */
export function keyFingerprint(hybridPublicKey: Uint8Array): Uint8Array {
  return blake3DeriveKey(FINGERPRINT_CONTEXT, hybridPublicKey);
}

export function checkNodeId(nodeId: string): void {
  if (!NODE_ID.test(nodeId)) {
    throw new TransferdError("a node id is 64 lowercase hex characters");
  }
}

/** Both halves of a hybrid signature must verify. The Ed25519 half uses the ordinary check, as the reference does. */
export function verifyHybrid(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
  context: Uint8Array = ML_DSA_SIGN_CONTEXT,
): boolean {
  if (publicKey.length !== HYBRID_PK_LEN || signature.length !== HYBRID_SIG_LEN) {
    return false;
  }
  const edOk = ed25519Verify(publicKey.subarray(0, ED25519_PK_LEN), message, signature.subarray(0, ED25519_SIG_LEN));
  const mlOk = mldsaVerify(publicKey.subarray(ED25519_PK_LEN), message, signature.subarray(ED25519_SIG_LEN), context);
  return edOk && mlOk;
}
