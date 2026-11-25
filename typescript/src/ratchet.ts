/**
 * Double ratchet: per-message forward and future secrecy (`crates/transferd-crypto/src/ratchet.rs`).
 *
 * Established on top of the authenticated handshake: the session key is the ratchet root. Each message is encrypted
 * under a key from a BLAKE3 chain, so one leaked message key reveals neither earlier nor later messages (forward
 * secrecy). Every `RATCHET_INTERVAL` sends, the sender takes a DH step: a fresh X25519 secret and a fresh ML-KEM-768
 * encapsulation are both mixed into the root, so a leaked root cannot decrypt what follows (future secrecy, with a
 * post-quantum component).
 *
 * Ordering: the transport delivers in order, so each chain advances once per message and no skipped-message keys are
 * kept.
 */
import { concatBytes, constantTimeEqual } from "./bytes.js";
import {
  aesGcmOpen,
  aesGcmSeal,
  blake3DeriveKey,
  mlkemDecapsulate,
  mlkemEncapsulate,
  mlkemKeypair,
  randomBytes,
  x25519Exchange,
  x25519Generate,
  x25519Public,
} from "./crypto.js";
import { TransferdError } from "./errors.js";

const CTX_CHAIN = "TransferDaemon-v3-ratchet-chain";
const CTX_MESSAGE_KEY = "TransferDaemon-v3-ratchet-message-key";
const CTX_ROOT_MIX = "TransferDaemon-v3-ratchet-root-mix";
const CTX_DH = "TransferDaemon-v3-ratchet-dh";
const CTX_KEM = "TransferDaemon-v3-ratchet-kem";
const CTX_INIT_SEND = "TransferDaemon-v3-ratchet-init-send";
const CTX_INIT_RECV = "TransferDaemon-v3-ratchet-init-recv";

/** How many sends before the sender takes a DH step. */
export const RATCHET_INTERVAL = 10;
const TAG_LEN = 16;
const KEM_EK_LEN = 1184;
const KEM_CT_LEN = 1088;
/** The most chain steps one message may skip ahead (a bound on a hostile index). */
const MAX_SKIP = 1_000_000;

export class RatchetError extends TransferdError {}

/**
 * The new root after a DH step: the DH output, and the ML-KEM output when there is one, mixed into the old root through a
 * KDF. Without the KEM output the root is what a classical-only attacker can reproduce; with it, it is not.
 */
export function mixRoot(root: Uint8Array, dhShared: Uint8Array, kemShared?: Uint8Array): Uint8Array {
  const parts = [root, blake3DeriveKey(CTX_DH, dhShared)];
  if (kemShared !== undefined) {
    parts.push(blake3DeriveKey(CTX_KEM, kemShared));
  }
  return blake3DeriveKey(CTX_ROOT_MIX, concatBytes(...parts));
}

function chainContexts(isInitiator: boolean): [string, string] {
  return isInitiator ? [CTX_INIT_SEND, CTX_INIT_RECV] : [CTX_INIT_RECV, CTX_INIT_SEND];
}

/** A deterministic per-message nonce from the chain index (each message key is used once, so this is safe). */
function nonceFor(index: number): Uint8Array {
  const nonce = new Uint8Array(12);
  const view = new DataView(nonce.buffer);
  view.setBigUint64(4, BigInt(index), false);
  return nonce;
}

/** A fresh ML-KEM-768 decapsulation key, and its encapsulation key. */
function freshKem(): { secretKey: Uint8Array; publicKey: Uint8Array } {
  return mlkemKeypair(randomBytes(64));
}

/** One message-key KDF chain: the symmetric half of the ratchet. */
export class RatchetChain {
  private chainKey: Uint8Array;
  index = 0;

  constructor(seed: Uint8Array, context: string) {
    this.chainKey = blake3DeriveKey(context, seed);
  }

  /** Advance the chain and return the message key for this step, with its index. */
  step(): [Uint8Array, number] {
    const messageKey = blake3DeriveKey(CTX_MESSAGE_KEY, this.chainKey);
    this.chainKey = blake3DeriveKey(CTX_CHAIN, this.chainKey);
    const index = this.index;
    this.index += 1;
    return [messageKey, index];
  }
}

/** The encrypted envelope for one application message. The ratchet fields are set on first sends and DH steps. */
export interface RatchetMessage {
  chainIndex: number;
  nonce: Uint8Array;
  tag: Uint8Array;
  ciphertext: Uint8Array;
  ratchetPk?: Uint8Array;
  kemEk?: Uint8Array;
  kemCt?: Uint8Array;
}

/** The double ratchet state for one pair of peers. `isInitiator` fixes which chain each side sends on. */
export class DoubleRatchet {
  private root: Uint8Array;
  private send: RatchetChain;
  private recv: RatchetChain;
  private dhSecret: Uint8Array;
  private dhPk: Uint8Array;
  private kemSecret: Uint8Array;
  private kemPublic: Uint8Array;
  private peerDhPk: Uint8Array | undefined;
  private peerKemEk: Uint8Array | undefined;
  private sendsSinceDh = 0;
  private sentAny = false;
  private readonly isInitiator: boolean;

  constructor(rootKey: Uint8Array, isInitiator: boolean) {
    if (rootKey.length !== 32) {
      throw new RatchetError("a ratchet root is 32 bytes");
    }
    this.root = Uint8Array.from(rootKey);
    const [sendContext, recvContext] = chainContexts(isInitiator);
    this.send = new RatchetChain(rootKey, sendContext);
    this.recv = new RatchetChain(rootKey, recvContext);
    this.dhSecret = x25519Generate();
    this.dhPk = x25519Public(this.dhSecret);
    const kem = freshKem();
    this.kemSecret = kem.secretKey;
    this.kemPublic = kem.publicKey;
    this.isInitiator = isInitiator;
  }

  /** The current X25519 ratchet public key. */
  ratchetPublicKey(): Uint8Array {
    return Uint8Array.from(this.dhPk);
  }

  private deriveNewRoot(dhShared: Uint8Array, kemShared: Uint8Array | undefined): void {
    this.root = mixRoot(this.root, dhShared, kemShared);
  }

  /** A send-side DH step: a fresh X25519 secret and, when the peer has published one, a fresh ML-KEM encapsulation. */
  private dhStepSend(): Uint8Array | undefined {
    const secret = x25519Generate();
    const pk = x25519Public(secret);
    if (this.peerDhPk === undefined) {
      throw new RatchetError("a DH step needs the peer's ratchet key");
    }
    const shared = x25519Exchange(secret, this.peerDhPk);
    let kemCt: Uint8Array | undefined;
    let kemSs: Uint8Array | undefined;
    if (this.peerKemEk !== undefined) {
      const fresh = freshKem();
      const out = mlkemEncapsulate(this.peerKemEk);
      kemSs = out.sharedSecret;
      kemCt = out.ciphertext;
      this.kemSecret = fresh.secretKey;
      this.kemPublic = fresh.publicKey;
    }
    this.deriveNewRoot(shared, kemSs);
    this.dhSecret = secret;
    this.dhPk = pk;
    const [sendContext] = chainContexts(this.isInitiator);
    this.send = new RatchetChain(this.root, sendContext);
    this.sendsSinceDh = 0;
    return kemCt;
  }

  /** A receive-side DH step, when a new peer key arrives: mix the DH and KEM outputs and reset the recv chain. */
  private dhStepRecv(newPeerPk: Uint8Array, kemCt: Uint8Array | undefined): void {
    const shared = x25519Exchange(this.dhSecret, newPeerPk);
    let kemSs: Uint8Array | undefined;
    if (kemCt !== undefined && kemCt.length === KEM_CT_LEN) {
      kemSs = mlkemDecapsulate(this.kemSecret, kemCt);
    }
    this.deriveNewRoot(shared, kemSs);
    this.peerDhPk = newPeerPk;
    const [, recvContext] = chainContexts(this.isInitiator);
    this.recv = new RatchetChain(this.root, recvContext);
  }

  /** Encrypts `plaintext` under a fresh message key. Publishes the ratchet keys on the first send, and takes a DH step
   * every `RATCHET_INTERVAL` sends once the peer's key is known. */
  encrypt(plaintext: Uint8Array): RatchetMessage {
    let ratchetPk: Uint8Array | undefined;
    let kemEk: Uint8Array | undefined;
    let kemCt: Uint8Array | undefined;
    if (!this.sentAny) {
      this.sentAny = true;
      ratchetPk = this.dhPk;
      kemEk = this.kemPublic;
    } else if (this.sendsSinceDh >= RATCHET_INTERVAL && this.peerDhPk !== undefined) {
      kemCt = this.dhStepSend();
      ratchetPk = this.dhPk;
      kemEk = this.kemPublic;
    }
    const [messageKey, index] = this.send.step();
    this.sendsSinceDh += 1;
    const msg = sealMessage(messageKey, index, plaintext, ratchetPk);
    msg.kemEk = kemEk;
    msg.kemCt = kemCt;
    return msg;
  }

  /** Decrypts an envelope, ratcheting the recv chain first if it carries a new ratchet key. */
  decrypt(msg: RatchetMessage): Uint8Array {
    if (msg.ratchetPk !== undefined) {
      if (this.peerDhPk === undefined) {
        // First sight of the peer's key: record it without changing the root.
        this.peerDhPk = msg.ratchetPk;
        if (msg.kemEk?.length === KEM_EK_LEN) {
          this.peerKemEk = msg.kemEk;
        }
      } else if (!constantTimeEqual(msg.ratchetPk, this.peerDhPk)) {
        this.dhStepRecv(msg.ratchetPk, msg.kemCt);
        if (msg.kemEk?.length === KEM_EK_LEN) {
          this.peerKemEk = msg.kemEk;
        }
      }
    }
    const messageKey = this.advanceRecv(msg.chainIndex);
    try {
      return aesGcmOpen(messageKey, msg.nonce, concatBytes(msg.ciphertext, msg.tag), new Uint8Array(0));
    } catch (error) {
      if (error instanceof TransferdError) {
        throw new RatchetError("ratchet decrypt: authentication failed");
      }
      throw error;
    }
  }

  /**
   * The message key for `chainIndex`, advancing the recv chain to it. Transport is in order, so an index behind the
   * chain has no key: the zero key then fails authentication, as the reference's does.
   */
  private advanceRecv(chainIndex: number): Uint8Array {
    const steps = Math.min(Math.max(chainIndex - this.recv.index, 0), MAX_SKIP) + 1;
    for (let i = 0; i < steps; i++) {
      const [key, index] = this.recv.step();
      if (index === chainIndex) {
        return key;
      }
    }
    return new Uint8Array(32);
  }

}

function sealMessage(messageKey: Uint8Array, index: number, plaintext: Uint8Array, ratchetPk: Uint8Array | undefined): RatchetMessage {
  const nonce = nonceFor(index);
  const sealed = aesGcmSeal(messageKey, nonce, plaintext, new Uint8Array(0));
  return {
    chainIndex: index,
    nonce,
    tag: sealed.slice(sealed.length - TAG_LEN),
    ciphertext: sealed.slice(0, sealed.length - TAG_LEN),
    ratchetPk,
  };
}
