/** Base class of every error this library throws. */
export class TransferdError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** A byte string that does not decode as the structure it claims to be. */
export class DecodeError extends TransferdError {}

/** The handshake was refused: a bad signature, an unexpected peer, or a malformed flight. */
export class HandshakeError extends TransferdError {}

/** A sealed tunnel frame failed to authenticate, was replayed, or is malformed. */
export class TunnelError extends TransferdError {}

/** An overlay frame is not ours, is oversized, or its body does not decode. */
export class FrameError extends TransferdError {}

/** An invite was refused: wrong prefix, expired, bad signature, or malformed fields. */
export class InviteError extends TransferdError {}

/** The hello exchange failed, or the peer refused the session. */
export class SessionError extends TransferdError {}

/** The relay answered a request with an error. `code` is the relay's error name. */
export class RelayRefused extends TransferdError {
  constructor(
    readonly code: string,
    readonly detail: string,
  ) {
    super(`the relay refused the request: ${code}: ${detail}`);
  }
}

/** The relay did not answer within the client's timeout. */
export class RelayTimeout extends TransferdError {}

/** The relay answered with a message that does not match the request. */
export class RelayProtocolError extends TransferdError {}

/** The peer refused a stream we opened. `code` is an OPEN_ERR code: `no_such_service`, `denied`, `rate_limited` or `protocol`. */
export class StreamRefused extends TransferdError {
  constructor(
    readonly code: string,
    readonly reason: string,
  ) {
    super(`the peer refused the stream: ${code}: ${reason}`);
  }
}
