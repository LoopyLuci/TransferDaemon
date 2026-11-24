"""Transferd: a Python implementation of the Transferd wire protocol.

The modules follow the specification in `docs/PROTOCOL.md`, `docs/CRYPTO.md` and `docs/RELAY.md`
of the Transferd repository:

- `identity`, `crypto`: the hybrid identity (Ed25519 + ML-DSA-87) and its primitives;
- `handshake`: the authenticated X25519 + ML-KEM-768 handshake, over asyncio streams;
- `tunnel`: per-direction keys, sealed frames, the 4096-wide replay window;
- `frames`, `bincode`: overlay frames and their bodies;
- `session`: the HELLO / HELLO_ACK exchange that opens a session after the handshake;
- `invite`: `tdov2:` invites;
- `relay`: relay messages, proof of work, and the relay payload padding;
- `relay_client`: a client of `relayd` (register, keepalive, locate, forward);
- `punch`: hole-punch probes and the gateway envelope.
"""

__version__ = "0.1.0"

from .errors import (  # noqa: F401
    DecodeError,
    FrameError,
    HandshakeError,
    InviteError,
    TransferdError,
    TunnelError,
)
from .identity import HybridIdentity, key_fingerprint, relay_token_for  # noqa: F401
