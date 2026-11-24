# Transferd Blind Relay Protocol

A Transferd relay is a simple, blind packet forwarder. It never sees plaintext, identities, or session contents beyond an opaque token.

## Registration

A node derives a 32-byte token:

```
token = BLAKE3-derive_key("transferd-overlay-relay-token-v1", node_id)
```

It registers this token with the relay, accompanied by a proof-of-work (BLAKE3-based, parameters are implementation-defined but must be verifiable by any conforming relay). Registration includes a sequence number that must be strictly increasing for that token. Clients typically initialize the sequence from the system clock so that a restart is accepted.

Registrations are renewed every 30 seconds.

## Forwarding

To send to a peer, a node emits:

```
Forward { token: [32], ciphertext: bytes }
```

The relay looks up the current address associated with the token and forwards the ciphertext. The ciphertext itself is the padded payload described in [PROTOCOL.md](PROTOCOL.md) §3.

## Locate

Tag `0x08` requests the addresses the relay currently sees for the asker and for another token. The reply is given only when the request arrives from the address that registered the asking token.

## Properties

- The relay learns neither the node identity nor the content of the ciphertext.
- Size is hidden to within a factor of two by padding.
- Multiple links between the same pair of nodes are demultiplexed by the recipient using the tunnel keys; the relay is unaware of them.
- Early payloads (arriving before registration completes) may be briefly buffered (implementation limit, typically ≤ 64 per peer).

Any party may operate a relay. Nodes are configured with one or more relay addresses; there is no central directory.
