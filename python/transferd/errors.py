"""Exceptions raised by the Transferd Python implementation."""


class TransferdError(Exception):
    """Base class for every error this package raises."""


class DecodeError(TransferdError, ValueError):
    """A byte string does not decode as the structure it claims to be."""


class HandshakeError(TransferdError):
    """A handshake flight is malformed, unsigned, or not from the node that was dialled."""


class TunnelError(TransferdError):
    """A tunnel frame does not authenticate, is replayed, or does not match its header."""


class FrameError(TransferdError):
    """An overlay frame is not one this implementation can read."""


class InviteError(TransferdError):
    """An invite is malformed, expired, oversized, or its signature does not verify."""


class SessionError(TransferdError):
    """The hello exchange failed, or the peer refused the session."""


class RelayRefused(TransferdError):
    """The relay answered a request with an error. `code` is the relay's error name."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"the relay refused the request: {code}: {detail}")
        self.code = code
        self.detail = detail


class RelayTimeout(TransferdError):
    """The relay did not answer within the client's timeout."""


class RelayProtocolError(TransferdError):
    """The relay answered with a message that does not match the request."""


class StreamRefused(TransferdError):
    """The peer refused a stream we opened. `code` is an OPEN_ERR code: `no_such_service`, `denied`, `rate_limited`
    or `protocol`."""

    def __init__(self, code: str, reason: str) -> None:
        super().__init__(f"the peer refused the stream: {code}: {reason}")
        self.code = code
        self.reason = reason


class StreamReset(TransferdError):
    """A stream ended with an error rather than the end: the peer closed it with a code other than `closed`, it
    left frames missing, it was refused, or it was never open here. `reason` says which."""

    def __init__(self, sid: int, reason: str) -> None:
        super().__init__(f"stream {sid}: {reason}")
        self.sid = sid
        self.reason = reason


class OverlayError(TransferdError):
    """A route or stream operation on an overlay session failed (`Unreachable`, `Closed`, ...)."""


class Unreachable(OverlayError):
    """The peer did not answer an operation in time, or no route to it is usable."""

    def __init__(self, node: str) -> None:
        super().__init__(f"{node} is unreachable")
        self.node = node


class Closed(OverlayError):
    """The session or stream is gone."""


class NoSuchService(OverlayError):
    """The peer does not expose the service asked for."""

    def __init__(self, service: str) -> None:
        super().__init__(f"the peer has no service named {service}")
        self.service = service


class Denied(OverlayError):
    """The peer's access list refuses this node the service."""

    def __init__(self, node: str, service: str) -> None:
        super().__init__(f"{node} may not use {service}")
        self.node = node
        self.service = service


class RateLimited(OverlayError):
    """The peer's rate limit refused the stream for now."""

    def __init__(self, service: str, reason: str) -> None:
        super().__init__(f"{service} is rate limited: {reason}")
        self.service = service
        self.reason = reason
