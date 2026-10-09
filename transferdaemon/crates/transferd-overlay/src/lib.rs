//! TransferDaemon's always-connected overlay.
//!
//! The overlay gives *any* application on *any* paired device a route to *any other* paired
//! device, over *any* network, without a firewall port, a router port-forward, or a server
//! somebody has to run.
//!
//! ## The shape of it
//!
//! * **Reachability is outbound-only.** Every node keeps authenticated *outbound* connections:
//!   to relay points (a self-hostable `relayd`, and any paired node that is itself reachable
//!   can serve as a relay for the rest), and to peers directly when a path exists. Nothing is
//!   ever dialled *into*, so no NAT, firewall or CGNAT mapping has to be configured. A NAT
//!   traversal upgrade (UDP hole punching) turns a relayed path into a direct one when the
//!   network allows it, and the relay stays as the always-works fallback.
//! * **Services are forwarded, not exposed.** A node publishes a local service with an ACL by
//!   node identity. Another node asks for it by node id (or by service group) and gets a stable
//!   local endpoint that survives reconnects. A local SOCKS5 and HTTP-CONNECT proxy let any
//!   app reach `<service>.<node>.td` with no per-service setup at all.
//! * **Routing is measured, not guessed.** Every route is probed continuously for RTT, loss
//!   and throughput. Traffic takes the best route per flow, fails over mid-stream without
//!   breaking the stream the application sees, and stripes bulk flows across routes. A service
//!   group is spread over every node offering that service, by load and route quality.
//! * **Everything is authenticated and encrypted end to end.** Node identity is TransferDaemon's
//!   hybrid post-quantum identity; every frame is authenticated and bound to its route and its
//!   position, so it cannot be replayed, reordered or moved. Nothing is exposed by default.
//!
//! The wire format, version negotiation and extension rules are specified in `docs/PROTOCOL.md`;
//! the architecture, the operations and the measured numbers are in `docs/OVERLAY.md`.

pub mod dns;
pub mod error;
pub mod events;
pub mod identity;
pub mod lanes;
pub mod link;
pub mod mux;
pub mod node;
pub mod ops;
pub mod protocol;
pub mod proxy;
pub mod relay;
pub mod session;
pub mod state;
pub mod wire;

pub use error::{OverlayError, Result};
pub use events::{Audit, AuditRecord, EventLog, OverlayEvent};
pub use identity::{Acl, ExposedService, Invite, NodeIdentity, NodeRecord, ServiceRate};
pub use link::{Link, LinkRegistry, LinkTransport, RouteKind, RouteMetrics, RouteStats};
pub use mux::{Mux, OutFrame, RecvSide, SendSide, StreamId, DEFAULT_WINDOW, MAX_FRAME};
pub use node::{OverlayConfig, OverlayNode, ProxyAddrs};
pub use protocol::{Frame, ServiceInfo, VERSION_CURRENT, VERSION_MIN};
pub use relay::RelayHub;
pub use session::{PeerInfo, SessionHandle};

/// The crate's own version, reported by `overlay.status`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
