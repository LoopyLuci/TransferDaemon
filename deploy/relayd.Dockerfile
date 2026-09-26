# Multi-stage build for the hosted relay stack: `relayd` (blind UDP relay) and
# `dhtd` (DHT bootstrap node). Builds only the two binaries' dependency closure
# (no tonic/webrtc/UI), so the image is small and the build is fast.
#
# Build (from the repo root, or CI):
#   docker build -t transferd-relay -f deploy/relayd.Dockerfile .
#
# Run (see deploy/docker-compose.yml for the wired-up pair):
#   docker run --rm -p 5901:5901/udp transferd-relay relayd
#   docker run --rm -p 7901:7901/udp -e DHTD_ADVERTISE=<public-ip>:7901 transferd-relay dhtd

FROM rust:1-slim AS builder
WORKDIR /build
# Cache the dependency layer.
COPY transferdaemon/Cargo.toml transferdaemon/Cargo.lock ./
COPY transferdaemon/crates ./crates
# Build only the relay stack binaries (faster than the whole workspace).
RUN cargo build --release -p relayd -p transferd-relay --bin relayd --bin dhtd

FROM debian:bookworm-slim
# relayd uses the UDP socket directly; no runtime libs required. Add ca-certs
# only for tooling; the relay itself needs nothing.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/relayd /usr/local/bin/relayd
COPY --from=builder /build/target/release/dhtd /usr/local/bin/dhtd
# relayd: UDP 5901. dhtd: UDP 7901.
EXPOSE 5901/udp 7901/udp
ENTRYPOINT ["/usr/local/bin/relayd"]