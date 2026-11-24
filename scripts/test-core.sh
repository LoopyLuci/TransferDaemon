#!/usr/bin/env bash
# Builds, lints and tests the Transferd core workspace. Stops at the first failure.
#
#   scripts/test-core.sh             debug build
#   scripts/test-core.sh --release   release build for the tests and binaries
set -euo pipefail
cd "$(dirname "$0")/.."

REL=""
[[ "${1:-}" == "--release" ]] && REL="--release"

echo "== format (informational until the cargo fmt sweep lands) =="
cargo fmt --all -- --check || echo "warning: some files are not rustfmt-clean"

echo "== clippy (library and binary targets; tests are exempt from unwrap_used) =="
cargo clippy --workspace --all-features -- -D warnings

echo "== tests =="
cargo test --workspace --all-features $REL

echo "== relay binaries =="
cargo build --release -p relayd -p transferd-relay -p transferd-cat

# The reference side of the Python and TypeScript interop tests. Without these
# variables those tests are skipped, so build them and point the suites at them.
echo "== interop binaries =="
cargo build -p transferd-overlay --example interop_peer
cargo build -p relayd --bin relayd
EXE=""
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) EXE=".exe" ;; esac
export TRANSFERD_INTEROP_PEER="$PWD/target/debug/examples/interop_peer$EXE"
export TRANSFERD_RELAYD="$PWD/target/debug/relayd$EXE"

if command -v python >/dev/null 2>&1; then
  echo "== python =="
  python -m pytest python/tests -q
else
  echo "== python: skipped (no python on PATH) =="
fi

if command -v npm >/dev/null 2>&1; then
  echo "== typescript =="
  npm --prefix typescript ci
  npm --prefix typescript test
else
  echo "== typescript: skipped (no npm on PATH) =="
fi

echo "Transferd core: all checks passed."
