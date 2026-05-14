#!/usr/bin/env bash
# Build a Debian/Ubuntu .deb package for TransferDaemon.
#
# Usage: ./installer/linux/build-deb.sh
# Output: dist/transferdaemon_1.0.0_amd64.deb
#
# Requires: cargo, dpkg-deb
set -euo pipefail

VERSION="1.0.0"
ARCH="amd64"
PACKAGE="transferdaemon"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STAGE="$ROOT/dist/deb-stage"
OUT="$ROOT/dist/${PACKAGE}_${VERSION}_${ARCH}.deb"

# ── Build release binaries ────────────────────────────────────────────────────
echo "==> Building release binaries..."
cd "$ROOT"
cargo build --release \
    -p transferd \
    -p transferd-ui \
    -p transferd-tui \
    -p launcher

# ── Stage the package layout ──────────────────────────────────────────────────
rm -rf "$STAGE"
install -Dm755 "$ROOT/target/release/launcher"        "$STAGE/usr/bin/transferdaemon"
install -Dm755 "$ROOT/target/release/transferd"        "$STAGE/usr/lib/transferdaemon/bin/transferd"
install -Dm755 "$ROOT/target/release/transferd-ui"     "$STAGE/usr/lib/transferdaemon/bin/transferd-ui"
install -Dm755 "$ROOT/target/release/transferd-tui"    "$STAGE/usr/lib/transferdaemon/bin/transferd-tui"

# .desktop file so it appears in application launchers.
install -Dm644 /dev/stdin "$STAGE/usr/share/applications/transferdaemon.desktop" <<'EOF'
[Desktop Entry]
Name=TransferDaemon
Comment=Privacy-first file transfer and encrypted calling
Exec=/usr/bin/transferdaemon
Terminal=false
Type=Application
Categories=Network;FileTransfer;
EOF

# ── DEBIAN control ────────────────────────────────────────────────────────────
mkdir -p "$STAGE/DEBIAN"
cat > "$STAGE/DEBIAN/control" <<EOF
Package: $PACKAGE
Version: $VERSION
Architecture: $ARCH
Maintainer: TransferDaemon Project <noreply@transferdaemon.example>
Description: Privacy-first file transfer and encrypted calling
 TransferDaemon is a post-quantum-secured peer-to-peer communication platform
 with end-to-end encrypted messaging, file transfer, and video calling.
 .
 Includes: daemon (gRPC), desktop GUI (egui), and terminal UI (ratatui).
Depends: libc6 (>= 2.17)
Section: net
Priority: optional
Homepage: https://github.com/LoopyLuci/TransferDaemon
EOF

# postinst: make the launcher wrapper aware of its library path.
cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
# Ensure the transferdaemon launcher finds its binaries in /usr/lib/transferdaemon/bin/.
# Nothing else needed; launcher already searches there by convention.
exit 0
EOF
chmod 0755 "$STAGE/DEBIAN/postinst"

# ── Build the .deb ────────────────────────────────────────────────────────────
mkdir -p "$ROOT/dist"
dpkg-deb --build --root-owner-group "$STAGE" "$OUT"

SIZE_MB=$(du -sh "$OUT" | cut -f1)
echo ""
echo "==> SUCCESS"
echo "    $OUT  ($SIZE_MB)"
echo ""
echo "To install:"
echo "    sudo dpkg -i $OUT"
echo ""
echo "To sign (requires GPG):"
echo "    dpkg-sig --sign builder -k YOUR_KEY_ID $OUT"
