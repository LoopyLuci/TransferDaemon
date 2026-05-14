#!/usr/bin/env bash
# Build an RPM package for TransferDaemon (Fedora / CentOS / RHEL).
#
# Usage: ./installer/linux/build-rpm.sh
# Output: dist/transferdaemon-1.0.0-1.x86_64.rpm
#
# Requires: cargo, rpmbuild
set -euo pipefail

VERSION="1.0.0"
RELEASE="1"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RPMBUILD="$HOME/rpmbuild"
SPEC="$ROOT/installer/linux/transferdaemon.spec"

# ── Build release binaries ────────────────────────────────────────────────────
echo "==> Building release binaries..."
cd "$ROOT"
cargo build --release \
    -p transferd \
    -p transferd-ui \
    -p transferd-tui \
    -p launcher

# ── Create tarball of staged files for rpmbuild ───────────────────────────────
STAGING="$ROOT/dist/rpm-stage/transferdaemon-${VERSION}"
rm -rf "$STAGING"
mkdir -p "$STAGING/bin"
cp "$ROOT/target/release/launcher"      "$STAGING/bin/transferdaemon"
cp "$ROOT/target/release/transferd"     "$STAGING/bin/transferd"
cp "$ROOT/target/release/transferd-ui"  "$STAGING/bin/transferd-ui"
cp "$ROOT/target/release/transferd-tui" "$STAGING/bin/transferd-tui"
chmod 755 "$STAGING/bin/"*

TARBALL="$RPMBUILD/SOURCES/transferdaemon-${VERSION}.tar.gz"
mkdir -p "$RPMBUILD/SOURCES"
tar -czf "$TARBALL" -C "$(dirname "$STAGING")" "transferdaemon-${VERSION}"

# ── Write the spec file ───────────────────────────────────────────────────────
mkdir -p "$RPMBUILD/SPECS"
cat > "$SPEC" <<EOF
Name:           transferdaemon
Version:        $VERSION
Release:        $RELEASE%{?dist}
Summary:        Privacy-first file transfer and encrypted calling
License:        MIT
URL:            https://github.com/LoopyLuci/TransferDaemon
Source0:        transferdaemon-%{version}.tar.gz

%description
TransferDaemon is a post-quantum-secured peer-to-peer communication platform
with end-to-end encrypted messaging, file transfer, and video calling.
Includes: gRPC daemon, egui desktop GUI, and ratatui terminal UI.

%prep
%setup -q

%install
install -Dm755 bin/transferdaemon %{buildroot}%{_bindir}/transferdaemon
install -Dm755 bin/transferd      %{buildroot}%{_libdir}/transferdaemon/bin/transferd
install -Dm755 bin/transferd-ui   %{buildroot}%{_libdir}/transferdaemon/bin/transferd-ui
install -Dm755 bin/transferd-tui  %{buildroot}%{_libdir}/transferdaemon/bin/transferd-tui

%files
%{_bindir}/transferdaemon
%{_libdir}/transferdaemon/

%changelog
* $(date '+%a %b %d %Y') TransferDaemon Project <noreply@transferdaemon.example> - $VERSION-$RELEASE
- Initial release
EOF

# ── Build RPM ────────────────────────────────────────────────────────────────
rpmbuild -bb "$SPEC"

RPM_FILE=$(find "$RPMBUILD/RPMS" -name "transferdaemon-${VERSION}-*.rpm" | head -1)
mkdir -p "$ROOT/dist"
cp "$RPM_FILE" "$ROOT/dist/"
DEST="$ROOT/dist/$(basename "$RPM_FILE")"

SIZE_MB=$(du -sh "$DEST" | cut -f1)
echo ""
echo "==> SUCCESS"
echo "    $DEST  ($SIZE_MB)"
echo ""
echo "To install:"
echo "    sudo rpm -ivh $DEST"
echo "  or"
echo "    sudo dnf localinstall $DEST"
