#!/usr/bin/env bash
# Build a macOS .dmg installer for TransferDaemon.
#
# Usage: ./installer/macos/build-dmg.sh
# Output: dist/TransferDaemon-1.0.0.dmg
#
# Requires: cargo, hdiutil (built-in on macOS)
# Optional: codesign + notarytool (Apple Developer account for distribution)
set -euo pipefail

VERSION="1.0.0"
APP_NAME="TransferDaemon"
BUNDLE_ID="com.transferdaemon.app"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STAGE="$ROOT/dist/macos-stage"
APP_BUNDLE="$STAGE/$APP_NAME.app"
DMG_OUT="$ROOT/dist/$APP_NAME-$VERSION.dmg"
DMG_STAGE="$ROOT/dist/dmg-contents"

# ── Build release binaries ────────────────────────────────────────────────────
echo "==> Building release binaries (macOS targets)..."
cd "$ROOT"
cargo build --release \
    -p transferd \
    -p transferd-ui \
    -p transferd-tui \
    -p launcher

# ── Create .app bundle ────────────────────────────────────────────────────────
echo "==> Assembling .app bundle..."
rm -rf "$APP_BUNDLE"
MACOS_DIR="$APP_BUNDLE/Contents/MacOS"
BIN_DIR="$APP_BUNDLE/Contents/Resources/bin"
mkdir -p "$MACOS_DIR" "$BIN_DIR"

# The user-visible binary at the bundle root (the launcher).
cp "$ROOT/target/release/launcher" "$MACOS_DIR/$APP_NAME"
chmod 755 "$MACOS_DIR/$APP_NAME"

# Supporting binaries in Resources/bin/ (launcher searches here).
for b in transferd transferd-ui transferd-tui; do
    cp "$ROOT/target/release/$b" "$BIN_DIR/$b"
    chmod 755 "$BIN_DIR/$b"
done

# Info.plist — required by macOS to treat the directory as an app.
cat > "$APP_BUNDLE/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>         <string>$BUNDLE_ID</string>
  <key>CFBundleName</key>               <string>$APP_NAME</string>
  <key>CFBundleDisplayName</key>        <string>$APP_NAME</string>
  <key>CFBundleVersion</key>            <string>$VERSION</string>
  <key>CFBundleShortVersionString</key> <string>$VERSION</string>
  <key>CFBundleExecutable</key>         <string>$APP_NAME</string>
  <key>CFBundlePackageType</key>        <string>APPL</string>
  <key>NSHighResolutionCapable</key>    <true/>
  <key>LSMinimumSystemVersion</key>     <string>11.0</string>
  <key>NSCameraUsageDescription</key>
    <string>TransferDaemon uses the camera for video calls.</string>
  <key>NSMicrophoneUsageDescription</key>
    <string>TransferDaemon uses the microphone for voice and video calls.</string>
</dict>
</plist>
EOF

# ── Optional: code-sign ───────────────────────────────────────────────────────
if [[ -n "${DEVELOPER_ID:-}" ]]; then
    echo "==> Code-signing with: $DEVELOPER_ID"
    codesign --deep --force --verify --verbose \
        --sign "$DEVELOPER_ID" \
        --options runtime \
        --entitlements "$ROOT/installer/macos/entitlements.plist" \
        "$APP_BUNDLE"
else
    echo "    (Skipping code-sign — set DEVELOPER_ID to sign)"
fi

# ── Build .dmg ────────────────────────────────────────────────────────────────
echo "==> Creating .dmg..."
rm -rf "$DMG_STAGE" "$DMG_OUT"
mkdir -p "$DMG_STAGE"
cp -R "$APP_BUNDLE" "$DMG_STAGE/"
# Symlink to /Applications for drag-and-drop install UX.
ln -s /Applications "$DMG_STAGE/Applications"

hdiutil create \
    -volname "$APP_NAME $VERSION" \
    -srcfolder "$DMG_STAGE" \
    -ov -format UDZO \
    "$DMG_OUT"

# ── Optional: notarize ───────────────────────────────────────────────────────
if [[ -n "${APPLE_ID:-}" && -n "${TEAM_ID:-}" && -n "${APP_PASSWORD:-}" ]]; then
    echo "==> Submitting for notarization..."
    ZIP="$ROOT/dist/$APP_NAME-$VERSION-notarize.zip"
    ditto -c -k --keepParent "$APP_BUNDLE" "$ZIP"
    xcrun notarytool submit "$ZIP" \
        --apple-id "$APPLE_ID" \
        --team-id  "$TEAM_ID" \
        --password "$APP_PASSWORD" \
        --wait
    xcrun stapler staple "$APP_BUNDLE"
    # Rebuild .dmg with the stapled bundle.
    rm -f "$DMG_OUT"
    hdiutil create \
        -volname "$APP_NAME $VERSION" \
        -srcfolder "$DMG_STAGE" \
        -ov -format UDZO \
        "$DMG_OUT"
    echo "    Notarized and stapled."
else
    echo "    (Skipping notarization — set APPLE_ID, TEAM_ID, APP_PASSWORD to notarize)"
fi

SIZE_MB=$(du -sh "$DMG_OUT" | cut -f1)
echo ""
echo "==> SUCCESS"
echo "    $DMG_OUT  ($SIZE_MB)"
echo ""
echo "To install: open $DMG_OUT and drag TransferDaemon to Applications."
