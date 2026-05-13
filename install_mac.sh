#!/usr/bin/env bash
# TransferDaemon all-in-one installer for macOS.
# Idempotent — safe to run multiple times.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${INSTALL_DIR:-${HOME}/.local/bin}"
DAEMON_ADDR="${DAEMON_ADDR:-http://127.0.0.1:50051}"
PLIST_LABEL="com.transferdaemon.daemon"

banner() { echo; echo "═══════════════════════════════════════════"; echo "  $*"; echo "═══════════════════════════════════════════"; }

banner "TransferDaemon — macOS Installer"

# ── 1. Xcode Command Line Tools ──────────────────────────────────────────────
if ! xcode-select -p &>/dev/null; then
    echo "► Installing Xcode Command Line Tools…"
    xcode-select --install || true
    echo "  Please complete the Xcode CLT installation and re-run this script."
    exit 1
fi

# ── 2. Homebrew + protobuf ───────────────────────────────────────────────────
if ! command -v brew &>/dev/null; then
    echo "► Homebrew not found — installing…"
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi
echo "► Installing system dependencies via Homebrew…"
brew install protobuf openssl pkg-config 2>/dev/null || true

# ── 3. Rust toolchain ────────────────────────────────────────────────────────
if ! command -v rustup &>/dev/null; then
    echo "► Installing Rust via rustup…"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
    # shellcheck source=/dev/null
    source "${HOME}/.cargo/env"
else
    echo "► Rust already present ($(rustc --version))"
fi
rustup default stable
rustup update --quiet

# ── 4. Build ─────────────────────────────────────────────────────────────────
echo "► Building TransferDaemon (release)…"
cd "${REPO_DIR}/transferdaemon"
cargo build --release -p transferd -p transferd-ui -p launcher 2>&1 | grep -E "^(Compiling|Finished|error)" || true
echo "  Build complete."

# ── 5. Install binaries ──────────────────────────────────────────────────────
mkdir -p "${INSTALL_DIR}"
echo "► Installing to ${INSTALL_DIR}…"
cp -f target/release/transferd      "${INSTALL_DIR}/transferd"
cp -f target/release/transferd-ui   "${INSTALL_DIR}/transferd-ui"
cp -f target/release/launcher       "${INSTALL_DIR}/transferdaemon"
[[ -f target/release/relayd ]] && cp -f target/release/relayd "${INSTALL_DIR}/relayd"
chmod +x "${INSTALL_DIR}/transferd" "${INSTALL_DIR}/transferd-ui" "${INSTALL_DIR}/transferdaemon"

for rc in "${HOME}/.bash_profile" "${HOME}/.zprofile"; do
    if [[ -f "$rc" ]] && ! grep -q "${INSTALL_DIR}" "$rc"; then
        echo "export PATH=\"${INSTALL_DIR}:\$PATH\"" >> "$rc"
    fi
done
export PATH="${INSTALL_DIR}:${PATH}"

# ── 6. launchd agent for autostart ──────────────────────────────────────────
LAUNCH_AGENTS="${HOME}/Library/LaunchAgents"
mkdir -p "${LAUNCH_AGENTS}"
PLIST_PATH="${LAUNCH_AGENTS}/${PLIST_LABEL}.plist"

cat > "${PLIST_PATH}" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>             <string>${PLIST_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/transferd</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>TRANSFERD_ADDR</key><string>${DAEMON_ADDR}</string>
    </dict>
    <key>RunAtLoad</key>         <true/>
    <key>KeepAlive</key>         <true/>
    <key>StandardErrorPath</key>
    <string>${HOME}/Library/Logs/transferd.log</string>
</dict>
</plist>
PLIST

launchctl unload "${PLIST_PATH}" 2>/dev/null || true
launchctl load   "${PLIST_PATH}"
echo "  launchd agent installed — daemon will start at login."

# ── 7. macOS .app bundle (minimal) ──────────────────────────────────────────
APP_DIR="${HOME}/Applications/TransferDaemon.app"
mkdir -p "${APP_DIR}/Contents/MacOS"
cat > "${APP_DIR}/Contents/Info.plist" <<INFOPLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>             <string>TransferDaemon</string>
    <key>CFBundleExecutable</key>       <string>transferdaemon</string>
    <key>CFBundleIdentifier</key>       <string>com.transferdaemon.app</string>
    <key>CFBundleVersion</key>          <string>1.0</string>
    <key>CFBundleShortVersionString</key><string>1.0</string>
    <key>LSMinimumSystemVersion</key>   <string>12.0</string>
    <key>NSHighResolutionCapable</key>  <true/>
    <key>LSUIElement</key>              <false/>
</dict>
</plist>
INFOPLIST
cp -f "${INSTALL_DIR}/transferdaemon" "${APP_DIR}/Contents/MacOS/transferdaemon"
echo "  TransferDaemon.app created in ~/Applications/"

# ── 8. Done ──────────────────────────────────────────────────────────────────
banner "Installation complete!"
echo "  Run:  transferdaemon"
echo "  Or open TransferDaemon from ~/Applications/"
echo
echo "  Daemon address: ${DAEMON_ADDR}"
echo "  Binaries:       ${INSTALL_DIR}/"
echo
