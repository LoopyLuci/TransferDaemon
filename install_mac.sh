#!/usr/bin/env bash
# TransferDaemon all-in-one installer for macOS.
# Places all binaries in <project-root>/bin/ and creates ./transferdaemon
# as a symlink to bin/launcher — no system-wide install required.
# Keeps the last 10 installer runs in logs/installer_log_N.log.
# Idempotent — safe to run multiple times.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DAEMON_ADDR="${DAEMON_ADDR:-http://127.0.0.1:50051}"
PLIST_LABEL="com.transferdaemon.daemon"
BIN_DIR="${ROOT_DIR}/bin"

banner() { echo; echo "═══════════════════════════════════════════"; echo "  $*"; echo "═══════════════════════════════════════════"; }

# ── Log rotation ──────────────────────────────────────────────────────────────
LOG_DIR="${ROOT_DIR}/logs"
mkdir -p "${LOG_DIR}"
MAX_LOGS=10
for ((i=MAX_LOGS-1; i>=0; i--)); do
    old="${LOG_DIR}/installer_log_${i}.log"
    if [[ -f "${old}" ]]; then
        if (( i < MAX_LOGS-1 )); then
            mv "${old}" "${LOG_DIR}/installer_log_$((i+1)).log"
        else
            rm -f "${old}"
        fi
    fi
done
INSTALL_LOG="${LOG_DIR}/installer_log_0.log"
exec > >(tee -a "${INSTALL_LOG}") 2>&1
echo "Installer started at $(date)"

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
cd "${ROOT_DIR}/transferdaemon"
cargo build --release -p transferd -p transferd-ui -p launcher 2>&1 | grep -E "^(Compiling|Finished|error)" || true
echo "  Build complete."

# ── 5. Install binaries into <root>/bin/ ─────────────────────────────────────
mkdir -p "${BIN_DIR}"
echo "► Installing binaries to ${BIN_DIR}…"
cp -f target/release/transferd    "${BIN_DIR}/transferd"
cp -f target/release/transferd-ui "${BIN_DIR}/transferd-ui"
cp -f target/release/launcher     "${BIN_DIR}/launcher"
[[ -f target/release/relayd ]] && cp -f target/release/relayd "${BIN_DIR}/relayd"
chmod +x "${BIN_DIR}/transferd" "${BIN_DIR}/transferd-ui" "${BIN_DIR}/launcher"

# ── 6. Root-level entry point ─────────────────────────────────────────────────
LAUNCHER_LINK="${ROOT_DIR}/transferdaemon"
rm -f "${LAUNCHER_LINK}"
ln -s "bin/launcher" "${LAUNCHER_LINK}"
echo "  Entry point: ${LAUNCHER_LINK} → bin/launcher"

# ── 7. launchd agent for autostart ──────────────────────────────────────────
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
        <string>${BIN_DIR}/transferd</string>
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

# ── 8. macOS .app bundle (minimal) ──────────────────────────────────────────
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
cp -f "${BIN_DIR}/launcher" "${APP_DIR}/Contents/MacOS/transferdaemon"
echo "  TransferDaemon.app created in ~/Applications/"

# ── 9. Done ──────────────────────────────────────────────────────────────────
banner "Installation complete!"
echo "  Run from project root:  ./transferdaemon"
echo "  Or open TransferDaemon from ~/Applications/"
echo
echo "  Daemon address: ${DAEMON_ADDR}"
echo "  Binaries:       ${BIN_DIR}/"
echo "  Install log:    ${INSTALL_LOG}"
echo
echo "Installer finished successfully at $(date)"
