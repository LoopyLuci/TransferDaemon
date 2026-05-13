#!/usr/bin/env bash
# TransferDaemon all-in-one installer for Linux.
# Places all binaries in <project-root>/bin/ and creates ./transferdaemon
# as a symlink to bin/launcher — no system-wide install required.
# Keeps the last 10 installer runs in logs/installer_log_N.log.
# Idempotent — safe to run multiple times.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DAEMON_ADDR="${DAEMON_ADDR:-http://127.0.0.1:50051}"
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
# Tee all subsequent output to both console and log file.
exec > >(tee -a "${INSTALL_LOG}") 2>&1
echo "Installer started at $(date)"

banner "TransferDaemon — Linux Installer"

# ── 1. Rust toolchain ────────────────────────────────────────────────────────
if ! command -v rustup &>/dev/null; then
    echo "► Rust not found — installing via rustup…"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
    # shellcheck source=/dev/null
    source "${HOME}/.cargo/env"
else
    echo "► Rust already present ($(rustc --version))"
fi
rustup default stable
rustup update --quiet

# ── 2. System dependencies ───────────────────────────────────────────────────
echo "► Installing system build dependencies…"
if command -v apt &>/dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y --no-install-recommends \
        build-essential libssl-dev pkg-config protobuf-compiler
elif command -v dnf &>/dev/null; then
    sudo dnf install -y gcc gcc-c++ openssl-devel pkgconf-pkg-config protobuf-compiler
elif command -v pacman &>/dev/null; then
    sudo pacman -S --noconfirm --needed base-devel openssl pkgconf protobuf
else
    echo "  [warn] Unknown package manager — skipping system packages."
    echo "  Please ensure: build tools, OpenSSL headers, protobuf-compiler."
fi

# ── 3. Hugepages (best-effort) ───────────────────────────────────────────────
if grep -q hugetlbfs /proc/filesystems 2>/dev/null; then
    echo "► Configuring hugepages (256 × 2 MiB)…"
    sudo sysctl -w vm.nr_hugepages=256 >/dev/null 2>&1 || true
    sudo mkdir -p /dev/hugepages
    if ! mountpoint -q /dev/hugepages 2>/dev/null; then
        sudo mount -t hugetlbfs none /dev/hugepages 2>/dev/null || true
    fi
    if ! grep -q "nr_hugepages" /etc/sysctl.d/99-transferdaemon.conf 2>/dev/null; then
        echo "vm.nr_hugepages=256" | sudo tee -a /etc/sysctl.d/99-transferdaemon.conf >/dev/null
    fi
    echo "  Hugepages enabled."
else
    echo "  [info] HugeTLB not available — using heap memory (still fully functional)."
fi

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

# ── 7. Systemd user service for autostart (optional) ─────────────────────────
if command -v systemctl &>/dev/null; then
    echo "► Installing systemd user service…"
    SERVICE_DIR="${HOME}/.config/systemd/user"
    mkdir -p "${SERVICE_DIR}"
    cat > "${SERVICE_DIR}/transferd.service" <<SERVICE
[Unit]
Description=TransferDaemon gRPC Background Service
After=network.target

[Service]
ExecStart=${BIN_DIR}/transferd
Environment=TRANSFERD_ADDR=${DAEMON_ADDR}
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=default.target
SERVICE
    systemctl --user daemon-reload
    systemctl --user enable --now transferd.service
    echo "  Daemon service installed and started."
else
    echo "  [info] systemd not available — the launcher will start the daemon on demand."
fi

# ── 8. Desktop shortcut ──────────────────────────────────────────────────────
DESKTOP_DIR="${HOME}/.local/share/applications"
mkdir -p "${DESKTOP_DIR}"
ICON_PATH="${ROOT_DIR}/assets/icon.png"
[[ -f "${ICON_PATH}" ]] || ICON_PATH="dialog-information"

cat > "${DESKTOP_DIR}/transferdaemon.desktop" <<DESKTOP
[Desktop Entry]
Version=1.0
Name=TransferDaemon
GenericName=Secure File Transfer
Comment=Universal, private, zero-knowledge data transfer and messaging
Exec=${BIN_DIR}/launcher
Icon=${ICON_PATH}
Terminal=false
Type=Application
Categories=Network;FileTransfer;Chat;
Keywords=transfer;secure;private;anonymous;
StartupNotify=true
DESKTOP
chmod +x "${DESKTOP_DIR}/transferdaemon.desktop"
command -v update-desktop-database &>/dev/null && update-desktop-database "${DESKTOP_DIR}" 2>/dev/null || true
echo "  Desktop shortcut created."

# ── 9. Done ──────────────────────────────────────────────────────────────────
banner "Installation complete!"
echo "  Run from project root:  ./transferdaemon"
echo "  Or click the TransferDaemon shortcut in your application menu."
echo
echo "  Daemon address: ${DAEMON_ADDR}"
echo "  Binaries:       ${BIN_DIR}/"
echo "  Install log:    ${INSTALL_LOG}"
echo
echo "Installer finished successfully at $(date)"
