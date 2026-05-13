#!/usr/bin/env bash
# TransferDaemon all-in-one installer for Linux.
# Idempotent — safe to run multiple times.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${INSTALL_DIR:-${HOME}/.local/bin}"
DAEMON_ADDR="${DAEMON_ADDR:-http://127.0.0.1:50051}"

banner() { echo; echo "═══════════════════════════════════════════"; echo "  $*"; echo "═══════════════════════════════════════════"; }

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
    # Persist across reboots.
    if ! grep -q "nr_hugepages" /etc/sysctl.d/99-transferdaemon.conf 2>/dev/null; then
        echo "vm.nr_hugepages=256" | sudo tee -a /etc/sysctl.d/99-transferdaemon.conf >/dev/null
    fi
    echo "  Hugepages enabled."
else
    echo "  [info] HugeTLB not available — using heap memory (still fully functional)."
fi

# ── 4. Build ─────────────────────────────────────────────────────────────────
echo "► Building TransferDaemon (release)…"
cd "${REPO_DIR}/transferdaemon"
cargo build --release -p transferd -p transferd-ui -p launcher 2>&1 | grep -E "^(Compiling|Finished|error)" || true
echo "  Build complete."

# ── 5. Install binaries ───────────────────────────────────────────────────────
mkdir -p "${INSTALL_DIR}"
echo "► Installing to ${INSTALL_DIR}…"
cp -f target/release/transferd      "${INSTALL_DIR}/transferd"
cp -f target/release/transferd-ui   "${INSTALL_DIR}/transferd-ui"
cp -f target/release/launcher       "${INSTALL_DIR}/transferdaemon"
# Optional relay daemon.
if [[ -f target/release/relayd ]]; then
    cp -f target/release/relayd "${INSTALL_DIR}/relayd"
fi
chmod +x "${INSTALL_DIR}/transferd" "${INSTALL_DIR}/transferd-ui" "${INSTALL_DIR}/transferdaemon"

# Ensure INSTALL_DIR is on PATH.
for rc in "${HOME}/.bashrc" "${HOME}/.zshrc" "${HOME}/.profile"; do
    if [[ -f "$rc" ]] && ! grep -q "${INSTALL_DIR}" "$rc"; then
        echo "export PATH=\"${INSTALL_DIR}:\$PATH\"" >> "$rc"
    fi
done
export PATH="${INSTALL_DIR}:${PATH}"

# ── 6. Systemd user service for autostart ────────────────────────────────────
if command -v systemctl &>/dev/null; then
    echo "► Installing systemd user service…"
    SERVICE_DIR="${HOME}/.config/systemd/user"
    mkdir -p "${SERVICE_DIR}"
    cat > "${SERVICE_DIR}/transferd.service" <<SERVICE
[Unit]
Description=TransferDaemon gRPC Background Service
After=network.target

[Service]
ExecStart=${INSTALL_DIR}/transferd
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
    echo "  [info] systemd not available — daemon will be started on-demand by the launcher."
fi

# ── 7. Desktop shortcut ──────────────────────────────────────────────────────
DESKTOP_DIR="${HOME}/.local/share/applications"
mkdir -p "${DESKTOP_DIR}"
ICON_PATH="${REPO_DIR}/assets/icon.png"
[[ -f "$ICON_PATH" ]] || ICON_PATH="dialog-information"  # fallback to theme icon

cat > "${DESKTOP_DIR}/transferdaemon.desktop" <<DESKTOP
[Desktop Entry]
Version=1.0
Name=TransferDaemon
GenericName=Secure File Transfer
Comment=Universal, private, zero-knowledge data transfer and messaging
Exec=${INSTALL_DIR}/transferdaemon
Icon=${ICON_PATH}
Terminal=false
Type=Application
Categories=Network;FileTransfer;Chat;
Keywords=transfer;secure;private;anonymous;
StartupNotify=true
DESKTOP
chmod +x "${DESKTOP_DIR}/transferdaemon.desktop"
# Refresh desktop database if available.
command -v update-desktop-database &>/dev/null && update-desktop-database "${DESKTOP_DIR}" 2>/dev/null || true
echo "  Desktop shortcut created."

# ── 8. Done ──────────────────────────────────────────────────────────────────
banner "Installation complete!"
echo "  Run:           transferdaemon"
echo "  Or click the   TransferDaemon shortcut in your application menu."
echo
echo "  Daemon address: ${DAEMON_ADDR}"
echo "  Binaries:       ${INSTALL_DIR}/"
echo
