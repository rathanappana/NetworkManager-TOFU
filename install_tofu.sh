#!/bin/bash
set -e

echo "===================================================="
echo "  NetworkManager TOFU - Automated Build & Install"
echo "===================================================="

# 1. Install base dependencies
echo "[1/4] Installing core build dependencies..."
sudo apt update
sudo apt install -y meson ninja-build build-essential cmake \
    libdbus-1-dev libbpf-dev libsystemd-dev libnss3-dev

# 2. Install NetworkManager specific dependencies
echo "[2/4] Fetching NetworkManager build dependencies..."
echo "NOTE: If this step fails, ensure 'deb-src' is enabled in your APT sources."
sudo apt build-dep -y network-manager

# 3. Build the project
echo "[3/4] Configuring and compiling NetworkManager..."
# Clean previous build if it exists
if [ -d "build" ]; then
    rm -rf build
fi

meson setup build --prefix=/usr --sysconfdir=/etc --localstatedir=/var -Dclat=false -Dnbft=false
ninja -C build

# 4. Install and restart services
echo "[4/4] Installing system-wide and restarting services..."
sudo ninja -C build install
sudo systemctl daemon-reload
sudo systemctl restart NetworkManager

echo "===================================================="
echo "Installation Complete!"
echo "Current Version:"
NetworkManager --version
echo "To view live logs, run: sudo journalctl -u NetworkManager -f"
echo "===================================================="