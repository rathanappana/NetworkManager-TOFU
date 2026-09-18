#!/bin/bash
# NetworkManager TOFU - Virtual Environment Simulation
# This script simulates an 802.1X Enterprise Wi-Fi network locally.

set -e

echo "===================================================="
echo "  NetworkManager TOFU - Mac80211_hwsim Simulation"
echo "===================================================="

# 1. Pre-flight Checks
if [ "$EUID" -ne 0 ]; then 
  echo "❌ Error: Please run this script as root (sudo ./simulate-tofu.sh)"
  exit 1
fi

for cmd in hostapd openssl nmcli ip modprobe iw; do
    if ! command -v $cmd &> /dev/null; then
        echo "❌ Error: Required command '$cmd' is not installed."
        echo "   Run: sudo apt install hostapd openssl iproute2 iw"
        exit 1
    fi
done

# Cleanup Trap: Ensures we don't leave rogue hostapd processes or virtual hardware running
cleanup() {
    echo ""
    echo "🧹 Cleaning up test environment..."
    kill $HOSTAPD_PID 2>/dev/null || true
    modprobe -r mac80211_hwsim 2>/dev/null || true
    nmcli connection delete TOFU-Sim-Net 2>/dev/null || true
    rm -rf /tmp/tofu-sim
    echo "✅ Cleanup complete."
}
trap cleanup EXIT

# 2. Setup Virtual Wi-Fi Hardware
echo "[1/4] Loading mac80211_hwsim to create virtual Wi-Fi cards..."
# Record existing interfaces to accurately identify the new virtual ones
BEFORE_IFS=$(ls /sys/class/net | grep wlan || true)

modprobe -r mac80211_hwsim 2>/dev/null || true
modprobe mac80211_hwsim radios=2
sleep 3 # Wait for udev to rename interfaces

AFTER_IFS=$(ls /sys/class/net | grep wlan || true)
NEW_IFS=$(comm -13 <(echo "$BEFORE_IFS" | sort) <(echo "$AFTER_IFS" | sort))

AP_IFACE=$(echo "$NEW_IFS" | sed -n 1p)
CLIENT_IFACE=$(echo "$NEW_IFS" | sed -n 2p)

if [ -z "$AP_IFACE" ] || [ -z "$CLIENT_IFACE" ]; then
    echo "❌ Error: Could not reliably identify the virtual Wi-Fi interfaces."
    exit 1
fi

echo "  -> Access Point Interface : $AP_IFACE"
echo "  -> NM Client Interface    : $CLIENT_IFACE"

# 3. Generate Fake Enterprise Certificates
echo "[2/4] Generating dummy self-signed certificate for the AP..."
mkdir -p /tmp/tofu-sim
cd /tmp/tofu-sim

openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.pem \
    -days 365 -nodes -subj "/C=BE/O=WiSec26/CN=TOFU-Simulated-Server" 2>/dev/null

# 4. Configure and Start hostapd (Virtual Access Point)
echo "[3/4] Starting hostapd EAP server on $AP_IFACE..."

cat <<EOF > hostapd.conf
interface=$AP_IFACE
ssid=TOFU-Sim-Net
hw_mode=g
channel=6
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-EAP
rsn_pairwise=CCMP
ieee8021x=1
eap_server=1
eap_user_file=/tmp/tofu-sim/hostapd.eap_user
server_cert=/tmp/tofu-sim/server.pem
private_key=/tmp/tofu-sim/server.key
EOF

cat <<EOF > hostapd.eap_user
"testuser" PEAP [ver=0]
"testuser" MSCHAPV2 "testpass" [2]
EOF

hostapd /tmp/tofu-sim/hostapd.conf > /tmp/tofu-sim/hostapd.log 2>&1 &
HOSTAPD_PID=$!
sleep 3

if ! kill -0 $HOSTAPD_PID 2>/dev/null; then
    echo "❌ Error: hostapd failed to start. Check /tmp/tofu-sim/hostapd.log"
    exit 1
fi

# 5. Configure NetworkManager Client Profile
echo "[4/4] Configuring NetworkManager client profile..."

# Create the WPA-Enterprise Wi-Fi connection profile
nmcli connection add type wifi ifname $CLIENT_IFACE con-name TOFU-Sim-Net ssid TOFU-Sim-Net \
    802-1x.eap peap \
    802-1x.phase2-auth mschapv2 \
    802-1x.identity "testuser" \
    802-1x.password "testpass" \
    > /dev/null

# ⚡ ENABLE THE TOFU FEATURE
nmcli connection modify TOFU-Sim-Net 802-1x.ca-verify-mode 1


echo "===================================================="
echo "✅ Test environment is ready!"
echo "📡 Attempting to connect to 'TOFU-Sim-Net'..."
echo ""
echo "👉 WATCH YOUR SCREEN: The GUI applet should prompt you to accept the certificate."
echo "   (Press Ctrl+C to stop the simulation and clean up once done)"
echo "===================================================="

# Connect! This will hang and wait for the GUI agent to respond to the D-Bus secret request
nmcli connection up TOFU-Sim-Net