#!/bin/bash
# NetworkManager TOFU - Virtual Environment Simulation
# Simulates an 802.1X Enterprise Wi-Fi (PEAP-MSCHAPv2) network locally with
# mac80211_hwsim, to exercise the TOFU first-use accept/reject flow.
#
# Assumes the TOFU-patched NetworkManager from install_tofu.sh is already
# built, installed system-wide, and running (systemctl status NetworkManager).
# This script only drives the AP + client profile side of the test; run
# nm-applet or nmtui in another terminal to answer the certificate prompt.

set -e

CERT_DIR="/tmp/tofu-sim"
FR_DIR="$CERT_DIR/frcerts"
CON_NAME="TOFU-Sim-Net"
SSID="TOFU-Sim-Net"

# Known locations for the FreeRADIUS raddb/certs bootstrap template files
# (Makefile, bootstrap, ca.cnf, server.cnf, xpextensions). Only openssl and
# make run this — the freeradius daemon itself is not needed.
FR_TEMPLATE_CANDIDATES=(
    "/usr/share/doc/freeradius/examples/certs"
    "/etc/freeradius/3.0/certs"
    "/etc/raddb/certs"
)

echo "===================================================="
echo "  NetworkManager TOFU - Mac80211_hwsim Simulation"
echo "===================================================="

# 1. Pre-flight checks
if [ "$EUID" -ne 0 ]; then
  echo "Error: run this script as root (sudo ./simulate-tofu.sh)"
  exit 1
fi

for cmd in hostapd openssl make nmcli ip modprobe iw; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: required command '$cmd' is not installed."
        echo "  Run: sudo apt install hostapd openssl make iproute2 iw network-manager"
        exit 1
    fi
done

FR_TEMPLATE_SRC=""
for d in "${FR_TEMPLATE_CANDIDATES[@]}"; do
    if [ -f "$d/bootstrap" ] && [ -f "$d/ca.cnf" ]; then
        FR_TEMPLATE_SRC="$d"
        break
    fi
done
if [ -z "$FR_TEMPLATE_SRC" ]; then
    echo "Error: FreeRADIUS raddb/certs bootstrap templates not found."
    echo "  Run: sudo apt install freeradius"
    exit 1
fi

# 2. Interactive options
recreate_certs="y"
if [ -f "$FR_DIR/server.crt" ]; then
    read -rp "Existing CA/server certificate chain found in $FR_DIR. Recreate it? [Y/n] " ans
    [[ "$ans" =~ ^[Nn]$ ]] && recreate_certs="n"
fi

if [ "$recreate_certs" = "y" ]; then
    # New certs make any pinned hash / ca-cert on the old profile stale —
    # always delete it too, no point asking.
    delete_profile="y"
else
    delete_profile="n"
    read -rp "Delete existing '$CON_NAME' connection profile before starting? [Y/n] " ans
    [[ "$ans" =~ ^[Nn]$ ]] || delete_profile="y"
fi

# FreeRADIUS bootstrap alone only ever produces a root->leaf chain directly
# (confirmed against its Makefile/*.cnf — no intermediate tier exists there to
# reuse). Building the extra intermediate tier is only needed when you want
# hostapd to serve leaf+intermediate (no root, the correct real-world server
# config) so ca-cert can be tested as root-only vs full-chain by hand.
build_chain="n"
read -rp "Build a 3-tier chain (root+intermediate+leaf), or is the plain bootstrap (root+leaf) enough? [chain/simple, default simple] " ans
[[ "$ans" =~ ^[Cc] ]] && build_chain="y"

# Cleanup trap: stop hostapd and virtual hardware, but keep the persistent
# cert directory and the connection profile so results can be inspected
# (and the pinned-cert re-TOFU path can be tested by rerunning) after exit.
cleanup() {
    echo ""
    echo "Cleaning up test environment..."
    [ -n "${HOSTAPD_PID:-}" ] && kill "$HOSTAPD_PID" 2>/dev/null || true
    modprobe -r mac80211_hwsim 2>/dev/null || true
    echo "Done. Cert dir kept at $CERT_DIR; connection profile '$CON_NAME' left in place."
}
trap cleanup EXIT

# 3. Setup virtual Wi-Fi hardware
echo "[1/5] Loading mac80211_hwsim to create virtual Wi-Fi cards..."
BEFORE_IFS=$(ls /sys/class/net | grep wlan || true)

modprobe -r mac80211_hwsim 2>/dev/null || true
modprobe mac80211_hwsim radios=2
sleep 3 # wait for udev to rename interfaces

AFTER_IFS=$(ls /sys/class/net | grep wlan || true)
NEW_IFS=$(comm -13 <(echo "$BEFORE_IFS" | sort) <(echo "$AFTER_IFS" | sort))

AP_IFACE=$(echo "$NEW_IFS" | sed -n 1p)
CLIENT_IFACE=$(echo "$NEW_IFS" | sed -n 2p)

if [ -z "$AP_IFACE" ] || [ -z "$CLIENT_IFACE" ]; then
    echo "Error: could not reliably identify the virtual Wi-Fi interfaces."
    exit 1
fi

echo "  -> Access Point Interface : $AP_IFACE"
echo "  -> NM Client Interface    : $CLIENT_IFACE"

# hwsim0 is mac80211_hwsim's shared-medium monitor netdev: every over-the-air
# frame between the simulated radios shows up here with a radiotap header.
# Point Wireshark/tcpdump at it to see the real EAPOL/EAP-TLS exchange.
ip link set hwsim0 up 2>/dev/null || true
echo "  -> Monitor interface      : hwsim0 (wireshark -k -i hwsim0, or tcpdump -i hwsim0 -w cap.pcap)"

# Bump NM's own debug logging so the supplicant/EAP/TOFU conversation is
# visible in the journal. Revert afterwards with:
#   nmcli general logging level INFO domains ALL
nmcli general logging level DEBUG domains SUPPLICANT,WIFI,DEVICE,TOFU > /dev/null 2>&1 || true
echo "  -> NM debug logging enabled for domains SUPPLICANT,WIFI,DEVICE,TOFU"
echo "     Watch with: sudo journalctl -u NetworkManager -f"

# 4. AP certificate chain (root CA + server leaf) via FreeRADIUS raddb/certs
#    bootstrap, self-contained under $FR_DIR — never touches the system
#    freeradius install or requires it to be running.
mkdir -p "$CERT_DIR"

if [ "$recreate_certs" = "y" ]; then
    echo "[2/5] Generating CA + server certificate chain via FreeRADIUS bootstrap..."
    rm -rf "$FR_DIR"
    mkdir -p "$FR_DIR"
    cp -r "$FR_TEMPLATE_SRC/." "$FR_DIR/"
    # Drop any certs/state the template dir may already carry so bootstrap
    # regenerates everything fresh (it skips steps whose output file exists).
    rm -f "$FR_DIR"/{ca.pem,ca.key,ca.der,server.pem,server.key,server.crt,server.csr,server.p12,client.pem,client.key,client.crt,client.csr,client.p12,dh,random,serial,index.txt}*
    (cd "$FR_DIR" && ./bootstrap > "$CERT_DIR/bootstrap.log" 2>&1) \
        || { echo "Error: bootstrap failed, see $CERT_DIR/bootstrap.log"; exit 1; }
else
    echo "[2/5] Reusing existing CA/server certificate chain in $FR_DIR."
fi

if [ ! -f "$FR_DIR/server.crt" ] || [ ! -f "$FR_DIR/ca.pem" ] || [ ! -f "$FR_DIR/server.key" ]; then
    echo "Error: expected $FR_DIR/{server.crt,ca.pem,server.key} not found after bootstrap."
    exit 1
fi

if [ "$build_chain" = "y" ] && { [ "$recreate_certs" = "y" ] || [ ! -f "$FR_DIR/server2.crt" ]; }; then
    echo "  -> Building 3-tier root->intermediate->leaf chain..."
    (
        cd "$FR_DIR"

        # Intermediate CA, signed by the bootstrap root.
        openssl genrsa -out intermediate.key 2048 2>/dev/null
        openssl req -new -key intermediate.key -out intermediate.csr \
            -subj "/C=BE/O=WiSec26/CN=TOFU-Sim Intermediate CA" 2>/dev/null
        # ca.key is passphrase-encrypted (ca.cnf output_password=whatever, same
        # as server.key) — without -passin, openssl blocks on a stdin prompt
        # that isn't there, fails, and set -e kills the whole script.
        openssl x509 -req -in intermediate.csr -CA ca.pem -CAkey ca.key -passin pass:whatever \
            -CAcreateserial -out intermediate.pem -days 3650 \
            -extfile <(printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n") \
            2>/dev/null

        # New leaf, signed by the intermediate (not the root) — mirrors a real
        # eduroam/campusroam chain (leaf issued by an intermediate, not the root).
        openssl genrsa -out server2.key 2048 2>/dev/null
        openssl req -new -key server2.key -out server2.csr \
            -subj "/C=BE/O=WiSec26/CN=TOFU-Simulated-Server" 2>/dev/null
        openssl x509 -req -in server2.csr -CA intermediate.pem -CAkey intermediate.key -CAcreateserial \
            -out server2.crt -days 365 \
            -extfile <(printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n") \
            2>/dev/null
    )
fi

if [ "$build_chain" = "y" ]; then
    # hostapd sends leaf+intermediate only — the correct real-world server
    # config (the root is never sent over the wire, only used locally as a
    # trust anchor).
    cat "$FR_DIR/server2.crt" "$FR_DIR/intermediate.pem" > "$CERT_DIR/server-chain.pem"
    SERVER_CRT="$FR_DIR/server2.crt"
    HOSTAPD_KEY="$FR_DIR/server2.key"
    HOSTAPD_KEY_PASSWD=""

    cat "$FR_DIR/intermediate.pem" "$FR_DIR/ca.pem" > "$CERT_DIR/full_chain.pem"
    echo "  -> Full chain (intermediate+root) for 802-1x.ca-cert : $CERT_DIR/full_chain.pem"
    echo "  -> Root only for 802-1x.ca-cert                      : $FR_DIR/ca.pem"
else
    # hostapd sends this whole chain during the TLS handshake, so wpa_supplicant's
    # Certification signal reports depth=0 (server leaf) then depth=1 (root CA) —
    # exercises the CA-chain pinning path, not just leaf-hash pinning.
    cat "$FR_DIR/server.crt" "$FR_DIR/ca.pem" > "$CERT_DIR/server-chain.pem"
    SERVER_CRT="$FR_DIR/server.crt"
    HOSTAPD_KEY="$FR_DIR/server.key"
    HOSTAPD_KEY_PASSWD="whatever"
fi

echo "  -> Server cert fingerprint:"
openssl x509 -in "$SERVER_CRT" -noout -fingerprint -sha256 | sed 's/^/     /'
echo "  -> Root CA fingerprint:"
openssl x509 -in "$FR_DIR/ca.pem" -noout -fingerprint -sha256 | sed 's/^/     /'

# 5. Configure and start hostapd (virtual Access Point, PEAP-MSCHAPv2)
echo "[3/5] Starting hostapd EAP server on $AP_IFACE..."

cat <<EOF > "$CERT_DIR/hostapd.conf"
interface=$AP_IFACE
ssid=$SSID
hw_mode=g
channel=6
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-EAP
rsn_pairwise=CCMP
ieee8021x=1
eap_server=1
eap_user_file=$CERT_DIR/hostapd.eap_user
server_cert=$CERT_DIR/server-chain.pem
private_key=$HOSTAPD_KEY
logger_syslog=-1
logger_syslog_level=0
logger_stdout=-1
logger_stdout_level=0
EOF
if [ -n "$HOSTAPD_KEY_PASSWD" ]; then
    echo "private_key_passwd=$HOSTAPD_KEY_PASSWD" >> "$CERT_DIR/hostapd.conf"
fi

cat <<EOF > "$CERT_DIR/hostapd.eap_user"
# Wildcard outer-identity entry: TOFU sends anonymous_identity ("anonymous",
# derived in nm_supplicant_config_add_setting_8021x since "testuser" has no
# '@' realm) as the phase-1 EAP-Identity, not the real "testuser". Without
# this line hostapd rejects that identity before PEAP/TLS ever starts, so
# no ServerHello/Certificate is ever sent.
*		PEAP
"testuser"	MSCHAPV2 "testpass" [2]
EOF

hostapd -dd "$CERT_DIR/hostapd.conf" > "$CERT_DIR/hostapd.log" 2>&1 &
HOSTAPD_PID=$!
sleep 3

if ! kill -0 "$HOSTAPD_PID" 2>/dev/null; then
    echo "Error: hostapd failed to start. Check $CERT_DIR/hostapd.log"
    exit 1
fi

# No DHCP server in this test environment, so 802.1X/WPA2 can complete fully
# and still fail at ip-config with 'ip-config-unavailable'. Assign static IPs
# on both sides instead of waiting on DHCP.
ip addr add 192.168.50.1/24 dev "$AP_IFACE" 2>/dev/null || true

# 6. Configure NetworkManager client profile
echo "[4/5] Configuring NetworkManager client profile..."

if [ "$delete_profile" = "y" ]; then
    nmcli connection delete "$CON_NAME" 2>/dev/null || true
fi

if ! nmcli -t -f NAME connection show | grep -qx "$CON_NAME"; then
    nmcli connection add type wifi ifname "$CLIENT_IFACE" con-name "$CON_NAME" ssid "$SSID" \
        wifi-sec.key-mgmt wpa-eap \
        802-1x.eap peap \
        802-1x.phase2-auth mschapv2 \
        802-1x.identity "testuser" \
        802-1x.password "testpass" \
#        802-1x.ca-verify-mode 0 \
#        802-1x.ca-cert "/tmp/tofu-sim/frcerts/ca.pem" \
        ipv4.method manual \
        ipv4.addresses 192.168.50.2/24 \
        ipv4.gateway 192.168.50.1 \
        ipv6.method disabled \
        connection.autoconnect no \
        > /dev/null
fi

# 802-1x.ca-verify-mode and 802-1x.ca-cert are left for you to set by hand —
# use the file paths printed above (full_chain.pem / ca.pem) to test
# root-only vs full-chain, or leave ca-cert unset with ca-verify-mode=1 for
# the normal TOFU accept/reject flow:
#   nmcli connection modify "TOFU-Sim-Net" 802-1x.ca-verify-mode <0|1>
#   nmcli connection modify "TOFU-Sim-Net" 802-1x.ca-cert <path from above>
# TOFU is set
nmcli connection modify "TOFU-Sim-Net" 802-1x.ca-verify-mode 1


# TEMPORARY DIAGNOSTIC: default supplicant/association timeout is 25s
# (SUPPLICANT_DEFAULT_TIMEOUT, src/core/devices/nm-device.c:19170), far
# shorter than the 180s cert-agent decision window (NM_CERT_AGENT_TIMEOUT_MS).
# Overriding it here to isolate whether NO_SECRETS is the 25s race firing, or
# a real EAP-TLS/Certification failure. Remove once nm-tofu.c manages its own
# timeout for TOFU sessions instead of relying on this race.
nmcli connection modify "$CON_NAME" 802-1x.auth-timeout 600

echo "[5/5] Ready."
echo "===================================================="
echo "Test environment is ready."
echo "Adjust 802-1x.ca-verify-mode / 802-1x.ca-cert as needed (see above), then:"
echo "if using TOFU, make sure a CertificateAgent is running ('nmtui' or the"
echo "modified nm-applet) in another terminal so the prompt has somewhere to show up."
echo ""
echo "Watch NetworkManager logs in another terminal with:"
echo "  sudo journalctl -u NetworkManager -f"
echo ""
read -rp "Press Enter to attempt connection to '$SSID' now or use GUI to connect (Ctrl+C to stop and clean up)... "

nmcli connection up "$CON_NAME"
