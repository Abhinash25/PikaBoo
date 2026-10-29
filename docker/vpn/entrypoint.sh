#!/bin/sh
set -e

# Generate server private/public keys if they don't exist
if [ ! -f /etc/wireguard/privatekey ]; then
    echo "Generating WireGuard keys..."
    wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey
fi

WG_PRIVATE_KEY=$(cat /etc/wireguard/privatekey)

# Get default network interface for NAT (usually eth0)
DEFAULT_ROUTE=$(ip route show default | awk '/default/ {print $5}')
if [ -z "$DEFAULT_ROUTE" ]; then
    DEFAULT_ROUTE="eth0"
fi

# Create wg0 interface configuration
cat <<EOF > /etc/wireguard/wg0.conf
[Interface]
PrivateKey = $WG_PRIVATE_KEY
ListenPort = 51820

# NAT masquerade to allow internet access for peers
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $DEFAULT_ROUTE -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $DEFAULT_ROUTE -j MASQUERADE
EOF

# Bring up WireGuard interface
wg-quick up wg0

# Start Node Controller API
echo "Starting Node Controller API..."
exec node dist/server.js
