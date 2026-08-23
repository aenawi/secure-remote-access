#!/usr/bin/env bash
# Masquerade one lab segment out onto the segment that stands in for the public
# internet, and nothing else. No port forwards, no DMZ: whatever gets through to
# a machine behind this router got there because Tailscale opened the way.
#
#   NAT_MODE=easy   one mapping per source port, reused for every destination.
#                   Endpoint-independent — the friendly kind, and the kind hole
#                   punching relies on.
#   NAT_MODE=hard   a fresh random source port per destination. Endpoint-
#                   dependent, so the port lab-roam learns about itself from
#                   STUN is not the port a peer would have to send to. This is
#                   the NAT that forces DERP, and it is why lab-roam is the one
#                   machine in this lab that behaves like a phone on 5G.
set -euo pipefail

WAN_SUBNET="${NAT_WAN_SUBNET:-203.0.113.0/24}"
LAN_SUBNET="${NAT_LAN_SUBNET:?NAT_LAN_SUBNET is required}"
NAT_MODE="${NAT_MODE:-easy}"

iface_for() {  # subnet -> interface name
  local want="${1%/*}"
  ip -o -4 addr show | awk -v ip="$want" '
    { split($4, a, "/"); split(ip, b, "."); split(a[1], c, ".")
      if (b[1]==c[1] && b[2]==c[2] && b[3]==c[3]) { print $2; exit } }'
}

WAN_IF="$(iface_for "$WAN_SUBNET")"
LAN_IF="$(iface_for "$LAN_SUBNET")"

if [ -z "$WAN_IF" ] || [ -z "$LAN_IF" ]; then
  echo "router: could not find both interfaces (wan=$WAN_SUBNET -> '$WAN_IF', lan=$LAN_SUBNET -> '$LAN_IF')" >&2
  ip -o -4 addr show >&2
  exit 1
fi

# /proc/sys is read-only in a container, so compose sets this for us. Writing it
# here anyway costs nothing and makes the failure obvious if it was forgotten.
sysctl -qw net.ipv4.ip_forward=1 2>/dev/null || true
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
  echo "router: ip_forward is off. Add 'sysctls: {net.ipv4.ip_forward: 1}' to this service." >&2
  exit 1
fi

iptables -t nat -F POSTROUTING
iptables -F FORWARD

if [ "$NAT_MODE" = "hard" ]; then
  iptables -t nat -A POSTROUTING -s "$LAN_SUBNET" -o "$WAN_IF" -j MASQUERADE --random
else
  iptables -t nat -A POSTROUTING -s "$LAN_SUBNET" -o "$WAN_IF" -j MASQUERADE
fi

iptables -A FORWARD -i "$LAN_IF" -o "$WAN_IF" -j ACCEPT
iptables -A FORWARD -i "$WAN_IF" -o "$LAN_IF" \
  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -j DROP

echo "router up: $LAN_SUBNET ($LAN_IF) -> $WAN_IF, mapping is $NAT_MODE"
exec sleep infinity
