#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Hashem Aldhaheri

# Take the on-path position on lab-ubuntu's segment: become the router its
# traffic leaves through, so every frame it sends really does pass through this
# machine's kernel and really is available to tcpdump.
#
# HOW THIS DIFFERS FROM THE CAFÉ
#
# In a café, an attacker takes this position by lying — ARP spoofing, a rogue
# DHCP lease, a hostile access point with the same SSID. Here, the control
# server simply points lab-ubuntu's default route at this container, because a
# Docker bridge is a learning switch and the alternative is a lot of machinery
# in service of arriving at the same place.
#
# What that changes: how the attacker got here. What it does not change: one
# byte of what follows. The frames are real, the capture is real, and the
# reason you cannot read them is real.
#
# Usage: lab-onpath on|off
set -euo pipefail

LAN_SUBNET="${LAB_ONPATH_SUBNET:-10.0.13.0/24}"

iface_for() {
  local want="${1%/*}"
  ip -o -4 addr show | awk -v ip="$want" '
    { split($4, a, "/"); split(ip, b, "."); split(a[1], c, ".")
      if (b[1]==c[1] && b[2]==c[2] && b[3]==c[3]) { print $2; exit } }'
}

case "${1:-on}" in
  on)
    IF="$(iface_for "$LAN_SUBNET")"
    [ -n "$IF" ] || { echo "evil-box is not attached to $LAN_SUBNET" >&2; exit 1; }
    sysctl -qw net.ipv4.ip_forward=1 2>/dev/null || true
    if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
      echo "ip_forward is off on evil-box; it cannot be on-path" >&2; exit 1
    fi
    iptables -t nat -C POSTROUTING -s "$LAN_SUBNET" ! -o "$IF" -j MASQUERADE 2>/dev/null \
      || iptables -t nat -A POSTROUTING -s "$LAN_SUBNET" ! -o "$IF" -j MASQUERADE
    echo "on-path on $IF for $LAN_SUBNET — forwarding and masquerading"
    ;;
  off)
    IF="$(iface_for "$LAN_SUBNET")"
    iptables -t nat -D POSTROUTING -s "$LAN_SUBNET" ! -o "${IF:-lo}" -j MASQUERADE 2>/dev/null || true
    sysctl -qw net.ipv4.ip_forward=0 2>/dev/null || true
    echo "off-path — nothing routes through evil-box any more"
    ;;
  *)
    echo "usage: lab-onpath on|off" >&2; exit 2 ;;
esac
