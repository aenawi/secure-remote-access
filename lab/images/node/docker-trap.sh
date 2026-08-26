#!/usr/bin/env bash
# Chapter 08's trap, reproduced on lab-vps: a published container port that
# answers from the internet through a firewall whose default policy is deny.
#
# WHAT IS REAL HERE, AND WHAT IS NOT
#
# Real: the chains, their order, the DNAT, the forwarded packet, the ufw policy
# that says deny, and the connection that succeeds anyway. `lab-vps-web` is a
# genuine second container on a bridge this machine routes for, so the packet
# really is forwarded rather than delivered locally — which is the whole reason
# ufw's INPUT rules never get a say.
#
# Not real: dockerd. These are the rules the daemon writes, written by hand.
# Running a real dockerd in here would mean a privileged container, and a
# privileged container is a genuine escape route onto the reader's own machine.
# The mechanism under test is the chain order, and the chain order is exact.
#
# Usage: lab-docker-trap on|off|status
set -euo pipefail

WEB_IP="${LAB_WEB_IP:-10.0.11.20}"
WEB_PORT="${LAB_WEB_PORT:-80}"
PUB_PORT="${LAB_PUB_PORT:-8080}"

# The bridge this machine routes for. Matched by subnet, not by name: Docker
# does not promise which of eth0/eth1 a network lands on.
lan_iface() {
  ip -o -4 addr show \
    | awk -v ip="$WEB_IP" '
        { split($4, a, "/"); split(ip, b, "."); split(a[1], c, ".")
          if (b[1]==c[1] && b[2]==c[2] && b[3]==c[3]) { print $2; exit } }'
}

ensure_chain() {  # table chain
  iptables -t "$1" -n -L "$2" >/dev/null 2>&1 || iptables -t "$1" -N "$2"
}

trap_on() {
  local iface; iface="$(lan_iface)"
  if [ -z "$iface" ]; then
    echo "no interface on ${WEB_IP%.*}.0/24 — is lab-vps-web's network attached?" >&2
    exit 1
  fi

  sysctl -qw net.ipv4.ip_forward=1 2>/dev/null || true
  if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
    echo "ip_forward is off on this machine, so nothing can be forwarded to a container" >&2
    exit 1
  fi

  ensure_chain nat DOCKER
  ensure_chain filter DOCKER
  ensure_chain filter DOCKER-USER

  # DOCKER-USER exists so operators have somewhere to put their own rules. It
  # returns by default, which is why "just add a rule to DOCKER-USER" is the
  # standard advice and why nobody ever does.
  iptables -C DOCKER-USER -j RETURN 2>/dev/null || iptables -A DOCKER-USER -j RETURN

  # The two inserts that are the entire lesson. Position 1 and 2 of FORWARD,
  # ahead of ufw-before-forward. dockerd does exactly this, every time it
  # starts, which is why enabling ufw first does not save you.
  iptables -C FORWARD -j DOCKER-USER 2>/dev/null || iptables -I FORWARD 1 -j DOCKER-USER
  iptables -C FORWARD -j DOCKER      2>/dev/null || iptables -I FORWARD 2 -j DOCKER

  iptables -C DOCKER -d "$WEB_IP/32" -p tcp --dport "$WEB_PORT" -j ACCEPT 2>/dev/null \
    || iptables -A DOCKER -d "$WEB_IP/32" -p tcp --dport "$WEB_PORT" -j ACCEPT

  iptables -t nat -C PREROUTING -m addrtype --dst-type LOCAL -j DOCKER 2>/dev/null \
    || iptables -t nat -A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER

  iptables -t nat -C DOCKER ! -i "$iface" -p tcp --dport "$PUB_PORT" \
      -j DNAT --to-destination "$WEB_IP:$WEB_PORT" 2>/dev/null \
    || iptables -t nat -A DOCKER ! -i "$iface" -p tcp --dport "$PUB_PORT" \
      -j DNAT --to-destination "$WEB_IP:$WEB_PORT"

  # Hairpin: the reply has to come back through us rather than out of the web
  # container's own default route.
  iptables -t nat -C POSTROUTING -d "$WEB_IP/32" -p tcp --dport "$WEB_PORT" \
      -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -d "$WEB_IP/32" -p tcp --dport "$WEB_PORT" \
      -j MASQUERADE

  echo "published :$PUB_PORT -> $WEB_IP:$WEB_PORT via DOCKER-USER/DOCKER on $iface"
}

trap_off() {
  local iface; iface="$(lan_iface)"
  iptables -t nat -D DOCKER ! -i "${iface:-lo}" -p tcp --dport "$PUB_PORT" \
    -j DNAT --to-destination "$WEB_IP:$WEB_PORT" 2>/dev/null || true
  iptables -t nat -D POSTROUTING -d "$WEB_IP/32" -p tcp --dport "$WEB_PORT" \
    -j MASQUERADE 2>/dev/null || true
  iptables -D DOCKER -d "$WEB_IP/32" -p tcp --dport "$WEB_PORT" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -j DOCKER 2>/dev/null || true
  iptables -D FORWARD -j DOCKER-USER 2>/dev/null || true
  iptables -t nat -D PREROUTING -m addrtype --dst-type LOCAL -j DOCKER 2>/dev/null || true
  echo "unpublished :$PUB_PORT — nothing forwards to the container any more"
}

trap_status() {
  if iptables -t nat -S DOCKER 2>/dev/null | grep -q -- "--dport $PUB_PORT"; then
    echo on
  else
    echo off
  fi
}

case "${1:-status}" in
  on)     trap_on ;;
  off)    trap_off ;;
  status) trap_status ;;
  *)      echo "usage: lab-docker-trap on|off|status" >&2; exit 2 ;;
esac
