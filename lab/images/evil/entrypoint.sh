#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Hashem Aldhaheri

# evil-box does nothing on boot. That is deliberate: every hostile thing in this
# lab is something you pressed, not something that was already running when you
# turned it on.
set -euo pipefail

STATE_DIR="${LAB_STATE_DIR:-/lab/state}"

# Wait for the CA rather than shrugging if it is not there yet. Without it every
# attempt to reach the coordination server dies with "certificate signed by
# unknown authority", which reads like a broken lab rather than a race.
for _ in $(seq 1 60); do
  [ -f "$STATE_DIR/ca/lab-ca.crt" ] && break
  sleep 1
done
if [ -f "$STATE_DIR/ca/lab-ca.crt" ]; then
  cp "$STATE_DIR/ca/lab-ca.crt" /usr/local/share/ca-certificates/lab-ca.crt
  update-ca-certificates >/dev/null 2>&1 || true
else
  echo "WARNING: no lab CA at $STATE_DIR/ca/lab-ca.crt — joining the tailnet will fail"
fi

if [ -n "${LAB_GATEWAY:-}" ]; then
  ip route replace default via "$LAB_GATEWAY"
fi

mkdir -p /var/lib/tailscale /var/run/tailscale
if [ -c /dev/net/tun ]; then
  # Started, but not logged in. Joining the tailnet is an attack you run, not a
  # state the lab boots into.
  tailscaled \
    --tun=tailscale0 \
    --state=/var/lib/tailscale/tailscaled.state \
    --socket=/var/run/tailscale/tailscaled.sock \
    --port=41641 \
    --no-logs-no-support \
    >/var/log/tailscaled.log 2>&1 &
fi

echo "evil-box is up and idle. Nothing has been attacked."
exec sleep infinity
