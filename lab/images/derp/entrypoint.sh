#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Hashem Aldhaheri

# Wait for the certificate, then relay. Nothing else: derper has no state worth
# keeping, no policy to hold and nobody to authenticate, which is the whole
# reason it is a fair stand-in for a public relay somebody else operates.
set -euo pipefail

STATE_DIR="${LAB_STATE_DIR:-/lab/state}"
HOSTNAME_="${LAB_DERP_HOSTNAME:-derp.lab.internal}"
CERT_DIR="$STATE_DIR/ca"

# The control server mints this from the lab CA before headscale boots. Waiting
# rather than shrugging: without the certificate derper exits immediately and
# the restart loop reads like a broken image rather than a race.
for _ in $(seq 1 90); do
  [ -f "$CERT_DIR/$HOSTNAME_.crt" ] && [ -f "$CERT_DIR/$HOSTNAME_.key" ] && break
  sleep 1
done
if [ ! -f "$CERT_DIR/$HOSTNAME_.crt" ]; then
  echo "no certificate at $CERT_DIR/$HOSTNAME_.crt — the control server mints it; is it running?" >&2
  exit 1
fi

# -verify-clients would ask a local tailscaled whether each client is a tailnet
# member, which is exactly the check this relay must not make. A public relay
# does not know who you are, and neither does this one.
exec derper \
  -hostname "$HOSTNAME_" \
  -certmode manual \
  -certdir "$CERT_DIR" \
  -a :443 \
  -stun \
  -verify-clients=false
