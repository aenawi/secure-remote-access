# The lab's second relay, and the only one with no control plane behind it.
#
# Headscale already embeds a DERP server, and for the tailnet that is the right
# answer: config/headscale/config.yaml says why, and nothing here changes it.
# This one exists for tailcat, which cannot use it — two reasons, and the second
# is the one that matters:
#
#   1. Mechanically, a tailcat address built with `genkey --region=<hostname>`
#      carries a bare hostname and nothing else, so its client dials :443 and
#      the standard /derp path. Headscale's relay lives on :8443 beside the
#      coordination API, and tailcat has no flag that would reach it without
#      hosting a DERP map for both ends to fetch.
#
#   2. Teaching. Chapter 01's claim about tailcat is that it is the data plane
#      with the control plane taken out. Sending its packets through the
#      container that holds the ACLs, the node keys and the expiry dates would
#      undercut that in the one place a reader looks to check it. This relay
#      holds nothing. It cannot: derper has nowhere to put a policy.
#
# Built from source and pinned, rather than pulled from somebody's untracked
# image. The certificate is minted by the control server from the lab CA the
# machines already trust, so this costs the lab no new trust root.
FROM golang:1.27 AS build
RUN GOBIN=/out go install tailscale.com/cmd/derper@v1.102.3

FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates iproute2 iputils-ping \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/derper /usr/local/bin/derper
COPY entrypoint.sh /usr/local/bin/lab-derp
RUN chmod +x /usr/local/bin/lab-derp
ENTRYPOINT ["/usr/local/bin/lab-derp"]
