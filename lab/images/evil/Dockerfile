# The attacker. It starts nowhere near the lab machines and does nothing until
# you ask it to, and it only ever exists when you pass --profile attack.
#
# It carries the tools somebody attacking this topology would actually reach
# for, and a tailscale client, because two of the interesting attacks are not
# network attacks at all — they are somebody turning up with a key.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg \
 && curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/noble.noarmor.gpg \
      -o /usr/share/keyrings/tailscale-archive-keyring.gpg \
 && curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/noble.tailscale-keyring.list \
      -o /etc/apt/sources.list.d/tailscale.list \
 && apt-get update && apt-get install -y --no-install-recommends \
      tailscale \
      nmap tcpdump tcpreplay hping3 dsniff \
      wireguard-tools \
      iproute2 iptables iputils-ping netcat-openbsd openssh-client \
      xxd jq procps \
 && rm -rf /var/lib/apt/lists/*

# ---- tailcat ------------------------------------------------------------
# Chapter 01's escape hatch, installed the way the chapter says to install it:
# one static binary, no daemon, no root, nothing registered with anything. It
# is deliberately not started here. A tunnel that was already running when you
# turned the lab on would be the one hostile thing in this stack that nobody
# pressed.
#
# Pinned, because an unpinned escape hatch is a moving target and this one has
# a chapter written about its flags. The release is a .deb, so the binary lands
# under a package manager rather than in an unowned /usr/local.
ARG TAILCAT_VERSION=0.6.0
RUN arch="$(dpkg --print-architecture)" \
 && curl -fsSL -o /tmp/tailcat.deb \
      "https://github.com/tailscale/tailcat/releases/download/v${TAILCAT_VERSION}/tailcat_${TAILCAT_VERSION}_linux_${arch}.deb" \
 && dpkg -i /tmp/tailcat.deb \
 && rm -f /tmp/tailcat.deb \
 && tailcat version

# An attacker has keys. It does not have *your* keys — that is the entire
# difference, and it is worth the image making it literal.
RUN mkdir -p /root/.ssh && chmod 700 /root/.ssh \
 && ssh-keygen -t ed25519 -N '' -C evil -f /root/.ssh/id_ed25519 \
 && printf '%s\n' 'Host *' '  StrictHostKeyChecking no' \
      '  UserKnownHostsFile /dev/null' '  LogLevel ERROR' '  ConnectTimeout 5' \
      > /root/.ssh/config

COPY entrypoint.sh /usr/local/bin/lab-evil
COPY onpath.sh /usr/local/bin/lab-onpath
RUN chmod +x /usr/local/bin/lab-evil /usr/local/bin/lab-onpath

ENTRYPOINT ["/usr/local/bin/lab-evil"]
