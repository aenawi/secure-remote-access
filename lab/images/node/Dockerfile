# A lab machine: Ubuntu, tailscaled on a real TUN device, sshd, ufw, mosh, tmux.
#
# One image plays all three roles — lab-vps, lab-ubuntu, lab-roam — because the
# roles differ only in where they sit on the network and what the configuration
# does to them. That is also the guide's claim, so it is worth the image being
# built that way.
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
      openssh-server openssh-client \
      ufw iptables nftables iproute2 iputils-ping \
      tcpdump netcat-openbsd \
      mosh tmux \
      jq procps less \
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

# ---- sshd ---------------------------------------------------------------
# Key-only, root login by key, which is where chapter 08 leaves a box before
# the configurations start moving things. Every node shares one keypair so any
# machine can reach any other; it is generated at build time and never leaves
# your Docker cache.
RUN mkdir -p /var/run/sshd /root/.ssh \
 && chmod 700 /root/.ssh \
 && ssh-keygen -t ed25519 -N '' -C lab -f /root/.ssh/id_ed25519 \
 && cp /root/.ssh/id_ed25519.pub /root/.ssh/authorized_keys \
 && chmod 600 /root/.ssh/authorized_keys \
 && printf '%s\n' \
      'Host *' \
      '  StrictHostKeyChecking no' \
      '  UserKnownHostsFile /dev/null' \
      '  LogLevel ERROR' \
      '  ConnectTimeout 5' \
      > /root/.ssh/config \
 && printf '%s\n' \
      'UseDNS no' \
      'KbdInteractiveAuthentication no' \
      > /etc/ssh/sshd_config.d/00-lab.conf
# The three settings the lab actually changes live in one file, written by the
# entrypoint and rewritten by the control server. They are deliberately NOT in
# 00-lab.conf: sshd takes the first value it sees for a keyword, so a second
# file setting PasswordAuthentication later in the sort order is silently
# ignored — which looks exactly like the switch not working.
ENV LAB_SSHD_CONF=/etc/ssh/sshd_config.d/10-lab-runtime.conf

# ---- ufw ----------------------------------------------------------------
# ufw's init runs `sysctl -p /etc/ufw/sysctl.conf`, and several of those knobs
# are read-only inside a container. Emptying the file is the difference between
# ufw working here and ufw refusing to enable; the rules themselves are real.
RUN sed -i 's/^IPV6=.*/IPV6=no/' /etc/default/ufw \
 && sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="DROP"/' /etc/default/ufw \
 && : > /etc/ufw/sysctl.conf

COPY entrypoint.sh /usr/local/bin/lab-entrypoint
COPY docker-trap.sh /usr/local/bin/lab-docker-trap
RUN chmod +x /usr/local/bin/lab-entrypoint /usr/local/bin/lab-docker-trap

ENTRYPOINT ["/usr/local/bin/lab-entrypoint"]
