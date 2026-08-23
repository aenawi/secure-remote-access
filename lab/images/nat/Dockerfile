# A home router. One of these sits between each lab machine and the segment
# standing in for the public internet, so the machines cannot see one another
# directly and Tailscale has to actually punch a hole to get a direct path.
#
# Without these, "isolated bridge per machine" means "no connectivity at all",
# and a lab where every path is relayed teaches the opposite of chapter 01.
FROM alpine:3.21

RUN apk add --no-cache iptables iproute2 conntrack-tools bash tcpdump

COPY entrypoint.sh /usr/local/bin/lab-nat
RUN chmod +x /usr/local/bin/lab-nat

ENTRYPOINT ["/usr/local/bin/lab-nat"]
