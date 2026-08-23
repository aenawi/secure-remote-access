package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Server-sent events
//
// Four streams, all one-way, all over plain SSE. No websockets and no client
// library: the readout panes are the only thing that needs live data, and they
// only ever need it pushed at them.
// ---------------------------------------------------------------------------

type sse struct {
	w  http.ResponseWriter
	fl http.Flusher
}

func newSSE(w http.ResponseWriter) (*sse, bool) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return nil, false
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fl.Flush()
	return &sse{w: w, fl: fl}, true
}

func (s *sse) send(event string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	if event != "" {
		fmt.Fprintf(s.w, "event: %s\n", event)
	}
	fmt.Fprintf(s.w, "data: %s\n\n", b)
	s.fl.Flush()
}

func (s *sse) line(event, text string) { s.send(event, map[string]string{"line": text}) }

// ---------------------------------------------------------------------------
// status — tailscale status and netcheck, polled, diffed, pushed on change
// ---------------------------------------------------------------------------

func (c *Controller) StreamStatus(w http.ResponseWriter, r *http.Request) {
	s, ok := newSSE(w)
	if !ok {
		return
	}
	ctx := r.Context()
	var lastStatus, lastNet, lastState string

	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()

	for {
		if text := c.statusText(ctx); text != lastStatus {
			lastStatus = text
			s.send("status", map[string]string{"text": text})
		}
		if text := c.netcheckText(ctx); text != lastNet {
			lastNet = text
			s.send("netcheck", map[string]string{"text": text})
		}
		c.Observe(ctx)
		if b, _ := json.Marshal(c.Snapshot()); string(b) != lastState {
			lastState = string(b)
			s.send("state", json.RawMessage(b))
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// statusText is `tailscale status` from the laptop's point of view — the same
// vantage point the sandbox page prints it from.
func (c *Controller) statusText(ctx context.Context) string {
	self := "lab-ubuntu"
	if !c.lab.Running(ctx, self) {
		self = "lab-vps"
	}
	if !c.lab.Running(ctx, self) {
		return "$ tailscale status\n  (no machine is running)"
	}
	r, err := c.lab.Exec(ctx, self, "tailscale", "status")
	if err != nil {
		return "$ tailscale status\n  " + err.Error()
	}
	out := strings.TrimRight(r.Out(), "\n")
	if out == "" {
		out = "  (nothing else is up)"
	}
	return self + " $ tailscale status\n" + out
}

func (c *Controller) netcheckText(ctx context.Context) string {
	self := "lab-ubuntu"
	if !c.lab.Running(ctx, self) {
		return "$ tailscale netcheck\n  (lab-ubuntu is not running)"
	}
	r, _ := c.lab.Exec(ctx, self, "tailscale", "netcheck")
	return self + " $ tailscale netcheck\n" + strings.TrimRight(r.Out(), "\n")
}

// ---------------------------------------------------------------------------
// tcpdump — the live capture, straight off the wire
// ---------------------------------------------------------------------------

func (c *Controller) StreamTcpdump(w http.ResponseWriter, r *http.Request) {
	s, ok := newSSE(w)
	if !ok {
		return
	}
	ctx := r.Context()

	machine := q(r, "machine", "evil-box")
	if !c.lab.Running(ctx, machine) {
		s.line("note", machine+" is not running, so there is nothing to listen to.")
		return
	}
	iface := q(r, "iface", "")
	if iface == "" {
		if machine == "evil-box" {
			iface = c.ifaceOn(ctx, "evil-box", c.lab.IPOn(ctx, "evil-box", "lan-ubuntu"))
		} else {
			iface = "eth0"
		}
	}
	filter := q(r, "filter", "udp port 41641")

	s.line("note", fmt.Sprintf("%s # tcpdump -l -n -X -i %s '%s'", machine, iface, filter))
	argv := []string{"tcpdump", "-l", "-n", "-X", "-i", iface, filter}

	err := c.lab.ExecStream(ctx, machine, argv, func(line string) {
		s.line("packet", line)
	})
	if err != nil && ctx.Err() == nil {
		s.line("note", "capture ended: "+err.Error())
	}
}

// ---------------------------------------------------------------------------
// logs — tailscaled, filtered to the lines about how it chose a path
// ---------------------------------------------------------------------------

var pathWords = []string{
	"magicsock", "derp", "endpoint", "portmap", "netcheck",
	"disco", "direct", "relay", "home is", "control:",
}

func (c *Controller) StreamLogs(w http.ResponseWriter, r *http.Request) {
	s, ok := newSSE(w)
	if !ok {
		return
	}
	ctx := r.Context()
	machine := q(r, "machine", "lab-ubuntu")
	if !c.lab.Running(ctx, machine) {
		s.line("note", machine+" is not running.")
		return
	}
	all := q(r, "all", "") == "1"
	s.line("note", machine+" # tail -f /var/log/tailscaled.log")

	err := c.lab.ExecStream(ctx, machine, []string{"tail", "-n", "40", "-f", "/var/log/tailscaled.log"},
		func(line string) {
			if all || matchesAny(strings.ToLower(line), pathWords) {
				s.line("log", line)
			}
		})
	if err != nil && ctx.Err() == nil {
		s.line("note", "log stream ended: "+err.Error())
	}
}

func matchesAny(s string, words []string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// stats — CPU, memory and interface counters, per container
// ---------------------------------------------------------------------------

func (c *Controller) StreamStats(w http.ResponseWriter, r *http.Request) {
	s, ok := newSSE(w)
	if !ok {
		return
	}
	ctx := r.Context()
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()

	for {
		var out []Stats
		for _, m := range Catalog {
			if !c.lab.Running(ctx, m.ID) {
				continue
			}
			if st, err := c.lab.Stats(ctx, m.ID); err == nil {
				out = append(out, st)
			}
		}
		s.send("stats", out)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func q(r *http.Request, key, def string) string {
	if v := r.URL.Query().Get(key); v != "" {
		return v
	}
	return def
}

// ---------------------------------------------------------------------------
// The rules pane — what the machine will tell you about itself
// ---------------------------------------------------------------------------

func (c *Controller) RulesText(ctx context.Context) string {
	var b strings.Builder
	if c.lab.Running(ctx, "lab-vps") {
		r, _ := c.lab.Exec(ctx, "lab-vps", "ufw", "status", "numbered")
		b.WriteString("lab-vps # ufw status numbered\n" + strings.TrimRight(r.Out(), "\n") + "\n")

		if t, _ := c.lab.Exec(ctx, "lab-vps", "lab-docker-trap", "status"); strings.TrimSpace(t.Stdout) == "on" {
			d, _ := c.lab.Sh(ctx, "lab-vps", "iptables -S FORWARD | head -4; echo; iptables -t nat -S DOCKER")
			b.WriteString("\n# and the ones ufw cannot see:\nlab-vps # iptables -S FORWARD\n" +
				strings.TrimRight(d.Out(), "\n") + "\n")
		}
		l, _ := c.lab.Sh(ctx, "lab-vps", "ss -tlnp 2>/dev/null | head -8")
		b.WriteString("\nlab-vps # ss -tlnp\n" + strings.TrimRight(l.Out(), "\n") + "\n")
	}

	var shaped []string
	for _, m := range Catalog {
		if !c.lab.Running(ctx, m.ID) {
			continue
		}
		q, _ := c.lab.Sh(ctx, m.ID, "tc qdisc show dev eth0 2>/dev/null | head -1")
		n, _ := c.lab.Sh(ctx, m.ID, "nft list ruleset 2>/dev/null | grep -c 41641 || true")
		line := strings.TrimSpace(q.Stdout)
		if strings.Contains(line, "netem") {
			shaped = append(shaped, "  "+pad(m.Label, 13)+line)
		}
		if strings.TrimSpace(n.Stdout) != "0" && strings.TrimSpace(n.Stdout) != "" {
			shaped = append(shaped, "  "+pad(m.Label, 13)+"udp/41641 dropped by nft")
		}
	}
	if len(shaped) > 0 {
		b.WriteString("\n# tc qdisc show ; nft list ruleset\n" + strings.Join(shaped, "\n") + "\n")
	} else {
		b.WriteString("\n# tc qdisc show ; nft list ruleset\n  every link is clean\n")
	}
	return b.String()
}

func pad(s string, n int) string {
	for len(s) < n {
		s += " "
	}
	return s
}

func ctxWithTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, d)
}
