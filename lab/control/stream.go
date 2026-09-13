// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hashem Aldhaheri

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
// One stream, one-way, over plain SSE. No websockets and no client library:
// nothing here needs to be asked a question, it only ever needs to be pushed
// at, and SSE reconnects on its own.
//
// This file is the plumbing and the two things the wire is made of that are
// also wanted elsewhere — `tailscale status` and `netcheck`, which the feed
// polls, and the rules pane, which is a plain GET. The wire itself, and every
// source on it, is in feed.go.
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
