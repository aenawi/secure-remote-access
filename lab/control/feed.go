// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hashem Aldhaheri

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// The feed
//
// One wire out of this server — /api/stream/hud — carrying every live thing
// that happens in the lab as a typed event. It replaces four separate SSE
// endpoints, each of which a consumer opened for itself and parsed for itself.
//
// The reason is not tidiness. Four streams means four places that know how to
// read the lab, so a widget somebody else writes has to pick the right one and
// parse it correctly before it can draw anything, and a recording of what
// happened has to be stitched together from four files whose clocks nobody
// reconciled. One ordered wire is a thing you can hand to a stranger, and a
// thing you can write to a file and play back later with no Docker at all.
//
// So the shape below is chosen for those two readers rather than for the page
// that exists today:
//
//   - Every event is the same envelope. A consumer that does not recognise a
//     type can skip it by reading one field, rather than by failing to parse.
//   - Every event carries its own sequence and its own timestamp. Replay needs
//     both: the order events happened in, and how long apart.
//   - Every event goes out as a `data:` line that is complete on its own. A
//     `.jsonl` file of those lines, one per line, is the recording — there is
//     no framing to reconstruct.
//
// Nothing here changes what is drawn. The board still renders an action from
// the reply to the POST that ran it; the feed carries the same Result so that
// a recording is complete, and so that a widget can watch one without being
// the thing that pressed the button.
// ---------------------------------------------------------------------------

// Event is the envelope. Every line on the wire is one of these, and the
// `data:` payload of every SSE frame is exactly this object.
//
// Seq is a position on one wire, not a global identity: two readers connected
// at the same time each count their own frames from 1, because what a replay
// needs is the order the events reached it. At is Unix milliseconds — the
// deltas between events are the thing replay does arithmetic on, and a
// timestamp that has to be parsed before it can be subtracted is a timestamp
// that will be parsed wrongly by somebody.
type Event struct {
	Seq  int64  `json:"seq"`
	At   int64  `json:"at"`
	Type string `json:"type"`
	Data any    `json:"data"`
}

// FeedTypes is every type name the feed emits, and it is served in the opening
// `hello` so a consumer can find out what this build carries rather than
// guessing from a version number.
//
// The three at the end are only present when they were asked for: packet and
// log cost a process inside a container, so they run when a query parameter
// names a machine and not otherwise.
var FeedTypes = []string{
	"hello",    // once, at open: what this wire carries and what was subscribed
	"state",    // the full State snapshot, on change
	"status",   // `tailscale status`, on change
	"netcheck", // `tailscale netcheck`, on change
	"stat",     // []Stats, one sample per running container, every tick
	"verdict",  // a Result from /api/action, /api/set or /api/preset
	"flow",     // a Result from /api/probe: a measured path between two machines
	"packet",   // one line of tcpdump, if capture= named a machine
	"log",      // one line of tailscaled.log, if logs= named a machine
	"note",     // a source saying something about itself, not about the lab
}

// feedResult is what a verdict or a flow carries. A bare Result does not say
// what produced it, and the set-piece a replay has to pick is chosen by id —
// so the id travels with the Result rather than being inferred from its shape.
type feedResult struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"` // action | set | preset | probe
	Result Result `json:"result"`
}

// ---------------------------------------------------------------------------
// The hub: events that belong to the lab rather than to one reader
// ---------------------------------------------------------------------------

// Feed broadcasts the events that are not any one reader's. Everything a
// reader can produce for itself — a poll of `tailscale status`, a tcpdump it
// asked for — is produced per connection; what goes through here is the things
// that happened *to the lab*, which is every Result the API returned.
//
// A subscriber that cannot keep up loses events. That is deliberate and it is
// the only safe direction: the alternative is /api/action blocking on a
// browser tab that has been backgrounded, which would make a stalled reader
// into a stalled lab. Dropped counts what was lost, so a consumer can say so
// rather than quietly showing a gap.
type Feed struct {
	mu      sync.Mutex
	subs    map[int]chan Event
	nextSub int
	dropped atomic.Int64
}

// feedBuffer is how far behind a reader may fall before it starts losing
// events. Sized for the burst an attack produces — a Result, a state change
// and a stats tick land within a few milliseconds of each other — with enough
// room left that an ordinary hiccup costs nothing.
const feedBuffer = 256

func NewFeed() *Feed { return &Feed{subs: map[int]chan Event{}} }

// Publish stamps an event with the time and hands it to every subscriber. Seq
// is left at zero: it is a position on a wire, and the wire assigns it.
func (f *Feed) Publish(kind string, data any) {
	ev := Event{At: time.Now().UnixMilli(), Type: kind, Data: data}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ch := range f.subs {
		select {
		case ch <- ev:
		default:
			f.dropped.Add(1)
		}
	}
}

// Subscribe returns a channel of broadcast events and the function that stops
// it. The channel is never closed — a reader leaves by calling the returned
// function and then not reading, and closing under a concurrent Publish is a
// panic waiting for a slow afternoon.
func (f *Feed) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, feedBuffer)
	f.mu.Lock()
	id := f.nextSub
	f.nextSub++
	f.subs[id] = ch
	f.mu.Unlock()

	return ch, func() {
		f.mu.Lock()
		delete(f.subs, id)
		f.mu.Unlock()
	}
}

// Dropped is how many events have been lost to subscribers that could not keep
// up, since the server started.
func (f *Feed) Dropped() int64 { return f.dropped.Load() }

// Subscribers is how many readers are attached.
func (f *Feed) Subscribers() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.subs)
}

// PublishResult puts a Result on the feed under the type its kind implies: a
// probe measured a path between two machines, which is a flow; everything else
// is a verdict about the lab's configuration or an attack against it.
//
// Called from the API handlers rather than from deeper down on purpose. What
// ran is a fact about the request, not about the function that served it, and
// the id is the thing a replay needs most.
func (c *Controller) PublishResult(kind, id string, res Result) {
	if c.feed == nil {
		return
	}
	t := "verdict"
	if kind == "probe" {
		t = "flow"
	}
	c.feed.Publish(t, feedResult{ID: id, Kind: kind, Result: res})
}

// ---------------------------------------------------------------------------
// The wire
// ---------------------------------------------------------------------------

// feedPollInterval is how often the polled sources are re-read. Three seconds,
// which is what the status and stats streams used before this file existed:
// `tailscale status` is an exec into a container and the lab is a laptop.
const feedPollInterval = 3 * time.Second

// StreamHUD serves the feed.
//
// Everything that can be produced is produced by its own goroutine writing
// into one channel, and one writer takes them off that channel and puts them
// on the wire. That is what makes the sequence mean something: the order is
// decided in a single place, so two events cannot be numbered by two
// goroutines racing over the same counter.
//
// Query parameters name the on-demand sources, because a capture costs a
// process inside a container and the reader is the only one who knows whether
// anybody is looking at it:
//
//	/api/stream/hud
//	/api/stream/hud?capture=evil-box
//	/api/stream/hud?capture=evil-box&iface=eth0&filter=udp+port+41641
//	/api/stream/hud?logs=lab-ubuntu&logsAll=1
//
// There is no server-side subscription state and nothing to POST: a reader
// that wants a capture reconnects with the parameter. That keeps a recording
// honest — the URL says what was being watched — and it keeps this handler a
// function of its request, which is the only version of it that is testable
// without a browser.
func (c *Controller) StreamHUD(w http.ResponseWriter, r *http.Request) {
	s, ok := newSSE(w)
	if !ok {
		return
	}

	// Cancelled when the reader goes away *or* when this handler returns, so
	// every producer below stops without being told twice.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	out := make(chan Event, feedBuffer)
	global, unsubscribe := c.feed.Subscribe()
	defer unsubscribe()

	capture := r.URL.Query().Get("capture")
	logs := r.URL.Query().Get("logs")

	var wg sync.WaitGroup
	start := func(fn func()) {
		wg.Add(1)
		go func() { defer wg.Done(); fn() }()
	}

	start(func() { c.pollFeed(ctx, out) })
	if capture != "" {
		start(func() { c.captureFeed(ctx, out, r, capture) })
	}
	if logs != "" {
		start(func() { c.logFeed(ctx, out, r, logs) })
	}

	// The producers hold the only senders on `out`; when they are all done
	// nothing further can arrive, and the writer below can stop looking.
	go func() { wg.Wait(); close(out) }()

	// First line on the wire, before anything is measured: what this build
	// carries and what this connection asked for. A recording that starts with
	// this can be read by something written against a different build.
	var seq int64
	write := func(ev Event) {
		seq++
		ev.Seq = seq
		if ev.At == 0 {
			ev.At = time.Now().UnixMilli()
		}
		s.send(ev.Type, ev)
	}

	sources := []string{"state", "status", "netcheck", "stat", "verdict", "flow"}
	if capture != "" {
		sources = append(sources, "packet")
	}
	if logs != "" {
		sources = append(sources, "log")
	}
	write(Event{Type: "hello", Data: map[string]any{
		"types":    FeedTypes,
		"sources":  sources,
		"capture":  capture,
		"logs":     logs,
		"pollMs":   feedPollInterval.Milliseconds(),
		"dropped":  c.feed.Dropped(),
		"readers":  c.feed.Subscribers(),
		"serverAt": time.Now().UnixMilli(),
	}})

	for {
		select {
		case <-ctx.Done():
			return
		case ev, open := <-out:
			if !open {
				// Every producer finished — a capture of a machine that is not
				// running ends this way, and so does a log tail whose file went
				// away. Hold the connection open for the broadcast events, which
				// have no producer of their own to finish.
				out = nil
				continue
			}
			write(ev)
		case ev := <-global:
			write(ev)
		}
	}
}

// emit puts one event on the connection's channel, and gives up if the reader
// has gone. Every producer goes through here, so none of them can outlive the
// request by blocking on a send nobody will ever receive.
func emit(ctx context.Context, out chan<- Event, kind string, data any) bool {
	select {
	case out <- Event{At: time.Now().UnixMilli(), Type: kind, Data: data}:
		return true
	case <-ctx.Done():
		return false
	}
}

func emitLine(ctx context.Context, out chan<- Event, kind, text string) bool {
	return emit(ctx, out, kind, map[string]string{"line": text})
}

// emitNote is a source saying something about itself rather than about the lab:
// the command it is about to run, or the reason it stopped.
//
// It carries which source it came from, and that field is not decoration. When
// these were four streams, a note could only have come from the stream it
// arrived on, so the capture pane printed the tcpdump banner and the log pane
// printed the tail banner and neither had to be told. On one wire both panes
// see both notes, and a capture pane headed `tail -f /var/log/tailscaled.log`
// is a pane lying about where its lines came from.
func emitNote(ctx context.Context, out chan<- Event, source, text string) bool {
	return emit(ctx, out, "note", map[string]string{"source": source, "line": text})
}

// ---------------------------------------------------------------------------
// The polled sources: status, netcheck, state, stats
// ---------------------------------------------------------------------------

// pollFeed reads the four things that have to be asked for rather than pushed.
//
// status, netcheck and state are diffed and only sent when they changed, which
// is what the status stream did: three seconds of an unchanged `tailscale
// status` is not news, and a recording full of it is a recording nobody will
// read. stat is sent every tick regardless, because a counter that did not
// move is the measurement, not the absence of one.
func (c *Controller) pollFeed(ctx context.Context, out chan<- Event) {
	var lastStatus, lastNet, lastState string

	tick := time.NewTicker(feedPollInterval)
	defer tick.Stop()

	for {
		if text := c.statusText(ctx); text != lastStatus {
			lastStatus = text
			if !emit(ctx, out, "status", map[string]string{"text": text}) {
				return
			}
		}
		if text := c.netcheckText(ctx); text != lastNet {
			lastNet = text
			if !emit(ctx, out, "netcheck", map[string]string{"text": text}) {
				return
			}
		}

		c.Observe(ctx)
		if b, _ := json.Marshal(c.Snapshot()); string(b) != lastState {
			lastState = string(b)
			if !emit(ctx, out, "state", json.RawMessage(b)) {
				return
			}
		}

		var stats []Stats
		for _, m := range Catalog {
			if !c.lab.Running(ctx, m.ID) {
				continue
			}
			if st, err := c.lab.Stats(ctx, m.ID); err == nil {
				stats = append(stats, st)
			}
		}
		if !emit(ctx, out, "stat", stats) {
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// ---------------------------------------------------------------------------
// The on-demand sources: tcpdump, and the tailscaled log
// ---------------------------------------------------------------------------

// captureFeed is the live capture, straight off the wire. One packet event per
// real frame — the motion a set-piece draws from this is measured, not
// invented, and that is the property the note above the tray is claiming.
func (c *Controller) captureFeed(ctx context.Context, out chan<- Event, r *http.Request, machine string) {
	if !c.lab.Running(ctx, machine) {
		emitNote(ctx, out, "capture", machine+" is not running, so there is nothing to listen to.")
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

	emitNote(ctx, out, "capture", fmt.Sprintf("%s # tcpdump -l -n -X -i %s '%s'", machine, iface, filter))
	argv := []string{"tcpdump", "-l", "-n", "-X", "-i", iface, filter}

	err := c.lab.ExecStream(ctx, machine, argv, func(line string) {
		emitLine(ctx, out, "packet", line)
	})
	if err != nil && ctx.Err() == nil {
		emitNote(ctx, out, "capture", "capture ended: "+err.Error())
	}
}

// pathWords are the tailscaled log lines about how it chose a path, which is
// the only part of that log this lab is about. Everything else is noise at a
// rate no reader can follow; logsAll=1 turns the filter off for someone who
// wants the rest.
var pathWords = []string{
	"magicsock", "derp", "endpoint", "portmap", "netcheck",
	"disco", "direct", "relay", "home is", "control:",
}

func (c *Controller) logFeed(ctx context.Context, out chan<- Event, r *http.Request, machine string) {
	if !c.lab.Running(ctx, machine) {
		emitNote(ctx, out, "logs", machine+" is not running.")
		return
	}
	all := q(r, "logsAll", "") == "1"
	emitNote(ctx, out, "logs", machine+" # tail -f /var/log/tailscaled.log")

	err := c.lab.ExecStream(ctx, machine, []string{"tail", "-n", "40", "-f", "/var/log/tailscaled.log"},
		func(line string) {
			if all || matchesAny(strings.ToLower(line), pathWords) {
				emitLine(ctx, out, "log", line)
			}
		})
	if err != nil && ctx.Err() == nil {
		emitNote(ctx, out, "logs", "log stream ended: "+err.Error())
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
