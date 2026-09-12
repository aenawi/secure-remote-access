// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hashem Aldhaheri

package main

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// The feed
//
// Nothing here needs a container, and that is most of the point: the hub, the
// envelope and the promise that a slow reader cannot stall the lab are all
// decidable without Docker, so they are decided here and CI gets to have an
// opinion about them.
//
// What is *not* here, and cannot be: whether `tailscale status` comes back,
// whether tcpdump finds an interface, whether the wire reconnects. Those are
// measured against the running lab and written into the pull request, because
// a test that claims them would be claiming something it did not observe.
// ---------------------------------------------------------------------------

func TestFeedFanOut(t *testing.T) {
	f := NewFeed()

	a, stopA := f.Subscribe()
	b, stopB := f.Subscribe()
	defer stopA()
	defer stopB()

	if got := f.Subscribers(); got != 2 {
		t.Fatalf("Subscribers() = %d, want 2", got)
	}

	f.Publish("verdict", map[string]string{"id": "nat-slam"})

	for i, ch := range []<-chan Event{a, b} {
		select {
		case ev := <-ch:
			if ev.Type != "verdict" {
				t.Errorf("subscriber %d got type %q, want verdict", i, ev.Type)
			}
			if ev.At == 0 {
				t.Errorf("subscriber %d got an event with no timestamp", i)
			}
			// Seq is the wire's to assign, not the hub's: two readers are two
			// wires, and an event numbered by the hub would be numbered for
			// whichever of them happened to be first.
			if ev.Seq != 0 {
				t.Errorf("subscriber %d got Seq %d from the hub, want 0", i, ev.Seq)
			}
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d never received the event", i)
		}
	}
}

func TestFeedUnsubscribeStopsDelivery(t *testing.T) {
	f := NewFeed()
	ch, stop := f.Subscribe()

	stop()
	if got := f.Subscribers(); got != 0 {
		t.Fatalf("Subscribers() = %d after stop, want 0", got)
	}

	f.Publish("state", nil)
	select {
	case ev := <-ch:
		t.Fatalf("a stopped subscriber still received %q", ev.Type)
	case <-time.After(50 * time.Millisecond):
	}

	// Calling stop twice is what a deferred unsubscribe does when the handler
	// also returned early, and it must not panic or take a second reader with
	// it.
	stop()
}

// A reader that stops reading must lose events rather than hold the lab up.
// The failure this is about is not hypothetical in shape: Publish is called
// from inside /api/action, so a send that blocks is an attack that never
// returns to the person who ran it.
func TestFeedDropsRatherThanBlocks(t *testing.T) {
	f := NewFeed()
	_, stop := f.Subscribe()
	defer stop()

	// Nothing reads the channel. Fill it, then overrun it by a clear margin.
	over := 32
	done := make(chan struct{})
	go func() {
		for range feedBuffer + over {
			f.Publish("stat", nil)
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a subscriber that was not reading")
	}

	if got := f.Dropped(); got != int64(over) {
		t.Errorf("Dropped() = %d, want %d", got, over)
	}
}

// The envelope is the contract with everything that is not this page: a widget
// somebody else writes, and a `.jsonl` recording played back with no server at
// all. Renaming a field here breaks both of them silently, so the names are
// pinned.
func TestEventEnvelopeJSON(t *testing.T) {
	b, err := json.Marshal(Event{Seq: 7, At: 1757660000000, Type: "flow",
		Data: map[string]string{"id": "probe"}})
	if err != nil {
		t.Fatalf("marshalling an Event: %v", err)
	}

	want := `{"seq":7,"at":1757660000000,"type":"flow","data":{"id":"probe"}}`
	if string(b) != want {
		t.Errorf("Event marshalled as\n  %s\nwant\n  %s", b, want)
	}
}

// A Result on the feed without the id of what produced it is a Result a replay
// cannot pick a set-piece for — which was the whole reason for putting it on
// the feed. So: what ran travels with what happened.
func TestPublishResultCarriesWhatRan(t *testing.T) {
	for _, tc := range []struct {
		kind, id  string
		wantType  string
		wantKind  string
		wantIDStr string
	}{
		{"action", "nat-slam", "verdict", "action", "nat-slam"},
		{"set", "vps.allowPublic22", "verdict", "set", "vps.allowPublic22"},
		{"preset", "weak", "verdict", "preset", "weak"},
		{"probe", "probe", "flow", "probe", "probe"},
	} {
		t.Run(tc.kind+"/"+tc.id, func(t *testing.T) {
			c := &Controller{feed: NewFeed()}
			ch, stop := c.feed.Subscribe()
			defer stop()

			c.PublishResult(tc.kind, tc.id, Result{OK: true, Rung: 4, Rule: "a rule"})

			select {
			case ev := <-ch:
				if ev.Type != tc.wantType {
					t.Errorf("type = %q, want %q", ev.Type, tc.wantType)
				}
				fr, ok := ev.Data.(feedResult)
				if !ok {
					t.Fatalf("Data is %T, want feedResult", ev.Data)
				}
				if fr.ID != tc.wantIDStr || fr.Kind != tc.wantKind {
					t.Errorf("carried {id:%q kind:%q}, want {id:%q kind:%q}",
						fr.ID, fr.Kind, tc.wantIDStr, tc.wantKind)
				}
				// The Result goes through whole. A feed that summarised it would
				// be a second engine, and the rung is the thing this repository
				// refuses to reduce to a pass/fail.
				if fr.Result.Rung != 4 || fr.Result.Rule != "a rule" {
					t.Errorf("Result arrived as %+v, want rung 4 and its rule", fr.Result)
				}
			case <-time.After(time.Second):
				t.Fatal("nothing was published")
			}
		})
	}
}

// A Controller built without a feed is what a test does, and it must not take
// the process down for it.
func TestPublishResultWithNoFeed(t *testing.T) {
	c := &Controller{}
	c.PublishResult("action", "nat-slam", Result{}) // must not panic
}

// FeedTypes is served in the opening hello, and a consumer is told to read it
// rather than guess. A type the wire emits but the list omits makes that
// promise false.
func TestFeedTypesCoversWhatIsEmitted(t *testing.T) {
	for _, want := range []string{
		"hello", "state", "status", "netcheck", "stat",
		"verdict", "flow", "packet", "log", "note",
	} {
		if !slices.Contains(FeedTypes, want) {
			t.Errorf("FeedTypes omits %q, which the wire emits", want)
		}
	}
	if len(FeedTypes) != 10 {
		t.Errorf("FeedTypes has %d entries; if a type was added, add it to this "+
			"test and to the feed's documentation in lab/README.md", len(FeedTypes))
	}
}

// Every producer sends through emit, which is what stops one outliving the
// request it belongs to. A cancelled context has to end the send rather than
// wait for a reader that has gone.
func TestEmitGivesUpWhenTheReaderHasGone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan Event) // unbuffered: the send cannot complete on its own

	cancel()
	if emit(ctx, out, "packet", nil) {
		t.Error("emit reported a send on a cancelled context")
	}
	if emitLine(ctx, out, "note", "anything") {
		t.Error("emitLine reported a send on a cancelled context")
	}
}

func TestEmitLineShape(t *testing.T) {
	ctx := context.Background()
	out := make(chan Event, 1)

	if !emitLine(ctx, out, "packet", "10.0.13.5.41641 > 10.0.66.9.41641") {
		t.Fatal("emitLine reported no send on a live context")
	}
	ev := <-out

	// The text sources all carry {"line": "..."} and the page reads that one
	// key for packet, log and note alike. Three shapes for three text streams
	// is three parsers, which is what this branch is removing.
	m, ok := ev.Data.(map[string]string)
	if !ok {
		t.Fatalf("Data is %T, want map[string]string", ev.Data)
	}
	if m["line"] != "10.0.13.5.41641 > 10.0.66.9.41641" {
		t.Errorf("line = %q, want the packet", m["line"])
	}
	if ev.At == 0 {
		t.Error("emitLine produced an event with no timestamp")
	}
}

// On four streams a note could only have come from the stream it arrived on. On
// one wire it has to say, or the capture pane prints the log tail's banner and
// claims the lines under it came from tcpdump.
func TestNotesSayWhichSourceTheyCameFrom(t *testing.T) {
	ctx := context.Background()
	out := make(chan Event, 2)

	emitNote(ctx, out, "capture", "evil-box # tcpdump -l -n -X -i eth1 'udp port 41641'")
	emitNote(ctx, out, "logs", "lab-ubuntu # tail -f /var/log/tailscaled.log")

	for _, want := range []struct{ source, contains string }{
		{"capture", "tcpdump"},
		{"logs", "tail -f"},
	} {
		ev := <-out
		if ev.Type != "note" {
			t.Fatalf("type = %q, want note", ev.Type)
		}
		m, ok := ev.Data.(map[string]string)
		if !ok {
			t.Fatalf("Data is %T, want map[string]string", ev.Data)
		}
		if m["source"] != want.source {
			t.Errorf("source = %q, want %q", m["source"], want.source)
		}
		if !strings.Contains(m["line"], want.contains) {
			t.Errorf("line %q does not mention %q", m["line"], want.contains)
		}
	}
}
