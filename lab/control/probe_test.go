// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hashem Aldhaheri

package main

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// The five-rung ladder
//
// Every fixture below was captured from a running lab — `docker compose up -d`,
// then the same two commands Probe itself runs, copied out verbatim. That is
// deliberate and it is the whole reason these tests are cheap: the rung is a
// pure function of what nc said at one end and what tcpdump saw at the other,
// so once the strings are checked in the classifier can be exercised without
// Docker, without a tailnet, and without waiting a minute for an audit.
//
// It is also not hypothetical. Finding 5 in lab/README.md was a rung
// misclassification — the audit reported "refused at rung 1" without probing,
// so tailnet lock took credit for a public :22 that UFW had left wide open. It
// survived for months and was caught by running containers, which is an
// expensive way to find a bug in a function that reads strings.
// ---------------------------------------------------------------------------

// lab-ubuntu → lab-vps:22 over tailscale0, in the boot configuration. The
// connection completed, and lab-vps watched the SYN land.
const (
	knockReached = `Connection to 100.71.4.3 22 port [tcp/ssh] succeeded!
rc=0`
	capReached = `06:36:24.838873 IP 100.71.4.1.41986 > 100.71.4.3.22: Flags [S], seq 1261468561, ` +
		`win 64480, options [mss 1240,sackOK,TS val 3547692470 ecr 0,nop,wscale 10], length 0`
)

// lab-ubuntu → lab-vps:8080 over tailscale0. The tailnet policy has nothing to
// say about 8080, so the packet never left the tailnet — and lab-vps's tcpdump
// ran for its full eight seconds and printed nothing at all. This is the rung-3
// signature: a timeout at one end and silence at the other.
const knockTailnetRefused = `nc: connect to 100.71.4.3 port 8080 (tcp) timed out: Operation now in progress
rc=1`

// evil-box → lab-vps:9999 across the segment standing in for the public
// internet, with ufw defaulting to deny. Byte for byte the same nc message as
// the rung-3 case above — which is exactly why the capture, not the knock, is
// what decides between them.
const (
	knockDropped = `nc: connect to 203.0.113.11 port 9999 (tcp) timed out: Operation now in progress
rc=1`
	capDropped = `06:37:21.159597 IP 203.0.113.66.43262 > 203.0.113.11.9999: Flags [S], seq 1922283739, ` +
		`win 64240, options [mss 1460,sackOK,TS val 3704786483 ecr 0,nop,wscale 10], length 0`
)

// A port with nothing behind it and nothing filtering it: every rule permitted
// the packet, it arrived, and the kernel sent back a reset. Rung 5, and the
// most misread of the five — the firewall did its job and the connection still
// failed, which is usually a bind address rather than a rule.
const (
	knockRefused = `nc: connect to 127.0.0.1 port 9999 (tcp) failed: Connection refused
rc=1`
	capRefused = `06:37:27.414387 IP 127.0.0.1.52954 > 127.0.0.1.9999: Flags [S], seq 3458624352, ` +
		`win 65495, options [mss 65495,sackOK,TS val 994147556 ecr 0,nop,wscale 10], length 0`
)

func TestKnockClassify(t *testing.T) {
	for _, tc := range []struct {
		name    string
		k       knock
		rung    int
		ok      bool
		saysIn  string // a phrase Why must carry, because Why is the answer here
		saysWhy string
	}{
		{
			name: "it worked",
			k: knock{from: "lab-ubuntu", to: "lab-vps", iface: "tailscale0",
				addr: "100.71.4.3", port: "22", out: knockReached, capture: capReached},
			rung: 5, ok: true, saysIn: "reached 100.71.4.3:22",
			saysWhy: "the address and port belong in Why so a caller does not have to reassemble them",
		},
		{
			// The one the model got wrong before. Nothing arrived AND the far
			// machine has no log line — those two facts together are the rung,
			// and neither one alone is.
			name: "nothing arrived, over the tailnet",
			k: knock{from: "lab-ubuntu", to: "lab-vps", iface: "tailscale0",
				addr: "100.71.4.3", port: "8080", out: knockTailnetRefused, capture: ""},
			rung: 3, ok: false, saysIn: "no log line",
			saysWhy: "a rung-3 denial is invisible on the far machine, and the prose has to say so",
		},
		{
			// Same nc output as the case above, on a path that is not the
			// tailnet. Nothing arrived, so there is no path — a claim about
			// routing, not about anybody's policy.
			name: "nothing arrived, off the tailnet",
			k: knock{from: "evil-box", to: "lab-vps", iface: "eth1",
				addr: "203.0.113.11", port: "9999", out: knockTailnetRefused, capture: ""},
			rung: 2, ok: false, saysIn: "no path between",
			saysWhy: "off the tailnet there is no policy to blame, so it must not claim one",
		},
		{
			name: "it arrived and died",
			k: knock{from: "evil-box", to: "lab-vps", iface: "eth1",
				addr: "203.0.113.11", port: "9999", out: knockDropped, capture: capDropped},
			rung: 4, ok: false, saysIn: "visible on the machine",
			saysWhy: "the whole difference from rung 3 is that this one leaves evidence",
		},
		{
			name: "it arrived and was refused",
			k: knock{from: "lab-vps", to: "lab-vps", iface: "lo",
				addr: "127.0.0.1", port: "9999", out: knockRefused, capture: capRefused},
			rung: 5, ok: false, saysIn: "bind address",
			saysWhy: "rung 5 is where the firewall is innocent, and the prose has to point elsewhere",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rung, ok, _, why := tc.k.classify()
			if rung != tc.rung || ok != tc.ok {
				t.Fatalf("classify() = rung %d, ok %v; want rung %d, ok %v\n%s",
					rung, ok, tc.rung, tc.ok, why)
			}
			if !strings.Contains(why, tc.saysIn) {
				t.Fatalf("Why should carry %q — %s\ngot: %s", tc.saysIn, tc.saysWhy, why)
			}
		})
	}
}

// The two endings that are identical from the sending side. This is the whole
// argument for starting a capture on the destination before knocking, and if it
// ever stops being true the probe has stopped measuring anything.
func TestRungThreeAndFourAreToldApartByTheCaptureAlone(t *testing.T) {
	if knockTailnetRefused != strings.Replace(knockDropped,
		"203.0.113.11 port 9999", "100.71.4.3 port 8080", 1) {
		t.Fatal("these two fixtures are supposed to differ only in the address nc printed — " +
			"if they have drifted, re-capture both rather than editing one")
	}

	base := knock{from: "lab-ubuntu", to: "lab-vps", iface: "tailscale0",
		addr: "100.71.4.3", port: "8080", out: knockTailnetRefused}

	silent := base
	rung3, _, _, _ := silent.classify()

	seen := base
	seen.capture = capDropped
	rung4, _, _, _ := seen.classify()

	if rung3 != 3 || rung4 != 4 {
		t.Fatalf("same knock, one capture apart, gave rungs %d and %d — want 3 and 4", rung3, rung4)
	}
}

// nc's exit status is the only thing that settles whether the connection
// completed. The success banner is not the same sentence across nc
// implementations, and a classifier reading it would go quiet on a rebuild.
func TestKnockReachedReadsTheReturnCode(t *testing.T) {
	if !(knock{out: knockReached}).reached() {
		t.Fatal("rc=0 is a completed connection")
	}
	for _, out := range []string{knockDropped, knockRefused, knockTailnetRefused} {
		if (knock{out: out}).reached() {
			t.Fatalf("a non-zero return code is not a connection: %q", out)
		}
	}
	// Neither is a two-digit code that happens to start with the same digit.
	if (knock{out: "nc: something\nrc=10"}).reached() {
		t.Fatal("rc=10 is not rc=0")
	}
}

// arrived asks the far machine. tcpdump writes nothing when it captures
// nothing, but a shell that redirected it may leave whitespace behind, and a
// stray newline must not read as a packet — that would turn every rung-3
// denial into a rung-4 one.
func TestKnockArrivedIgnoresWhitespace(t *testing.T) {
	for _, cap := range []string{"", "\n", "  \n\t", "\n\n"} {
		if (knock{capture: cap}).arrived() {
			t.Fatalf("%q is not a captured packet", cap)
		}
	}
	if !(knock{capture: capReached}).arrived() {
		t.Fatal("a tcpdump line is a captured packet")
	}
}

// ---------------------------------------------------------------------------
// Rung 2 — which way, if any
// ---------------------------------------------------------------------------

// lab-roam → lab-vps with WireGuard's UDP port dropped on lab-roam, so the
// session falls back to the relay. Captured whole: the first attempt timed out
// while the fallback was still settling, four pongs came back over DERP, and
// the summary line underneath says the direct path never happened.
//
// That summary is the trap. It is the last line, it contains no pong, and a
// classifier reading `lastLine` here would report a working relayed session as
// no session at all.
const pingRelayed = `ping "100.71.4.3" timed out
pong from lab-vps (100.71.4.3) via DERP(lab) in 1ms
pong from lab-vps (100.71.4.3) via DERP(lab) in 1ms
pong from lab-vps (100.71.4.3) via DERP(lab) in 2ms
pong from lab-vps (100.71.4.3) via DERP(lab) in 1ms
direct connection not established`

// The same pair with UDP allowed again: one line, straight through the NAT.
const pingDirect = `pong from lab-vps (100.71.4.3) via 203.0.113.11:41641 in 1ms`

// What `tailscale ping` says about a peer the policy never sent this machine.
const pingNoPeer = `no matching peer`

func TestTailnetPath(t *testing.T) {
	for _, tc := range []struct {
		name     string
		in       string
		path     string
		settled  bool
		ruleSays string
	}{
		{"relayed, with a discouraging summary underneath it",
			pingRelayed, "relay", true, "DERP"},
		{"direct", pingDirect, "direct", true, "both NATs held a mapping open"},
		{"a session each and no path between them",
			pingNoPeer, "", false, "no matching peer"},
		{"tailscale ping said nothing at all", "", "", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, rule, why, settled := tailnetPath(tc.in)
			if path != tc.path || settled != tc.settled {
				t.Fatalf("tailnetPath() = path %q, settled %v; want %q, %v",
					path, settled, tc.path, tc.settled)
			}
			if !strings.Contains(rule, tc.ruleSays) {
				t.Fatalf("Rule should carry %q, got %q", tc.ruleSays, rule)
			}
			if settled && why != "" {
				t.Fatalf("a settled path owes no explanation, got %q", why)
			}
			if !settled && !strings.Contains(why, "no path between them") {
				t.Fatalf("an unsettled path has to say so, got %q", why)
			}
		})
	}

	// The specific regression: the answer is the last line that reported a
	// pong, not the last line. Asserted against the real capture rather than a
	// trimmed one, because the summary line is the entire hazard.
	if !strings.HasSuffix(pingRelayed, "direct connection not established") {
		t.Fatal("this fixture is only worth having while it still ends in the summary line")
	}
	if _, _, _, settled := tailnetPath(pingRelayed); !settled {
		t.Fatal("a relayed session is a session — reading the summary line as the verdict " +
			"turns every relayed pair into no path at all")
	}
}

// A peer the policy removed rather than blocked. It is a rung-3 denial with a
// distinguishing feature, and the feature is the point: there is nothing to
// capture on the far machine, so the reader who goes looking for a log line
// will not find one and must be told why before they start.
func TestNoPeerInNetmap(t *testing.T) {
	r := noPeerInNetmap("evil-box", "lab-vps")
	if r.Rung != 3 {
		t.Fatalf("a peer that was never sent is rung 3, got %d", r.Rung)
	}
	if r.OK {
		t.Fatal("nothing was reached")
	}
	for _, want := range []string{"netmap", "no log line"} {
		if !strings.Contains(r.Rule+r.Why, want) {
			t.Errorf("the prose should mention %q: %s / %s", want, r.Rule, r.Why)
		}
	}
	if len(r.Cmds) == 0 || !strings.Contains(r.Cmds[0], "tailscale status") {
		t.Fatalf("it should hand the reader the command that shows the absence: %v", r.Cmds)
	}
}

// The ladder is the board's X axis and the sandbox's, so a rung outside 1..5 is
// a drawing with no lane to put it in. Cheap to assert over every ending the
// classifier has.
func TestEveryEndingIsOnTheLadder(t *testing.T) {
	endings := []knock{
		{iface: "tailscale0", out: knockReached, capture: capReached},
		{iface: "tailscale0", out: knockTailnetRefused},
		{iface: "eth1", out: knockDropped},
		{iface: "eth1", out: knockDropped, capture: capDropped},
		{iface: "lo", out: knockRefused, capture: capRefused},
	}
	for _, k := range endings {
		rung, _, _, why := k.classify()
		if rung < 1 || rung > 5 {
			t.Fatalf("rung %d is not on the ladder: %s", rung, why)
		}
		if why == "" {
			t.Fatalf("rung %d came back with no explanation, and the probe never answers "+
				"yes or no — it answers which rung, and why", rung)
		}
	}
	if r := noPeerInNetmap("a", "b").Rung; r < 1 || r > 5 {
		t.Fatalf("rung %d is not on the ladder", r)
	}
}
