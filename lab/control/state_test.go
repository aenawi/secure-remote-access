// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hashem Aldhaheri

package main

import (
	"encoding/json"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// What the machine says about itself
//
// Three of the eleven checks are decided by these two parsers and nothing else:
// whether passwords can be used, whether root can log in, and whether sshd is
// exposed on the public interface. They read human-readable command output with
// substring searches, which is the right trade here — asking the machine beats
// reading a file and hoping — but it means a reworded table or an extra line is
// a silently wrong answer rather than an error.
//
// Every fixture below is verbatim output from `docker compose up -d`.
// ---------------------------------------------------------------------------

// `ufw status verbose` on lab-vps in the boot configuration: default deny, the
// tailnet allowed wholesale, and the public :22 rule chapter 08 exists to get
// you out of still in place.
const ufwBoot = `Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
Anywhere on tailscale0     ALLOW IN    Anywhere
22/tcp                     ALLOW IN    Anywhere
`

// The same machine after "Remove the public :22 rule": the row is gone, and
// nothing else moved.
const ufwHardened = `Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
Anywhere on tailscale0     ALLOW IN    Anywhere
`

// Day one: ufw installed and never enabled. Nothing is denied, and there is no
// table at all to read a rule out of.
const ufwInactive = "Status: inactive\n"

func TestReadUFW(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		in                      string
		deny, tailnet, public22 bool
	}{
		{"the boot state", ufwBoot, true, true, true},
		{"public :22 removed", ufwHardened, true, true, false},
		{"never enabled", ufwInactive, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var v VPSState
			v.readUFW(tc.in)
			if v.UFWDefaultDeny != tc.deny || v.AllowTailscale != tc.tailnet ||
				v.AllowPublic22 != tc.public22 {
				t.Fatalf("readUFW() = deny %v, tailscale0 %v, 22/tcp %v; want %v, %v, %v",
					v.UFWDefaultDeny, v.AllowTailscale, v.AllowPublic22,
					tc.deny, tc.tailnet, tc.public22)
			}
		})
	}

	// The lock-out this lab has a button for: both rules gone, the default
	// still deny. It is the one configuration where "closed" and "secure" come
	// apart hardest, and the audit can only notice it if this reads correctly.
	var lockedOut VPSState
	lockedOut.readUFW("Status: active\nDefault: deny (incoming), allow (outgoing), deny (routed)\n" +
		"\nTo                         Action      From\n--                         ------      ----\n")
	if !lockedOut.UFWDefaultDeny || lockedOut.AllowTailscale || lockedOut.AllowPublic22 {
		t.Fatalf("a machine with no rules at all: %#v", lockedOut)
	}
}

// `sshd -T` on lab-vps as the entrypoint leaves it. Note that sshd prints
// ListenAddress with the port appended and PermitRootLogin in its canonical
// spelling, neither of which is what was written into the file — which is the
// argument for asking sshd rather than reading the config.
const sshdBoot = `listenaddress 0.0.0.0:22
permitrootlogin without-password
passwordauthentication no
`

// After "Bind sshd to the tailnet address". A packet arriving on eth0 is now
// permitted by every firewall and answered by nothing, which is the rung-5
// failure no rule you can read explains.
const sshdTailnetOnly = `listenaddress 100.71.4.3:22
permitrootlogin without-password
passwordauthentication no
`

// Day one, which is where every guide starts: root over the network with a
// password, from anywhere on earth.
const sshdDayOne = `listenaddress 0.0.0.0:22
permitrootlogin yes
passwordauthentication yes
`

func TestReadSSHD(t *testing.T) {
	for _, tc := range []struct {
		name           string
		in             string
		listen         string
		password, root bool
	}{
		{"the boot state", sshdBoot, "all", false, false},
		{"bound to the tailnet", sshdTailnetOnly, "tailnet", false, false},
		{"day one", sshdDayOne, "all", true, true},
		// sshd defaults to every address when no ListenAddress is set, and
		// "not stated" must not read as "bound to the tailnet".
		{"nothing to read", "", "all", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := VPSState{SSHDListen: "all"} // what observeVPS starts from
			v.readSSHD(tc.in)
			if v.SSHDListen != tc.listen || v.PasswordAuth != tc.password || v.PermitRoot != tc.root {
				t.Fatalf("readSSHD() = listen %q, password %v, root %v; want %q, %v, %v",
					v.SSHDListen, v.PasswordAuth, v.PermitRoot, tc.listen, tc.password, tc.root)
			}
		})
	}

	// "without-password" is what sshd prints for `prohibit-password`, and it
	// contains the word password. Only the exact word yes enables either of
	// these, and getting that backwards would report a machine as wide open —
	// or, far worse, report an open one as closed.
	var v VPSState
	v.readSSHD("permitrootlogin without-password\npasswordauthentication no\n")
	if v.PermitRoot || v.PasswordAuth {
		t.Fatalf("prohibit-password is not a password login: %#v", v)
	}

	// sshd prints one line per address, and a machine bound to both its
	// tailnet address and 0.0.0.0 is exposed on the public interface. Reading
	// "a tailnet address appeared somewhere" as "bound to the tailnet" would
	// pass the check on a machine that still answers a stranger on eth0 — the
	// same shape of mistake as finding 4, one layer down.
	var both VPSState
	both.SSHDListen = "all"
	both.readSSHD("listenaddress 100.71.4.3:22\nlistenaddress 0.0.0.0:22\n")
	if both.SSHDListen == "tailnet" {
		t.Fatal("sshd is listening on 0.0.0.0 as well, so it is exposed — and the check " +
			"that reads this is the one chapter 08 is written around")
	}
}

// ---------------------------------------------------------------------------
// The link readout
// ---------------------------------------------------------------------------

// `tc qdisc show dev eth0` after the lab adds 20% loss and 150ms of delay.
const qdiscImpaired = `qdisc netem 8001: root refcnt 2 limit 1000 delay 150ms loss 20%`

func TestParseTrailingInt(t *testing.T) {
	for _, tc := range []struct {
		in, key string
		want    int
	}{
		{qdiscImpaired, "loss ", 20},
		{qdiscImpaired, "delay ", 150},
		// A clean link: pfifo_fast has neither, and the readout has to say
		// nought rather than carrying over whatever it saw last.
		{"qdisc pfifo_fast 0: root refcnt 2 bands 3 priomap 1 2 2 2 1 2 0 0", "loss ", 0},
		{"qdisc pfifo_fast 0: root refcnt 2 bands 3", "delay ", 0},
		{"", "loss ", 0},
		// The key present with something unparseable after it. Nought is the
		// only honest answer; guessing would put a number on the readout that
		// nothing measured.
		{"delay unknown", "delay ", 0},
	} {
		if got := parseTrailingInt(tc.in, tc.key); got != tc.want {
			t.Errorf("parseTrailingInt(%q, %q) = %d, want %d", tc.in, tc.key, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// headscale's wire format
// ---------------------------------------------------------------------------

// Every time field headscale emits is a protobuf timestamp: an object on the
// wire, a readable string in the table it prints for humans. Decoding it as a
// string makes every call to `nodes list` fail the moment one node actually has
// an expiry — which takes the whole control server down, quietly, on the one
// configuration where the expiry check could have passed.
func TestHeadscaleTimestampsDecodeAsObjects(t *testing.T) {
	const raw = `[{"id":1,"name":"lab-ubuntu","given_name":"lab-ubuntu",
	  "node_key":"nodekey:484168cada3f8ed7678bd35d65e69733172f374271e27bad692e29884e3b3c50",
	  "tags":["tag:laptop"],"online":true,
	  "expiry":{"seconds":1790319306,"nanos":331658610}}]`

	var ns []hsNode
	if err := json.Unmarshal([]byte(raw), &ns); err != nil {
		t.Fatal(err)
	}
	if len(ns) != 1 {
		t.Fatalf("decoded %d nodes", len(ns))
	}
	if got := ns[0].Expiry.Time(); !got.Equal(time.Unix(1790319306, 331658610)) {
		t.Fatalf("expiry decoded as %v", got)
	}
	if ns[0].NodeKey == "" {
		t.Fatal("the node key is what a rotation is supposed to replace, and it has to " +
			"survive the decode or rotate-key reports \"not measured\" forever")
	}

	// A node with no expiry recorded — which is every node in this lab up to
	// Headscale 0.26, and none of them since 0.29's `node.expiry`. The zero
	// time is what expiryVerdict reads as "no expiry at all", so it has to be
	// the zero time and not the epoch.
	var none []hsNode
	if err := json.Unmarshal([]byte(`[{"given_name":"lab-vps","expiry":null}]`), &none); err != nil {
		t.Fatal(err)
	}
	if !none[0].Expiry.Time().IsZero() {
		t.Fatalf("an absent expiry is the zero time, got %v", none[0].Expiry.Time())
	}
	// And the same for a field that decoded into an object of zeroes, which is
	// what headscale emits for `created_at` on a node it has no date for.
	if !(&hsTime{}).Time().IsZero() {
		t.Fatal("a zeroed timestamp is not 1970")
	}
}

// The tag list headscale prints, under the name 0.29 gives it.
//
// It was `forced_tags` up to 0.26 and is `tags` from 0.29, and the rename is
// silent in the worst way: JSON decoding into a field nothing populates leaves
// an empty slice, EnsureNodes reads that as "this node has no tag yet", tags it
// again, sees a change and restarts the coordination server — on every pass of
// the observe loop, forever. Nothing errors and the lab merely feels broken.
func TestHeadscaleNodeTagsDecode(t *testing.T) {
	const raw = `[{"id":1,"given_name":"lab-ubuntu","online":true,
	  "tags":["tag:laptop"]}]`

	var ns []hsNode
	if err := json.Unmarshal([]byte(raw), &ns); err != nil {
		t.Fatal(err)
	}
	if len(ns) != 1 || len(ns[0].Tags) != 1 || ns[0].Tags[0] != "tag:laptop" {
		t.Fatalf("headscale 0.29 calls this field `tags`, and EnsureNodes has to read it "+
			"or it re-tags and restarts the coordination server on every pass: %+v", ns)
	}
}

// ---------------------------------------------------------------------------
// The catalog and the configurations
// ---------------------------------------------------------------------------

// The four machines are the sandbox's four, and the audit reaches for three of
// them by name. A rename here is a probe that returns "no such machine" for
// every check, which scores nought and reads like a broken lab.
func TestCatalogHoldsTheMachinesTheAuditNames(t *testing.T) {
	for _, id := range []string{"lab-vps", "lab-ubuntu", "lab-roam", "evil-box"} {
		if _, ok := machineByID(id); !ok {
			t.Errorf("%q is named in audit.go and is not in the catalog", id)
		}
	}
	if _, ok := machineByID("lab-vps-web"); ok {
		t.Error("lab-vps-web sits behind the published port and is not a machine you drive")
	}

	hostile := 0
	for _, m := range Catalog {
		if m.Hostile {
			hostile++
		}
		if m.Tag == "" {
			t.Errorf("%q has no tag, and every grant in this lab is written against tags", m.ID)
		}
	}
	if hostile != 1 {
		t.Fatalf("%d machines are marked hostile; expiryVerdict skips exactly the one, and "+
			"counting a second would fail the check for a reason that is not the reader's",
			hostile)
	}
}

// The four named configurations are the sandbox's four, with the same ids,
// because the comparison the whole pair exists for only means anything if the
// inputs match. The audit fixture in audit_test.go scores each of them by id.
func TestPresetsMatchWhatIsScored(t *testing.T) {
	for _, id := range []string{"day-one", "typical", "weak", "hardened"} {
		p, ok := presetByID(id)
		if !ok {
			t.Fatalf("%q is scored in the README's comparison table and there is no preset for it", id)
		}
		if p.Note == "" || p.Sub == "" {
			t.Errorf("%q has no prose, and a configuration nobody explains is a switch flip", id)
		}
		switch p.Tone {
		case "ok", "warn", "danger":
		default:
			t.Errorf("%q has tone %q, which the page has no colour for", id, p.Tone)
		}
	}

	// The boot state is the fifth row of that table and is deliberately not a
	// preset: it is where `docker compose up -d` leaves you, and the point of
	// publishing its score is that nobody chose it.
	if _, ok := presetByID("the boot state"); ok {
		t.Fatal("the boot state is defaultState(), not a preset — if that has changed, the " +
			"README's table has a row that means something different now")
	}
	d := defaultState()
	if !d.ACL.Lock || !d.VPS.AllowPublic22 {
		t.Fatal("the boot state scores 7 of 11 precisely because tailnet lock is on and " +
			"public :22 is still open — that pair is finding 4, and the score moves if " +
			"either half of it does")
	}
}
