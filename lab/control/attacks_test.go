// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hashem Aldhaheri

package main

import (
	"encoding/json"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// nmap's own output, from `nmap -Pn -n -p 22,80,8080,41641` against lab-vps in
// the "typical" configuration. Kept verbatim rather than trimmed, because the
// parser has to survive the banner and the header row as well as the table.
const nmapTypical = `Starting Nmap 7.93 ( https://nmap.org ) at 2026-08-26 09:14 UTC
Nmap scan report for 203.0.113.11
Host is up (0.000042s latency).

PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    closed   http
8080/tcp  open     http-proxy
41641/tcp filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 0.21 seconds
`

const nmapHardened = `Starting Nmap 7.93 ( https://nmap.org ) at 2026-08-26 09:19 UTC
Nmap scan report for 203.0.113.11
Host is up (0.000031s latency).

PORT      STATE    SERVICE
22/tcp    filtered ssh
80/tcp    filtered http
8080/tcp  filtered http-proxy
41641/tcp filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 2.09 seconds
`

func TestParseOpenPorts(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want []string
	}{
		{"typical", nmapTypical, []string{"22/tcp", "8080/tcp"}},
		// Every port filtered. "open|filtered" is not open, and the word
		// "open" in the STATE column of a filtered row must not count.
		{"hardened", nmapHardened, nil},
		{"open|filtered is not open", "PORT STATE\n41641/udp open|filtered unknown\n", nil},
		{"nothing at all", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parseOpenPorts(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parseOpenPorts() = %#v, want %#v", got, tc.want)
			}
		})
	}
}

// The HUD lights one dot per open port, so it needs the number rather than
// nmap's "22/tcp". Anything it cannot read is dropped rather than guessed.
func TestPortNumber(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int
	}{
		{"22/tcp", 22},
		{"8080/tcp", 8080},
		{"41641/udp", 41641},
		{"22", 22},
		{"ssh/tcp", 0},
		{"", 0},
	} {
		if got := portNumber(tc.in); got != tc.want {
			t.Errorf("portNumber(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// Evidence is what the HUD reads instead of Why. The two have to agree: if the
// prose names two open ports, there are two keys in the map.
func TestScanEvidence(t *testing.T) {
	ev := scanEvidence(parseOpenPorts(nmapTypical), scanPorts)
	want := map[string]int{"scanned": 4, "open:22": 1, "open:8080": 1}
	if !reflect.DeepEqual(ev, want) {
		t.Fatalf("scanEvidence() = %#v, want %#v", ev, want)
	}

	clean := scanEvidence(parseOpenPorts(nmapHardened), scanPorts)
	if !reflect.DeepEqual(clean, map[string]int{"scanned": 4}) {
		t.Fatalf("a clean scan should carry only the count it probed, got %#v", clean)
	}
}

func TestParseKV(t *testing.T) {
	const counts = "cleartext=1\ntunnelled=0\nframes=214\n"
	for k, want := range map[string]int{
		"cleartext": 1, "tunnelled": 0, "frames": 214, "missing": 0,
	} {
		if got := parseKV(counts, k); got != want {
			t.Errorf("parseKV(%q) = %d, want %d", k, got, want)
		}
	}
}

// Evidence is a wire contract: the HUD reads these keys instead of Why, so
// the shape has to survive the round trip and stay absent when an action
// measured nothing countable.
func TestEvidenceRoundTrip(t *testing.T) {
	in := Result{Rung: 4, Evidence: scanEvidence(parseOpenPorts(nmapTypical), scanPorts)}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"open:8080":1`) {
		t.Fatalf("Evidence did not survive marshalling: %s", b)
	}
	var out Result
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Evidence["open:22"] != 1 || out.Evidence["scanned"] != 4 {
		t.Fatalf("round trip lost keys: %#v", out.Evidence)
	}

	// Most actions measure nothing countable, and the field is omitted rather
	// than serialised as null — a caller reading res.evidence.frames on one
	// of those gets undefined, not a crash.
	plain, err := json.Marshal(Result{Rung: 1})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), "evidence") {
		t.Fatalf("an action that measured nothing should omit evidence: %s", plain)
	}
}

// The outage demonstration measures four numbers and every one of them has to
// arrive under its own name. Two of them used to leave on Packets and
// Retransmits, so a good run printed "70 packets · 45 retransmits" for a run
// that sent no packets and retransmitted nothing; the other two never left the
// function at all. The inequality asserted here is the lesson the whole
// demonstration exists to show, so a transposed key is a wrong drawing, not a
// cosmetic slip.
func TestOutageEvidence(t *testing.T) {
	// A happy path: both sessions ride out the blackout, then the address
	// changes and only Mosh keeps counting.
	ev := outageEvidence(45, 46, 45, 70)
	want := map[string]int{
		"sshAfterBlackout":  45,
		"moshAfterBlackout": 46,
		"sshAfterRoam":      45,
		"moshAfterRoam":     70,
	}
	if !reflect.DeepEqual(ev, want) {
		t.Fatalf("outageEvidence() = %#v, want %#v", ev, want)
	}
	if ev["moshAfterRoam"] <= ev["sshAfterRoam"] {
		t.Fatalf("the happy path is mosh outlasting ssh across the roam, got mosh %d, ssh %d",
			ev["moshAfterRoam"], ev["sshAfterRoam"])
	}

	// A run that proves nothing still carries four keys with zeroes in them:
	// "both sessions stopped" and "the demonstration never ran" are different
	// results, and the keys are what lets a drawing tell them apart.
	dead := outageEvidence(0, 0, 0, 0)
	for _, k := range []string{"sshAfterBlackout", "moshAfterBlackout", "sshAfterRoam", "moshAfterRoam"} {
		if _, ok := dead[k]; !ok {
			t.Fatalf("a run that measured zero still owes the key %q: %#v", k, dead)
		}
	}
}

// The rung is the board's X axis, and the outage set-piece draws two lanes
// reaching lab-vps for any session that printed a tick. If those two disagree
// the drawing is wrong, so the rule lives in one function and is asserted from
// both ends: any tick anywhere means rung 5, and no ticks at all means the
// opening claim stands.
func TestOutageRung(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		ssh1, mosh1, ssh2, mosh2 int
		want                     int
	}{
		{"the happy path", 45, 46, 45, 70, 5},
		{"mosh never started", 45, 0, 45, 0, 5},
		{"ssh never started", 0, 46, 0, 70, 5},
		// Only act two measured anything — a slow start, and still a session
		// that reached sshd. The set-piece draws a lane for it either way.
		{"nothing until the second act", 0, 0, 12, 30, 5},
		{"neither session ever printed", 0, 0, 0, 0, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := outageRung(tc.ssh1, tc.mosh1, tc.ssh2, tc.mosh2); got != tc.want {
				t.Fatalf("outageRung(%d, %d, %d, %d) = %d, want %d",
					tc.ssh1, tc.mosh1, tc.ssh2, tc.mosh2, got, tc.want)
			}
		})
	}

	// The set-piece's own "did anything run" test is the same disjunction over
	// the same four keys it reads off Evidence. Kept in step here so a change
	// to one is a failing test rather than a board that draws past its rung.
	ev := outageEvidence(0, 0, 12, 30)
	ran := ev["sshAfterBlackout"] > 0 || ev["moshAfterBlackout"] > 0 ||
		ev["sshAfterRoam"] > 0 || ev["moshAfterRoam"] > 0
	if ran != (outageRung(0, 0, 12, 30) == 5) {
		t.Fatal("Evidence says a session ran and the rung disagrees")
	}
}

// Detail carries the strings a drawing needs to be true about. The outage
// set-piece changes lab-roam's address label in act two, and the only honest
// source for what it changes to is the value demoOutage handed to `ip addr
// add` — not a regex over Raw, and not a constant copied into the JavaScript
// where the next edit to the Go side would leave it lying.
func TestDetailRoundTrip(t *testing.T) {
	b, err := json.Marshal(Result{
		Rung:   5,
		Detail: map[string]string{"addrBefore": "10.0.27.2", "addrAfter": "10.0.27.77"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var out Result
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Detail["addrBefore"] != "10.0.27.2" || out.Detail["addrAfter"] != "10.0.27.77" {
		t.Fatalf("round trip lost the addresses: %#v", out.Detail)
	}

	// Like Evidence, absent rather than null: a set-piece reading
	// res.detail.addrAfter on an action that measured no strings gets
	// undefined and draws nothing, instead of throwing.
	plain, err := json.Marshal(Result{Rung: 1})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), "detail") {
		t.Fatalf("an action with no strings to report should omit detail: %s", plain)
	}
}

func TestBoolToInt(t *testing.T) {
	if boolToInt(true) != 1 || boolToInt(false) != 0 {
		t.Fatal("boolToInt is the only thing separating two of atkExpiredKey's endings")
	}
}

// The dispatch table is the answer to "what can be posted to /api/action", and
// it is deliberately longer than AttackList. Two of its entries are not
// attacks — rotate-key is maintenance, outage is the session layer — and that
// gap is not cosmetic: the board reports which dispatchable ids have no
// set-piece, and while it was handed AttackList it structurally could not see
// either of them. One then went a whole release with no shot and nothing said
// so. This test is that blind spot, written down.
func TestActionIDsCoversMoreThanAttackList(t *testing.T) {
	ids := ActionIDs()
	in := make(map[string]bool, len(ids))
	for _, id := range ids {
		in[id] = true
	}

	for _, a := range AttackList {
		if !in[a.ID] {
			t.Errorf("%q is a button on the page and RunAttack will not dispatch it", a.ID)
		}
	}

	listed := make(map[string]bool, len(AttackList))
	for _, a := range AttackList {
		listed[a.ID] = true
	}
	for _, id := range []string{"rotate-key", "outage"} {
		if !in[id] {
			t.Errorf("%q has its own button and is not in the dispatch table", id)
		}
		if listed[id] {
			t.Errorf("%q is in AttackList, which it should not be — it is not an attack. "+
				"If that has genuinely changed, this test is what needs rewriting.", id)
		}
	}

	if !sort.StringsAreSorted(ids) {
		t.Fatalf("ActionIDs is served to a browser and has to be stable: %v", ids)
	}
}

// The mechanical half of the console warning app.js prints: every id RunAttack
// will dispatch has an entry in the set-piece register. The warning tells
// whoever has the page open; this tells whoever added the action, at the point
// they added it, which is the cheaper of the two places to find out.
func TestEverySetpieceExistsForEveryAction(t *testing.T) {
	src, err := uiFS.ReadFile("ui/hud/setpieces.js")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(src), "export const SETPIECES = {")
	if !ok {
		t.Fatal("no SETPIECES register in setpieces.js — did it get renamed?")
	}
	body, _, ok := strings.Cut(rest, "\n};")
	if !ok {
		t.Fatal("the SETPIECES register has no closing brace on its own line")
	}

	keys := regexp.MustCompile(`"([a-z-]+)"\s*:`).FindAllStringSubmatch(body, -1)
	drawn := make(map[string]bool, len(keys))
	for _, m := range keys {
		drawn[m[1]] = true
	}
	if len(drawn) == 0 {
		t.Fatal("read the register and found no ids in it, so this test proves nothing")
	}

	for _, id := range ActionIDs() {
		if !drawn[id] {
			t.Errorf("%q is dispatchable and has no set-piece. The board falls back to the "+
				"text trace, which works — but it is the one place the board stops being "+
				"the board, and that is worth noticing here rather than at a console.", id)
		}
	}
	for id := range drawn {
		if _, ok := Actions[id]; !ok {
			t.Errorf("there is a set-piece for %q and nothing dispatches it", id)
		}
	}
}

// The rotation is the whole of what the rotate-key shot is allowed to draw, so
// every claim it makes has to survive the round trip under its own name. The
// three that matter are the three parts of the continuity claim: it re-keyed,
// it stayed a member at the same address, and the session did not drop.
func TestRotationEvidence(t *testing.T) {
	// The demonstration working: a session was up, the key changed underneath
	// it, the address did not move, and the ticks kept coming.
	good := rotation{
		wasMember: true, isMember: true,
		keyRead: true, keyChanged: true,
		expiryMoved: true, addrKept: true,
		probeOK: true, probeRung: 5,
		ticksBefore: 8, ticksAfter: 20,
	}
	want := map[string]int{
		"wasMember": 1, "isMember": 1, "keyRead": 1, "keyChanged": 1,
		"expiryMoved": 1, "addrKept": 1, "probeOK": 1,
		"ticksBefore": 8, "ticksAfter": 20,
	}
	if !reflect.DeepEqual(good.evidence(), want) {
		t.Fatalf("evidence() = %#v, want %#v", good.evidence(), want)
	}
	if !good.sessionRan() || !good.sessionKept() {
		t.Fatal("a session that went from tick 8 to tick 20 both ran and kept counting")
	}

	// The one the shot must not draw as a success: the ticks stopped where
	// they were. Same final number as the first reading, which is exactly why
	// sessionKept is a comparison and not a threshold.
	dropped := rotation{wasMember: true, isMember: true, keyRead: true, keyChanged: true,
		ticksBefore: 8, ticksAfter: 8}
	if !dropped.sessionRan() || dropped.sessionKept() {
		t.Fatal("a session stuck on the tick it had before the re-auth did not keep counting")
	}

	// keyChanged is never true without keyRead, because "the two keys differ"
	// and "there were no two keys to compare" are different findings and the
	// shot draws a rotation for one of them and a sentence for the other.
	none := rotation{isMember: true}
	if none.evidence()["keyRead"] != 0 || none.evidence()["keyChanged"] != 0 {
		t.Fatalf("an unread key is not an unchanged one: %#v", none.evidence())
	}
	// And a run that measured zero still owes every key, so a drawing can tell
	// "nothing happened" apart from "nothing was reported".
	for _, k := range []string{"wasMember", "isMember", "keyRead", "keyChanged",
		"expiryMoved", "addrKept", "probeOK", "ticksBefore", "ticksAfter"} {
		if _, ok := none.evidence()[k]; !ok {
			t.Fatalf("a run that measured zero still owes the key %q: %#v", k, none.evidence())
		}
	}
}

// The rung is the board's X axis, and the rotate-key shot draws a lane all the
// way to lab-vps for any session that printed a tick. A tick is a shell on
// lab-vps answering, which is rung 5 whatever the probe afterwards found;
// without one the probe is the only thing that measured a distance.
func TestRotationRung(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		ticksBefore, ticksAfter int
		probeRung               int
		want                    int
	}{
		{"a session rode through it", 8, 20, 5, 5},
		{"a session that dropped still reached sshd", 8, 8, 3, 5},
		{"restored, and the probe got in", 0, 0, 5, 5},
		{"restored, and rung 3 refused it", 0, 0, 3, 3},
		{"nothing measured a distance at all", 0, 0, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := rotation{ticksBefore: tc.ticksBefore, ticksAfter: tc.ticksAfter,
				probeRung: tc.probeRung}
			if got := r.rung(); got != tc.want {
				t.Fatalf("rung() = %d, want %d", got, tc.want)
			}
		})
	}
}

// ok on this action means maintenance did what maintenance is for. A rotation
// that dropped a working session is a real finding, and the one ending here
// that must not come back green however well the rest of it went.
func TestRotationVerdict(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    rotation
		ok   bool
		says string
	}{
		{"the session rode through it",
			rotation{wasMember: true, isMember: true, keyRead: true, keyChanged: true,
				addrKept: true, ticksBefore: 8, ticksAfter: 20},
			true, "did not notice"},
		{"the session dropped",
			rotation{wasMember: true, isMember: true, keyRead: true, keyChanged: true,
				ticksBefore: 8, ticksAfter: 8},
			false, "not free"},
		{"nothing re-keyed, and it says so rather than claiming one",
			rotation{wasMember: true, isMember: true, keyRead: true,
				addrKept: true, ticksBefore: 8, ticksAfter: 20},
			true, "did not demonstrate a re-key"},
		{"an expired machine brought back",
			rotation{isMember: true, keyRead: true, keyChanged: true, probeOK: true, probeRung: 5},
			true, "re-register put it back"},
		{"it never came back",
			rotation{wasMember: true},
			false, "did not come back onto the tailnet"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, why := tc.r.verdict("100.71.4.3")
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v — %s", ok, tc.ok, why)
			}
			if !strings.Contains(why, tc.says) {
				t.Fatalf("expected the prose to say %q, got: %s", tc.says, why)
			}
		})
	}
}

// A label with a blank where a key should be reads as a key that went missing,
// which is a different claim from one that was never asked for. Empty in,
// empty out, and the caller draws nothing.
func TestShortKey(t *testing.T) {
	for in, want := range map[string]string{
		"":                         "",
		"nodekey:abcdef0123456789": "abcdef0123…",
		"abcdef0123456789":         "abcdef0123…",
		"nodekey:abcd":             "abcd…",
		"nodekey:":                 "…",
	} {
		if got := shortKey(in); got != want {
			t.Errorf("shortKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// The tunnel
//
// atkTailcatTunnel's whole claim is a pair of rungs that were never asked, and
// a claim about an absence is the easiest kind to make without measuring
// anything. So the rung, the rule and the verdict are a pure function of six
// numbers, and this is where they are held.
// ---------------------------------------------------------------------------

// `pgrep -af tailcat` on lab-ubuntu with a tunnel up, captured from a running
// lab. The second line is the point of keeping it verbatim: a client is a
// tailcat process too, and a panel that read one as a server would report a
// tunnel on whichever machine somebody last connected *from*.
const pgrepServing = `412 tailcat serve --key=lab --ssh-authorized-keys=/root/.ssh/authorized_keys ssh
`

const pgrepServingPinned = `412 tailcat serve --key=lab --ssh-authorized-keys=/root/.ssh/authorized_keys --allow=nodekey:8b7aa21a58fe14047ba22119ef8f31732f58efa751899bafffbda83bf5f5732c ssh
`

const pgrepClientOnly = `901 tailcat ssh root@tcpGFwWCDm4pBv-5cUnZ1v6CBXtC
903 ssh -o ProxyCommand=tailcat proxy root@tcpGFwWCDm4pBv
`

func TestReadTailcatServe(t *testing.T) {
	for _, tc := range []struct {
		name    string
		out     string
		running bool
		service string
		allow   bool
	}{
		{"a server, serving ssh", pgrepServing, true, "ssh", false},
		{"a server with the pin on", pgrepServingPinned, true, "ssh", true},
		{"serving every port", "7 tailcat serve --key=lab all\n", true, "all", false},
		{"no auth at all", "7 tailcat serve --key=lab no-auth-ssh\n", true, "no-auth-ssh", false},
		// A client is not a tunnel. Reading one as a server would put the panel's
		// idea of "which machine is it on" on whichever machine last connected.
		{"only a client", pgrepClientOnly, false, "", false},
		{"nothing at all", "", false, "", false},
		// A service the panel does not offer is not one it may report: the two
		// halves of this pair share three, and a fourth appearing on one side
		// is how a shared vocabulary stops being shared.
		{"a service this lab does not offer", "7 tailcat serve exit-node\n", false, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			running, service, allow := readTailcatServe(tc.out)
			if running != tc.running || service != tc.service || allow != tc.allow {
				t.Errorf("readTailcatServe = (%v, %q, %v), want (%v, %q, %v)",
					running, service, allow, tc.running, tc.service, tc.allow)
			}
		})
	}
}

// The address is a bearer credential: whoever holds it connects, there is no
// identity behind it and nothing to revoke. So a readout may show enough of one
// to recognise it and never enough to use it.
func TestShortTailcatAddrNeverPrintsAWholeCredential(t *testing.T) {
	const full = "tcpGFwWCDm4pBv-5cUnZ1v6CBXtCGSTc73wUvCo2PIf-_i67LVN2FrWCB1Ig3AEFDR9VX_zFEPyPrDtD"
	got := shortTailcatAddr(full)
	if strings.Contains(full, got) {
		t.Errorf("shortTailcatAddr returned %q, which is a prefix of the whole address", got)
	}
	if len(got) >= len(full) {
		t.Errorf("shortTailcatAddr did not shorten anything: %q", got)
	}
	if !strings.HasPrefix(got, "tcpGFwWCDm4pBv-5") {
		t.Errorf("shortTailcatAddr(%q) = %q, which is not recognisable as the same address",
			full, got)
	}
	// Short enough not to need it, and truncating it would only produce a
	// string that looks like an address and is not one.
	if s := shortTailcatAddr("tcshort"); s != "tcshort" {
		t.Errorf("a short address came back as %q", s)
	}
}

// The four endings, and they are four different lessons. The one that matters
// most is the third: `serve all` reaching the machine's own sshd and being
// refused by a key is not tailcat holding the line, and a verdict that said so
// would credit the tunnel with a defence it had nothing to do with.
func TestTailcatRunVerdict(t *testing.T) {
	base := tailcatRun{service: "ssh", ordinaryRung: 2}

	// The contrast is the argument, and against a machine whose public :22 is
	// still open there is no contrast to draw. Saying "the same probe stopped
	// at rung 5" about a probe that got all the way in would be the one number
	// in this verdict that describes a different lab.
	t.Run("the contrast is the one this run produced", func(t *testing.T) {
		r := base
		r.banner, r.shell = true, true
		r.ordinaryRung, r.ordinaryOK = 5, true
		_, _, why := r.verdict("lab-vps", "")
		if strings.Contains(why, "stopped at rung 5") {
			t.Errorf("a probe that reached sshd was reported as stopped:\n%s", why)
		}
		if !strings.Contains(why, "reached lab-vps anyway") {
			t.Errorf("the verdict does not say the ordinary way worked too:\n%s", why)
		}
	})

	t.Run("a shell is a red frame and names both skipped rungs", func(t *testing.T) {
		r := base
		r.banner, r.shell, r.service = true, true, "no-auth-ssh"
		ok, danger, why := r.verdict("lab-ubuntu", "")
		if ok || !danger {
			t.Errorf("a shell on the far machine reported ok=%v danger=%v", ok, danger)
		}
		if r.rung() != 5 {
			t.Errorf("rung = %d, want 5", r.rung())
		}
		for _, want := range []string{"never consulted", "dialled out", "rung 2 of 5"} {
			if !strings.Contains(why, want) {
				t.Errorf("the verdict does not mention %q:\n%s", want, why)
			}
		}
	})

	t.Run("a key refusing it is not a green tick", func(t *testing.T) {
		r := base
		r.banner = true
		ok, danger, why := r.verdict("lab-ubuntu", "")
		// It held, and it held at rung 5, on one lock. `ok` here would say the
		// configuration answered this, and the configuration was never asked.
		if ok || !danger {
			t.Errorf("ok=%v danger=%v — one SSH key is not the layered defence holding", ok, danger)
		}
		if !strings.Contains(why, "one lock") {
			t.Errorf("the verdict does not count what is holding it:\n%s", why)
		}
	})

	t.Run("serve all is the machine's own sshd, not tailcat holding", func(t *testing.T) {
		r := base
		r.banner, r.service = true, "all"
		_, danger, why := r.verdict("lab-vps", "")
		if !danger {
			t.Error("every port behind one leaked string is not a warning")
		}
		if !strings.Contains(why, "own sshd") {
			t.Errorf("the verdict does not say what refused it:\n%s", why)
		}
	})

	t.Run("the pin holds, and the control experiment is what shows it", func(t *testing.T) {
		r := base
		r.allow, r.pinnedRan, r.pinnedIn = true, true, true
		if r.rung() != 2 {
			t.Errorf("a handshake the server ignored is rung %d, want 2", r.rung())
		}
		ok, danger, why := r.verdict("lab-ubuntu", "lab-roam")
		if !ok || danger {
			t.Errorf("ok=%v danger=%v — the pin refused the attacker and let the holder in", ok, danger)
		}
		if !strings.Contains(why, "lab-roam still got in") {
			t.Errorf("the verdict does not report the control arm:\n%s", why)
		}
	})

	t.Run("a tunnel that refused everybody proves nothing about the pin", func(t *testing.T) {
		// Same rung, same refusal, and a completely different finding: without
		// the control arm this is indistinguishable from a broken tunnel, and
		// reporting it as a defence would be the sniff attack claiming a win
		// on a capture whose control marker never appeared.
		r := base
		r.allow, r.pinnedRan, r.pinnedIn = true, true, false
		ok, _, why := r.verdict("lab-ubuntu", "lab-roam")
		if ok {
			t.Error("a tunnel nobody could reach was reported as a pin working")
		}
		if !strings.Contains(why, "proves nothing") {
			t.Errorf("the verdict does not say the run was inconclusive:\n%s", why)
		}
	})
}

// Evidence is what the board draws from, so every number the shot needs has to
// survive the round trip through JSON under the name reading.js asks for.
func TestTailcatEvidenceRoundTrip(t *testing.T) {
	r := tailcatRun{service: "ssh", banner: true, direct: true,
		inbound: 0, ifaces: 0, ordinaryRung: 2}
	b, err := json.Marshal(Result{Rung: r.rung(), Evidence: r.evidence()})
	if err != nil {
		t.Fatal(err)
	}
	var back Result
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]int{
		"banner": 1, "shell": 0, "direct": 1, "inbound": 0, "ifaces": 0,
		"ordinaryRung": 2, "ordinaryOK": 0, "skipped": 2,
	} {
		if got := back.Evidence[k]; got != want {
			t.Errorf("evidence[%q] = %d, want %d", k, got, want)
		}
	}
	// Absent rather than zero: the control experiment either ran or it did
	// not, and a 0 would read as "the pinned machine was refused".
	if _, ok := back.Evidence["pinnedIn"]; ok {
		t.Error("pinnedIn is present on a run where --allow was off")
	}
}

// The last pong is the answer, and the summary underneath it is not — the same
// reading tailnetPath makes of `tailscale ping`, and wrong the same way if you
// take the last line instead.
func TestOnlyDERP(t *testing.T) {
	const punched = `pong in 1.08ms via DERP(1)
pong in 440µs via 198.51.100.10:40921
`
	const relayOnly = `pong in 3.1ms via DERP(1)
pong in 2.9ms via DERP(1)
direct connection not established
`
	if onlyDERP(punched) {
		t.Error("a run that ended on a direct pong was read as relay-only")
	}
	if !onlyDERP(relayOnly) {
		t.Error("a run that never left the relay was read as direct")
	}
	if !onlyDERP("") {
		t.Error("no pong at all is not a direct path")
	}
}

// The banner is not a check and must never start behaving like one. It says
// something for every tunnel and nothing at all for no tunnel, and the two
// shapes chapter 01 calls out — no-auth-ssh and all — are the ones that read
// as bad rather than as a warning.
func TestHatchBanner(t *testing.T) {
	if text, tone := hatchBanner(TailcatState{}); text != "" || tone != "" {
		t.Errorf("a lab with no tunnel printed a banner: %q / %q", text, tone)
	}
	for _, tc := range []struct {
		st   TailcatState
		tone string
		want string
	}{
		{TailcatState{On: true, Host: "lab-ubuntu", Service: "ssh"}, "warn", "One SSH key"},
		{TailcatState{On: true, Host: "lab-vps", Service: "all"}, "bad", "every port"},
		{TailcatState{On: true, Host: "lab-vps", Service: "no-auth-ssh", Shared: true},
			"bad", "evil-box is holding it"},
		// The pin is the mitigated shape and still a way in nothing scores.
		{TailcatState{On: true, Host: "lab-roam", Service: "ssh", Allow: true}, "warn", "--allow"},
	} {
		text, tone := hatchBanner(tc.st)
		if tone != tc.tone {
			t.Errorf("%+v: tone = %q, want %q", tc.st, tone, tc.tone)
		}
		if !strings.Contains(text, tc.want) {
			t.Errorf("%+v: the banner does not mention %q:\n%s", tc.st, tc.want, text)
		}
		// The claim that separates this half from the sandbox's, and the
		// reason it is a banner rather than a twelfth check.
		if !strings.Contains(text, "The score does not move") {
			t.Errorf("%+v: the banner does not say the score is blind:\n%s", tc.st, text)
		}
	}
}

// The switch in the machines panel and every attack button share one failure:
// the attacker was never created. They must share the sentence too. This is the
// message a reader hits within minutes of first opening the lab, because
// `make up` deliberately does not build evil-box, so it is worth a test that it
// still names the command that does.
func TestEvilNotHereNamesTheCommand(t *testing.T) {
	r := evilNotHere()
	if r.OK {
		t.Error("a missing attacker is not an ok result")
	}
	if r.Rung != 1 {
		t.Errorf("rung = %d, want 1 — a container that does not exist stops at 'is anything alive'", r.Rung)
	}
	// Both spellings, because the reader may be in the UI or at a prompt.
	for _, want := range []string{"--profile attack", "make attack"} {
		if !strings.Contains(r.Why, want) {
			t.Errorf("the message does not name %q:\n%s", want, r.Why)
		}
	}
}

// ping's own summary, from evil-box with nat-evil down and then up. The exit
// code is not the measurement — busybox exits 1 for a lost packet and for an
// address it could not parse — so the summary line is, and it is the reason
// this parser exists rather than a `.Code != 0`.
const pingLost = `PING 203.0.113.3 (203.0.113.3): 56 data bytes

--- 203.0.113.3 ping statistics ---
1 packets transmitted, 0 received, +1 errors, 100% packet loss
`

const pingFine = `PING 203.0.113.3 (203.0.113.3): 56 data bytes
64 bytes from 203.0.113.3: seq=0 ttl=63 time=0.151 ms

--- 203.0.113.3 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, round-trip min/avg/max = 0.151/0.151/0.151 ms
`

func TestPingGotThrough(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want bool
	}{
		{"a reply", pingFine, true},
		{"every packet lost", pingLost, false},
		// Partial loss is still a route. A lossy wire is a condition this lab
		// sets on purpose, and refusing to measure on one would be refusing to
		// measure most of chapter 03.
		{"lossy but carrying", "5 packets transmitted, 2 received, 60% packet loss", true},
		{"no summary at all", "ping: bad address '203.0.113.3'", false},
		{"nothing", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := pingGotThrough(tc.in); got != tc.want {
				t.Fatalf("pingGotThrough() = %v, want %v", got, tc.want)
			}
		})
	}
}

// The bug this guards is the one the lab is least able to notice about itself:
// a stopped nat-evil reading as a firewall that held. Every attack that crosses
// the public segment now refuses instead, and the refusal has three jobs — stop
// at rung 1, claim nothing, and name the router — so all three are pinned here.
func TestEvilStranded(t *testing.T) {
	for _, tc := range []struct {
		name                string
		exists, running     bool
		wantRule, wantInWhy string
	}{
		{"the router was never created", false, false,
			"nat-evil is not in this stack", "--no-deps"},
		{"the router is stopped", true, false,
			"nat-evil is stopped", "docker start nat-evil"},
		// Running, and still nothing came back: the lab's own link switches can
		// do that, and pointing at the router would be pointing at the wrong
		// thing.
		{"the router is up and the wire is not", true, true,
			"no route out of evil-box's segment", "network panel"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := evilStranded("nat-evil", "10.0.66.254", tc.exists, tc.running, pingLost)

			if r.OK || r.Danger {
				t.Error("a run that reached nothing is neither a pass nor a breach")
			}
			if r.Rung != 1 {
				t.Errorf("rung = %d, want 1 — nothing on this path was alive, so no higher "+
					"rung was consulted", r.Rung)
			}
			if r.Rule != tc.wantRule {
				t.Errorf("rule = %q, want %q", r.Rule, tc.wantRule)
			}
			if !strings.Contains(r.Why, tc.wantInWhy) {
				t.Errorf("the message does not name %q:\n%s", tc.wantInWhy, r.Why)
			}
			// The whole point: no defence is credited by name, and the numbers
			// say nothing was reached rather than leaving a drawing to guess.
			if strings.Contains(r.Rule, "ufw") || strings.Contains(r.Why, "firewall held") {
				t.Errorf("a defence took credit for a packet nobody carried: %q / %s", r.Rule, r.Why)
			}
			if r.Evidence["reached"] != 0 {
				t.Errorf("evidence claims something was reached: %v", r.Evidence)
			}
			if !strings.Contains(r.Why, "nobody measured") {
				t.Errorf("the message does not say why nothing is scored:\n%s", r.Why)
			}
			if r.Raw == "" {
				t.Error("the refusal carries no measurement to show for itself")
			}
		})
	}
}

// nat-evil is the only one of the three routers a reader is ever told to stop,
// but all three strand the machine behind them the same way, and the state has
// to be able to say so. lab-vps is the machine with no router at all: a field
// that went true for it would be a lie in the other direction.
func TestEveryMachineBehindNATHasItsRouterNamed(t *testing.T) {
	for _, m := range Catalog {
		if m.ID == "lab-vps" {
			if m.Router != "" || m.Gateway != "" {
				t.Errorf("lab-vps has an address on the public segment itself and needs no "+
					"router, but the catalog gives it %q / %q", m.Router, m.Gateway)
			}
			continue
		}
		if m.Router == "" || m.Gateway == "" {
			t.Errorf("%s is behind a NAT with no router or gateway named: %q / %q",
				m.ID, m.Router, m.Gateway)
		}
	}
}
