package main

import (
	"encoding/json"
	"reflect"
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
