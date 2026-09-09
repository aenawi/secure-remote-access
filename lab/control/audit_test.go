// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hashem Aldhaheri

package main

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// The eleven, and the number they add up to
//
// lab/README.md publishes five scores in its sandbox-versus-lab table, and that
// table is the most valuable thing this pair produces: a gap between the model
// and the containers means the model is wrong about something real. A number
// like that should not be able to move quietly, and until now it could — the
// only thing that computed it needed Docker, a tailnet and about a minute, so
// nothing checked it on the way past.
//
// What follows is the outcome of each of the eleven in each of the five
// configurations, written down once, and the arithmetic asserted against the
// table in the README itself. A change to the scoring, to the order of the
// checks, or to which of them a configuration passes now fails here first.
// ---------------------------------------------------------------------------

// outcome is one configuration's answer sheet: which of the eleven held.
// Written as the indices that passed rather than eleven booleans, because the
// interesting question about a configuration is always "which ones", and a row
// of true/false is unreadable at the point where somebody has to change it.
type outcome struct {
	name   string
	passed []int
	// stuck names the checks this lab answers for you, whichever way it
	// answers them. In practice it is always the expiry check: Headscale
	// records an expiry on every registration because `node.expiry` is set in
	// config/headscale/config.yaml, and offers no per-node way to turn one
	// off — so the answer is the same whatever the configuration says.
	stuck []int
}

func (o outcome) checks() []Check {
	pass := make(map[int]bool, len(o.passed))
	for _, i := range o.passed {
		pass[i] = true
	}
	stuck := make(map[int]bool, len(o.stuck))
	for _, i := range o.stuck {
		stuck[i] = true
	}

	out := make([]Check, 0, auditCheckCount)
	for i := 0; i < auditCheckCount; i++ {
		ch := auditPlan[i]
		// Got is what was measured; Want is what the check wanted. Deriving
		// Got from the two keeps the fixture honest: a check that wants false
		// and passed was measured false, and if Want ever flips in the plan
		// the fixture flips with it rather than silently disagreeing.
		ch.Got = ch.Want == pass[i]
		ch.Pass = ch.Got == ch.Want
		ch.Stuck = stuck[i]
		out = append(out, ch)
	}
	return out
}

// The five configurations, as this lab scores them against real containers.
//
// The expiry check is stuck in every one of them, which is why every row
// carries it — and since Headscale 0.29 it is stuck *passing*: `node.expiry`
// records one on every registration and nothing can turn it off, so three of
// these five score a point the sandbox does not give them. The score counts it
// as a pass anyway, because a number that argues with what was measured is
// worth nothing. Finding 1 in lab/README.md is that gap.
var scored = []outcome{
	{
		// A fresh VPS that has never heard of a tailnet. You can reach it
		// because :22 is open to the whole internet — and so can everybody
		// else, which is the same fact read twice.
		name: "day-one",
		passed: []int{
			ckYouCanGetIn, ckRoamCanGetIn,
			ckStrangerPublishedPort, // nothing is published
			ckUntrustedToLaptop,     // no route to it at all, which is not a policy
			ckExpiry,                // Headscale's, not this configuration's
		},
		stuck: []int{ckExpiry},
	},
	{
		// The visible half of the job, done properly, and then it stopped.
		// The two that hold are the two that cost nothing.
		name: "typical",
		passed: []int{
			ckYouCanGetIn, ckRoamCanGetIn,
			ckNoPasswords, ckNoRootLogin,
			ckExpiry, // Headscale's, not this configuration's
		},
		stuck: []int{ckExpiry},
	},
	{
		// Every protection that got in somebody's way, switched off on
		// purpose. Nothing holds except the two that ask whether you can still
		// work, and those hold for the wrong reason.
		name:   "weak",
		passed: []int{ckYouCanGetIn, ckRoamCanGetIn, ckExpiry},
		stuck:  []int{ckExpiry},
	},
	{
		// What chapters 01 through 11 build towards. Everything closed, and
		// the same eleven out of eleven the sandbox gives it.
		name: "hardened",
		passed: []int{
			ckYouCanGetIn, ckRoamCanGetIn,
			ckStrangerSSH, ckStrangerPublishedPort, ckStolenKey,
			ckUntrustedToServer, ckUntrustedToLaptop,
			ckNoPasswords, ckNoRootLogin, ckExpiry, ckSSHDNotPublic,
		},
		stuck: []int{ckExpiry},
	},
	{
		// Where `docker compose up -d` leaves you: a sensible policy and a
		// public :22 still open. Two of the three failures are the same
		// failure seen from two directions — a stranger reaches sshd, and so
		// does the holder of a key the tailnet refused. The second of those is
		// finding 4 in the README, and it is the reason this row says 8 and
		// not 9.
		name: "the boot state",
		passed: []int{
			ckYouCanGetIn, ckRoamCanGetIn,
			ckStrangerPublishedPort,
			ckUntrustedToServer, ckUntrustedToLaptop,
			ckNoPasswords, ckNoRootLogin, ckExpiry,
		},
		stuck: []int{ckExpiry},
	},
}

// The link between the fixture above and the prose a reader is asked to trust.
// Parsing the README rather than restating it is the point: the number in the
// table and the number the code computes are now the same number, and moving
// one without the other is a failing test rather than a documentation bug
// nobody notices for a release.
func TestPublishedScoresMatchTheReadmeTable(t *testing.T) {
	published := readReadmeScores(t)

	for _, o := range scored {
		want, ok := published[o.name]
		if !ok {
			t.Errorf("%q is scored here and has no row in lab/README.md's comparison table", o.name)
			continue
		}
		got := scoreAudit(o.checks())
		if got.Passed != want {
			t.Errorf("%s: scoreAudit says %d of %d, lab/README.md publishes %d of 11.\n"+
				"One of the two is wrong, and which one is not for this test to guess — "+
				"if the lab genuinely scores differently now, the table is what needs "+
				"rewriting, and the \"Where this lab and the sandbox disagree\" section "+
				"below it probably does too.",
				o.name, got.Passed, got.Total, want)
		}
		if got.Total != 11 {
			t.Errorf("%s: %d checks ran, and the table, the README and the sandbox all "+
				"say eleven", o.name, got.Total)
		}
	}

	for name := range published {
		found := false
		for _, o := range scored {
			if o.name == name {
				found = true
			}
		}
		if !found {
			t.Errorf("lab/README.md publishes a score for %q and nothing here scores it", name)
		}
	}
}

var readmeRow = regexp.MustCompile(`^\|\s*(.+?)\s*\|\s*\*{0,2}(\d+)/(\d+)\*{0,2}\s*\|\s*\*{0,2}(\d+)/(\d+)\*{0,2}\s*\|`)

// readReadmeScores lifts the "This lab" column out of the comparison table.
// It fails rather than returning nothing if the table has moved, because a
// test that silently stops checking anything is worse than no test.
func readReadmeScores(t *testing.T) map[string]int {
	t.Helper()
	b, err := os.ReadFile("../README.md")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(b), "\n")

	start := -1
	for i, l := range lines {
		if strings.Contains(l, "| Configuration | Sandbox | This lab |") {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatal("no sandbox-versus-lab comparison table in lab/README.md — if it has been " +
			"renamed, this test needs to follow it rather than be deleted")
	}

	out := map[string]int{}
	for _, l := range lines[start+1:] {
		if !strings.HasPrefix(strings.TrimSpace(l), "|") {
			break
		}
		m := readmeRow.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			continue // the |---|---| separator row
		}
		lab, err := strconv.Atoi(m[4])
		if err != nil {
			t.Fatalf("could not read the lab score out of %q", l)
		}
		if total := m[5]; total != "11" {
			t.Errorf("the table publishes a score out of %s, and there are eleven checks", total)
		}
		out[strings.Trim(m[1], "`")] = lab
	}
	if len(out) == 0 {
		t.Fatal("found the table and read no rows out of it, so this test proves nothing")
	}
	return out
}

// The three endings that are different claims, and are easy to collapse into
// one another. Each is asserted on its tone as well as its wording, because the
// tone is what colours the banner and a green banner over a lock-out is the
// single most dangerous thing this page could print.
func TestScoreAuditVerdicts(t *testing.T) {
	t.Run("everything held", func(t *testing.T) {
		// scored[3] is `hardened`, which since Headscale 0.29 is a real
		// eleven-out-of-eleven rather than a fixture invented to reach one.
		rep := scoreAudit(scored[3].checks())
		if rep.Tone != "ok" || rep.Passed != 11 {
			t.Fatalf("tone %q, %d passed: %s", rep.Tone, rep.Passed, rep.Verdict)
		}
		if !strings.Contains(rep.Verdict, "All 11 held") {
			t.Fatalf("verdict: %s", rep.Verdict)
		}
	})

	t.Run("only a stuck failure is left", func(t *testing.T) {
		// No configuration produces this on 0.29 — expiry is stuck passing
		// now, not stuck failing. It is asserted from a fixture because the
		// branch is the general one ("every failure left is one this lab
		// decided"), and the next gap of that shape should not have to
		// rediscover that the good-news ending exists.
		one := outcome{passed: allElevenIndicesExcept(ckExpiry), stuck: []int{ckExpiry}}
		rep := scoreAudit(one.checks())
		if rep.Stuck != 1 || rep.Passed != 10 {
			t.Fatalf("%d of %d, stuck %d", rep.Passed, rep.Total, rep.Stuck)
		}
		// Good news, and it has to read as good news: everything the reader
		// controls is closed, and the remainder is not theirs to close.
		if rep.Tone != "ok" {
			t.Fatalf("a run whose only failure is one this lab decided is not a warning: %q — %s",
				rep.Tone, rep.Verdict)
		}
		for _, want := range []string{"cannot pass in this lab at all", "Everything you can"} {
			if !strings.Contains(rep.Verdict, want) {
				t.Errorf("verdict should say %q: %s", want, rep.Verdict)
			}
		}
		// And it must not be excused away in the note as well — that sentence
		// is for the case where real failures sit alongside it.
		if strings.HasPrefix(rep.Note, "One of the failures below cannot pass") {
			t.Error("the verdict already said it; the note is for the mixed case")
		}
	})

	t.Run("a stuck failure alongside real ones", func(t *testing.T) {
		mixed := outcome{
			passed: []int{
				ckYouCanGetIn, ckRoamCanGetIn,
				ckStrangerPublishedPort,
				ckUntrustedToServer, ckUntrustedToLaptop,
				ckNoPasswords, ckNoRootLogin,
			},
			stuck: []int{ckExpiry},
		}
		rep := scoreAudit(mixed.checks())
		if rep.Stuck != 1 || rep.Passed != 7 {
			t.Fatalf("%d of %d, stuck %d", rep.Passed, rep.Total, rep.Stuck)
		}
		if rep.Tone == "ok" {
			t.Fatalf("four failures, three of them real, is not an ok: %s", rep.Verdict)
		}
		if !strings.HasPrefix(rep.Note, "One of the failures below cannot pass") {
			t.Errorf("the reader has to be told which failure is not their fault, without "+
				"the others being excused with it: %s", rep.Note)
		}
	})

	// Both marks at once. Nothing produces this today — there is one stuck
	// check and it passes — but the note builds itself from two independent
	// warnings, and the failure mode of choosing between them is silence about
	// the flattering one, which is the harder of the two to notice missing.
	t.Run("both marks are declared, not one of them", func(t *testing.T) {
		both := outcome{
			passed: []int{
				ckYouCanGetIn, ckRoamCanGetIn,
				ckStrangerPublishedPort,
				ckUntrustedToServer, ckUntrustedToLaptop,
				ckNoPasswords, ckExpiry,
			},
			stuck: []int{ckExpiry, ckNoRootLogin},
		}
		rep := scoreAudit(both.checks())
		if rep.Stuck != 2 {
			t.Fatalf("two checks are marked and the report counts %d", rep.Stuck)
		}
		for _, want := range []string{"cannot pass in this lab at all", "whatever you set"} {
			if !strings.Contains(rep.Note, want) {
				t.Errorf("both marks have to reach the reader, and %q did not: %s",
					want, rep.Note)
			}
		}
	})

	// The direction this lab is actually in since Headscale 0.29, and the more
	// dangerous of the two: a green tick nothing the reader did produced. The
	// note has to say so, or three of the five configurations quietly claim a
	// point the sandbox does not give them.
	t.Run("a stuck pass is declared", func(t *testing.T) {
		rep := scoreAudit(scored[0].checks()) // day-one: 5 of 11, one of them Headscale's
		if rep.Stuck != 1 || rep.Passed != 5 {
			t.Fatalf("%d of %d, stuck %d", rep.Passed, rep.Total, rep.Stuck)
		}
		for _, want := range []string{"whatever you set", "sandbox"} {
			if !strings.Contains(rep.Note, want) {
				t.Errorf("a pass the configuration did not earn has to be named, and the "+
					"note should say %q: %s", want, rep.Note)
			}
		}
	})

	t.Run("locked out", func(t *testing.T) {
		// Everything an attacker tried was refused and the owner cannot get
		// in. This is the score people mistake for success, and it is the
		// reason two of the eleven exist at all.
		lockedOut := outcome{passed: []int{
			ckStrangerSSH, ckStrangerPublishedPort, ckStolenKey,
			ckUntrustedToServer, ckUntrustedToLaptop,
			ckNoPasswords, ckNoRootLogin, ckExpiry, ckSSHDNotPublic,
		}}
		rep := scoreAudit(lockedOut.checks())
		if !rep.LockedOut {
			t.Fatal("both access checks failed and the report does not say so")
		}
		if rep.Tone != "bad" {
			t.Fatalf("9 of 11 with no way in is the worst outcome on this page, not a "+
				"warning: tone %q", rep.Tone)
		}
		if !strings.Contains(rep.Verdict, "the score is meaningless") {
			t.Fatalf("verdict: %s", rep.Verdict)
		}

		// One of the two is enough. The roaming client is the machine the
		// whole guide exists for, and losing only that one still counts.
		onlyRoam := outcome{passed: append([]int{ckYouCanGetIn}, lockedOut.passed...)}
		if rep := scoreAudit(onlyRoam.checks()); !rep.LockedOut || rep.Tone != "bad" {
			t.Fatalf("losing the roaming client is a lock-out too: locked %v, tone %q",
				rep.LockedOut, rep.Tone)
		}
	})
}

// The mark changes the prose and never the arithmetic. That is a deliberate
// choice and the kind that gets quietly reversed by somebody trying to make a
// number look better or worse, so it is written down: a run with a stuck check
// scores exactly the same as the same run without the mark, in both
// directions, and only what is said about it differs.
func TestTheMarkNeverMovesTheScore(t *testing.T) {
	t.Run("a stuck pass still earns its point", func(t *testing.T) {
		marked := scored[0] // day-one, whose expiry pass is Headscale's
		unmarked := outcome{name: marked.name, passed: marked.passed}

		a, b := scoreAudit(marked.checks()), scoreAudit(unmarked.checks())
		if a.Passed != b.Passed || a.Total != b.Total {
			t.Fatalf("marking a pass as this lab's moved the score: %d/%d vs %d/%d",
				a.Passed, a.Total, b.Passed, b.Total)
		}
		if a.Stuck == b.Stuck {
			t.Fatal("the mark has to be visible somewhere, or a reader trusts a tick " +
				"nothing they did produced")
		}
		if a.Note == b.Note {
			t.Fatal("the two say the same thing, and they are different findings")
		}
	})

	t.Run("a stuck failure still costs one", func(t *testing.T) {
		marked := outcome{passed: allElevenIndicesExcept(ckExpiry), stuck: []int{ckExpiry}}
		unmarked := outcome{passed: marked.passed}

		a, b := scoreAudit(marked.checks()), scoreAudit(unmarked.checks())
		if a.Passed != b.Passed || a.Total != b.Total {
			t.Fatalf("marking a failure as this lab's moved the score: %d/%d vs %d/%d",
				a.Passed, a.Total, b.Passed, b.Total)
		}
		if a.Verdict == b.Verdict {
			t.Fatal("the two say the same thing, and they are different findings")
		}
	})
}

// An audit that never ran is not a score of nought. Nothing on this page should
// read as a verdict on a configuration nobody measured.
func TestScoreAuditWithNothingMeasured(t *testing.T) {
	rep := scoreAudit(nil)
	if rep.Total != 0 || rep.Passed != 0 {
		t.Fatalf("%d of %d", rep.Passed, rep.Total)
	}
	if rep.LockedOut {
		t.Fatal("no access check failed, because no access check ran")
	}
}

// ---------------------------------------------------------------------------
// Check 10 — the one this lab answers for you
// ---------------------------------------------------------------------------

// Real output from `headscale nodes list -o json` in this lab: a pre-auth-key
// registration, which is every registration this lab makes. Since 0.29 those
// carry the expiry `node.expiry` asks for; before it they carried none, and
// the check could not pass at all. The wire format is a protobuf timestamp —
// an object, not the string the human-readable table prints — and decoding it
// as a string is a quiet way to break the whole control server.
func node(name string, exp *hsTime) hsNode {
	return hsNode{Name: name, GivenName: name, Expiry: exp}
}

func TestExpiryVerdict(t *testing.T) {
	now := time.Unix(1787800000, 0)
	future := &hsTime{Seconds: now.Add(180 * 24 * time.Hour).Unix()}
	past := &hsTime{Seconds: now.Add(-time.Hour).Unix()}

	t.Run("no expiry at all is a lab that needs fixing", func(t *testing.T) {
		// What Headscale returned before 0.29, on every registration. With
		// `node.expiry` set in config/headscale/config.yaml it should not
		// happen any more, so it is no longer this lab's answer to give: it
		// means the image was rolled back, the key was tagged, or the config
		// key was dropped, and the prose has to send the reader at the lab
		// rather than at their own switches.
		ok, rule, stuck := expiryVerdict([]hsNode{
			node("lab-ubuntu", nil), node("lab-roam", nil), node("lab-vps", nil),
		}, now)
		if ok || stuck {
			t.Fatalf("ok %v, stuck %v — %s", ok, stuck, rule)
		}
		if !strings.Contains(rule, "node.expiry") {
			t.Errorf("the prose has to name the config key that should have set one: %s", rule)
		}
	})

	t.Run("an expiry that has passed is an ordinary failure", func(t *testing.T) {
		// A machine that dropped out and was never reauthenticated — which is
		// what the "Let a key expire" button produces. This one IS the
		// reader's problem, and marking it as this lab's would excuse a real
		// finding.
		ok, rule, stuck := expiryVerdict([]hsNode{
			node("lab-ubuntu", future), node("lab-roam", past), node("lab-vps", future),
		}, now)
		if ok {
			t.Fatalf("an expired member is not a member: %s", rule)
		}
		if stuck {
			t.Fatalf("this is a real state somebody produced, not one this lab decided: %s", rule)
		}
		if !strings.Contains(rule, "lab-roam") {
			t.Errorf("it should name the machine: %s", rule)
		}
	})

	t.Run("every machine you own carries a real one", func(t *testing.T) {
		// The only answer any of the four configurations produces on 0.29, and
		// it has to be marked as this lab's rather than the reader's: three of
		// the four ask for expiry to be off, Headscale has no switch for that,
		// and the sandbox scores them a point lower for it.
		ok, rule, stuck := expiryVerdict([]hsNode{
			node("lab-ubuntu", future), node("lab-roam", future), node("lab-vps", future),
		}, now)
		if !ok || !stuck {
			t.Fatalf("ok %v, stuck %v — %s", ok, stuck, rule)
		}
		if !strings.Contains(rule, "whatever the configuration says") {
			t.Errorf("a pass nothing the reader did produced has to say so: %s", rule)
		}
	})

	t.Run("the attacker does not get a vote", func(t *testing.T) {
		// evil-box's registration is expired by construction the moment it
		// logs out. Counting it would fail this check for a reason that has
		// nothing to do with the reader's configuration — and, worse, an
		// attacker that never joined would let the check pass on two machines
		// while the third was never looked at.
		ok, rule, _ := expiryVerdict([]hsNode{
			node("lab-ubuntu", future), node("lab-roam", future),
			node("lab-vps", future), node("evil-box", past),
		}, now)
		if !ok {
			t.Fatalf("the hostile machine's expiry is not the reader's problem: %s", rule)
		}
	})

	t.Run("nothing registered at all", func(t *testing.T) {
		for _, ns := range [][]hsNode{nil, {node("evil-box", past)}} {
			ok, rule, stuck := expiryVerdict(ns, now)
			if ok {
				t.Fatalf("no machine of yours was checked, so nothing was proved: %s", rule)
			}
			if stuck {
				t.Fatalf("an empty lab has not decided anything: %s", rule)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// The eleven themselves
// ---------------------------------------------------------------------------

// The lab and the sandbox are meant to be drivable blind, one after the other:
// same eleven, same order, same wording. The sandbox's copy lives in
// assets/sandbox.js, and the two have drifted apart before.
func TestTheElevenMatchTheSandbox(t *testing.T) {
	b, err := os.ReadFile("../../assets/sandbox.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	_, rest, ok := strings.Cut(src, "var AUDIT = [")
	if !ok {
		t.Fatal("no AUDIT table in assets/sandbox.js — if it has been renamed, this test " +
			"needs to follow it")
	}
	body, _, ok := strings.Cut(rest, "\n  ];")
	if !ok {
		t.Fatal("the AUDIT table has no closing bracket where this test expects one")
	}

	labels := regexp.MustCompile(`label: "([^"]*)"`).FindAllStringSubmatch(body, -1)
	if len(labels) != auditCheckCount {
		t.Fatalf("the sandbox asks %d questions and this lab asks %d. If a check has "+
			"genuinely been added or dropped, it belongs in both halves — a score that "+
			"is out of a different number cannot be compared with anything.",
			len(labels), auditCheckCount)
	}
	for i, m := range labels {
		if got := auditPlan[i].Label; got != m[1] {
			t.Errorf("check %d: this lab asks %q and the sandbox asks %q, in that position",
				i+1, got, m[1])
		}
	}
}

// Two of the eleven ask whether you can still get in, and they are not padding:
// without them a machine you have locked yourself out of scores nearly
// perfectly and "closed" reads as "secure". Asserted here rather than trusted,
// because they are also the two an optimiser would drop first.
func TestTwoOfTheElevenAskWhetherYouCanStillGetIn(t *testing.T) {
	access := 0
	for _, ch := range auditPlan {
		if ch.Kind == "access" {
			access++
			if !ch.Want {
				t.Errorf("%q is an access check that wants to fail", ch.Label)
			}
		}
		if ch.Label == "" || ch.Why == "" || ch.Fail == "" {
			t.Errorf("%q is missing the prose that makes a score an explanation", ch.Label)
		}
		if _, ok := AuditGroups[ch.Kind]; !ok {
			t.Errorf("%q is kind %q, which the page has no heading for", ch.Label, ch.Kind)
		}
	}
	if access != 2 {
		t.Fatalf("%d of the eleven ask whether you can still get in, and the README, the "+
			"page and audit.go's own comment all say two", access)
	}

	// A configuration that refuses everybody, including you, and the number
	// that would print if nobody had thought to ask.
	if got := scoreAudit(outcome{passed: allElevenIndices()}.checks()); got.LockedOut {
		t.Fatal("everything held, so nobody is locked out")
	}
}

func allElevenIndices() []int {
	out := make([]int, auditCheckCount)
	for i := range out {
		out[i] = i
	}
	return out
}

// allElevenIndicesExcept is the answer sheet for "everything held except one",
// which is how a run reads when the only thing left is something this lab
// decided rather than something the reader left open.
func allElevenIndicesExcept(skip int) []int {
	out := make([]int, 0, auditCheckCount-1)
	for i := 0; i < auditCheckCount; i++ {
		if i != skip {
			out = append(out, i)
		}
	}
	return out
}
