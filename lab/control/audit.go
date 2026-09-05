// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hashem Aldhaheri

package main

import (
	"context"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// The audit
//
// The same eleven checks as the sandbox page, in the same order, with the same
// labels and the same rubric. The only thing that changed is run(): there it
// asks a model, here it asks a container.
//
// Two of the eleven ask whether *you* can still get in. They are not padding.
// Without them a machine you have locked yourself out of scores nearly
// perfectly, and "closed" would read as "secure".
//
// If this lab ever scores a configuration differently from the sandbox, do not
// quietly reconcile them. That gap is the most valuable thing this pair can
// produce: it means the model is wrong about something real.
// ---------------------------------------------------------------------------

type Check struct {
	Kind  string `json:"kind"` // access | attack | config
	Want  bool   `json:"want"`
	Label string `json:"label"`
	Why   string `json:"why"`
	Fail  string `json:"fail"`

	Got     bool   `json:"got"`
	Pass    bool   `json:"pass"`
	Rung    int    `json:"rung,omitempty"`
	Rule    string `json:"rule,omitempty"`
	Measure string `json:"measure,omitempty"`

	// Stuck marks a check this lab answers for you: the stack underneath does
	// not expose the thing the configuration is supposed to change, so no
	// arrangement of the switches moves it. It runs in both directions and
	// both of them are dishonest in a different way. A stuck *failure* takes a
	// point the reader did not deserve to lose, and leaves them hunting for a
	// switch that does not exist — that was this lab up to Headscale 0.26,
	// when a pre-auth-key registration recorded no expiry at all. A stuck
	// *pass* hands them one they did not earn, which is the worse of the two
	// and is where this lab is now: 0.29's `node.expiry` records one on every
	// registration and there is still no per-node way to turn it off.
	//
	// It changes no arithmetic. A stuck check scores exactly as any other,
	// because a number that argues with what was measured is worth nothing;
	// the mark exists so the prose can say which of the two it is.
	Stuck bool `json:"stuck,omitempty"`
}

var AuditGroups = map[string]string{
	"access": "Can you still do your job?",
	"attack": "Does it hold against someone hostile?",
	"config": "Is the machine itself sensibly set up?",
}

type AuditReport struct {
	Checks    []Check `json:"checks"`
	Total     int     `json:"total"`
	Passed    int     `json:"passed"`
	LockedOut bool    `json:"lockedOut"`
	Stuck     int     `json:"stuck,omitempty"` // answers this lab gave, not your configuration
	Tone      string  `json:"tone"`
	Verdict   string  `json:"verdict"`
	Note      string  `json:"note,omitempty"`
}

// ---------------------------------------------------------------------------
// The eleven
//
// One ordered table rather than eleven literals buried in Audit, for two
// reasons. The order is the order the sandbox asks them in and a reader is
// meant to be able to lay the two lists side by side; and a test can only score
// a checked-in fixture — the five numbers in lab/README.md's comparison table —
// if it can build the eleven without a running lab underneath it.
//
// Audit fills in Got, Pass, Rung, Rule and Measure. Everything here is the
// question, not the answer.
// ---------------------------------------------------------------------------

const (
	ckYouCanGetIn = iota
	ckRoamCanGetIn
	ckStrangerSSH
	ckStrangerPublishedPort
	ckStolenKey
	ckUntrustedToServer
	ckUntrustedToLaptop
	ckNoPasswords
	ckNoRootLogin
	ckExpiry
	ckSSHDNotPublic
	auditCheckCount
)

var auditPlan = [auditCheckCount]Check{
	ckYouCanGetIn: {Kind: "access", Want: true, Label: "You can still get in",
		Why: "The laptop reaches sshd over the tailnet.",
		Fail: "You cannot reach your own server. A configuration that locks you out is not " +
			"secure, it is broken — and this is the failure people mistake for success."},

	ckRoamCanGetIn: {Kind: "access", Want: true, Label: "…and so can the roaming client",
		Why:  "The phone's stand-in reaches it too.",
		Fail: "The roaming client is locked out, which is the one machine the whole guide exists for."},

	ckStrangerSSH: {Kind: "attack", Want: false, Label: "A stranger cannot reach SSH",
		Why:  "The public address does not answer on :22.",
		Fail: "Anyone on the internet can knock on your SSH port. They already are."},

	ckStrangerPublishedPort: {Kind: "attack", Want: false, Label: "…nor a published container port",
		Why: "Nothing is exposed on :8080.",
		Fail: "A container's published port answers from the internet — through UFW, because " +
			"Docker's chain is consulted first. UFW will still tell you it is denied."},

	ckStolenKey: {Kind: "attack", Want: false, Label: "A stolen node key is refused",
		Why: "An unsigned key gets no tailnet session — and no other route answers either.",
		Fail: "A machine holding a key nobody vouched for still reaches sshd. Tailnet lock " +
			"keeps it off the tailnet; only a closed public :22 keeps it off the machine."},

	ckUntrustedToServer: {Kind: "attack", Want: false, Label: "An untrusted member cannot reach the server",
		Why: "It is on the tailnet and the policy still refuses it.",
		Fail: "Being on the tailnet was enough to reach the server. Membership is not " +
			"authorisation unless the policy says so."},

	ckUntrustedToLaptop: {Kind: "attack", Want: false, Label: "…nor your laptop",
		Why:  "The policy protects the clients too, not just the server.",
		Fail: "One hostile member reaches your laptop. A flat tailnet is a flat network."},

	ckNoPasswords: {Kind: "config", Want: false, Label: "Passwords cannot be used to log in",
		Why: "PasswordAuthentication is off.",
		Fail: "Password login is enabled. That is precisely what the scanners are trying, " +
			"thousands of times a day."},

	ckNoRootLogin: {Kind: "config", Want: false, Label: "Root cannot log in directly",
		Why:  "PermitRootLogin is off.",
		Fail: "Root can log in over the network, so one credential is the whole machine."},

	ckExpiry: {Kind: "config", Want: true,
		Label: "A lost device stops being a member on its own",
		Why:   "Key expiry is on, so an unattended device drops out.",
		Fail: "Key expiry is off. The phone you left in a taxi is a member forever, or until " +
			"you remember to remove it."},

	ckSSHDNotPublic: {Kind: "config", Want: true, Label: "sshd is not exposed on the public interface",
		Why: "Bound to the tailnet address, or the public rule is gone.",
		Fail: "sshd is listening on 0.0.0.0 with the public rule still in place — the exact " +
			"state chapter 08 is written to get you out of."},
}

// Audit runs all eleven against the stack as it stands.
func (c *Controller) Audit(ctx context.Context) AuditReport {
	c.loadDesired()
	rep := AuditReport{}

	// Checks 3 to 7 need somewhere hostile to fire from. Without it the score
	// is not comparable to anything, so say so rather than scoring five checks
	// out of thin air.
	if !c.lab.Running(ctx, "evil-box") {
		if r := c.needEvil(ctx); r != nil {
			rep.Tone = "warn"
			rep.Verdict = "Five of the eleven checks fire an attacker at this stack, and there " +
				"is no attacker in it. Start one with `make attack` (or " +
				"`docker compose --profile attack up -d`) and run the audit again — a " +
				"score with five holes in it cannot be compared with the sandbox's."
			return rep
		}
	}

	// Remember what the attacker was doing, and put it back afterwards.
	before := c.Snapshot()
	evilWasOn := before.Machines["evil-box"].OnTailnet
	lockWasOn := before.ACL.Lock
	defer func() {
		// Put the shared file back before anything reads it again: the checks
		// below deliberately turn "tailnet lock" off to test the one after it,
		// and that must not survive the audit.
		c.with(func(s *State) { s.ACL.Lock = lockWasOn })
		c.saveDesired()
		if !evilWasOn {
			_, _ = c.lab.Exec(ctx, "evil-box", "tailscale", "logout")
		}
		c.Observe(ctx)
	}()

	probe := func(from, to, port string) (bool, int, string, string) {
		p := c.Probe(ctx, from, to, port)
		return p.OK, p.Rung, p.Rule, strings.Join(p.Cmds, "\n")
	}

	offTailnet := func() {
		_, _ = c.lab.Exec(ctx, "evil-box", "tailscale", "logout")
		time.Sleep(1500 * time.Millisecond)
	}
	onTailnet := func() bool {
		c.with(func(s *State) { s.ACL.Lock = false })
		r := c.evilJoin(ctx, true)
		if r.OK {
			c.EnsureTags(ctx)
			time.Sleep(1500 * time.Millisecond)
		}
		return r.OK
	}

	add := func(ch Check, got bool, rung int, rule, measure string) {
		ch.Got = got
		ch.Pass = got == ch.Want
		ch.Rung, ch.Rule, ch.Measure = rung, rule, measure
		rep.Checks = append(rep.Checks, ch)
	}

	// ---- 1 · you ---------------------------------------------------------
	got, rung, rule, m := probe("lab-ubuntu", "lab-vps", "22")
	add(auditPlan[ckYouCanGetIn], got, rung, rule, m)

	got, rung, rule, m = probe("lab-roam", "lab-vps", "22")
	add(auditPlan[ckRoamCanGetIn], got, rung, rule, m)

	// ---- 2 · a stranger --------------------------------------------------
	offTailnet()
	got, rung, rule, m = probe("evil-box", "lab-vps", "22")
	add(auditPlan[ckStrangerSSH], got, rung, rule, m)

	got, rung, rule, m = probe("evil-box", "lab-vps", "8080")
	add(auditPlan[ckStrangerPublishedPort], got, rung, rule, m)

	// ---- 3 · a key nobody vouched for ------------------------------------
	//
	// Whether the coordination server issued the key is not the question. The
	// question is whether its holder reaches sshd — and a machine the tailnet
	// refused is an ordinary machine on the internet, which is the host
	// firewall's problem rather than the tailnet's. So probe either way.
	//
	// This used to stop at the failed join and report "refused at rung 1",
	// which let tailnet lock take credit for a public :22 that UFW had left
	// wide open. The sandbox had the same bug; lab/README.md 5 has the story.
	c.with(func(s *State) { s.ACL.Lock = lockWasOn })
	joined := c.evilJoin(ctx, true)
	if joined.OK {
		c.EnsureTags(ctx)
		time.Sleep(1500 * time.Millisecond)
	}
	stolenWorked, rung, rule, m := probe("evil-box", "lab-vps", "22")
	if !joined.OK {
		// Say both halves out loud: the key was refused, and here is what the
		// ordinary network gave its holder anyway.
		rule = joined.Rule + " — then, with no tailnet session: " + rule
		m = strings.Join(joined.Cmds, "\n") + "\n" + m
	}
	add(auditPlan[ckStolenKey], stolenWorked, rung, rule, m)

	// ---- 4 · a member who should not have broad access -------------------
	if onTailnet() {
		got, rung, rule, m = probe("evil-box", "lab-vps", "22")
	} else {
		got, rung, rule, m = false, 1, "it could not be joined at all", ""
	}
	add(auditPlan[ckUntrustedToServer], got, rung, rule, m)

	got, rung, rule, m = probe("evil-box", "lab-ubuntu", "22")
	add(auditPlan[ckUntrustedToLaptop], got, rung, rule, m)

	// ---- 5 · the machine itself ------------------------------------------
	c.observeVPS(ctx)
	v := c.Snapshot().VPS

	add(auditPlan[ckNoPasswords],
		v.PasswordAuth, 5, "sshd -T | grep passwordauthentication",
		"docker exec lab-vps sshd -T | grep -i passwordauthentication")

	add(auditPlan[ckNoRootLogin],
		v.PermitRoot, 5, "sshd -T | grep permitrootlogin",
		"docker exec lab-vps sshd -T | grep -i permitrootlogin")

	expiry, expiryRule, expiryStuck := c.expiryHonoured(ctx)
	expiryCheck := auditPlan[ckExpiry]
	expiryCheck.Stuck = expiryStuck
	add(expiryCheck, expiry, 1, expiryRule, "headscale nodes list -o json | jq '.[].expiry'")

	exposed := v.SSHDListen == "tailnet" || !v.AllowPublic22
	add(auditPlan[ckSSHDNotPublic],
		exposed, 5, "ss -tlnp ; ufw status", "docker exec lab-vps ss -tlnp")

	// ---- the score -------------------------------------------------------
	return scoreAudit(rep.Checks)
}

// scoreAudit is the arithmetic and the verdict, over eleven checks that have
// already been answered. It is split out from Audit for one reason: Audit needs
// containers and this does not, so the number the README publishes — and the
// sentence printed above it — can be asserted from a fixture rather than from a
// running lab. The five scores in the sandbox-versus-lab table are decided
// here, and they should not be able to move quietly.
//
// Three of the endings are easy to get wrong and each one is a different claim:
// a locked-out machine scores whatever it scores and the score is meaningless;
// a run where every remaining failure is one this lab decided is "everything
// you control is closed", which is good news; and one of those alongside real
// failures is neither, so the note has to name it without excusing the rest.
// A fourth, quieter one: a check this lab decided in the reader's *favour*
// still has to be declared, or a tick nothing they did produced reads as one
// they earned.
func scoreAudit(checks []Check) AuditReport {
	rep := AuditReport{Checks: checks}
	rep.Total = len(rep.Checks)
	stuckFails := 0
	for _, ch := range rep.Checks {
		if ch.Pass {
			rep.Passed++
		}
		if ch.Kind == "access" && !ch.Pass {
			rep.LockedOut = true
		}
		if ch.Stuck {
			rep.Stuck++
			if !ch.Pass {
				stuckFails++
			}
		}
	}
	failed := rep.Total - rep.Passed

	switch {
	case rep.LockedOut:
		rep.Tone = "bad"
		rep.Verdict = plur(rep.Passed, rep.Total) + " held — but you are locked out of your " +
			"own server, so the score is meaningless. Closed is not the same as secure."
	case rep.Passed == rep.Total:
		rep.Tone = "ok"
		rep.Verdict = "All " + itoa(rep.Total) + " held. Everything the attacker was allowed " +
			"to try was refused, and you can still work. This is the configuration the " +
			"guide builds towards — measured on real kernels, not modelled."

	// Everything that can be closed is closed, and the only thing left is
	// something this stack cannot do. Say that plainly instead of leaving the
	// reader to hunt for a switch that does not exist.
	case failed > 0 && failed == stuckFails:
		rep.Tone = "ok"
		rep.Verdict = plur(rep.Passed, rep.Total) + " held, and the " +
			map[bool]string{true: "one", false: "ones"}[failed == 1] +
			" that did not cannot pass in this lab at all. Everything you can " +
			"control is closed. The remainder is a gap in the stack underneath, not in " +
			"your configuration — read it below, then read the same eleven in the " +
			"sandbox, where it does pass."

	case rep.Passed >= rep.Total-3:
		rep.Tone = "warn"
		rep.Verdict = plur(rep.Passed, rep.Total) + " held. Each failure below names what it costs you."
	default:
		rep.Tone = "bad"
		rep.Verdict = plur(rep.Passed, rep.Total) + " held. Each failure below names what it costs you."
	}
	rep.Note = "Run the same eleven in the sandbox on chapter 14 with the same configuration " +
		"loaded. If the two scores disagree, the model is wrong about something real, and " +
		"that is worth an issue."
	// The two marks are different warnings and a run can carry both, so each
	// is prepended on its own terms rather than chosen between. Choosing would
	// mean a check decided in the reader's favour going unannounced because an
	// unrelated one was decided against them.
	if stuckFails > 0 && failed > stuckFails {
		rep.Note = "One of the failures below cannot pass in this lab at all — it is marked, " +
			"and it is a gap in the stack underneath rather than in your configuration. " +
			rep.Note
	}
	if stuckPasses := rep.Stuck - stuckFails; stuckPasses > 0 {
		// The flattering direction, and the one this lab is in. It goes
		// nearest the reader because it is the one that reads as good news:
		// the sandbox can switch key expiry off and scores three of the four
		// configurations a point lower for it.
		rep.Note = itoa(stuckPasses) + " of the " + itoa(rep.Total) + " below " +
			isAre(stuckPasses) + " marked: this lab answers " +
			map[bool]string{true: "it", false: "them"}[stuckPasses == 1] +
			" for you whatever you set here, so the pass is the stack's and not your " +
			"configuration's. That is the gap to look at first. " + rep.Note
	}
	return rep
}

// expiryHonoured reads the real expiry the coordination server holds for each
// node, rather than a switch somebody set. Headscale has no per-node "disable
// key expiry", so this check can only ever observe — see setExpiry.
//
// The third return says the answer was this lab's rather than the reader's.
// Since 0.29, `node.expiry` in config/headscale/config.yaml records an expiry
// on every pre-auth-key registration, and there is still nothing that turns
// one off, so a pass here is the stack's and not the configuration's — which
// matters, because three of the four configurations ask for expiry to be off
// and get it anyway. Finding 1 in lab/README.md is that gap.
func (c *Controller) expiryHonoured(ctx context.Context) (bool, string, bool) {
	ns, err := c.nodes(ctx)
	if err != nil {
		return false, "the coordination server listed no nodes", false
	}
	return expiryVerdict(ns, time.Now())
}

// expiryVerdict is the deciding half of the check above, over the node list
// headscale already printed. Separate because this is the one of the eleven
// this lab answers for you, and a check nothing can move is exactly the kind
// that stops being read: the difference between "every machine carries one and
// you could not have stopped it" (this lab's answer, and not something you
// did) and "the expiry has passed and nobody reauthenticated" (an ordinary
// failure, and the one the *Let a key expire* button produces) is one line of
// prose and one boolean, and both of them are load-bearing in the score.
func expiryVerdict(ns []hsNode, now time.Time) (bool, string, bool) {
	if len(ns) == 0 {
		return false, "the coordination server listed no nodes", false
	}
	seen := 0
	for _, n := range ns {
		// Only the machines you own. The attacker's registration is expired by
		// construction the moment it logs out, and letting that count would
		// make this check pass for the wrong reason.
		m, ok := machineByID(n.GivenName)
		if !ok || m.Hostile {
			continue
		}
		seen++
		exp := n.Expiry.Time()
		if exp.IsZero() {
			// Up to Headscale 0.26 this was every machine, every time, and
			// nothing could be done about it. From 0.29 it should not happen
			// at all, so it is no longer this lab's answer to give: it means
			// `node.expiry` is missing from config/headscale/config.yaml, the
			// image was rolled back, or the key the machine registered with
			// carried tags — tagged pre-auth keys are exempt from the default.
			return false, n.GivenName + " has no expiry at all, which Headscale 0.29's " +
				"`node.expiry` is meant to record at registration. Check that the setting " +
				"is still in config/headscale/config.yaml, that the image has not been " +
				"rolled back, and that the pre-auth key was created without tags", false
		}
		if exp.Before(now) {
			return false, n.GivenName + " expired at " + exp.Format(time.RFC3339) +
				" and has not been reauthenticated", false
		}
	}
	if seen == 0 {
		return false, "none of your three machines are registered", false
	}
	return true, "every machine you own carries a real expiry in the future — Headscale's " +
		"`node.expiry` set it at registration and offers no per-node way to turn it off, " +
		"so this one holds whatever the configuration says", true
}

// isAre lets a sentence that counts something be written once rather than
// twice. Small, and it earns its place: the alternative is two nearly
// identical strings that drift apart the first time one of them is reworded.
func isAre(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func plur(a, b int) string { return itoa(a) + " of " + itoa(b) + " checks" }
