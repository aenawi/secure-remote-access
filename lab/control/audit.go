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
	Tone      string  `json:"tone"`
	Verdict   string  `json:"verdict"`
	Note      string  `json:"note,omitempty"`
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
	add(Check{Kind: "access", Want: true, Label: "You can still get in",
		Why: "The laptop reaches sshd over the tailnet.",
		Fail: "You cannot reach your own server. A configuration that locks you out is not " +
			"secure, it is broken — and this is the failure people mistake for success."},
		got, rung, rule, m)

	got, rung, rule, m = probe("lab-roam", "lab-vps", "22")
	add(Check{Kind: "access", Want: true, Label: "…and so can the roaming client",
		Why:  "The phone's stand-in reaches it too.",
		Fail: "The roaming client is locked out, which is the one machine the whole guide exists for."},
		got, rung, rule, m)

	// ---- 2 · a stranger --------------------------------------------------
	offTailnet()
	got, rung, rule, m = probe("evil-box", "lab-vps", "22")
	add(Check{Kind: "attack", Want: false, Label: "A stranger cannot reach SSH",
		Why:  "The public address does not answer on :22.",
		Fail: "Anyone on the internet can knock on your SSH port. They already are."},
		got, rung, rule, m)

	got, rung, rule, m = probe("evil-box", "lab-vps", "8080")
	add(Check{Kind: "attack", Want: false, Label: "…nor a published container port",
		Why: "Nothing is exposed on :8080.",
		Fail: "A container's published port answers from the internet — through UFW, because " +
			"Docker's chain is consulted first. UFW will still tell you it is denied."},
		got, rung, rule, m)

	// ---- 3 · a key nobody vouched for ------------------------------------
	c.with(func(s *State) { s.ACL.Lock = lockWasOn })
	joined := c.evilJoin(ctx, true)
	stolenWorked := false
	if joined.OK {
		c.EnsureTags(ctx)
		time.Sleep(1500 * time.Millisecond)
		stolenWorked, rung, rule, m = probe("evil-box", "lab-vps", "22")
	} else {
		rung, rule, m = 1, joined.Rule, strings.Join(joined.Cmds, "\n")
	}
	add(Check{Kind: "attack", Want: false, Label: "A stolen node key is refused",
		Why:  "An unsigned key gets no session from any peer.",
		Fail: "A key lifted from a backup is a working login. Tailnet lock is what stops this."},
		stolenWorked, rung, rule, m)

	// ---- 4 · a member who should not have broad access -------------------
	if onTailnet() {
		got, rung, rule, m = probe("evil-box", "lab-vps", "22")
	} else {
		got, rung, rule, m = false, 1, "it could not be joined at all", ""
	}
	add(Check{Kind: "attack", Want: false, Label: "An untrusted member cannot reach the server",
		Why: "It is on the tailnet and the policy still refuses it.",
		Fail: "Being on the tailnet was enough to reach the server. Membership is not " +
			"authorisation unless the policy says so."},
		got, rung, rule, m)

	got, rung, rule, m = probe("evil-box", "lab-ubuntu", "22")
	add(Check{Kind: "attack", Want: false, Label: "…nor your laptop",
		Why:  "The policy protects the clients too, not just the server.",
		Fail: "One hostile member reaches your laptop. A flat tailnet is a flat network."},
		got, rung, rule, m)

	// ---- 5 · the machine itself ------------------------------------------
	c.observeVPS(ctx)
	v := c.Snapshot().VPS

	add(Check{Kind: "config", Want: false, Label: "Passwords cannot be used to log in",
		Why: "PasswordAuthentication is off.",
		Fail: "Password login is enabled. That is precisely what the scanners are trying, " +
			"thousands of times a day."},
		v.PasswordAuth, 5, "sshd -T | grep passwordauthentication",
		"docker exec lab-vps sshd -T | grep -i passwordauthentication")

	add(Check{Kind: "config", Want: false, Label: "Root cannot log in directly",
		Why:  "PermitRootLogin is off.",
		Fail: "Root can log in over the network, so one credential is the whole machine."},
		v.PermitRoot, 5, "sshd -T | grep permitrootlogin",
		"docker exec lab-vps sshd -T | grep -i permitrootlogin")

	expiry, expiryRule := c.expiryHonoured(ctx)
	add(Check{Kind: "config", Want: true, Label: "A lost device stops being a member on its own",
		Why: "Key expiry is on, so an unattended device drops out.",
		Fail: "Key expiry is off. The phone you left in a taxi is a member forever, or until " +
			"you remember to remove it."},
		expiry, 1, expiryRule, "headscale nodes list -o json | jq '.[].expiry'")

	exposed := v.SSHDListen == "tailnet" || !v.AllowPublic22
	add(Check{Kind: "config", Want: true, Label: "sshd is not exposed on the public interface",
		Why: "Bound to the tailnet address, or the public rule is gone.",
		Fail: "sshd is listening on 0.0.0.0 with the public rule still in place — the exact " +
			"state chapter 08 is written to get you out of."},
		exposed, 5, "ss -tlnp ; ufw status", "docker exec lab-vps ss -tlnp")

	// ---- the score -------------------------------------------------------
	rep.Total = len(rep.Checks)
	for _, ch := range rep.Checks {
		if ch.Pass {
			rep.Passed++
		}
		if ch.Kind == "access" && !ch.Pass {
			rep.LockedOut = true
		}
	}
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
	return rep
}

// expiryHonoured reads the real expiry the coordination server holds for each
// node, rather than a switch somebody set. Headscale has no per-node "disable
// key expiry", so this check can only ever observe — see setExpiry.
func (c *Controller) expiryHonoured(ctx context.Context) (bool, string) {
	ns, err := c.nodes(ctx)
	if err != nil || len(ns) == 0 {
		return false, "the coordination server listed no nodes"
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
			return false, n.GivenName + " has no expiry at all, so it is a member until " +
				"somebody remembers to remove it. Headscale records an expiry only when the " +
				"registration asked for one — see \"Where the lab and the sandbox disagree\" " +
				"in lab/README.md"
		}
		if exp.Before(time.Now()) {
			return false, n.GivenName + " expired at " + exp.Format(time.RFC3339) +
				" and has not been reauthenticated"
		}
	}
	if seen == 0 {
		return false, "none of your three machines are registered"
	}
	return true, "every machine you own carries a real expiry in the future"
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
