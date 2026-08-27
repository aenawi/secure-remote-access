// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hashem Aldhaheri

package main

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// The attacks
//
// Same nine buttons as the sandbox page, in the same order, with the same
// labels. The difference is that these run. Every one of them ends by saying
// which defence answered it and at which rung — because "it failed" is not a
// finding, and "it failed at rung 3" is.
//
// All of them require evil-box, and evil-box only exists if you started the lab
// with --profile attack. Nothing here reaches past the lab's own bridges.
// ---------------------------------------------------------------------------

type AttackDef struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Sub    string `json:"sub"`
	Danger bool   `json:"danger,omitempty"`
}

var AttackList = []AttackDef{
	{ID: "scan-public", Label: "Scan from the open internet",
		Sub: "What a stranger sees of lab-vps with no credentials at all"},
	{ID: "scan-tailnet", Label: "Scan from inside the tailnet",
		Sub: "Membership is not authorisation — unless you left it that way"},
	{ID: "sniff", Label: "Sit on the wire and capture",
		Sub: "Real ciphertext, and a marker that never appears in it"},
	{ID: "replay", Label: "Replay a captured frame",
		Sub: "The cheapest attack there is, and what answers it"},
	{ID: "stolen-key", Label: "Join with a stolen node key",
		Sub: "The one tailnet lock exists for"},
	{ID: "expired-key", Label: "Let a key expire",
		Sub: "The lost phone that removes itself"},
	{ID: "rogue-exit", Label: "Advertise a rogue exit node",
		Sub: "Offering to be everybody's default route"},
	{ID: "docker-bypass", Label: "Publish a Docker port",
		Sub: "UFW says deny. The port answers anyway."},
	{ID: "lock-out", Label: "Run the build order wrong", Danger: true,
		Sub: "Close both doors, in the wrong sequence, and be outside"},
}

// Actions is the dispatch table, and it is deliberately a table rather than a
// switch. Two of its entries are not in AttackList — `rotate-key` is
// maintenance and `outage` is the session layer, both of them have their own
// button, and neither is an attack — which for a long time meant that a tool
// asking "which of these has no set-piece yet?" was handed AttackList and
// structurally could not see them. One of them then went a whole release with
// no shot on the board and nothing reported it. So the list of what can be
// dispatched now has one home, ActionIDs serves it to the browser, and the
// gap-reporting walks this instead.
var Actions = map[string]func(*Controller, context.Context) Result{
	"scan-public":   (*Controller).atkScanPublic,
	"scan-tailnet":  (*Controller).atkScanTailnet,
	"sniff":         (*Controller).atkSniff,
	"replay":        (*Controller).atkReplay,
	"stolen-key":    (*Controller).atkStolenKey,
	"expired-key":   (*Controller).atkExpiredKey,
	"rotate-key":    (*Controller).atkRotateKey,
	"outage":        (*Controller).demoOutage,
	"rogue-exit":    (*Controller).atkRogueExit,
	"docker-bypass": (*Controller).atkDockerBypass,
	"lock-out":      (*Controller).atkLockOut,
}

// ActionIDs is every id RunAttack will dispatch, sorted so the browser gets a
// stable list. `reset` is not in here and does not belong here: it is handled
// before RunAttack ever sees it, it produces no Result worth drawing, and its
// button clears the board rather than playing a shot at it.
func ActionIDs() []string {
	ids := make([]string, 0, len(Actions))
	for id := range Actions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (c *Controller) RunAttack(ctx context.Context, id string) Result {
	c.loadDesired()
	if fn, ok := Actions[id]; ok {
		return fn(c, ctx)
	}
	return Result{Why: "no attack called " + id}
}

// needEvil is the one precondition every attack shares.
func (c *Controller) needEvil(ctx context.Context) *Result {
	if c.lab.Running(ctx, "evil-box") {
		return nil
	}
	if c.lab.Exists(ctx, "evil-box") {
		if err := c.lab.Start(ctx, "evil-box"); err == nil {
			time.Sleep(2 * time.Second)
			return nil
		}
	}
	return &Result{
		Rung: 1,
		Rule: "evil-box is not in this stack",
		Why: "The attacker is behind a compose profile and never starts by default. Bring it " +
			"up with `docker compose --profile attack up -d`, or `make attack`.",
	}
}

// ---------------------------------------------------------------------------

func (c *Controller) atkScanPublic(ctx context.Context) Result {
	if r := c.needEvil(ctx); r != nil {
		return *r
	}
	target := c.lab.IPOn(ctx, "lab-vps", "wan")
	portList := strings.Join(scanPorts, ",")
	res := Result{Rung: 4, From: "evil-box", To: "lab-vps", Path: "public",
		Cmds: []string{"nmap -Pn -n -p " + portList + " " + target + "   # on evil-box"}}

	r, _ := c.lab.Exec(ctx, "evil-box", "nmap", "-Pn", "-n", "-p", portList, target)
	res.Raw = r.Out()

	open := parseOpenPorts(r.Stdout)
	// The same finding as Why, in numbers. A drawing that has to regex English
	// to find out which ports answered is one rewording away from lying.
	res.Evidence = scanEvidence(open, scanPorts)
	if len(open) > 0 {
		res.Danger = true
		res.Rule = "the host firewall let them through"
		res.Why = fmt.Sprintf("From the open internet, %d port%s answer: %s. Every one of "+
			"those is reachable by anyone, from anywhere.",
			len(open), plural(len(open)), strings.Join(open, ", "))
	} else {
		res.OK = true
		res.Rule = "ufw default incoming policy: deny"
		res.Why = "Every public port is closed. The only way in now is the tailnet — which is " +
			"the state chapter 08 is trying to get you to."
	}
	return res
}

func (c *Controller) atkScanTailnet(ctx context.Context) Result {
	if r := c.needEvil(ctx); r != nil {
		return *r
	}
	// The defence under test is the policy, so make sure the machine is on the
	// tailnet first — otherwise the lock answers and the lesson lands on the
	// wrong rung.
	if join := c.evilJoin(ctx, true); !join.OK {
		join.Rule = "it never got onto the tailnet: " + join.Rule
		return join
	}
	c.EnsureNodes(ctx)

	res := Result{Rung: 3, From: "evil-box", Path: "direct",
		Cmds: []string{"tailscale status", "nmap -Pn -n -p 22 100.71.4.0/24   # on evil-box"}}

	targets := []string{"lab-vps", "lab-ubuntu", "lab-roam"}
	var reached []string
	var lines []string
	// Which destinations answered, per destination. "one of the three" and
	// "all three" are different findings, and a caller that has only Why to
	// read cannot tell them apart.
	res.Evidence = map[string]int{"tried": len(targets)}
	for _, target := range targets {
		p := c.Probe(ctx, "evil-box", target, "22")
		lines = append(lines, fmt.Sprintf("%-12s rung %d — %s", target, p.Rung, p.Rule))
		res.Evidence["rung:"+target] = p.Rung
		if p.OK {
			reached = append(reached, target)
			res.Evidence["reached:"+target] = 1
		}
	}
	res.Raw = strings.Join(lines, "\n")

	if len(reached) > 0 {
		res.Danger = true
		res.Rule = "the policy allowed it"
		res.Why = "Being inside the tailnet was enough to reach " + strings.Join(reached, ", ") +
			". A flat tailnet is a flat network — the policy is the only thing that makes " +
			"membership mean less than total access."
	} else {
		res.OK = true
		res.Rule = "no grant matched, and the default action is deny"
		res.Why = "It holds a key the tailnet accepts and still reaches nothing. Every attempt " +
			"died before the far machine was involved — that is the policy doing work at a " +
			"rung the host firewalls never even hear about."
	}
	return res
}

// atkSniff is the one attack with a control experiment built in. Capturing
// nothing readable proves very little on its own: it might mean the capture is
// broken. So the lab sends the same marker twice — once in the clear, once
// through the tunnel — and reports both counts. One appears, one does not.
func (c *Controller) atkSniff(ctx context.Context) Result {
	if r := c.needEvil(ctx); r != nil {
		return *r
	}
	res := Result{Rung: 2, From: "evil-box", To: "lab-ubuntu"}

	if on := c.setOnPath(ctx, true); !on.OK {
		on.Rung = 2
		return on
	}
	iface := c.ifaceOn(ctx, "evil-box", c.lab.IPOn(ctx, "evil-box", "lan-ubuntu"))
	vpsWAN := c.lab.IPOn(ctx, "lab-vps", "wan")
	vpsTS := c.tsAddr(ctx, "lab-vps")
	if vpsTS == "" {
		res.Why = "lab-vps has no tailnet address, so there is no tunnelled traffic to capture"
		return res
	}

	res.Cmds = []string{
		fmt.Sprintf("tcpdump -n -i %s -s0 -w /tmp/cap.pcap   # on evil-box", iface),
		fmt.Sprintf("printf LABMARKER-CLEARTEXT | nc -u -w1 %s 9999   # on lab-ubuntu", vpsWAN),
		fmt.Sprintf("printf LABMARKER-TUNNELLED | nc -w1 %s 22   # on lab-ubuntu, inside WireGuard", vpsTS),
		"grep -a -o LABMARKER-… /tmp/cap.pcap | wc -l   # on evil-box",
	}

	_, _ = c.lab.Sh(ctx, "evil-box", fmt.Sprintf(
		"rm -f /tmp/cap.pcap; (timeout 12 tcpdump -n -i %s -s0 -w /tmp/cap.pcap 2>/dev/null &); sleep 1", iface))

	_, _ = c.lab.Sh(ctx, "lab-ubuntu", fmt.Sprintf(
		`printf 'LABMARKER-CLEARTEXT' | nc -u -w1 %s 9999 >/dev/null 2>&1; `+
			`for i in 1 2 3 4 5; do printf 'LABMARKER-TUNNELLED' | nc -w1 %s 22 >/dev/null 2>&1; done; `+
			`ping -c 3 -W 1 %s >/dev/null 2>&1`, vpsWAN, vpsTS, vpsTS))

	time.Sleep(4 * time.Second)
	// grep -a rather than `strings`: binutils is not in this image, and the
	// point of the check is that a byte sequence is or is not on the wire.
	counts, _ := c.lab.Sh(ctx, "evil-box",
		`echo "cleartext=$(grep -a -o LABMARKER-CLEARTEXT /tmp/cap.pcap 2>/dev/null | wc -l)"; `+
			`echo "tunnelled=$(grep -a -o LABMARKER-TUNNELLED /tmp/cap.pcap 2>/dev/null | wc -l)"; `+
			`echo "frames=$(tcpdump -nr /tmp/cap.pcap 2>/dev/null | wc -l)"`)

	hexr, _ := c.lab.Sh(ctx, "evil-box",
		`tcpdump -nr /tmp/cap.pcap -c 1 -X 'udp port 41641' 2>/dev/null | head -8`)
	res.Hex = strings.TrimSpace(hexr.Stdout)

	clear := parseKV(counts.Stdout, "cleartext")
	tunnelled := parseKV(counts.Stdout, "tunnelled")
	frames := parseKV(counts.Stdout, "frames")
	res.Packets = frames
	res.Raw = strings.TrimSpace(counts.Stdout)
	// All three counts, not just the one that fits in Packets. The control
	// experiment is only an experiment if a reader gets both arms of it.
	res.Evidence = map[string]int{"cleartext": clear, "tunnelled": tunnelled, "frames": frames}

	switch {
	case frames == 0:
		res.Why = "The capture came back empty, so this proves nothing either way. Check that " +
			"evil-box really is on lab-ubuntu's segment."
	case clear == 0:
		res.Why = "The control marker did not appear in the clear either, so the capture is " +
			"not seeing this traffic. A clean result here would have been meaningless — " +
			"which is exactly why the lab sends a marker it expects to find."
	case tunnelled == 0:
		res.OK = true
		res.Rule = "WireGuard transport data — sealed for a key evil-box does not have"
		res.Why = fmt.Sprintf("evil-box captured %d frames. The marker sent in the clear "+
			"appears %d time(s). The identical marker sent through the tunnel appears %d "+
			"times. The attacker holds every byte of that session and cannot read one of "+
			"them — and the capture is demonstrably working, because the cleartext one is "+
			"right there.", frames, clear, tunnelled)
	default:
		res.Danger = true
		res.Why = fmt.Sprintf("The tunnelled marker appeared %d time(s) in the capture. That "+
			"should not happen — check whether the traffic really went over the tailnet.", tunnelled)
	}
	return res
}

func (c *Controller) atkReplay(ctx context.Context) Result {
	if r := c.needEvil(ctx); r != nil {
		return *r
	}
	res := Result{Rung: 2, From: "evil-box", To: "lab-vps"}

	if have, _ := c.lab.Sh(ctx, "evil-box", "test -s /tmp/cap.pcap && echo yes || echo no"); !strings.Contains(have.Stdout, "yes") {
		if s := c.atkSniff(ctx); !s.OK {
			s.Why = "nothing captured yet, so there is nothing to replay. " + s.Why
			return s
		}
	}
	iface := c.ifaceOn(ctx, "evil-box", c.lab.IPOn(ctx, "evil-box", "lan-ubuntu"))
	res.Cmds = []string{
		"tcpdump -nr /tmp/cap.pcap -w /tmp/wg.pcap 'udp port 41641'   # on evil-box",
		"cat /sys/class/net/tailscale0/statistics/rx_packets   # on lab-vps, before",
		"tcpreplay -i " + iface + " --loop 20 /tmp/wg.pcap   # on evil-box",
		"cat /sys/class/net/tailscale0/statistics/rx_packets   # on lab-vps, after",
	}

	before, _ := c.lab.Sh(ctx, "lab-vps", "cat /sys/class/net/tailscale0/statistics/rx_packets 2>/dev/null || echo 0")
	out, _ := c.lab.Sh(ctx, "evil-box", fmt.Sprintf(
		`tcpdump -nr /tmp/cap.pcap -w /tmp/wg.pcap 'udp port 41641' 2>/dev/null; `+
			`n=$(tcpdump -nr /tmp/wg.pcap 2>/dev/null | wc -l); echo "frames=$n"; `+
			`tcpreplay -i %s --loop 20 /tmp/wg.pcap 2>&1 | tail -6`, iface))
	time.Sleep(2 * time.Second)
	after, _ := c.lab.Sh(ctx, "lab-vps", "cat /sys/class/net/tailscale0/statistics/rx_packets 2>/dev/null || echo 0")

	b, _ := strconv.Atoi(strings.TrimSpace(before.Stdout))
	a, _ := strconv.Atoi(strings.TrimSpace(after.Stdout))
	replayed := parseKV(out.Stdout, "frames") * 20
	res.Packets = replayed
	res.Retransmits = a - b
	res.Raw = strings.TrimSpace(out.Out()) +
		fmt.Sprintf("\n\nlab-vps tailscale0 rx_packets: %d -> %d (delta %d)", b, a, a-b)

	if replayed == 0 {
		res.Why = "No WireGuard frames in the capture to replay. Run the capture first."
		return res
	}
	res.OK = true
	res.Rule = "the anti-replay window discarded them"
	res.Why = fmt.Sprintf("%d frames put back on the wire, byte for byte valid, and lab-vps's "+
		"tailnet interface moved by %d packets. The bytes were never the check that fails: "+
		"WireGuard's counter for that session has already moved past them, so they land "+
		"outside the replay window and are dropped before anything tries to decrypt them.",
		replayed, a-b)
	return res
}

func (c *Controller) atkStolenKey(ctx context.Context) Result {
	if r := c.needEvil(ctx); r != nil {
		return *r
	}
	join := c.evilJoin(ctx, true)
	s := c.Snapshot()

	// A refused key is not the end of the story, and treating it as one was
	// this lab's version of the bug lab/README.md 5 describes. Refusing the key
	// puts evil-box exactly where any stranger stands; what it reaches from
	// there is the host firewall's answer, not the tailnet's. So probe either
	// way and let the rung say which half did the work.
	if !join.OK && !s.ACL.Lock {
		return join // a genuine join failure, not lock turning the key away
	}
	refused := !join.OK
	if join.OK {
		c.EnsureNodes(ctx)
	}
	p := c.Probe(ctx, "evil-box", "lab-vps", "22")
	p.Cmds = append(join.Cmds, p.Cmds...)

	if refused {
		if p.OK {
			p.OK = false
			p.Danger = true
			p.Why = fmt.Sprintf("The key was refused — on real Tailscale that is tailnet "+
				"lock, here it is that the lab never issued a key for a machine you did "+
				"not authorise. It did not need one. With no tailnet session evil-box is "+
				"just another machine on the internet, and lab-vps still answered on :22: "+
				"in at rung %d. Lock decides who is a member. Closing public :22 decides "+
				"who can reach the machine.", p.Rung)
			return p
		}
		p.OK = true
		p.Why = fmt.Sprintf("The key was refused, and the ordinary network gave its holder "+
			"nothing either: stopped at rung %d of 5. Both halves had to hold, and the rung "+
			"says which one did the stopping: anything past rung 2 means the tailnet was "+
			"never what turned it away.", p.Rung)
		return p
	}

	if p.OK {
		p.OK = false
		p.Danger = true
		p.Why = "The stolen key was enough. With nothing vouching for node keys and a " +
			"permissive grant, a leaked key is a login."
		return p
	}
	p.OK = true
	p.Why = fmt.Sprintf("The key worked and it still got nowhere: stopped at rung %d of 5. %s",
		p.Rung, p.Why)
	return p
}

func (c *Controller) atkExpiredKey(ctx context.Context) Result {
	res := Result{Rung: 1, From: "lab-roam", To: "lab-vps",
		Cmds: []string{"headscale nodes expire -i <lab-roam>   # 180 days pass, and nobody reauthenticated"}}

	n, ok := c.nodeFor(ctx, "lab-roam")
	if !ok {
		res.Why = "lab-roam is not registered with the coordination server"
		return res
	}
	r, err := c.lab.Exec(ctx, "headscale", "headscale", "nodes", "expire", "-i", n.ID.String(), "--force")
	res.Raw = r.Out()
	if err != nil {
		res.Why = err.Error()
		return res
	}

	dropped := WaitFor(ctx, 30*time.Second, 2*time.Second, func() bool {
		st, err := c.tailscaleStatus(ctx, "lab-roam")
		return err == nil && st.BackendState != "Running"
	})
	c.with(func(s *State) { s.Machines["lab-roam"].KeyExpired = true })

	p := c.Probe(ctx, "lab-roam", "lab-vps", "22")
	res.Rung = p.Rung
	res.Rule = p.Rule
	// Two of the three endings below are OK=false at the same rung, and only
	// this tells them apart: whether the machine actually fell out of the
	// tailnet. Without it a caller cannot distinguish "expiry worked and the
	// public door undid it" from "expiry has not taken effect yet".
	res.Evidence = map[string]int{"dropped": boolToInt(dropped), "probeOK": boolToInt(p.OK)}
	res.Raw += "\n\nprobe after expiry: rung " + strconv.Itoa(p.Rung) + " — " + p.Why

	switch {
	case dropped && p.OK:
		// Expiry worked and bought nothing, because the public door is open.
		// Reporting only the first half was the same mistake as check 3.
		res.Why = fmt.Sprintf("lab-roam fell out of the tailnet on its own, with nobody "+
			"doing anything to the machine itself — that part worked exactly as it should. "+
			"And it reached sshd anyway, at rung %d, because :22 is open to the whole "+
			"internet and a machine that is no longer a member is just another stranger. "+
			"Expiry ends membership. It does not close a port.", p.Rung)
	case dropped || !p.OK:
		res.OK = true
		res.Why = fmt.Sprintf("lab-roam fell out of the tailnet on its own, with nobody doing "+
			"anything to the machine itself, and there was no other way in: rung %d stopped "+
			"it. That is the point of expiry — the phone you left in a taxi stops being a "+
			"member whether or not you remember to remove it — and it counts for something "+
			"only because nothing else answered either. Bring it back with 'Rotate the key'.",
			p.Rung)
	default:
		res.Why = "the node was expired and still has a session — give it a few more seconds"
	}
	c.Observe(ctx)
	return res
}

// atkRotateKey is the one button on this board that is neither an attack nor a
// defence answering one. Nothing is attacking anything: rotating a node key is
// maintenance, and maintenance is judged by what it does not disturb. The claim
// is therefore continuity, in three parts — the coordination server stops
// holding the old key, the machine stays inside the tailnet at the same
// address, and a session running over that address does not notice.
//
// All three are claims a drawing makes, so all three are measured here. This
// used to return ok=true unconditionally and say that rotation "is a
// thirty-second job when you have planned for it" — true, well meant, and not
// a thing the run had shown. A shot drawn from that would have been inventing
// its subject, which is the one thing the board may not do.
//
// It has two situations and they are different demonstrations, so the command
// differs and the reading differs:
//
//	rotate   lab-roam is a member right now. There is something to disturb, so
//	         the run opens a session over the tailnet address first and forces
//	         the re-auth underneath it.
//	restore  lab-roam is out — usually because "Let a key expire" just put it
//	         there. Nothing to disturb; the demonstration is that a re-register
//	         brings it back, which is what atkExpiredKey's own Why sends the
//	         reader here to try.
func (c *Controller) atkRotateKey(ctx context.Context) Result {
	res := Result{Rung: 1, From: "lab-roam", To: "lab-vps", Rule: "re-register lab-roam"}
	key, err := readFileTrimmed(c.StateFile("authkey"))
	if err != nil {
		res.Why = "no pre-auth key on disk: " + err.Error()
		return res
	}
	if !c.lab.Running(ctx, "lab-roam") {
		res.Why = "lab-roam is not running, so there is nothing to re-register. Start it from " +
			"the machines panel first."
		return res
	}

	// ---- before ---------------------------------------------------------
	var rot rotation
	nodeBefore, _ := c.nodeFor(ctx, "lab-roam")
	if st, err := c.tailscaleStatus(ctx, "lab-roam"); err == nil {
		rot.wasMember = st.BackendState == "Running"
	}
	addrBefore := ""
	if rot.wasMember {
		addrBefore = c.tsAddr(ctx, "lab-roam")
	}

	// The session runs to lab-vps's TAILNET address, and that is the whole
	// point of it. Over the public address a node-key rotation is something
	// the session could not feel even in principle, so a surviving one would
	// prove nothing about the rotation — it would prove that the rotation was
	// irrelevant to it. Up on the tailnet the two are genuinely connected, and
	// "it did not notice" is a finding.
	vpsTS := ""
	if rot.wasMember {
		vpsTS = c.tsAddr(ctx, "lab-vps")
	}
	const sshOpts = `-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=8`
	const highest = `echo "ticks=$(tr -d '\r' < /tmp/rotate.out 2>/dev/null | grep -o 'tick [0-9]*' | awk '{print $2}' | sort -n | tail -1)"`
	if vpsTS != "" {
		start := fmt.Sprintf(`
rm -f /tmp/rotate.out
cat > /tmp/run-rotate.sh <<'RUNEOF'
#!/bin/sh
exec ssh %s root@%s 'i=1; while [ $i -le 120 ]; do echo tick $i; sleep 1; i=$((i+1)); done'
RUNEOF
chmod +x /tmp/run-rotate.sh
(/tmp/run-rotate.sh > /tmp/rotate.out 2>&1 &)
sleep 8
`, sshOpts, vpsTS)
		if _, err := c.lab.Sh(ctx, "lab-roam", start); err == nil {
			if r, err := c.lab.Sh(ctx, "lab-roam", highest); err == nil {
				rot.ticksBefore = parseKV(r.Stdout, "ticks")
			}
		}
	}

	// ---- the rotation ---------------------------------------------------
	// --force-reauth only where there is a live registration to force. A
	// machine that is already out has to re-register whatever is asked of it,
	// and the plain command is the one the entrypoint and the reset path have
	// always used to bring one back.
	up := []string{"tailscale", "up",
		"--login-server=https://headscale:8443", "--authkey=" + key,
		"--hostname=lab-roam", "--accept-routes=false", "--accept-dns=false", "--timeout=30s"}
	if rot.wasMember {
		up = append(up, "--force-reauth")
	}
	res.Cmds = []string{
		"headscale nodes list -o json   # the node key it holds for lab-roam, before and after",
	}
	if vpsTS != "" {
		res.Cmds = append(res.Cmds,
			"ssh root@"+vpsTS+" 'while …; do echo tick $i; sleep 1; done'   # on lab-roam, over the tailnet")
	}
	// The key itself is elided, as it always has been here. It is a lab key on
	// a loopback-only server and it is still not going in the script tab, the
	// transcript under the shot, or anybody's screen recording.
	shown := make([]string, 0, len(up))
	for _, arg := range up {
		if strings.HasPrefix(arg, "--authkey=") {
			arg = "--authkey=…"
		}
		shown = append(shown, arg)
	}
	res.Cmds = append(res.Cmds, strings.Join(shown, " ")+"   # on lab-roam")

	r, _ := c.lab.Exec(ctx, "lab-roam", up...)
	res.Raw = r.Out()

	// The session survives a re-auth or it does not, and that is measured
	// below; what must not happen is measuring it before tailscaled has
	// finished coming back, which would report a stall as a drop.
	rot.isMember = WaitFor(ctx, 45*time.Second, 2*time.Second, func() bool {
		st, err := c.tailscaleStatus(ctx, "lab-roam")
		return err == nil && st.BackendState == "Running"
	})
	c.EnsureNodes(ctx)
	c.with(func(s *State) { s.Machines["lab-roam"].KeyExpired = !rot.isMember })

	// ---- after ----------------------------------------------------------
	addrAfter := ""
	if rot.isMember {
		addrAfter = c.tsAddr(ctx, "lab-roam")
	}
	rot.addrKept = addrBefore != "" && addrBefore == addrAfter
	nodeAfter, _ := c.nodeFor(ctx, "lab-roam")
	rot.keyRead = nodeBefore.NodeKey != "" && nodeAfter.NodeKey != ""
	rot.keyChanged = rot.keyRead && nodeBefore.NodeKey != nodeAfter.NodeKey
	rot.expiryMoved = nodeAfter.Expiry.Time().After(nodeBefore.Expiry.Time())

	if rot.ticksBefore > 0 {
		// Long enough for the loop to print past the rotation, and no longer:
		// the figure is the count the session reached, not a count this waited
		// for. A session that died at the re-auth reports the tick it died on.
		time.Sleep(12 * time.Second)
		if r, err := c.lab.Sh(ctx, "lab-roam", highest); err == nil {
			rot.ticksAfter = parseKV(r.Stdout, "ticks")
		}
	}
	if vpsTS != "" {
		// Whether or not it printed anything. demoOutage leaves its two
		// sessions to run themselves out, which is survivable there because
		// both of them are the demonstration; a stray loop left behind by this
		// one would still be ticking the next time somebody presses the button,
		// and the reading afterwards would be its ticks and not the new run's.
		_, _ = c.lab.Sh(ctx, "lab-roam",
			`pkill -f run-rotate.sh 2>/dev/null; pkill -f 'root@`+vpsTS+`' 2>/dev/null; true`)
	}

	p := c.Probe(ctx, "lab-roam", "lab-vps", "22")
	rot.probeOK, rot.probeRung = p.OK, p.Rung
	res.Raw = strings.TrimSpace(res.Raw + "\n\nprobe after the rotation: rung " +
		strconv.Itoa(p.Rung) + " — " + p.Why)

	res.Evidence = rot.evidence()
	// Only what was read. An empty string here would be a label with a blank
	// where a key should be, which reads as a key that is missing rather than
	// as one that was never asked for.
	res.Detail = map[string]string{}
	for k, v := range map[string]string{
		"addrBefore": addrBefore, "addrAfter": addrAfter,
		"keyBefore": shortKey(nodeBefore.NodeKey), "keyAfter": shortKey(nodeAfter.NodeKey),
	} {
		if v != "" {
			res.Detail[k] = v
		}
	}
	res.Rung = rot.rung()
	res.Rule = rot.rule()
	res.OK, res.Why = rot.verdict(addrAfter)
	c.Observe(ctx)
	return res
}

// rotation is what one run of atkRotateKey measured, and every field in it is
// a fact a drawing is entitled to draw. Kept together so the three claims the
// set-piece makes — re-keyed, still a member, nothing dropped — have one place
// to be decided and one place to be tested, rather than being re-derived from
// prose at the far end of a JSON round trip.
type rotation struct {
	wasMember, isMember     bool
	keyRead, keyChanged     bool
	expiryMoved, addrKept   bool
	probeOK                 bool
	probeRung               int
	ticksBefore, ticksAfter int
}

// sessionRan is whether there was anything to disturb. Without it the run says
// nothing about continuity either way, and the shot draws no lane rather than
// drawing one that survived a rotation it was never in.
func (r rotation) sessionRan() bool { return r.ticksBefore > 0 }

// sessionKept is a comparison between the two readings, not a guess from the
// second one: a session that died at the re-auth reports the same tick it had
// reached before it.
func (r rotation) sessionKept() bool { return r.sessionRan() && r.ticksAfter > r.ticksBefore }

func (r rotation) evidence() map[string]int {
	return map[string]int{
		"wasMember":   boolToInt(r.wasMember),
		"isMember":    boolToInt(r.isMember),
		"keyRead":     boolToInt(r.keyRead),
		"keyChanged":  boolToInt(r.keyChanged),
		"expiryMoved": boolToInt(r.expiryMoved),
		"addrKept":    boolToInt(r.addrKept),
		"probeOK":     boolToInt(r.probeOK),
		"ticksBefore": r.ticksBefore,
		"ticksAfter":  r.ticksAfter,
	}
}

// rung is the board's X axis. A session that printed a tick over the tailnet
// went all the way: sshd answered and a shell ran a loop, and that is rung 5,
// whatever the probe afterwards happened to find. Otherwise the probe is the
// only thing that measured a distance, so it decides — the same arrangement
// atkExpiredKey has, and for the same reason.
func (r rotation) rung() int {
	if r.ticksBefore > 0 || r.ticksAfter > 0 {
		return 5
	}
	if r.probeRung > 0 {
		return r.probeRung
	}
	return 1
}

func (r rotation) rule() string {
	switch {
	case !r.isMember:
		return "the re-registration did not take"
	case !r.wasMember:
		return "a re-register puts an expired machine back"
	case r.sessionRan():
		return "the key rotates underneath a live session"
	default:
		return "re-register lab-roam"
	}
}

// verdict is ok plus the prose, and the two are decided together because they
// are the same judgement. ok here means the rotation did what maintenance is
// supposed to do; a dropped session is a real finding and not a green frame.
func (r rotation) verdict(addr string) (bool, string) {
	where := "the tailnet"
	if addr != "" {
		where = addr
	}
	switch {
	case !r.isMember:
		return false, "lab-roam did not come back onto the tailnet within 45 seconds of the " +
			"re-register. Check the coordination server is up and that the pre-auth key on " +
			"disk has not expired — `headscale preauthkeys list -u lab` will say."

	case r.sessionKept():
		keyed := "The coordination server holds a different node key for it than it held a " +
			"minute ago"
		if !r.keyChanged {
			keyed = "The coordination server reports the same node key it reported before, so " +
				"this run did not demonstrate a re-key — what it did demonstrate is the " +
				"re-registration"
		}
		return true, fmt.Sprintf("A session was running over %s while the key rotated, and it "+
			"did not notice: tick %d before, tick %d after, the same connection throughout. "+
			"%s, and the machine is still on the tailnet at the same address. That is what "+
			"rotation is supposed to look like — the credential changes and nothing that was "+
			"relying on it stops. It is a thirty-second job when you have planned for it, and "+
			"the reason to plan for it is that the alternative is doing this to a machine you "+
			"cannot reach any other way.", where, r.ticksBefore, r.ticksAfter, keyed)

	case r.sessionRan():
		return false, fmt.Sprintf("The session stopped at tick %d and printed nothing after "+
			"the re-auth, so this rotation was not free: something that was working across "+
			"the tailnet stopped working. Read the tail in the packets tab — if sshd is "+
			"reachable again now, the connection was dropped rather than the machine, and "+
			"that is a rotation you would want to do at a quiet hour.", r.ticksBefore)

	case !r.wasMember:
		return true, fmt.Sprintf("lab-roam was outside the tailnet and a re-register put it "+
			"back, at %s. There was no session to keep, so this run says nothing about "+
			"continuity — it says the machine that removed itself can be brought back with one "+
			"command and the key you already had. Run it again now that it is a member and "+
			"the demonstration is the other one: a rotation underneath something that is "+
			"running.", where)

	default:
		return true, fmt.Sprintf("lab-roam re-registered and is still a member, at %s. No "+
			"session was measured across the rotation — the tailnet address for lab-vps was "+
			"not readable, or ssh over it never printed — so continuity is the one part of "+
			"this that went untested. The membership and the address are measured, and both "+
			"held.", where)
	}
}

// shortKey is a node key with enough of it left to see that two of them differ
// and not so much that it stops fitting on a label. Empty in, empty out: the
// drawing then knows there was nothing to read rather than showing a blank
// where a key should be.
func shortKey(k string) string {
	if k == "" {
		return ""
	}
	if _, rest, ok := strings.Cut(k, ":"); ok {
		k = rest
	}
	if len(k) > 10 {
		k = k[:10]
	}
	return k + "…"
}

func (c *Controller) atkRogueExit(ctx context.Context) Result {
	if r := c.needEvil(ctx); r != nil {
		return *r
	}
	if join := c.evilJoin(ctx, true); !join.OK {
		return join
	}
	res := Result{Rung: 3, From: "evil-box",
		Cmds: []string{
			"tailscale set --advertise-exit-node   # on evil-box",
			"headscale nodes list-routes",
		}}
	r1, _ := c.lab.Exec(ctx, "evil-box", "tailscale", "set", "--advertise-exit-node")
	time.Sleep(2 * time.Second)
	r2, _ := c.lab.Exec(ctx, "headscale", "headscale", "nodes", "list-routes")
	res.Raw = strings.TrimSpace(r1.Out() + "\n" + r2.Out())

	approved := strings.Contains(r2.Stdout, "0.0.0.0/0") &&
		!strings.Contains(strings.ToLower(r2.Stdout), "false")
	if approved {
		res.Danger = true
		res.Rule = "the route was approved"
		res.Why = "The offer was accepted. Every byte of a client's internet traffic would " +
			"leave through a machine you do not own."
	} else {
		res.OK = true
		res.Rule = "an exit node is a route offer, not a route"
		res.Why = "Advertised, and ignored. Approval is explicit and separate from membership, " +
			"so being on the tailnet bought this machine nothing at the routing layer. " +
			"Check yours with `tailscale exit-node list`."
	}
	return res
}

func (c *Controller) atkDockerBypass(ctx context.Context) Result {
	if r := c.needEvil(ctx); r != nil {
		return *r
	}
	_ = c.Set(ctx, "vps.ufwDefaultDeny", true)
	trap := c.dockerTrap(ctx, true)
	if !trap.OK {
		return trap
	}
	target := c.lab.IPOn(ctx, "lab-vps", "wan")

	res := Result{Rung: 4, From: "evil-box", To: "lab-vps", Port: "8080", Path: "public"}
	res.Cmds = append(trap.Cmds,
		"ufw status verbose   # on lab-vps: says deny",
		"curl -sS -m 5 -o /dev/null -w '%{http_code}' http://"+target+":8080/   # on evil-box")

	ufw, _ := c.lab.Exec(ctx, "lab-vps", "ufw", "status", "verbose")
	curl, _ := c.lab.Sh(ctx, "evil-box", fmt.Sprintf(
		`curl -sS -m 5 -o /dev/null -w 'HTTP %%{http_code}\n' http://%s:8080/ 2>&1`, target))
	res.Raw = "lab-vps # ufw status verbose\n" + strings.TrimSpace(ufw.Stdout) +
		"\n\nevil-box # curl http://" + target + ":8080/\n" + strings.TrimSpace(curl.Out())

	if strings.Contains(curl.Stdout, "HTTP 2") || strings.Contains(curl.Stdout, "HTTP 3") {
		res.Danger = true
		res.Rule = "DOCKER-USER accepted it before ufw's chain ever ran"
		res.Why = "ufw says deny. The port answers anyway. A published container port is " +
			"forwarded, not delivered locally, and the FORWARD chain jumps into Docker's " +
			"chains before it reaches ufw's — so publishing a port silently punches " +
			"through the firewall you were trusting. This is chapter 08's trap, and it is " +
			"the single most useful thing in this lab."
	} else {
		res.OK = true
		res.Why = "Nothing answered on :8080."
	}
	return res
}

func (c *Controller) atkLockOut(ctx context.Context) Result {
	res := Result{Rung: 4, Danger: true, Rule: "both doors, in the wrong order"}
	r1 := c.Set(ctx, "vps.allowPublic22", false)
	r2 := c.Set(ctx, "vps.allowTailscale0", false)
	res.Cmds = append(r1.Cmds, r2.Cmds...)

	overTailnet := c.Probe(ctx, "lab-ubuntu", "lab-vps", "22")
	overPublic := c.Probe(ctx, "evil-box", "lab-vps", "22")
	if !c.lab.Running(ctx, "evil-box") {
		overPublic = Result{Rung: 1, Why: "no machine outside to try from — evil-box is not running"}
	}
	res.Raw = fmt.Sprintf("over the tailnet: rung %d — %s\nfrom outside:     rung %d — %s",
		overTailnet.Rung, overTailnet.Why, overPublic.Rung, overPublic.Why)

	res.Why = "Both doors are shut and you are outside. On a VPS this is a support ticket and " +
		"a console session. Chapter 11's build order exists precisely so the tailnet route " +
		"is proven working before the public one is removed — never the other way round. " +
		"Put it back with 'Reset everything'."
	if overTailnet.OK {
		res.OK = true
		res.Why = "The tailnet route survived, so you are still in. Check the rules tab: " +
			"something is still allowing tailscale0."
	}
	return res
}

// ---------------------------------------------------------------------------
// The demonstration chapter 03 is built around
//
// Two sessions from lab-roam to lab-vps, started at the same moment: one over
// SSH, one over Mosh. Then the link goes away for twenty seconds, the way it
// does in a tunnel, and comes back. Both are real sessions doing real work, and
// what happens to them is not a claim in a chapter — it is a tick count.
// ---------------------------------------------------------------------------

func (c *Controller) demoOutage(ctx context.Context) Result {
	res := Result{Rung: 2, From: "lab-roam", To: "lab-vps"}

	// Deliberately the public address, not the tailnet one.
	//
	// Over a tailnet both sessions survive everything this does, because the
	// tailnet address never changes — which is a real result, and the reason
	// the rest of this guide exists. It is also not the comparison chapter 03
	// is making. That chapter is about what happens to a plain SSH session when
	// the network underneath it moves, so the demonstration runs where that is
	// actually true: straight at lab-vps's public address, no tailnet involved.
	vps := c.lab.IPOn(ctx, "lab-vps", "wan")
	if vps == "" || !c.lab.Running(ctx, "lab-roam") {
		res.Why = "lab-roam and lab-vps both need to be running for this one"
		return res
	}

	// Mosh needs a UDP range as well as :22 — the rule people forget, and the
	// reason a first Mosh setup logs in and then eats every keystroke. Opened
	// for the duration, named here, and taken away again at the end.
	_, _ = c.lab.Exec(ctx, "lab-vps", "ufw", "allow", "60000:61000/udp")
	defer func() {
		_, _ = c.lab.Exec(context.WithoutCancel(ctx), "lab-vps",
			"ufw", "--force", "delete", "allow", "60000:61000/udp")
	}()

	gw := c.gatewayFor("lab-roam")
	oldIP, newIP := "10.0.27.2", "10.0.27.77"

	res.Cmds = []string{
		"sudo ufw allow 60000:61000/udp   # on lab-vps, for the duration: Mosh's range",
		"ssh root@" + vps + " 'while …; do echo tick $i; sleep 1; done'   # on lab-roam",
		"mosh root@" + vps + " -- …the same loop…   # on lab-roam",
		"ip link set eth0 down; sleep 20; ip link set eth0 up   # act one: the tunnel",
		"ip addr flush dev eth0; ip addr add " + newIP + "/24 dev eth0   # act two: a different network",
	}

	// Both sessions are started from a file rather than a nested quoted string.
	// Mosh needs a terminal and a TERM to go with it, which is why each one runs
	// under `script`; without that it exits before it has said anything and the
	// demonstration silently proves nothing.
	sshOpts := `-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=8`
	start := fmt.Sprintf(`
rm -f /tmp/ssh.out /tmp/mosh.out
cat > /tmp/run-ssh.sh <<'RUNEOF'
#!/bin/sh
exec ssh %s root@%s 'i=1; while [ $i -le 120 ]; do echo tick $i; sleep 1; i=$((i+1)); done'
RUNEOF
cat > /tmp/run-mosh.sh <<'RUNEOF'
#!/bin/sh
# mosh-client asserts on a zero-sized terminal, and the pty that script hands
# it has no window size unless one is set here.
stty rows 40 cols 120 2>/dev/null || true
exec mosh --ssh="ssh %s" root@%s -- sh -c 'i=1; while [ $i -le 120 ]; do echo tick $i; sleep 1; i=$((i+1)); done'
RUNEOF
chmod +x /tmp/run-ssh.sh /tmp/run-mosh.sh
(TERM=xterm LANG=C.UTF-8 script -qec /tmp/run-ssh.sh /dev/null  > /tmp/ssh.out  2>&1 &)
(TERM=xterm LANG=C.UTF-8 script -qec /tmp/run-mosh.sh /dev/null > /tmp/mosh.out 2>&1 &)
sleep 10
`, sshOpts, vps, sshOpts, vps)

	if r, err := c.lab.Sh(ctx, "lab-roam", start); err != nil {
		res.Why = "could not start the two sessions: " + r.Out()
		return res
	}

	// The highest tick each session has printed. Counting lines does not work
	// for Mosh: it repaints, so the same tick appears more than once and a
	// count understates it. The largest number seen is the honest measure of
	// how far each session actually got.
	const highest = `
echo "ssh=$(tr -d '\r' < /tmp/ssh.out 2>/dev/null | grep -o 'tick [0-9]*' | awk '{print $2}' | sort -n | tail -1)"
echo "mosh=$(tr -d '\r' < /tmp/mosh.out 2>/dev/null | grep -o 'tick [0-9]*' | awk '{print $2}' | sort -n | tail -1)"`

	// ---- act one: the tunnel --------------------------------------------
	// Run to completion rather than in the background, so the link is provably
	// back before anything is measured. Taking eth0 down does not take this
	// command with it: the Docker socket is not on the lab's network. On a real
	// machine you would wrap it exactly like this and run it from the console.
	act1, _ := c.lab.Sh(ctx, "lab-roam", fmt.Sprintf(
		`ip link set eth0 down; echo "eth0 down at $(date +%%T)"; sleep 20; `+
			`ip link set eth0 up; ip route replace default via %s; echo "eth0 up at $(date +%%T)"`, gw))
	time.Sleep(15 * time.Second)
	after1, _ := c.lab.Sh(ctx, "lab-roam", highest)
	ssh1, mosh1 := parseKV(after1.Stdout, "ssh"), parseKV(after1.Stdout, "mosh")

	// ---- act two: a different network ------------------------------------
	// The blackout on its own is not what kills SSH, and the lab is about to
	// prove that. What kills it is the address changing underneath the
	// connection — the train leaving the station on a different tower, the
	// laptop moving from wifi to tethering. Same machine, same session, new IP.
	// Flush rather than add-then-delete: removing the primary address of a
	// subnet takes every other address in that subnet with it, so the obvious
	// order leaves the machine with no address at all.
	act2, _ := c.lab.Sh(ctx, "lab-roam", fmt.Sprintf(
		`ip addr flush dev eth0; ip addr add %s/24 dev eth0; `+
			`ip route replace default via %s; echo "roamed to %s at $(date +%%T)"; ip -4 -o addr show eth0`,
		newIP, gw, newIP))
	time.Sleep(25 * time.Second)
	after2, _ := c.lab.Sh(ctx, "lab-roam", highest+`
echo "--- ssh, last lines ---"; tr -d '\r' < /tmp/ssh.out 2>/dev/null | tail -3
echo "--- mosh, last lines ---"; tr -d '\r' < /tmp/mosh.out 2>/dev/null | grep -o 'tick [0-9]*' | tail -3`)
	ssh2, mosh2 := parseKV(after2.Stdout, "ssh"), parseKV(after2.Stdout, "mosh")

	// Put the machine back where compose expects to find it.
	_, _ = c.lab.Sh(ctx, "lab-roam", fmt.Sprintf(
		`ip addr flush dev eth0; ip addr add %s/24 dev eth0; ip route replace default via %s`, oldIP, gw))

	res.Raw = strings.Join([]string{
		strings.TrimSpace(act1.Out()),
		fmt.Sprintf("after the blackout:  ssh reached tick %d, mosh reached tick %d", ssh1, mosh1),
		"",
		strings.TrimSpace(act2.Out()),
		fmt.Sprintf("after the roam:      ssh reached tick %d, mosh reached tick %d", ssh2, mosh2),
		"",
		strings.TrimSpace(after2.Out()),
	}, "\n")
	res.Evidence = outageEvidence(ssh1, mosh1, ssh2, mosh2)
	res.Detail = map[string]string{"addrBefore": oldIP, "addrAfter": newIP}
	res.Rung = outageRung(ssh1, mosh1, ssh2, mosh2)

	switch {
	case ssh2 == 0 && mosh2 == 0:
		res.Why = "Neither session produced anything. Check that lab-roam can reach " + vps +
			" on :22 at all — run the ssh-from-the-phone probe first."
	case mosh1 == 0:
		res.Why = fmt.Sprintf("SSH reached tick %d and Mosh printed nothing, which almost always "+
			"means the UDP range never opened. That is the failure mode chapter 03 warns "+
			"about: a firewall that permits :22 and nothing else lets you log in and then "+
			"eats every keystroke.", ssh1)
	case mosh2 > ssh2+5:
		res.OK = true
		res.Rule = "Mosh followed the machine to its new address; SSH's connection did not"
		res.Why = fmt.Sprintf(
			"Two acts, and the first one is the surprise. Twenty seconds with no link at all: "+
				"both survived it (ssh %d, mosh %d), because TCP does not give up on a stalled "+
				"connection anywhere near that fast — a blackout alone is not what kills SSH, "+
				"whatever the folklore says. Then the address changed underneath both sessions, "+
				"which is what actually happens when a phone moves. SSH stopped at tick %d: its "+
				"connection is a four-tuple and one corner of it no longer exists. Mosh reached "+
				"%d, because it is not holding a connection to lose — it is holding state, and "+
				"state does not care which address the next datagram arrives from. That is "+
				"chapter 03, measured.\n\nOne more thing worth knowing: run the same two "+
				"sessions over the tailnet address instead and SSH survives the roam as "+
				"well, because the tailnet address does not change when the network under "+
				"it does. That is the tailnet earning its keep, and it is why chapters 01 "+
				"and 03 are worth having together.", ssh1, mosh1, ssh2, mosh2)
	default:
		res.Why = fmt.Sprintf("After the blackout: ssh %d, mosh %d. After the roam: ssh %d, "+
			"mosh %d. Not the split this expects — read the tails below.", ssh1, mosh1, ssh2, mosh2)
	}
	c.Observe(ctx)
	return res
}

// ---------------------------------------------------------------------------

// The four ports the public scan asks about: sshd, a web server somebody put
// there, the port a published container lands on, and the one WireGuard uses.
// Named once so the command, the Evidence and the test cannot drift apart.
var scanPorts = []string{"22", "80", "8080", "41641"}

// parseOpenPorts pulls the open rows out of nmap's table. "open|filtered" is
// nmap saying it could not tell, which is not the same as open — the guide is
// careful about that distinction everywhere else and this is where it starts.
func parseOpenPorts(stdout string) []string {
	var open []string
	for _, line := range strings.Split(stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[1] == "open" {
			open = append(open, fields[0])
		}
	}
	return open
}

// portNumber turns nmap's "22/tcp" into 22. Anything it cannot read is
// dropped rather than guessed at.
func portNumber(s string) int {
	num, _, _ := strings.Cut(s, "/")
	n, err := strconv.Atoi(num)
	if err != nil {
		return 0
	}
	return n
}

// scanEvidence records how many ports were asked about and which of them
// answered, as one key per open port. A scan that found nothing still carries
// the count it probed, because "four ports, none open" and "nothing was ever
// scanned" are different results and a drawing has to be able to tell them
// apart.
func scanEvidence(open, scanned []string) map[string]int {
	ev := map[string]int{"scanned": len(scanned)}
	for _, p := range open {
		if n := portNumber(p); n > 0 {
			ev["open:"+strconv.Itoa(n)] = 1
		}
	}
	return ev
}

// outageEvidence carries all four tick counts the outage demonstration
// measured, one key per session per act. The names say what the numbers are:
// the highest tick each session printed, after the blackout and after the
// roam. They used to ride out on Packets and Retransmits, which meant a
// successful run reported "70 packets · 45 retransmits" when nothing had sent
// a packet or retransmitted anything — the two acts are the whole argument
// here, and both of them have to reach the browser under their own names.
func outageEvidence(sshAfterBlackout, moshAfterBlackout, sshAfterRoam, moshAfterRoam int) map[string]int {
	return map[string]int{
		"sshAfterBlackout":  sshAfterBlackout,
		"moshAfterBlackout": moshAfterBlackout,
		"sshAfterRoam":      sshAfterRoam,
		"moshAfterRoam":     moshAfterRoam,
	}
}

// outageRung is how far the two sessions travelled, which is the question the
// Rung field answers and the one the board's X axis draws. A session that
// printed a tick went all the way: sshd answered and a shell ran a loop, and
// that is rung 5. It used to report the rung-2 opening value whatever
// happened — two rungs short of where two live sessions demonstrably reached,
// which nobody noticed while the result was a paragraph of prose and which
// became a wrong drawing the moment the board grew a set-piece for it.
//
// All four counts, not just the first act's: the set-piece draws a lane for
// any session that printed a tick in either act, and a Result claiming rung 2
// under a drawing that reaches lab-vps is the exact disagreement the ladder
// exists to make impossible.
func outageRung(sshAfterBlackout, moshAfterBlackout, sshAfterRoam, moshAfterRoam int) int {
	if sshAfterBlackout > 0 || moshAfterBlackout > 0 ||
		sshAfterRoam > 0 || moshAfterRoam > 0 {
		return 5
	}
	// Nothing printed anything, so nothing was shown to get past the opening
	// claim that there is a path at all.
	return 2
}

func parseKV(s, key string) int {
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && k == key {
			n, _ := strconv.Atoi(strings.TrimSpace(v))
			return n
		}
	}
	return 0
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
