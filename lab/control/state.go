// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hashem Aldhaheri

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// The machines
//
// Same four machines as the sandbox page, same ids, same roles, same chapters.
// A reader who has driven one should be able to drive the other blind, and that
// starts here.
// ---------------------------------------------------------------------------

type Machine struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Role    string `json:"role"`
	Chapter string `json:"chapter"`
	Tag     string `json:"tag"`
	NAT     string `json:"nat"` // none | easy | hard
	Hostile bool   `json:"hostile,omitempty"`

	// Which compose network carries this machine's own segment, and which
	// carries the one standing in for the public internet.
	LANNet string `json:"-"`
	WANNet string `json:"-"`
}

var Catalog = []Machine{
	{ID: "lab-vps", Label: "lab-vps", Role: "the public box", Chapter: "08",
		Tag: "tag:server", NAT: "none", WANNet: "wan", LANNet: "vpslan"},
	{ID: "lab-ubuntu", Label: "lab-ubuntu", Role: "the laptop", Chapter: "09",
		Tag: "tag:laptop", NAT: "easy", LANNet: "lan-ubuntu"},
	{ID: "lab-roam", Label: "lab-roam", Role: "the phone's stand-in", Chapter: "03",
		Tag: "tag:roam", NAT: "hard", LANNet: "lan-roam"},
	{ID: "evil-box", Label: "evil-box", Role: "a hostile machine", Chapter: "10",
		Tag: "tag:untrusted", NAT: "easy", LANNet: "lan-evil", Hostile: true},
}

func machineByID(id string) (Machine, bool) {
	for _, m := range Catalog {
		if m.ID == id {
			return m, true
		}
	}
	return Machine{}, false
}

// ---------------------------------------------------------------------------
// Desired state — what the UI asked for
// ---------------------------------------------------------------------------

type ACLState struct {
	Def    string          `json:"def"` // deny | accept
	Grants map[string]bool `json:"grants"`
	Lock   bool            `json:"lock"`
	Expiry bool            `json:"expiry"`
	SSH    bool            `json:"ssh"`
}

type VPSState struct {
	UFWDefaultDeny bool   `json:"ufwDefaultDeny"`
	AllowPublic22  bool   `json:"allowPublic22"`
	AllowTailscale bool   `json:"allowTailscale0"`
	DockerPublish  bool   `json:"dockerPublish"`
	SSHDListen     string `json:"sshdListen"` // all | tailnet
	PasswordAuth   bool   `json:"passwordAuth"`
	PermitRoot     bool   `json:"permitRoot"`
}

type LinkState struct {
	Up         bool `json:"up"`
	Loss       int  `json:"loss"`
	Delay      int  `json:"delay"`
	UDPBlocked bool `json:"udpBlocked"`
}

type MachineState struct {
	Online     bool   `json:"online"`
	OnTailnet  bool   `json:"onTailnet"`
	Signed     bool   `json:"signed"`
	KeyExpired bool   `json:"keyExpired"`
	TSAddr     string `json:"tsAddr,omitempty"`
	LANAddr    string `json:"lanAddr,omitempty"`
	WANAddr    string `json:"wanAddr,omitempty"`
	PathTo     string `json:"pathTo,omitempty"` // how this machine reaches lab-vps
}

// TailcatState is chapter 01's escape hatch, and the one part of this lab that
// is not part of the build. Same five switches as the sandbox, same names, same
// meanings — the panel is the shared vocabulary and this is the other end of
// it.
//
// Four of the five are read back off a running process rather than remembered:
// `pgrep` finds the tunnel, its command line says which service and whether
// --allow is on, and the machine holding the process is Host. Shared is a file
// on evil-box. Only the Host and Service a reader has *chosen* while the
// tunnel is off have nowhere to be observed from, which is why this rides in
// desired.json alongside the policy.
type TailcatState struct {
	On      bool   `json:"on"`
	Host    string `json:"host"`
	Service string `json:"service"` // ssh | no-auth-ssh | all
	Allow   bool   `json:"allow"`
	Shared  bool   `json:"shared"`

	// Addr is the tailcat address the running server printed, truncated the
	// way the sandbox truncates its own. It is a bearer credential — whoever
	// holds it can connect — so the readout shows enough of it to recognise
	// and not enough to use, and the full string never leaves the machine
	// that printed it except when Shared puts it on evil-box.
	Addr string `json:"addr,omitempty"`
}

type State struct {
	Machines      map[string]*MachineState `json:"machines"`
	Links         map[string]*LinkState    `json:"links"`
	SegmentShared bool                     `json:"segmentShared"`
	ACL           ACLState                 `json:"acl"`
	VPS           VPSState                 `json:"vps"`
	Tailcat       TailcatState             `json:"tailcat"`

	// Read-only observations, for the readout panes.
	Catalog []Machine `json:"catalog"`
	Notes   []string  `json:"notes,omitempty"`
	Ready   bool      `json:"ready"`
}

// The state the lab boots into: the same defaults the sandbox page starts from,
// so the two agree before you have touched anything.
func defaultState() *State {
	s := &State{
		Machines: map[string]*MachineState{},
		Links:    map[string]*LinkState{},
		ACL: ACLState{
			Def:    "deny",
			Grants: map[string]bool{"laptop": true, "roam": true, "untrusted": false, "any": false},
			Lock:   true, Expiry: true, SSH: true,
		},
		VPS: VPSState{
			UFWDefaultDeny: true, AllowPublic22: true, AllowTailscale: true,
			DockerPublish: false, SSHDListen: "all",
			PasswordAuth: false, PermitRoot: false,
		},
		// Off, on the laptop, in the shape chapter 01 recommends. Every switch
		// under it is then a deliberate step away from that advice, which is
		// the same starting point the sandbox uses.
		Tailcat: TailcatState{On: false, Host: "lab-ubuntu", Service: "ssh"},
		Catalog: Catalog,
	}
	for _, m := range Catalog {
		s.Machines[m.ID] = &MachineState{
			Online: !m.Hostile, OnTailnet: !m.Hostile, Signed: !m.Hostile,
		}
		s.Links[m.ID] = &LinkState{Up: true}
	}
	return s
}

// ---------------------------------------------------------------------------
// Named configurations
//
// The same four ids as the sandbox, with the same meanings, because a stack
// that scores differently from the model is the most useful thing this pair can
// produce — and that comparison only means anything if the inputs match.
// ---------------------------------------------------------------------------

type Preset struct {
	ID    string   `json:"id"`
	Label string   `json:"label"`
	Tone  string   `json:"tone"`
	Sub   string   `json:"sub"`
	Note  string   `json:"note"`
	ACL   ACLState `json:"acl"`
	VPS   VPSState `json:"vps"`
	// Whether the machines are on the tailnet at all. "Day one" is a box that
	// has never heard of it.
	Tailnet bool `json:"tailnet"`
}

var Presets = []Preset{
	{
		ID: "day-one", Label: "Day one", Tone: "danger",
		Sub:  "a fresh VPS, an hour old, nothing done to it yet",
		Note: "Root can log in with a password from anywhere on earth, and the scanners already know the address exists. Every guide starts here.",
		ACL: ACLState{Def: "accept",
			Grants: map[string]bool{"laptop": false, "roam": false, "untrusted": false, "any": false},
			Lock:   false, Expiry: false, SSH: false},
		VPS: VPSState{UFWDefaultDeny: false, AllowPublic22: true, AllowTailscale: false,
			DockerPublish: false, SSHDListen: "all", PasswordAuth: true, PermitRoot: true},
		Tailnet: false,
	},
	{
		ID: "typical", Label: "Typical", Tone: "warn",
		Sub:  "the half-done state most people are actually in",
		Note: "Keys instead of passwords, a tailnet up and working — the visible half of the job, done properly. Then it stopped: :22 is still open to the internet, the policy still permits everything, and a container has published a port nobody audited.",
		ACL: ACLState{Def: "accept",
			Grants: map[string]bool{"laptop": true, "roam": true, "untrusted": false, "any": true},
			Lock:   false, Expiry: false, SSH: true},
		VPS: VPSState{UFWDefaultDeny: true, AllowPublic22: true, AllowTailscale: true,
			DockerPublish: true, SSHDListen: "all", PasswordAuth: false, PermitRoot: false},
		Tailnet: true,
	},
	{
		ID: "weak", Label: "Weak", Tone: "danger",
		Sub:  "choices were made here, and they were the wrong ones",
		Note: "Every protection that got in somebody's way was switched off on purpose. Worse than the fresh box, because it looks configured.",
		ACL: ACLState{Def: "accept",
			Grants: map[string]bool{"laptop": true, "roam": true, "untrusted": true, "any": true},
			Lock:   false, Expiry: false, SSH: false},
		VPS: VPSState{UFWDefaultDeny: false, AllowPublic22: true, AllowTailscale: true,
			DockerPublish: true, SSHDListen: "all", PasswordAuth: true, PermitRoot: true},
		Tailnet: true,
	},
	{
		ID: "hardened", Label: "Hardened", Tone: "ok",
		Sub:  "what chapters 01 through 11 build towards",
		Note: "Default-deny policy with two narrow grants, no spare key for a machine nobody authorised, expiry on, public :22 gone, and sshd bound to the tailnet address so it never even sees a packet from eth0.",
		ACL: ACLState{Def: "deny",
			Grants: map[string]bool{"laptop": true, "roam": true, "untrusted": false, "any": false},
			Lock:   true, Expiry: true, SSH: true},
		VPS: VPSState{UFWDefaultDeny: true, AllowPublic22: false, AllowTailscale: true,
			DockerPublish: false, SSHDListen: "tailnet", PasswordAuth: false, PermitRoot: false},
		Tailnet: true,
	},
}

func presetByID(id string) (Preset, bool) {
	for _, p := range Presets {
		if p.ID == id {
			return p, true
		}
	}
	return Preset{}, false
}

// ---------------------------------------------------------------------------
// The controller: desired state in, real containers out
// ---------------------------------------------------------------------------

type Controller struct {
	lab   *Lab
	mu    sync.Mutex
	state *State

	stateDir string
	// Held back until "tailnet lock" is turned off. An attacker with no key
	// gets no session, which is the property the check is really about.
	untrustedKey string
	log          func(string, ...any)
}

func NewController(lab *Lab, stateDir string) *Controller {
	return &Controller{
		lab: lab, state: defaultState(), stateDir: stateDir,
		log: func(f string, a ...any) { fmt.Printf("[control] "+f+"\n", a...) },
	}
}

func (c *Controller) Snapshot() *State {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, _ := json.Marshal(c.state)
	var out State
	_ = json.Unmarshal(b, &out)
	return &out
}

func (c *Controller) with(fn func(*State)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fn(c.state)
}

// ---------------------------------------------------------------------------
// Observation — read the truth back out of the containers
// ---------------------------------------------------------------------------

type tsPeer struct {
	HostName string
	TailAddr []string `json:"TailscaleIPs"`
	Relay    string
	CurAddr  string
	Online   bool
	Active   bool
}

type tsStatus struct {
	BackendState string
	Self         tsPeer
	Peer         map[string]tsPeer
}

// ---------------------------------------------------------------------------
// Desired state that no container can be asked about
//
// Almost everything in this lab is observed rather than remembered: ufw is
// asked about its rules, sshd about its effective configuration, tailscaled
// about its path. Three things have nowhere to be observed from — whether
// "tailnet lock" is on, and the shape of the policy before it was pushed — so
// they are written to the shared state volume instead of held in memory.
//
// That is not tidiness. `docker compose --profile weak up` runs a *second*
// process, which applies the configuration and exits; without a shared file the
// long-running server keeps its old idea of the policy, refuses to let the
// attacker join because it still thinks lock is on, and then reports that the
// weak configuration held. A score that good for the wrong reason is worse than
// no score.
// ---------------------------------------------------------------------------

type desiredState struct {
	ACL           ACLState     `json:"acl"`
	SegmentShared bool         `json:"segmentShared"`
	Tailcat       TailcatState `json:"tailcat"`
}

func (c *Controller) saveDesired() {
	s := c.Snapshot()
	b, err := json.MarshalIndent(desiredState{
		ACL: s.ACL, SegmentShared: s.SegmentShared, Tailcat: s.Tailcat}, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(c.StateFile("desired.json"), b, 0o644)
}

func (c *Controller) loadDesired() {
	b, err := os.ReadFile(c.StateFile("desired.json"))
	if err != nil {
		return
	}
	var d desiredState
	if err := json.Unmarshal(b, &d); err != nil || d.ACL.Grants == nil {
		return
	}
	c.with(func(s *State) {
		s.ACL = d.ACL
		s.SegmentShared = d.SegmentShared
		// A file written before the tailcat panel existed has the zero value
		// here, and a Host of "" would leave the panel with no machine
		// selected and every command it prints addressed to nowhere.
		if d.Tailcat.Host != "" {
			s.Tailcat = d.Tailcat
		}
	})
}

// Observe reads real state from real containers. Nothing in the UI is believed;
// every switch shown is the switch the machine is actually in.
func (c *Controller) Observe(ctx context.Context) {
	c.loadDesired()
	for _, m := range Catalog {
		running := c.lab.Running(ctx, m.ID)
		ms := &MachineState{Online: running}

		if running {
			ms.LANAddr = c.lab.IPOn(ctx, m.ID, m.LANNet)
			if m.WANNet != "" {
				ms.WANAddr = c.lab.IPOn(ctx, m.ID, m.WANNet)
			}
			if st, err := c.tailscaleStatus(ctx, m.ID); err == nil {
				ms.OnTailnet = st.BackendState == "Running"
				// Only while there is a session. tailscaled keeps reporting the
				// address it was last given after `tailscale down`, and showing
				// it then says "this machine is on the tailnet" when it is not.
				if ms.OnTailnet && len(st.Self.TailAddr) > 0 {
					ms.TSAddr = st.Self.TailAddr[0]
				}
				// Only while the session is actually carrying something. An idle
				// peer reports no current address, which reads as "relay" — and
				// saying "relay" about a pair that has simply not spoken yet is
				// the most misleading thing this whole page could do. Left empty
				// instead, so the drawing says "idle" and invites a probe.
				if m.ID != "lab-vps" {
					for _, p := range st.Peer {
						if p.HostName != "lab-vps" || !p.Active {
							continue
						}
						if p.CurAddr != "" {
							ms.PathTo = "direct"
						} else if p.Relay != "" {
							ms.PathTo = "relay"
						}
					}
				}
			}
		}
		// evil-box has no key it did not steal, so "signed" means the operator
		// deliberately handed it one.
		ms.Signed = ms.OnTailnet
		c.with(func(s *State) {
			old := s.Machines[m.ID]
			ms.KeyExpired = old != nil && old.KeyExpired
			s.Machines[m.ID] = ms
		})
	}

	c.observeLinks(ctx)
	c.observeVPS(ctx)
	c.observeTailcat(ctx)
	c.with(func(s *State) { s.Ready = true })
}

// tsAddr asks the machine for its own tailnet address rather than trusting the
// last observation. The control server can be restarted while the lab keeps
// running, and a cached address that is merely stale is worse than none.
func (c *Controller) tsAddr(ctx context.Context, id string) string {
	r, err := c.lab.Exec(ctx, id, "tailscale", "ip", "-4")
	if err != nil || r.Code != 0 {
		return ""
	}
	return strings.TrimSpace(strings.Split(strings.TrimSpace(r.Stdout), "\n")[0])
}

func (c *Controller) tailscaleStatus(ctx context.Context, id string) (tsStatus, error) {
	var st tsStatus
	r, err := c.lab.Exec(ctx, id, "tailscale", "status", "--json")
	if err != nil || r.Code != 0 {
		return st, fmt.Errorf("tailscale status on %s: %v", id, err)
	}
	if err := json.Unmarshal([]byte(r.Stdout), &st); err != nil {
		return st, err
	}
	return st, nil
}

func (c *Controller) observeLinks(ctx context.Context) {
	for _, m := range Catalog {
		l := &LinkState{Up: true}
		if c.lab.Running(ctx, m.ID) {
			if r, err := c.lab.Sh(ctx, m.ID, `ip -o link show eth0 2>/dev/null || ip -o link show | head -2 | tail -1`); err == nil {
				l.Up = strings.Contains(r.Stdout, "UP") && !strings.Contains(r.Stdout, "NO-CARRIER")
			}
			if r, err := c.lab.Sh(ctx, m.ID, `tc qdisc show dev eth0 2>/dev/null | head -1`); err == nil {
				l.Loss = parseTrailingInt(r.Stdout, "loss ")
				l.Delay = parseTrailingInt(r.Stdout, "delay ")
			}
			if r, err := c.lab.Sh(ctx, m.ID, `nft list ruleset 2>/dev/null | grep -c "udp dport 41641 drop" || true`); err == nil {
				l.UDPBlocked = strings.TrimSpace(r.Stdout) != "0" && strings.TrimSpace(r.Stdout) != ""
			}
		}
		c.with(func(s *State) { s.Links[m.ID] = l })
	}
}

func parseTrailingInt(s, key string) int {
	i := strings.Index(s, key)
	if i < 0 {
		return 0
	}
	rest := s[i+len(key):]
	n := 0
	for n < len(rest) && (rest[n] >= '0' && rest[n] <= '9') {
		n++
	}
	if n == 0 {
		return 0
	}
	v, _ := strconv.Atoi(rest[:n])
	return v
}

func (c *Controller) observeVPS(ctx context.Context) {
	if !c.lab.Running(ctx, "lab-vps") {
		return
	}
	v := VPSState{SSHDListen: "all"}

	if r, err := c.lab.Exec(ctx, "lab-vps", "ufw", "status", "verbose"); err == nil {
		v.readUFW(r.Stdout)
	}
	if r, err := c.lab.Exec(ctx, "lab-vps", "lab-docker-trap", "status"); err == nil {
		v.DockerPublish = strings.TrimSpace(r.Stdout) == "on"
	}
	// Ask sshd what it is actually doing rather than reading a file and hoping.
	// `sshd -T` prints the effective configuration, which is the only version
	// of it that matters.
	if r, err := c.lab.Sh(ctx, "lab-vps",
		`sshd -T 2>/dev/null | grep -iE '^(listenaddress|passwordauthentication|permitrootlogin) '`); err == nil {
		v.readSSHD(r.Stdout)
	}
	c.with(func(s *State) { s.VPS = v })
}

// readUFW turns `ufw status verbose` into the three facts the audit asks it
// for. It is a substring search over a human-readable table, which is fragile
// enough to be worth pinning: "22/tcp" appearing anywhere means the public rule
// is still there, and the row that says so also carries the word ALLOW, so a
// table that ever prints a denied 22/tcp row would read as permitted here.
func (v *VPSState) readUFW(out string) {
	v.UFWDefaultDeny = strings.Contains(out, "deny (incoming)")
	v.AllowTailscale = strings.Contains(out, "on tailscale0")
	v.AllowPublic22 = strings.Contains(out, "22/tcp")
}

// readSSHD turns `sshd -T`'s effective configuration into the three facts three
// of the eleven checks are decided by. Two of them are read as "yes", which
// means anything that is not the word yes — including a line that never
// appeared — is off; that is the safe direction for PasswordAuthentication and
// PermitRootLogin, because reporting them off when they are on is the failure
// that matters, and it cannot happen from a missing line.
//
// ListenAddress is the odd one: sshd prints one line per address, and a machine
// bound to both a tailnet address and 0.0.0.0 is exposed. "tailnet" therefore
// has to mean every printed address is a tailnet one, not that a tailnet one
// appeared somewhere in the list.
func (v *VPSState) readSSHD(out string) {
	listens, tailnet := 0, 0
	for _, line := range strings.Split(strings.ToLower(out), "\n") {
		key, val, _ := strings.Cut(strings.TrimSpace(line), " ")
		switch key {
		case "listenaddress":
			listens++
			if strings.HasPrefix(val, "100.") {
				tailnet++
			}
		case "passwordauthentication":
			v.PasswordAuth = val == "yes"
		case "permitrootlogin":
			v.PermitRoot = val == "yes"
		}
	}
	if listens > 0 && listens == tailnet {
		v.SSHDListen = "tailnet"
	}
}

// ---------------------------------------------------------------------------
// Tailcat — the escape hatch, observed rather than remembered
//
// The sandbox has to be told a tunnel is running. Here there either is a
// process or there is not, and that difference is the whole reason this half
// of the pair was worth building: a tunnel is a thing a machine can be
// inspected for, and the inspection is four lines of shell.
// ---------------------------------------------------------------------------

// tailcatAddrFile is where the serving machine keeps the address it printed,
// and it is deliberately not under /lab/state. That volume is mounted by every
// container in the lab including evil-box, so an address written there would
// already be in the attacker's hands and the "the address got out" switch
// would have nothing left to model.
const tailcatAddrFile = "/run/lab-tailcat.address"

// tailcatLogFile is where the server's own output goes, which is where the
// address comes from in the first place and where a failure to start says why.
const tailcatLogFile = "/var/log/lab-tailcat.log"

// tailcatSharedFile is the address in somebody else's hands. A file on
// evil-box, because that is what "pasted into a chat" leaves behind.
const tailcatSharedFile = "/root/tailcat-address"

// tailcatServices are the three the panel offers, which are three of the five
// tailcat has. `files` and `exit-node` are left out for the same reason the
// sandbox leaves them out: the panel is a shared vocabulary, and a switch on
// one side that does not exist on the other is how the two stop being
// comparable.
var tailcatServices = []string{"ssh", "no-auth-ssh", "all"}

// tailcatHosts is every machine that may run one: the three you own. evil-box
// is not on the list, and that is the lesson rather than an omission — this
// attack starts with somebody on the inside.
func tailcatHosts() []string {
	var out []string
	for _, m := range Catalog {
		if !m.Hostile {
			out = append(out, m.ID)
		}
	}
	return out
}

// readTailcatServe reads `pgrep -af tailcat` output and says what the running
// server is serving. It is a pure function of one string so the panel's idea
// of the tunnel can be tested without a container, and because the alternative
// — believing whatever the last button press asked for — is exactly the kind
// of remembered state this lab exists to avoid.
//
// The service is the last bare argument. Everything tailcat takes before it is
// a --flag, and the flags that carry values carry them with an `=`, so there is
// no argument to skip and no ambiguity to resolve.
func readTailcatServe(pgrepOut string) (running bool, service string, allow bool) {
	for _, line := range strings.Split(pgrepOut, "\n") {
		fields := strings.Fields(line)
		// pgrep -af prints "<pid> <command line>", and a line without a
		// `serve` in it is a client — `tailcat ssh`, or the ProxyCommand it
		// execs — which is not a server and must not read as one.
		if len(fields) < 3 || !containsWord(fields, "serve") {
			continue
		}
		svc := ""
		for _, f := range fields[2:] {
			if strings.HasPrefix(f, "-") {
				if strings.HasPrefix(f, "--allow=") {
					allow = true
				}
				continue
			}
			svc = f
		}
		for _, known := range tailcatServices {
			if svc == known {
				return true, svc, allow
			}
		}
	}
	return false, "", false
}

func containsWord(fields []string, want string) bool {
	for _, f := range fields {
		if f == want {
			return true
		}
	}
	return false
}

// shortTailcatAddr truncates an address for the readouts. The full string is a
// bearer credential: whoever holds it can connect, there is no identity behind
// it and nothing to revoke, so the page shows enough to recognise one and not
// enough to use one. The sandbox truncates its own the same way and to the
// same shape.
func shortTailcatAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if len(addr) <= 24 {
		return addr
	}
	return addr[:16] + "\u2026" + addr[len(addr)-4:]
}

func (c *Controller) observeTailcat(ctx context.Context) {
	found := TailcatState{}
	for _, id := range tailcatHosts() {
		if !c.lab.Running(ctx, id) {
			continue
		}
		// The bracket keeps the search from finding the shell running it: that
		// shell's own command line contains the word being searched for, and a
		// panel that read it would report a tunnel on every machine it asked.
		r, err := c.lab.Sh(ctx, id, `pgrep -af '[t]ailcat' 2>/dev/null || true`)
		if err != nil {
			continue
		}
		running, svc, allow := readTailcatServe(r.Stdout)
		if !running {
			continue
		}
		found = TailcatState{On: true, Host: id, Service: svc, Allow: allow}
		// Only from a machine that is actually serving. A file left behind by
		// a tunnel that has since stopped is a dead address, and printing one
		// as though it were live is the readout telling a lie it cannot be
		// caught in — so stopping a tunnel deletes it, whoever started it.
		//
		// A tunnel somebody started by hand has no file and shows no address,
		// which is the honest answer: the lab found the process by inspecting
		// the machine, and inspecting a machine does not hand you a credential
		// the process only ever printed to whoever ran it.
		if a, err := c.lab.Sh(ctx, id, "cat "+tailcatAddrFile+" 2>/dev/null || true"); err == nil {
			found.Addr = shortTailcatAddr(a.Stdout)
		}
		break
	}

	// Who is holding the address is a fact about evil-box, and it survives the
	// tunnel that produced it — which is the point chapter 01 makes about a
	// saved key and the reason the switch is worth its own line.
	if c.lab.Running(ctx, "evil-box") {
		if r, err := c.lab.Sh(ctx, "evil-box",
			"test -s "+tailcatSharedFile+" && echo yes || true"); err == nil {
			found.Shared = strings.TrimSpace(r.Stdout) == "yes"
		}
	}

	c.with(func(s *State) {
		// With no tunnel running, Host and Service are a choice the reader has
		// made and not an observation, so they are kept rather than blanked.
		if !found.On {
			s.Tailcat.On, s.Tailcat.Allow, s.Tailcat.Addr = false, false, ""
			s.Tailcat.Shared = found.Shared
			return
		}
		s.Tailcat = found
	})
}

// ---------------------------------------------------------------------------
// Bootstrap — CA, coordination server, keys, tags
// ---------------------------------------------------------------------------

func (c *Controller) StateFile(parts ...string) string {
	return filepath.Join(append([]string{c.stateDir}, parts...)...)
}

// Bootstrap waits for the coordination server, creates the lab user and the
// pre-auth keys, and hands the nodes the one they are waiting on. Everything it
// writes lives in a Docker volume and is thrown away by `make reset`.
func (c *Controller) Bootstrap(ctx context.Context) error {
	c.log("waiting for the coordination server…")
	ok := WaitFor(ctx, 3*time.Minute, 2*time.Second, func() bool {
		if !c.lab.Running(ctx, "headscale") {
			return false
		}
		r, err := c.lab.Exec(ctx, "headscale", "headscale", "users", "list", "-o", "json")
		return err == nil && r.Code == 0
	})
	if !ok {
		return fmt.Errorf("the coordination server never answered")
	}

	uid, err := c.ensureUser(ctx, "lab")
	if err != nil {
		return err
	}

	// One reusable key for the three machines you own. The attacker does not
	// get one until you turn "tailnet lock" off — see lab/README.md for why
	// that is the nearest honest equivalent Headscale has.
	//
	// Reusable is what costs these machines the `node.expiry` default: Headscale
	// 0.29 records an expiry at registration for a single-use key and none for a
	// reusable one. Sharing one key through /lab/state/authkey is worth more than
	// the setting — a per-machine key would have to be reissued on every rejoin,
	// and rejoining is something half the buttons in this lab do — so EnsureNodes
	// puts the expiry back afterwards.
	key, err := c.createKey(ctx, uid)
	if err != nil {
		return err
	}
	if err := os.WriteFile(c.StateFile("authkey"), []byte(key), 0o600); err != nil {
		return err
	}
	c.untrustedKey, err = c.createKey(ctx, uid)
	if err != nil {
		return err
	}
	c.log("pre-auth key written; the machines can join now")

	// Give the policy a shape before anyone asks for one.
	if err := c.applyPolicy(ctx); err != nil {
		c.log("initial policy: %v", err)
	}
	return nil
}

func (c *Controller) ensureUser(ctx context.Context, name string) (uint64, error) {
	if id, err := c.findUser(ctx, name); err == nil {
		return id, nil
	}
	if _, err := c.lab.Exec(ctx, "headscale", "headscale", "users", "create", name); err != nil {
		return 0, err
	}
	return c.findUser(ctx, name)
}

func (c *Controller) findUser(ctx context.Context, name string) (uint64, error) {
	r, err := c.lab.Exec(ctx, "headscale", "headscale", "users", "list", "-o", "json")
	if err != nil {
		return 0, err
	}
	var users []struct {
		ID   json.Number `json:"id"`
		Name string      `json:"name"`
	}
	if err := json.Unmarshal([]byte(r.Stdout), &users); err != nil {
		return 0, err
	}
	for _, u := range users {
		if u.Name == name {
			v, err := strconv.ParseUint(u.ID.String(), 10, 64)
			return v, err
		}
	}
	return 0, fmt.Errorf("no user %q yet", name)
}

func (c *Controller) createKey(ctx context.Context, uid uint64) (string, error) {
	r, err := c.lab.Exec(ctx, "headscale", "headscale", "preauthkeys", "create",
		"-u", strconv.FormatUint(uid, 10), "--reusable", "-e", "720h", "-o", "json")
	if err != nil {
		return "", err
	}
	var k struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal([]byte(r.Stdout), &k); err != nil {
		return "", fmt.Errorf("pre-auth key: %w (%s)", err, r.Out())
	}
	if k.Key == "" {
		return "", fmt.Errorf("pre-auth key came back empty: %s", r.Out())
	}
	return k.Key, nil
}

// ---------------------------------------------------------------------------
// Headscale nodes
// ---------------------------------------------------------------------------

// hsTime is a protobuf timestamp, which is what headscale's JSON output emits
// for every time field. It looks like a string in the human-readable table and
// is an object on the wire; decoding it as a string makes every call to
// `nodes list` fail the moment one node actually has an expiry, which is a
// quiet way to break the whole control server.
type hsTime struct {
	Seconds int64 `json:"seconds"`
	Nanos   int64 `json:"nanos"`
}

func (t *hsTime) Time() time.Time {
	if t == nil || t.Seconds == 0 {
		return time.Time{}
	}
	return time.Unix(t.Seconds, t.Nanos)
}

type hsNode struct {
	ID        json.Number `json:"id"`
	Name      string      `json:"name"`
	GivenName string      `json:"given_name"`
	// The tags the node carries. Headscale called this `forced_tags` up to
	// 0.26 and renamed it `tags` in 0.29, at the same time as it started
	// describing `headscale nodes tag` as "converting a user-owned node to a
	// tagged node". Reading the old name against a new server decodes to
	// nothing, which EnsureNodes cannot tell apart from an untagged node.
	Tags   []string `json:"tags"`
	Expiry *hsTime  `json:"expiry"`
	Online bool     `json:"online"`
	// The node key, which is the thing a rotation is supposed to replace. It
	// is read rather than assumed: `tailscale up --force-reauth` is what the
	// rotate button runs, and whether the coordination server ends up holding
	// a different key for the same machine is a fact about this Headscale, not
	// a promise the guide gets to make on its behalf. Empty when the field is
	// absent, which the caller reports as "not measured" rather than "unchanged".
	NodeKey string `json:"node_key"`
}

func (c *Controller) nodes(ctx context.Context) ([]hsNode, error) {
	r, err := c.lab.Exec(ctx, "headscale", "headscale", "nodes", "list", "-o", "json")
	if err != nil {
		return nil, err
	}
	var ns []hsNode
	if err := json.Unmarshal([]byte(r.Stdout), &ns); err != nil {
		return nil, fmt.Errorf("nodes list: %w (%s)", err, r.Out())
	}
	return ns, nil
}

func (c *Controller) nodeFor(ctx context.Context, host string) (hsNode, bool) {
	ns, err := c.nodes(ctx)
	if err != nil {
		return hsNode{}, false
	}
	for _, n := range ns {
		if n.Name == host || n.GivenName == host {
			return n, true
		}
	}
	return hsNode{}, false
}

// nodeExpiry is how long a registration lasts before the machine has to
// reauthenticate — 180 days, because that is Tailscale's default and the
// control surface's toggle says so out loud.
//
// It lives here rather than only in config/headscale/config.yaml because
// `node.expiry` does not reach the machines in this lab. That was measured:
// Headscale 0.29.3 records an expiry at registration for a *single-use*
// pre-auth key and records none at all for a `--reusable` one, and this lab
// hands the same reusable key to all three machines through
// /lab/state/authkey. So the yaml setting is real and simply does not apply,
// and EnsureNodes stamps the expiry on afterwards instead.
const nodeExpiry = 4320 * time.Hour

// EnsureNodes reconciles the three things a registration needs after the
// machine has joined: no stale duplicates, the right tag, and an expiry.
//
// Tags are what turn "this specific laptop" into "any laptop", and every grant
// in this lab is written against them.
//
// The expiry is stamped only when the node has none. That is what keeps this
// idempotent — re-running it must not slide the date forward every few seconds
// — and it is also what keeps it out of the way of `atkExpiredKey`, which sets
// an expiry in the *past* to show a lost device dropping out. Re-stamping that
// would quietly undo the demonstration. A machine that re-registers afterwards
// comes back with no expiry and gets a fresh one here, which is the behaviour
// you want.
//
// This used to restart the coordination server whenever a tag changed, and the
// restart was not tidiness: Headscale 0.26's policy manager held its own
// snapshot of the nodes and did not refresh it when `headscale nodes tag`
// changed one, so a tag applied while it was running was visible in
// `headscale nodes list` and invisible to every ACL — every rule mentioning it
// silently compiled to nothing and the reader got a rung-3 denial with no
// explanation.
//
// 0.29 fixed it, and that was measured rather than read: with the coordination
// server left running, retagging `lab-vps` away from `tag:server` closes the
// grant within seconds and retagging it back opens it again, and the same
// holds for `lab-ubuntu` on the source side of the same rule. So the restart
// is gone. If it ever comes back, it will look like a grant that stops working
// after a configuration change and starts again after `docker restart
// headscale`.
func (c *Controller) EnsureNodes(ctx context.Context) {
	ns, err := c.nodes(ctx)
	if err != nil {
		return
	}
	for _, n := range ns {
		m, ok := machineByID(n.GivenName)
		if !ok {
			if m, ok = machineByID(n.Name); !ok {
				// A registration for a machine that no longer exists. Headscale
				// renames the duplicate rather than refusing it, so these pile
				// up quietly and then `tailscale status` lists ghosts.
				c.log("removing a stale registration: %s", n.GivenName)
				_, _ = c.lab.Exec(ctx, "headscale", "headscale", "nodes", "delete",
					"-i", n.ID.String(), "--force")
				continue
			}
		}
		if n.Expiry.Time().IsZero() {
			until := time.Now().Add(nodeExpiry).UTC().Format(time.RFC3339)
			if _, err := c.lab.Exec(ctx, "headscale", "headscale", "nodes", "expire",
				"-i", n.ID.String(), "-e", until, "--force"); err != nil {
				c.log("expiry for %s: %v", m.ID, err)
			} else {
				c.log("%s now expires at %s", m.ID, until)
			}
		}

		if len(n.Tags) == 1 && n.Tags[0] == m.Tag {
			continue
		}
		if _, err := c.lab.Exec(ctx, "headscale", "headscale", "nodes", "tag",
			"-i", n.ID.String(), "-t", m.Tag); err != nil {
			c.log("tagging %s: %v", m.ID, err)
		} else {
			c.log("tagged %s as %s", m.ID, m.Tag)
		}
	}
}

func decodeJSON(r io.Reader, v any) error { return json.NewDecoder(r).Decode(v) }
