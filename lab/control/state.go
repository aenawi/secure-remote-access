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

type State struct {
	Machines      map[string]*MachineState `json:"machines"`
	Links         map[string]*LinkState    `json:"links"`
	SegmentShared bool                     `json:"segmentShared"`
	ACL           ACLState                 `json:"acl"`
	VPS           VPSState                 `json:"vps"`

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
	ACL           ACLState `json:"acl"`
	SegmentShared bool     `json:"segmentShared"`
}

func (c *Controller) saveDesired() {
	s := c.Snapshot()
	b, err := json.MarshalIndent(desiredState{ACL: s.ACL, SegmentShared: s.SegmentShared}, "", "  ")
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
				if len(st.Self.TailAddr) > 0 {
					ms.TSAddr = st.Self.TailAddr[0]
				}
				if m.ID != "lab-vps" {
					for _, p := range st.Peer {
						if p.HostName == "lab-vps" {
							if p.Relay != "" && p.CurAddr == "" {
								ms.PathTo = "relay"
							} else if p.CurAddr != "" {
								ms.PathTo = "direct"
							}
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
		out := r.Stdout
		v.UFWDefaultDeny = strings.Contains(out, "deny (incoming)")
		v.AllowTailscale = strings.Contains(out, "on tailscale0")
		v.AllowPublic22 = strings.Contains(out, "22/tcp")
	}
	if r, err := c.lab.Exec(ctx, "lab-vps", "lab-docker-trap", "status"); err == nil {
		v.DockerPublish = strings.TrimSpace(r.Stdout) == "on"
	}
	// Ask sshd what it is actually doing rather than reading a file and hoping.
	// `sshd -T` prints the effective configuration, which is the only version
	// of it that matters.
	if r, err := c.lab.Sh(ctx, "lab-vps",
		`sshd -T 2>/dev/null | grep -iE '^(listenaddress|passwordauthentication|permitrootlogin) '`); err == nil {
		for _, line := range strings.Split(strings.ToLower(r.Stdout), "\n") {
			key, val, _ := strings.Cut(strings.TrimSpace(line), " ")
			switch key {
			case "listenaddress":
				if strings.HasPrefix(val, "100.") {
					v.SSHDListen = "tailnet"
				}
			case "passwordauthentication":
				v.PasswordAuth = val == "yes"
			case "permitrootlogin":
				v.PermitRoot = val == "yes"
			}
		}
	}
	c.with(func(s *State) { s.VPS = v })
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
	ID         json.Number `json:"id"`
	Name       string      `json:"name"`
	GivenName  string      `json:"given_name"`
	ForcedTags []string    `json:"forced_tags"`
	Expiry     *hsTime     `json:"expiry"`
	Online     bool        `json:"online"`
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

// EnsureTags gives every machine the tag the policy talks about. Tags are what
// turn "this specific laptop" into "any laptop", and every grant in this lab is
// written against them.
//
// The restart at the end is not tidiness. Headscale 0.26's policy manager holds
// its own snapshot of the nodes and does not refresh it when `headscale nodes
// tag` changes one, so a tag applied while it is running is visible in
// `headscale nodes list` and invisible to every ACL — every rule mentioning
// that tag silently compiles to nothing, and the reader gets a rung-3 denial
// with no explanation. Restarting is the cheapest honest fix; the nodes
// reconnect on their own within a few seconds. If a later Headscale drops this
// behaviour, drop the restart with it.
func (c *Controller) EnsureTags(ctx context.Context) {
	ns, err := c.nodes(ctx)
	if err != nil {
		return
	}
	changed := false
	defer func() {
		if !changed {
			return
		}
		c.log("tags changed — restarting the coordination server so its policy sees them")
		if err := c.lab.Restart(ctx, "headscale"); err != nil {
			c.log("restarting headscale: %v", err)
			return
		}
		WaitFor(ctx, 60*time.Second, 2*time.Second, func() bool {
			_, err := c.nodes(ctx)
			return err == nil
		})
		if err := c.applyPolicy(ctx); err != nil {
			c.log("re-pushing the policy: %v", err)
		}
	}()
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
				changed = true
				continue
			}
		}
		if len(n.ForcedTags) == 1 && n.ForcedTags[0] == m.Tag {
			continue
		}
		if _, err := c.lab.Exec(ctx, "headscale", "headscale", "nodes", "tag",
			"-i", n.ID.String(), "-t", m.Tag); err != nil {
			c.log("tagging %s: %v", m.ID, err)
		} else {
			c.log("tagged %s as %s", m.ID, m.Tag)
			changed = true
		}
	}
}

func decodeJSON(r io.Reader, v any) error { return json.NewDecoder(r).Decode(v) }
