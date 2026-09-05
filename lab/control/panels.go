// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hashem Aldhaheri

package main

// ---------------------------------------------------------------------------
// The control panels
//
// Declared here rather than written into the markup, for the same reason the
// sandbox page declares its own: the panel names, the switch labels and the
// order they appear in are the shared vocabulary between the two halves of this
// pair, and a shared vocabulary that lives in two hand-written HTML files stops
// being shared within a week.
//
// Machines / The network / Tailnet policy / The host — same four panels, same
// four titles, same switches, in the same order as chapter 14.
// ---------------------------------------------------------------------------

type Row struct {
	T      string   `json:"t"` // toggle | seg | grants | linkgrid | hr
	Path   string   `json:"p,omitempty"`
	Label  string   `json:"label,omitempty"`
	Sub    string   `json:"sub,omitempty"`
	Danger bool     `json:"danger,omitempty"`
	Dep    string   `json:"dep,omitempty"`
	Opts   []Option `json:"options,omitempty"`
	Note   string   `json:"note,omitempty"`
}

type Option struct {
	V string `json:"v"`
	L string `json:"l"`
}

type Panel struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Note  string `json:"note"`
	Rows  []Row  `json:"rows"`
}

var Panels = []Panel{
	{
		ID: "machines", Title: "Machines",
		Note: "Who is running, and who the tailnet will accept.",
		Rows: []Row{
			{T: "toggle", Path: "machines.lab-vps.online", Label: "lab-vps",
				Sub: "the public box · chapter 08"},
			{T: "toggle", Path: "machines.lab-ubuntu.online", Label: "lab-ubuntu",
				Sub: "the laptop · chapter 09"},
			{T: "toggle", Path: "machines.lab-roam.online", Label: "lab-roam",
				Sub: "the phone's stand-in · chapter 03"},
			{T: "hr"},
			{T: "toggle", Path: "machines.evil-box.online", Label: "evil-box", Danger: true,
				Sub: "a hostile machine, on your network — needs --profile attack"},
			{T: "toggle", Path: "machines.evil-box.onTailnet", Label: "…hand it a node key",
				Sub: "as if one leaked from a backup", Danger: true,
				Dep: "machines.evil-box.online"},
			{T: "toggle", Path: "machines.evil-box.signed", Label: "…and let a peer accept it",
				Sub:    "what an attacker cannot do without something vouching for the key",
				Danger: true, Dep: "machines.evil-box.onTailnet"},
			{T: "toggle", Path: "segmentShared", Label: "Put evil-box on lab-ubuntu's segment",
				Sub: "the on-path position — a café, an office switch"},
		},
	},
	{
		ID: "network", Title: "The network",
		Note: "The three levers chapter 13 shapes with tc and nft. These run them.",
		Rows: []Row{{T: "linkgrid"}},
	},
	{
		ID: "policy", Title: "Tailnet policy",
		Note: "Who may talk to whom, before any host firewall is consulted.",
		Rows: []Row{
			{T: "seg", Path: "acl.def", Label: "Default action",
				Opts: []Option{{V: "deny", L: "deny"}, {V: "accept", L: "accept"}}},
			{T: "grants"},
			{T: "hr"},
			{T: "toggle", Path: "acl.lock", Label: "Tailnet lock",
				Sub: "no key exists for a machine you did not authorise — see the README"},
			{T: "toggle", Path: "acl.expiry", Label: "Key expiry (180 days)",
				Sub: "a stolen key stops working on its own"},
			{T: "toggle", Path: "acl.ssh", Label: "Tailscale SSH",
				Sub: "the tailnet checks the login, not just the route"},
		},
	},
	{
		ID: "host", Title: "The host — lab-vps",
		Note: "Everything here runs on the box itself, after the tailnet has had its say.",
		Rows: []Row{
			{T: "toggle", Path: "vps.ufwDefaultDeny", Label: "UFW default deny (incoming)"},
			{T: "toggle", Path: "vps.allowTailscale0", Label: "allow in on tailscale0",
				Sub: "your way in once :22 is shut"},
			{T: "toggle", Path: "vps.allowPublic22", Label: "allow 22/tcp from anywhere",
				Sub: "the rule the whole guide builds towards deleting"},
			{T: "hr"},
			{T: "toggle", Path: "vps.dockerPublish", Label: "publish a container port on :8080",
				Sub: "writes the chains dockerd writes — ufw cannot see them", Danger: true},
			{T: "hr"},
			{T: "seg", Path: "vps.sshdListen", Label: "sshd ListenAddress",
				Opts: []Option{{V: "all", L: "0.0.0.0"}, {V: "tailnet", L: "the tailnet address only"}}},
			{T: "toggle", Path: "vps.passwordAuth", Label: "PasswordAuthentication yes", Danger: true},
			{T: "toggle", Path: "vps.permitRoot", Label: "PermitRootLogin yes", Danger: true},
		},
	},
}
