/* Chapter index. Defined as a plain global (not fetched) so the guide works
   from file:// — fetch() is blocked on the file: scheme in most browsers. */
window.GUIDE_NAV = [
  { group: "Start here", items: [
    { n: "00", id: "index",            file: "index.html",                          title: "Overview & architecture",
      desc: "What you are building, the three planes it rests on, and how the pieces fit." },
  ]},
  { group: "The technologies", items: [
    { n: "01", id: "tailscale",        file: "chapters/01-tailscale.html",           title: "Tailscale & WireGuard",
      desc: "Mesh VPN, NAT traversal, DERP relays, ACLs, tailnet lock, MagicDNS." },
    { n: "02", id: "ssh",              file: "chapters/02-ssh.html",                 title: "SSH, keys & hardening",
      desc: "Key cryptography, the auth handshake, sshd config, host keys, agents." },
    { n: "03", id: "mosh-blink",       file: "chapters/03-mosh-blink.html",          title: "Mosh & Blink Shell",
      desc: "Why SSH drops on mobile, how Mosh's state-sync protocol fixes it." },
    { n: "04", id: "tmux-herdr",       file: "chapters/04-tmux-herdr.html",          title: "tmux & Herdr",
      desc: "Session persistence, agent multiplexing, and the nesting problem." },
  ]},
  { group: "Build it", items: [
    { n: "05", id: "macos",            file: "chapters/05-macos.html",               title: "Securing the MacBook Pro",
      desc: "FileVault, firewall, sshd as a launchd daemon, tailnet-only binding." },
    { n: "06", id: "iphone",           file: "chapters/06-iphone.html",              title: "The iPhone client",
      desc: "Blink Shell, Secure Enclave keys, Tailscale on iOS, Mosh profiles." },
    { n: "07", id: "android",          file: "chapters/07-android.html",             title: "The Android client",
      desc: "Termux, hardware-backed keys, and the battery settings that kill sessions." },
    { n: "08", id: "vps",              file: "chapters/08-vps.html",                 title: "Hardening a Linux VPS",
      desc: "First-10-minutes, firewall, SSH lockdown, fail2ban, auto-updates." },
    { n: "09", id: "ubuntu",           file: "chapters/09-ubuntu.html",              title: "The Ubuntu laptop",
      desc: "LUKS, UFW, Secure Boot, and joining the same tailnet." },
  ]},
  { group: "Operate it", items: [
    { n: "10", id: "threat-model",     file: "chapters/10-threat-model.html",        title: "Threat model & key custody",
      desc: "What you are defending against, where keys live, and blast radius." },
    { n: "11", id: "runbooks",         file: "chapters/11-runbooks.html",            title: "Runbooks & checklists",
      desc: "Day-one build order, rotation, onboarding a device, offboarding." },
    { n: "12", id: "troubleshooting",  file: "chapters/12-troubleshooting.html",     title: "Troubleshooting",
      desc: "A diagnostic ladder for connections that fail, hang, or drop." },
  ]},
  { group: "Prove it", items: [
    { n: "13", id: "lab",              file: "chapters/13-lab.html",                 title: "The lab",
      desc: "Build the topology as throwaway VMs, shape the network, and prove the guide works." },
    { n: "14", id: "sandbox",         file: "sandbox.html",                   title: "The sandbox",
      desc: "An operable model of the whole topology: flip a switch, add a hostile machine, read what breaks." },
  ]},
];

/* Flat list for prev/next paging. */
window.GUIDE_FLAT = window.GUIDE_NAV.reduce(function (acc, g) {
  return acc.concat(g.items);
}, []);
