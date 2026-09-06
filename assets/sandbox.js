/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Hashem Aldhaheri */

/* ============================================================
   sandbox.js — an operable model of the guide's topology.

   Every other diagram in this guide is a scripted timeline: the
   author decided what happens on step 3. This one has no timeline.
   It has state, a rules engine, and a render. You change the state;
   the engine decides the consequence. That is the whole difference,
   and it is why you can ask it a question nobody wrote down.

   The engine walks the same five-rung ladder chapter 12 teaches,
   in the same order, and reports the rung that decided the outcome —
   never a bare true/false.

     1  is the machine up, and is anything leaving it?
     2  is there a path at all, and is it the tailnet or the ordinary network?
     3  does the tailnet policy allow this?
     4  does the host firewall allow this?
     5  is anything actually listening, on an address this path reaches?

   Real, not modelled: the X25519/ECDH keypairs, the shared-secret
   derivation and the AES-GCM seal. When evil-box fails to open a
   captured frame it is because the cipher rejected it, in your
   browser, not because a script said so. See Crypto below.

   Two rules here were rewritten by lab/, which runs this same
   topology as containers: a machine behind a NAT has no inbound
   address at all, and `netcheck` measures UDP rather than
   WireGuard's port. Both were modelled wrongly until the real
   thing disagreed. Where the two still differ, lab/README.md
   says where and why — that pair is the point of having both.

   Progressive enhancement: with JS off the page keeps a static
   poster and the topology SVG. sandbox.js adds .sb-on and takes over.
   ============================================================ */
(function () {
  "use strict";

  var root = document.querySelector("[data-sandbox]");
  if (!root) return;

  var svg = root.querySelector("svg");
  var reduced = window.matchMedia("(prefers-reduced-motion: reduce)");

  /* ============================================================
     1 · The machines
     ============================================================ */

  /* Two different facts about NAT, and they are not the same one:

       nat      how hard the outbound punch is — easy, hard, or none at all
       natName  the router doing it, when there is one

     A machine with a natName sits behind something that masquerades outbound
     and forwards nothing in. It therefore has no inbound address at all, which
     is what a laptop on a home network actually looks like, and which the
     containers in lab/ proved this model had wrong. lab-vps has no natName,
     because it is the public box and the whole guide turns on that. */
  var CATALOG = [
    { id: "lab-vps", label: "lab-vps", role: "the public box", chapter: "08",
      ts: "100.71.4.11", lan: "10.0.11.2", pub: "203.0.113.11",
      nat: "none", natName: null, tag: "tag:server" },
    { id: "lab-ubuntu", label: "lab-ubuntu", role: "the laptop", chapter: "09",
      ts: "100.71.4.13", lan: "10.0.13.2", pub: "198.51.100.13",
      nat: "easy", natName: "nat-ubuntu", tag: "tag:laptop" },
    { id: "lab-roam", label: "lab-roam", role: "the phone's stand-in", chapter: "03",
      ts: "100.71.4.27", lan: "10.0.27.2", pub: "198.51.100.27",
      nat: "hard", natName: "nat-roam", tag: "tag:roam" },
    { id: "evil-box", label: "evil-box", role: "a hostile machine", chapter: "10",
      ts: "100.71.4.99", lan: "10.0.66.2", lanShared: "10.0.13.66", pub: "192.0.2.66",
      nat: "easy", natName: "nat-evil", tag: "tag:untrusted", hostile: true }
  ];

  var BY_ID = {};
  CATALOG.forEach(function (m) { BY_ID[m.id] = m; });

  /* The grants offered in the policy panel. Order matters: the engine
     takes the first match, exactly as Tailscale does. */
  var GRANTS = [
    { key: "laptop", src: "tag:laptop", dst: "tag:server", ports: ["22"],
      label: "tag:laptop → tag:server : 22" },
    { key: "roam", src: "tag:roam", dst: "tag:server", ports: ["22"],
      label: "tag:roam → tag:server : 22" },
    { key: "untrusted", src: "tag:untrusted", dst: "*", ports: ["*"],
      label: "tag:untrusted → * : *", danger: true,
      sub: "one tag, given everything — the over-broad grant" },
    { key: "any", src: "*", dst: "*", ports: ["*"],
      label: "* → * : *", danger: true,
      sub: "membership becomes total access — the default nobody meant to keep" }
  ];

  var LOSS_STEPS = [0, 5, 20, 40];
  var DELAY_STEPS = [0, 40, 180];

  /* ---- named configurations ----------------------------------------
     Four states worth comparing. "Typical" is the one that matters most:
     it is not a strawman, it is the half-done configuration of somebody
     who did the interesting part and stopped. Its audit score is barely
     above the fresh box, and that is the lesson. */
  var PRESETS = [
    {
      id: "day-one", label: "Day one", tone: "danger",
      sub: "a fresh VPS, an hour old, nothing done to it yet",
      note: "Root can log in with a password from anywhere on earth, and the " +
            "scanners already know the address exists. Every guide starts here.",
      acl: { def: "accept", grants: { laptop: false, roam: false, untrusted: false, any: false },
             lock: false, expiry: false, ssh: false },
      vps: { ufwDefaultDeny: false, allowPublic22: true, allowTailscale0: false,
             dockerPublish: false, sshdListen: "all", passwordAuth: true, permitRoot: true },
      tailnet: false
    },
    {
      id: "typical", label: "Typical", tone: "warn",
      sub: "the half-done state most people are actually in",
      note: "Keys instead of passwords, a tailnet up and working — the visible half " +
            "of the job, done properly. Then it stopped: :22 is still open to the " +
            "internet, the policy still permits everything, and a container has " +
            "published a port nobody audited.",
      acl: { def: "accept", grants: { laptop: true, roam: true, untrusted: false, any: true },
             lock: false, expiry: false, ssh: true },
      vps: { ufwDefaultDeny: true, allowPublic22: true, allowTailscale0: true,
             dockerPublish: true, sshdListen: "all", passwordAuth: false, permitRoot: false },
      tailnet: true
    },
    {
      id: "weak", label: "Weak", tone: "danger",
      sub: "choices were made here, and they were the wrong ones",
      note: "Every protection that got in somebody's way was switched off on purpose: " +
            "lock disabled, expiry disabled, the firewall opened, passwords and root " +
            "login re-enabled 'temporarily'. Worse than the fresh box, because it " +
            "looks configured.",
      acl: { def: "accept", grants: { laptop: true, roam: true, untrusted: true, any: true },
             lock: false, expiry: false, ssh: false },
      vps: { ufwDefaultDeny: false, allowPublic22: true, allowTailscale0: true,
             dockerPublish: true, sshdListen: "all", passwordAuth: true, permitRoot: true },
      tailnet: true
    },
    {
      id: "hardened", label: "Hardened", tone: "ok",
      sub: "what chapters 01 through 11 build towards",
      note: "Default-deny policy with two narrow grants, tailnet lock signing every " +
            "node key, expiry on, public :22 gone, and sshd bound to the tailnet " +
            "address so it never even sees a packet from eth0.",
      acl: { def: "deny", grants: { laptop: true, roam: true, untrusted: false, any: false },
             lock: true, expiry: true, ssh: true },
      vps: { ufwDefaultDeny: true, allowPublic22: false, allowTailscale0: true,
             dockerPublish: false, sshdListen: "tailnet", passwordAuth: false, permitRoot: false },
      tailnet: true
    }
  ];

  /* Human names for the diff between two configurations. */
  var LABELS = {
    "acl.def": "tailnet default action",
    "acl.lock": "tailnet lock",
    "acl.expiry": "key expiry",
    "acl.ssh": "Tailscale SSH",
    "acl.grants.laptop": "grant · tag:laptop → tag:server:22",
    "acl.grants.roam": "grant · tag:roam → tag:server:22",
    "acl.grants.untrusted": "grant · tag:untrusted → *:*",
    "acl.grants.any": "grant · * → *:*",
    "vps.ufwDefaultDeny": "UFW default deny incoming",
    "vps.allowPublic22": "public 22/tcp allowed",
    "vps.allowTailscale0": "allow in on tailscale0",
    "vps.dockerPublish": "Docker publishes :8080",
    "vps.sshdListen": "sshd ListenAddress",
    "vps.passwordAuth": "PasswordAuthentication",
    "vps.permitRoot": "PermitRootLogin",
    "tailcat.on": "tailcat serve running",
    "tailcat.host": "tailcat serve · host",
    "tailcat.service": "tailcat serve · service",
    "tailcat.allow": "tailcat --allow pins one client key",
    "tailcat.shared": "tailcat address held by evil-box"
  };

  /* A tailcat address is one long opaque string, not an address your network
     means anything by. Truncated ones, fixed per machine, so the packet log
     reads like the real thing and there is visibly nothing here to write a
     firewall rule against. */
  var TAILCAT_ADDR = {
    "lab-vps":    "tcomFwWCCcjS5nKN…dKdn",
    "lab-ubuntu": "tcq7Xb2LhVn0PsAe…R4mv",
    "lab-roam":   "tck93Twz1BdQfYuC…8HtL",
    "evil-box":   "tcZx4Nc7pKrLg2Vm…s10Q"
  };

  /* ============================================================
     2 · State
     ============================================================ */

  function defaults() {
    return {
      machines: {
        "lab-vps":    { online: true,  onTailnet: true,  signed: true,  keyExpired: false },
        "lab-ubuntu": { online: true,  onTailnet: true,  signed: true,  keyExpired: false },
        "lab-roam":   { online: true,  onTailnet: true,  signed: true,  keyExpired: false },
        "evil-box":   { online: false, onTailnet: false, signed: false, keyExpired: false }
      },
      links: {
        "lab-vps":    { up: true, loss: 0, delay: 0, udpBlocked: false },
        "lab-ubuntu": { up: true, loss: 0, delay: 0, udpBlocked: false },
        "lab-roam":   { up: true, loss: 0, delay: 0, udpBlocked: false },
        "evil-box":   { up: true, loss: 0, delay: 0, udpBlocked: false }
      },
      segmentShared: false,
      acl: {
        def: "deny",
        grants: { laptop: true, roam: true, untrusted: false, any: false },
        lock: true,
        expiry: true,
        ssh: true
      },
      vps: {
        ufwDefaultDeny: true,
        allowPublic22: true,
        allowTailscale0: true,
        dockerPublish: false,
        sshdListen: "all",
        passwordAuth: false,
        permitRoot: false
      },
      /* The escape hatch from chapter 01, off until somebody runs it. When it
         comes on it starts in the shape that chapter recommends — `serve ssh`
         against real authorized_keys, address still in your own hands — so
         every switch below it is a deliberate step away from the advice. */
      tailcat: {
        on: false,
        host: "lab-ubuntu",
        service: "ssh",
        allow: false,
        shared: false
      },
      probe: { from: "lab-ubuntu", to: "lab-vps", port: "22" }
    };
  }

  var S = defaults();
  var script = [];   /* the real commands, in the order they were provoked */
  var log = [];      /* the packet log */

  function get(path) {
    return path.split(".").reduce(function (o, k) {
      return o == null ? undefined : o[k];
    }, S);
  }

  function set(path, v) {
    var parts = path.split(".");
    var last = parts.pop();
    var host = parts.reduce(function (o, k) { return o[k]; }, S);
    host[last] = v;
  }

  /* ============================================================
     3 · Crypto — the one part of this page that is not a model
     ============================================================ */

  var Crypto = {
    mode: "pending",   /* x25519 | p256 | none */
    keys: {},
    note: "",

    init: function () {
      var subtle = window.crypto && window.crypto.subtle;
      if (!subtle) {
        Crypto.mode = "none";
        Crypto.note = "This browser exposes no WebCrypto here, so the frames below " +
          "are placeholder bytes. Serve the page over http:// or https:// to get real ones.";
        return Promise.resolve();
      }
      return Crypto.tryCurve({ name: "X25519" })
        .then(function () {
          Crypto.mode = "x25519";
          Crypto.note = "Real X25519 keypairs, generated in this tab — the same curve " +
            "WireGuard uses.";
        })
        .catch(function () {
          return Crypto.tryCurve({ name: "ECDH", namedCurve: "P-256" })
            .then(function () {
              Crypto.mode = "p256";
              Crypto.note = "This browser has no X25519, so these are real ECDH P-256 " +
                "keypairs instead. Genuine cryptography, a different curve from WireGuard's.";
            })
            .catch(function () {
              Crypto.mode = "none";
              Crypto.note = "Key generation was refused here, so the frames below are " +
                "placeholder bytes rather than real ciphertext.";
            });
        });
    },

    tryCurve: function (algo) {
      var ids = CATALOG.map(function (m) { return m.id; });
      return Promise.all(ids.map(function () {
        return window.crypto.subtle.generateKey(algo, false, ["deriveBits"]);
      })).then(function (pairs) {
        Crypto.algo = algo;
        Crypto.keys = {};
        ids.forEach(function (id, i) { Crypto.keys[id] = pairs[i]; });
      });
    },

    /* ECDH -> HKDF -> AES-GCM, the shape of a real session key schedule. */
    sessionKey: function (mineId, theirsId) {
      var algo = Crypto.algo.name === "X25519"
        ? { name: "X25519", public: Crypto.keys[theirsId].publicKey }
        : { name: "ECDH", public: Crypto.keys[theirsId].publicKey };
      return window.crypto.subtle
        .deriveBits(algo, Crypto.keys[mineId].privateKey, 256)
        .then(function (bits) {
          return window.crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
        })
        .then(function (ikm) {
          return window.crypto.subtle.deriveKey(
            { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32),
              info: new TextEncoder().encode("secure-remote-access/lab") },
            ikm, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
          );
        });
    },

    seal: function (fromId, toId, text, counter) {
      var iv = new Uint8Array(12);
      iv[11] = counter & 0xff;
      iv[10] = (counter >> 8) & 0xff;
      if (Crypto.mode === "none") {
        return Promise.resolve({
          iv: iv, bytes: mockBytes(text.length + 16), fake: true, counter: counter
        });
      }
      return Crypto.sessionKey(fromId, toId)
        .then(function (key) {
          return window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv }, key, new TextEncoder().encode(text)
          );
        })
        .then(function (buf) {
          return { iv: iv, bytes: new Uint8Array(buf), fake: false, counter: counter };
        });
    },

    /* Deliberately called with the wrong identity. It must fail. */
    open: function (asId, fromId, frame) {
      if (Crypto.mode === "none") {
        return Promise.reject(new Error(
          "no key material — this browser refused to generate any"));
      }
      return Crypto.sessionKey(asId, fromId)
        .then(function (key) {
          return window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: frame.iv }, key, frame.bytes
          );
        })
        .then(function (buf) { return new TextDecoder().decode(buf); });
    }
  };

  function mockBytes(n) {
    var a = new Uint8Array(n);
    for (var i = 0; i < n; i++) a[i] = (i * 37 + 11) & 0xff;
    return a;
  }

  function hex(bytes, max) {
    var out = [], n = Math.min(bytes.length, max || bytes.length);
    for (var i = 0; i < n; i++) {
      out.push(("0" + bytes[i].toString(16)).slice(-2));
    }
    var s = out.join(" ");
    return bytes.length > n ? s + " …" : s;
  }

  /* ============================================================
     4 · The engine
     ============================================================ */

  function tagOf(id) { return BY_ID[id].tag; }

  /* Membership is a property of the key, not of the wire. A machine that is
     switched off is still a member; a machine whose key nobody signed is not
     one however healthy its link. Liveness is rung 1's question and is asked
     there, which is why this function no longer asks it.

     Keeping the two apart matters more than it looks. This page used to refuse
     an unsigned or expired key at rung 1, which meant tailnet lock stopped
     traffic it has no say over — a plain TCP connection to a public address,
     nothing to do with the tailnet at all. A node the tailnet refuses is simply
     not on the tailnet, so choosePath falls through to the ordinary network and
     whatever was publicly reachable stays publicly reachable. */
  function onTailnet(id) {
    var m = S.machines[id];
    if (!m.onTailnet) return false;
    if (S.acl.expiry && m.keyExpired) return false;
    if (S.acl.lock && !m.signed) return false;
    return true;
  }

  /* The tailcat address is the whole credential, so "who can reach this" is
     exactly "who was sent the string". Your own machines started it and have
     it; the hostile one has it only once you say the address got out. */
  function holdsTailcat(id) {
    return BY_ID[id].hostile ? S.tailcat.shared : true;
  }

  /* Rung 2. Which way do these two reach each other, if at all? */
  function choosePath(from, to) {
    var lf = S.links[from], lt = S.links[to];

    /* Tailcat answers before either of the paths below it, because it is
       neither of them and does not care what either would have said. The data
       plane is the one the tailnet uses — DERP to find each other, a direct
       punch when the NATs allow it — with no control plane above it to ask.
       That is the whole of the lesson and it happens here, in the path, before
       a single rung of the ladder has run. */
    if (S.tailcat.on && to === S.tailcat.host && from !== to && holdsTailcat(from)) {
      if (S.tailcat.allow && BY_ID[from].hostile) {
        return { kind: "none", iface: "tailcat0", base: 0,
                 note: "tailcat --allow pins the server to one client public key",
                 why: from + " holds the address and the address is not enough: the " +
                      "server was started with --allow, and its key is not the pinned one" };
      }
      return { kind: "tailcat", iface: "tailcat0", base: 18,
               note: "tailcat — the tailnet's data plane with no control plane over it" };
    }

    if (onTailnet(from) && onTailnet(to)) {
      if (lf.udpBlocked || lt.udpBlocked) {
        return { kind: "relay", iface: "tailscale0", base: 46,
                 note: 'UDP is blocked, so the session rides DERP over TCP 443' };
      }
      if (BY_ID[from].nat === "hard" && BY_ID[to].nat === "hard") {
        return { kind: "relay", iface: "tailscale0", base: 46,
                 note: "both ends are behind hard NATs, so the punch cannot complete" };
      }
      return { kind: "direct", iface: "tailscale0", base: 12,
               note: "both NATs held a mapping open and the punch completed" };
    }

    /* Not both on the tailnet. What is left is the ordinary network. */
    if (S.segmentShared && sharesSegment(from, to)) {
      return { kind: "lan", iface: "eth0", base: 1,
               note: "same layer-2 segment — no routing involved at all" };
    }

    /* Off the tailnet, the only machine anyone can aim at is the one with a
       public address. The others are behind routers that masquerade outbound
       and forward nothing in, so there is no path to fail further along —
       there is no path. This page used to give every machine a reachable
       public address and let an attacker walk in on :22; the containers in
       lab/ said otherwise, and the containers were right. */
    if (BY_ID[to].natName) {
      return { kind: "none", iface: "eth0", base: 0,
               note: BY_ID[to].natName + " masquerades " + to + " outbound and " +
                     "forwards nothing in — there is no address to aim at" };
    }

    return { kind: "public", iface: "eth0", base: 24,
             note: "over the public internet, to whatever the address answers on" };
  }

  function sharesSegment(a, b) {
    var pair = { "evil-box": 1, "lab-ubuntu": 1 };
    return pair[a] && pair[b];
  }

  /* evil-box has two addresses — its own segment, and the one it takes when you
     move it onto lab-ubuntu's wire. Which is true depends on the state. */
  function lanAddr(id) {
    var m = BY_ID[id];
    return S.segmentShared && m.lanShared ? m.lanShared : m.lan;
  }

  /* Rung 3. First matching grant wins, exactly as the real policy file does. */
  function aclCheck(from, to, port) {
    for (var i = 0; i < GRANTS.length; i++) {
      var g = GRANTS[i];
      if (!S.acl.grants[g.key]) continue;
      var srcOk = g.src === "*" || g.src === tagOf(from);
      var dstOk = g.dst === "*" || g.dst === tagOf(to);
      var portOk = g.ports.indexOf("*") !== -1 || g.ports.indexOf(String(port)) !== -1;
      if (srcOk && dstOk && portOk) {
        return { allow: true, rule: 'grant #' + (i + 1) + ' — ' + g.label };
      }
    }
    if (S.acl.def === "accept") {
      return { allow: true, rule: 'the default action, "accept" — nothing was consulted' };
    }
    return { allow: false, rule: "no grant matched, and the default action is deny" };
  }

  /* Rung 4. Order is the lesson here: Docker's chain is consulted before
     UFW's, which is why a published port answers through a deny-all. */
  function firewallCheck(to, port, path) {
    /* Nothing arrives inbound on a tailcat path. The serving machine dialled
       out to a relay and the session came back down that connection, so a
       default-deny incoming policy is still in force, still correct, and was
       never asked. This is rung 4 being skipped, not rung 4 being beaten. */
    if (path.iface === "tailcat0") {
      return { allow: true, danger: true,
        rule: "no firewall rule was consulted — the tunnel was dialled outbound, so " +
              "nothing ever arrived on an interface UFW filters" };
    }
    if (to !== "lab-vps") {
      return { allow: true, rule: "no firewall configured on " + to + " in this lab" };
    }
    var v = S.vps;
    var external = path.iface === "eth0";

    if (external && v.dockerPublish && String(port) === "8080") {
      return { allow: true, danger: true,
        rule: "DOCKER-USER accepted it before UFW's chain ever ran" };
    }
    if (!external) {
      if (v.allowTailscale0) {
        return { allow: true, rule: "ufw rule: ALLOW IN on tailscale0" };
      }
      return { allow: false, rule: "nothing allows tailscale0, and the default is deny" };
    }
    if (String(port) === "22" && v.allowPublic22) {
      return { allow: true, rule: "ufw rule: 22/tcp ALLOW IN from Anywhere" };
    }
    if (!v.ufwDefaultDeny) {
      return { allow: true, rule: "ufw default incoming policy is allow" };
    }
    return { allow: false, rule: "ufw default incoming policy: deny" };
  }

  /* Rung 5. A rule that permits a packet is not a service that answers it. */
  function listenCheck(to, port, path, from) {
    port = String(port);
    /* Tailcat is its own listener. `serve ssh` runs tailcat's SSH server and
       not sshd, which is why binding sshd to the tailnet address does nothing
       to it — and that server still wants a key, which is the one lock left
       standing on this path. */
    if (path.iface === "tailcat0") {
      var svc = S.tailcat.service;
      if (svc === "all") {
        return { ok: true, what: "tailcat serve all, proxying straight through to :" + port };
      }
      if (port !== "22") {
        return { ok: false, why: "tailcat is serving ssh only, so nothing answers on :" + port };
      }
      if (svc === "no-auth-ssh") {
        return { ok: true, what: "tailcat's own SSH server, with authentication switched off" };
      }
      if (from && BY_ID[from].hostile) {
        return { ok: false, why: "tailcat's SSH server answered and asked for a key " + from +
          " does not have — the address got it to the door and no further" };
      }
      return { ok: true, what: "tailcat's own SSH server, checking authorized_keys" };
    }
    if (to !== "lab-vps") {
      if (port === "22") return { ok: true, what: "sshd" };
      return { ok: false, what: null, why: "nothing is listening on :" + port };
    }
    var v = S.vps;
    if (port === "22") {
      if (v.sshdListen === "tailnet" && path.iface === "eth0") {
        return { ok: false, why: "sshd is bound to " + BY_ID["lab-vps"].ts +
          " only, so it never sees a packet that arrived on eth0" };
      }
      return { ok: true, what: "sshd" };
    }
    if (port === "8080") {
      if (v.dockerPublish) return { ok: true, what: "nginx, in a container" };
      return { ok: false, why: "nothing is listening on :8080" };
    }
    return { ok: false, why: "nothing is listening on :" + port };
  }

  /* The whole ladder, in order. */
  function deliver(o) {
    var from = o.from, to = o.to, port = String(o.port);
    var bytes = o.bytes || 2048;
    var t = {
      from: from, to: to, port: port, ok: false, rung: 0, rule: "", why: "",
      path: null, rttMs: 0, lossPct: 0, packets: 0, retransmits: 0,
      bytesSent: 0, bytesDelivered: 0, danger: false, skipped: []
    };

    /* Which way these two would reach each other is settled before the ladder
       starts. It decides nothing here — rung 1 still answers first — but a
       failure has to be able to name the address the packet was aimed at, and
       quoting a tailnet address for a path that is not the tailnet was a lie
       this page used to tell. */
    var path = choosePath(from, to);
    t.path = path;

    /* --- rung 1 · liveness --------------------------------------- */
    t.rung = 1;
    if (!S.machines[from].online) {
      t.why = from + " is not running"; return t;
    }
    if (!S.machines[to].online) {
      t.why = to + " is not running"; return t;
    }
    if (!S.links[from].up) {
      t.why = "eth0 is down on " + from + " — nothing leaves the machine"; return t;
    }
    if (!S.links[to].up) {
      t.why = "eth0 is down on " + to + " — nothing arrives"; return t;
    }

    /* --- rung 2 · path --------------------------------------------
       An unsigned or expired key lands here, not above: the tailnet declines
       to carry it, and the question becomes what the ordinary network does
       instead. Often the answer is "nothing" — but not always, and pretending
       otherwise taught the wrong lesson twice over. */
    t.rung = 2;
    t.rule = path.note;
    if (path.kind === "none") {
      t.why = path.why ||
              "nothing on the public internet has an address for " + to + ", so the " +
              "packet has nowhere to go — no firewall was ever consulted";
      return t;
    }

    /* --- rung 3 · tailnet policy ---------------------------------- */
    if (path.iface === "tailscale0") {
      t.rung = 3;
      var acl = aclCheck(from, to, port);
      t.rule = acl.rule;
      if (!acl.allow) {
        t.why = "the tailnet refused it before a single packet reached " + to;
        return t;
      }
    } else if (path.iface === "tailcat0") {
      /* Not "the ACL allowed it" — the ACL was never a participant. Saying so
         out loud is the entire point of this path existing. */
      t.skipped.push("rung 3 · tailnet policy — never consulted: tailcat has no " +
                     "control plane, so there is no grant and no default action to ask");
    }

    /* --- rung 4 · host firewall ----------------------------------- */
    t.rung = 4;
    var fw = firewallCheck(to, port, path);
    t.rule = fw.rule;
    t.danger = !!fw.danger;
    if (!fw.allow) {
      t.why = "the packet reached " + to + " and its firewall dropped it";
      return t;
    }
    if (path.iface === "tailcat0") {
      t.skipped.push("rung 4 · host firewall — never consulted: the tunnel was dialled " +
                     "outbound, so nothing arrived on an interface UFW filters");
    }

    /* --- rung 5 · a listener -------------------------------------- */
    t.rung = 5;
    var li = listenCheck(to, port, path, from);
    if (!li.ok) {
      t.why = li.why;
      t.rule = path.iface === "tailcat0"
        ? "nothing in the network stopped this — the key policy did"
        : "the firewall permitted it — that is not the same as an answer";
      return t;
    }

    /* --- it worked. Now the numbers. ------------------------------ */
    var lf = S.links[from], lt = S.links[to];
    var lossFrac = 1 - (1 - lf.loss / 100) * (1 - lt.loss / 100);
    var mtu = path.iface === "tailscale0" ? 1280 : 1500;

    t.ok = true;
    t.rule = fw.rule;
    t.why = "reached " + li.what + " on " + addrFor(to, path) + ":" + port;
    t.rttMs = path.base + lf.delay + lt.delay;
    t.lossPct = Math.round(lossFrac * 1000) / 10;
    t.packets = Math.ceil(bytes / (mtu - 80));
    t.retransmits = Math.round(t.packets * lossFrac);
    t.bytesSent = bytes + t.retransmits * (mtu - 80);
    t.bytesDelivered = bytes;
    return t;
  }

  function addrFor(id, path) {
    if (!path) return BY_ID[id].ts;
    /* Not an address in any sense your network understands — which is why the
       log shows it rather than an IP. There is nothing here to filter on. */
    if (path.iface === "tailcat0") return TAILCAT_ADDR[id];
    if (path.iface === "tailscale0") return BY_ID[id].ts;
    if (path.kind === "lan") return lanAddr(id);
    /* On the "none" path that address belongs to the router, not the machine —
       it is where the packet actually lands and dies, and saying whose it is
       keeps this line from contradicting the reason printed under it. */
    if (path.kind === "none" && BY_ID[id].natName) {
      return BY_ID[id].natName + " " + BY_ID[id].pub;
    }
    /* The public address is what an attacker aims at, and reporting it is how
       the failure reads as an answer. */
    return BY_ID[id].pub;
  }

  /* ============================================================
     5 · Readouts
     ============================================================ */

  function tsStatus() {
    var out = ["$ tailscale status"];
    var self = "lab-ubuntu";
    CATALOG.forEach(function (m) {
      var st = S.machines[m.id];
      if (!st.onTailnet) return;
      var line = pad(m.ts, 14) + pad(m.label, 13) + "linux   ";
      if (m.id === self) { out.push(line + "-"); return; }
      if (!st.online || !S.links[m.id].up) { out.push(line + "offline"); return; }
      if (S.acl.expiry && st.keyExpired) { out.push(line + "offline; key expired"); return; }
      if (S.acl.lock && !st.signed) {
        out.push(line + "offline; not signed by tailnet lock"); return;
      }
      var p = choosePath(self, m.id);
      if (p.kind === "relay") out.push(line + 'active; relay "fra"');
      else if (p.kind === "direct") out.push(line + "active; direct " + m.pub + ":41641");
      /* Neither end is on the tailnet, so there is no path to describe. An idle
         peer reports no current address, and calling that "direct" would be the
         most misleading line this readout could print. */
      else out.push(line + "idle; no current address");
    });
    if (out.length === 1) out.push("  (nothing else is up)");
    return out.join("\n");
  }

  /* netcheck asks whether UDP works at all, not whether WireGuard's port is
     open: it probes STUN on 3478. So dropping udp/41641 leaves this saying
     UDP: true, and moves the path to relay instead. The model used to print
     UDP: false here, and the real thing in lab/ never did. */
  function netcheck() {
    var l = S.links["lab-ubuntu"];
    var base = 24.1 + l.delay;
    var out = [
      "$ tailscale netcheck",
      "  UDP: true",
      "  IPv4: yes, " + BY_ID["lab-ubuntu"].pub + ":41641",
      "  MappingVariesByDestIP: false",
      "  PortMapping: none",
      "  Nearest DERP: Frankfurt",
      "  DERP latency:",
      "      fra: " + base.toFixed(1) + "ms  (Frankfurt)",
      "      lhr: " + (base + 7.5).toFixed(1) + "ms  (London)"
    ];
    if (l.udpBlocked) {
      out.push("");
      out.push("# udp/41641 is dropped and this still says UDP: true, because the");
      out.push("# probe above went to STUN on 3478, which nothing here blocks. Read");
      out.push("# `tailscale status` instead: the path is what changed. A network");
      out.push("# blocking outbound UDP wholesale is what makes this line say false.");
    }
    return out.join("\n");
  }

  function shapingLines() {
    var out = [];
    CATALOG.forEach(function (m) {
      var l = S.links[m.id];
      if (!S.machines[m.id].online) return;
      var bits = [];
      if (!l.up) bits.push("eth0 DOWN");
      if (l.loss) bits.push(l.loss + "% loss");
      if (l.delay) bits.push(l.delay + "ms delay");
      if (l.udpBlocked) bits.push("udp/41641 dropped");
      if (bits.length) out.push("  " + pad(m.label, 13) + bits.join(" · "));
    });
    if (!out.length) return "$ tc qdisc show\n  every link is clean";
    return "$ tc qdisc show ; nft list ruleset\n" + out.join("\n");
  }

  function ufwText() {
    var v = S.vps;
    var out = ["lab-vps # ufw status numbered", "Status: active",
      "Default: " + (v.ufwDefaultDeny ? "deny" : "allow") + " (incoming), allow (outgoing)",
      "", "     To                         Action      From",
      "     --                         ------      ----"];
    var n = 0;
    if (v.allowTailscale0) {
      out.push("[" + pad(String(++n), 2) + "] Anywhere on tailscale0     ALLOW IN    Anywhere");
    }
    if (v.allowPublic22) {
      out.push("[" + pad(String(++n), 2) + "] 22/tcp                     ALLOW IN    Anywhere");
    }
    if (!n) out.push("     (no rules — the default policy decides everything)");
    if (v.dockerPublish) {
      out.push("", "# and the one ufw cannot see:",
        "lab-vps # iptables -S DOCKER-USER",
        "-A DOCKER-USER -j RETURN        <- 0.0.0.0:8080 answers regardless of the above");
    }
    return out.join("\n");
  }

  function listenText() {
    var v = S.vps;
    var out = ["lab-vps # ss -tlnp"];
    out.push("LISTEN 0  128  " +
      (v.sshdListen === "tailnet" ? BY_ID["lab-vps"].ts : "0.0.0.0") + ":22       sshd");
    if (v.dockerPublish) {
      out.push("LISTEN 0  4096 0.0.0.0:8080     docker-proxy");
    }
    out.push("", "lab-vps # sshd -T | grep -E 'passwordauth|permitroot|listenaddress'");
    out.push("listenaddress " + (v.sshdListen === "tailnet" ? BY_ID["lab-vps"].ts : "0.0.0.0"));
    out.push("passwordauthentication " + (v.passwordAuth ? "yes" : "no"));
    out.push("permitrootlogin " + (v.permitRoot ? "yes" : "no"));
    /* `ss` sees it, because it is an ordinary process holding an ordinary
       outbound socket. That is the only place a tailcat tunnel shows up on the
       host at all — there is no bound inbound port to find. */
    if (S.tailcat.on) {
      out.push("", S.tailcat.host + " # ss -tnp | grep tailcat");
      out.push("ESTAB 0 0  " + lanAddr(S.tailcat.host) + ":52104  derp:443   tailcat");
      out.push("# no LISTEN line anywhere: the socket is outbound, so a port audit " +
               "finds nothing");
    }
    return out.join("\n");
  }

  function aclJson() {
    var rules = [];
    GRANTS.forEach(function (g) {
      if (!S.acl.grants[g.key]) return;
      rules.push('    { "action": "accept", "src": ["' + g.src + '"], ' +
                 '"dst": ["' + g.dst + ':' + g.ports.join(",") + '"] }');
    });
    var out = ["// the tailnet policy file, as the admin console would hold it", "{"];
    out.push('  "tagOwners": {');
    out.push('    "tag:server": ["autogroup:admin"], "tag:laptop": ["autogroup:admin"],');
    out.push('    "tag:roam":   ["autogroup:admin"], "tag:untrusted": ["autogroup:admin"]');
    out.push("  },");
    out.push('  "acls": [');
    out.push(rules.length ? rules.join(",\n") : "    // nothing — every packet falls through");
    out.push("  ],");
    if (S.acl.ssh) {
      out.push('  "ssh": [');
      out.push('    { "action": "check", "src": ["autogroup:member"], ' +
               '"dst": ["tag:server"], "users": ["autogroup:nonroot"] }');
      out.push("  ],");
    }
    out.push('  "//": "default action when nothing matches: ' + S.acl.def + '"');
    out.push("}");
    var extra = [];
    extra.push("");
    extra.push("$ tailscale lock status");
    extra.push("  Tailnet lock is " + (S.acl.lock ? "ENABLED" : "disabled"));
    if (S.acl.lock) {
      CATALOG.forEach(function (m) {
        if (!S.machines[m.id].onTailnet) return;
        extra.push("  " + pad(m.label, 13) +
          (S.machines[m.id].signed ? "signed" : "NOT SIGNED — cannot join"));
      });
    }
    extra.push("");
    extra.push("$ tailscale status --json | jq .Self.KeyExpiry");
    extra.push("  key expiry is " + (S.acl.expiry ? "on (180 days)" : "DISABLED"));
    return out.join("\n") + "\n" + extra.join("\n");
  }

  function pad(s, n) {
    s = String(s);
    while (s.length < n) s += " ";
    return s;
  }

  /* ============================================================
     6 · The packet log and the script
     ============================================================ */

  function note(cmd, where) {
    script.push({ cmd: cmd, where: where || null });
    paintScript();
  }

  function record(entry) {
    log.unshift(entry);
    if (log.length > 40) log.pop();
    paintPackets();
  }

  function recordTrace(label, t) {
    var lines = [];
    if (t.ok) {
      lines.push(t.packets + " packets · " + fmtBytes(t.bytesSent) + " sent · " +
        fmtBytes(t.bytesDelivered) + " delivered");
      lines.push("rtt " + t.rttMs + "ms · loss " + t.lossPct + "% · " +
        t.retransmits + " retransmit" + (t.retransmits === 1 ? "" : "s"));
      lines.push("path: " + t.path.kind + " (" + t.rule + ")");
    } else {
      lines.push("0 bytes delivered — stopped at rung " + t.rung + " of 5");
      if (t.rule) lines.push(t.rule);
    }
    /* A rung that was never asked is not a rung that passed, and the log has
       to say which of the two happened or the reader draws the wrong lesson
       from a green line. */
    if (t.skipped && t.skipped.length) {
      t.skipped.forEach(function (s) { lines.push(s); });
    }
    record({
      ok: t.ok, danger: t.danger, rung: t.rung,
      title: label,
      head: t.from + " → " + addrFor(t.to, t.path) + ":" + t.port,
      why: t.why, lines: lines
    });
    verdict(t.ok
      ? (t.danger ? "warn" : "ok")
      : "bad",
      (t.ok ? "Delivered. " : "Stopped at rung " + t.rung + " of 5. ") + t.why);
    return t;
  }

  function fmtBytes(n) {
    if (n < 1024) return n + " B";
    return (n / 1024).toFixed(1) + " KB";
  }

  /* ============================================================
     7 · Rendering
     ============================================================ */

  var el = {};

  function q(sel) { return root.querySelector(sel); }

  function paintAll() {
    paintTopology();
    paintStatus();
    paintRules();
    paintControls();
    /* The score is a live gauge, not a snapshot. It used to redraw only when
       the Audit button was pressed, which left a stale number sitting there
       looking current while you changed the configuration underneath it. */
    paintAudit();
    saveHash();
  }

  function paintStatus() {
    if (!el.status) return;
    el.status.textContent = tsStatus() + "\n\n" + netcheck() + "\n\n" + shapingLines();
  }

  function paintRules() {
    if (!el.rules) return;
    el.rules.textContent = ufwText() + "\n\n" + listenText() + "\n\n" + aclJson();
  }

  function paintScript() {
    if (!el.script) return;
    if (!script.length) {
      el.script.textContent =
        "# Nothing yet. Every switch you flip above appends the real command here.\n" +
        "# Run the result against the three VMs in chapter 13 and you get the same outcome.";
      return;
    }
    /* This header travels with the script when it is copied. The page it came
       from will be closed long before anyone runs this, so the warning has to
       be in the artifact rather than only in the UI. */
    var out = [
      "#!/bin/sh",
      "# Generated by the sandbox (chapter 14) of the Secure Remote Access guide.",
      "# Each line is the real command for a change made in a simulation.",
      "#",
      "# ---------------------------------------------------------------------",
      "# READ THIS BEFORE RUNNING ANY OF IT",
      "#",
      "# These commands change firewall rules and SSH configuration. Several of",
      "# them remove the only route into a machine. Run in the wrong order, or on",
      "# a box you cannot physically reach, they WILL lock you out.",
      "#",
      "#   - This came from a model. Your machines are not that model.",
      "#   - Run it on something disposable first — chapter 13 builds exactly that.",
      "#   - Keep a second way in, proven working, before you start.",
      "#   - Read each line and understand it. Do not paste this whole file.",
      "#",
      "# Provided AS IS, with no warranty of any kind — see LICENSE. You accept",
      "# the risk of running it. Not the risk of this repository, its owner, or",
      "# any contributor.",
      "# ---------------------------------------------------------------------",
      ""
    ];
    var last = null;
    script.forEach(function (s) {
      /* A command with no machine runs on your own host — limactl, the admin
         console. Give it its own heading rather than letting it inherit the
         previous machine's, which reads as a lie. */
      var where = s.where || "your host — limactl, and the admin console";
      if (where !== last) {
        out.push("");
        out.push("# --- on " + where + " ---");
        last = where;
      }
      out.push(s.cmd);
    });
    el.script.textContent = out.join("\n");
  }

  function paintPackets() {
    if (!el.packets) return;
    if (!log.length) {
      el.packets.innerHTML = '<p class="sb-empty">Run a probe or an attack and the ' +
        "trace lands here — which rung decided it, and how many bytes actually moved.</p>";
      return;
    }
    var html = "";
    log.forEach(function (e) {
      var cls = e.ok ? (e.danger ? "warn" : "ok") : "bad";
      html += '<div class="sb-pkt is-' + cls + '">' +
        '<div class="pk-top"><span class="pk-title">' + esc(e.title) + "</span>" +
        (e.rung ? '<span class="pk-rung">rung ' + e.rung + "/5</span>" : "") + "</div>" +
        '<div class="pk-head">' + esc(e.head) + "</div>" +
        '<div class="pk-why">' + esc(e.why) + "</div>";
      e.lines.forEach(function (l) {
        html += '<div class="pk-line">' + esc(l) + "</div>";
      });
      if (e.hex) {
        html += '<div class="pk-hex">' + esc(e.hex) + "</div>";
      }
      html += "</div>";
    });
    el.packets.innerHTML = html;
  }

  function esc(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function verdict(kind, text) {
    if (!el.verdict) return;
    el.verdict.className = "sb-verdict is-" + kind;
    el.verdict.textContent = text;
  }

  /* ---- the drawing ------------------------------------------------ */

  function pick(name) { return svg ? svg.querySelector('[data-el="' + name + '"]') : null; }

  /* ---- route geometry --------------------------------------------
     The right edge of each machine box, in the SVG's own coordinates.
     Every route is built from these two numbers rather than written out
     by hand, so the line always leaves the box it belongs to. */
  var ANCHOR = {
    "lab-roam": 58,
    "evil-box": 132,
    "lab-ubuntu": 206,
    "lab-vps": 206
  };
  var VPS_X = 676;      /* lab-vps's left edge */
  var LEFT_X = 164;     /* the right edge of the left column */
  var LANE_Y = 274;     /* the middle of the public-internet band along the bottom */
  var CORRIDOR = 292;   /* clear vertical space between the NATs and the tailnet */

  /* Returns { in: d, out: d } — "out" only for the relayed path, which is
     drawn as two legs so the tailnet box sits between them. */
  function routeD(kind, from, to) {
    if (from === to) return null;

    /* A path is undirected here, so normalise onto "a left machine, and
       possibly lab-vps" rather than carrying a direction through. */
    var a = from, b = to;
    if (a === "lab-vps") { a = to; b = "lab-vps"; }
    var sy = ANCHOR[a], dy = ANCHOR[b];
    if (sy == null || dy == null) return null;

    if (kind === "lan") return { in: "M89 160 L89 178" };

    /* Neither end is the public box: loop through the corridor between the
       NAT column and the tailnet, rather than pretending to cross the page. */
    if (b !== "lab-vps") {
      return { in: "M" + LEFT_X + " " + sy + " L258 " + sy +
                   " C " + CORRIDOR + " " + sy + " " + CORRIDOR + " " + dy + " 258 " + dy +
                   " L" + LEFT_X + " " + dy };
    }

    if (kind === "relay") {
      /* into the tailnet box's left edge, clamped to its height */
      var ey = Math.min(150, Math.max(36, sy));
      return {
        in: "M" + LEFT_X + " " + sy + " L258 " + sy +
            " C " + CORRIDOR + " " + sy + " " + CORRIDOR + " " + ey + " 322 " + ey,
        out: "M518 118 C 592 118 634 170 " + VPS_X + " " + dy
      };
    }

    /* Tailcat draws on the direct line deliberately: it goes straight to the
       machine, under the tailnet box, touching nothing the tailnet owns. */
    if (kind === "direct" || kind === "tailcat") {
      /* straight across, under the tailnet box */
      return { in: "M" + LEFT_X + " " + sy + " L258 " + sy +
                   " C " + CORRIDOR + " " + sy + " " + CORRIDOR + " " + dy + " 322 " + dy +
                   " L" + VPS_X + " " + dy };
    }

    /* public: down into the bottom lane, across, and up into the box */
    return { in: "M" + LEFT_X + " " + sy + " L258 " + sy +
                 " C " + CORRIDOR + " " + sy + " " + CORRIDOR + " " + LANE_Y + " 316 " + LANE_Y +
                 " L640 " + LANE_Y + " C 668 " + LANE_Y + " 672 " + (dy + 34) + " " +
                 VPS_X + " " + (dy + 14) };
  }

  function paintTopology() {
    if (!svg) return;

    CATALOG.forEach(function (m) {
      var g = pick("node-" + m.id);
      if (!g) return;
      var st = S.machines[m.id];
      var live = !!(st.online && S.links[m.id].up);
      g.classList.toggle("is-off", !live);
      /* toggle() with an undefined second argument flips instead of setting,
         which quietly hid every non-hostile machine. Coerce. */
      var gone = !!(m.hostile && !st.online);
      g.classList.toggle("is-hidden", gone);
      var nat = pick("nat-" + m.id);
      if (nat) nat.classList.toggle("is-hidden", gone);
      var ip = pick("ip-" + m.id);
      if (ip) {
        ip.textContent = st.onTailnet ? m.ts
          : m.natName ? lanAddr(m.id) + " behind NAT"
          : m.pub + " (public)";
      }
      var badge = pick("cond-" + m.id);
      if (badge) {
        var l = S.links[m.id], bits = [];
        if (!l.up) bits.push("eth0 DOWN");
        if (l.loss) bits.push(l.loss + "% loss");
        if (l.delay) bits.push(l.delay + "ms");
        if (l.udpBlocked) bits.push("udp dropped");
        badge.textContent = bits.length ? bits.join(" · ") : m.role;
        badge.setAttribute("class", bits.length ? "svg-mono-warn sb-svg-cond" : "svg-sub");
      }
    });

    var seg = pick("seg-shared");
    if (seg) seg.classList.toggle("is-hidden", !S.segmentShared);
    var segLabel = pick("seg-label");
    if (segLabel) segLabel.classList.toggle("is-hidden", !S.segmentShared);

    var evilStub = pick("path-evil-stub");
    if (evilStub) evilStub.classList.toggle("is-hidden", !S.machines["evil-box"].online);
    var evilTap = pick("path-evil-tap");
    if (evilTap) {
      evilTap.classList.toggle("is-hidden",
        !(S.machines["evil-box"].online && S.segmentShared));
    }

    /* The focused pair decides which route is drawn, and where it starts.
       deliver() now settles a path before rung 1 so a failure line can name the
       right address — but a stopped box or a dead link has no route to draw,
       whatever that path says, so rung 1 still renders as no path at all. */
    var t = deliver({ from: S.probe.from, to: S.probe.to, port: S.probe.port });
    var kind = t.rung > 1 && t.path && t.path.kind !== "none" ? t.path.kind : null;
    var d = kind ? routeD(kind, S.probe.from, S.probe.to) : null;

    ["direct", "relay", "public", "lan", "tailcat"].forEach(function (k) {
      var els = svg.querySelectorAll('[data-route="' + k + '"]');
      Array.prototype.forEach.call(els, function (p) {
        var leg = p.getAttribute("data-leg") === "out" ? "out" : "in";
        var geom = kind === k && d ? d[leg] : null;
        if (geom) p.setAttribute("d", geom);
        var on = !!geom;
        p.classList.toggle("is-live", on && t.ok);
        p.classList.toggle("is-dead", on && !t.ok);
        p.classList.toggle("is-hidden", !on);
      });
    });

    /* The chip lives inside the tailnet box, so it has to describe the
       tailnet's involvement — not just name the path. Saying "public
       internet" in there read as though the tailnet were carrying it. */
    var usesTailnet = kind === "direct" || kind === "relay";
    var chip = pick("chip-path");
    if (chip) {
      chip.textContent = !kind ? "no path at all"
        : kind === "relay" ? 'relay "fra"'
        : kind === "direct" ? "direct · punched"
        : kind === "lan" ? "not used · same wire"
        : "not used · public path";
    }
    var chipBox = pick("chip-path-box");
    if (chipBox) {
      chipBox.setAttribute("class", "svg-card " +
        (!kind ? "svg-danger-s" : usesTailnet ? "svg-accent-s" : "svg-warn-s"));
    }
    if (chip) {
      chip.setAttribute("class",
        !kind ? "svg-mono-danger" : usesTailnet ? "svg-mono-accent" : "svg-mono-warn");
    }
    var services = pick("tailnet-services");
    if (services) services.classList.toggle("is-off", !usesTailnet);

    /* The dip in a public route is the whole message: it is the traffic
       leaving your private network. Light the band it dips into so the
       shape explains itself. */
    ["public-lane", "public-lane-label"].forEach(function (name) {
      var n = pick(name);
      if (n) n.classList.toggle("is-live", kind === "public");
    });
    var focus = pick("focus-label");
    if (focus) {
      focus.textContent = S.probe.from + " → " + S.probe.to + ":" + S.probe.port;
    }
  }

  /* ============================================================
     8 · Controls
     ============================================================ */

  var PANELS = [
    {
      id: "machines", title: "Machines",
      note: "Who is running, and who the tailnet will accept.",
      rows: [
        { t: "toggle", p: "machines.lab-vps.online", label: "lab-vps",
          sub: "the public box · chapter 08",
          cmd: function (v) { return { c: v ? "limactl start lab-vps" : "limactl stop lab-vps" }; } },
        { t: "toggle", p: "machines.lab-ubuntu.online", label: "lab-ubuntu",
          sub: "the laptop · chapter 09",
          cmd: function (v) { return { c: v ? "limactl start lab-ubuntu" : "limactl stop lab-ubuntu" }; } },
        { t: "toggle", p: "machines.lab-roam.online", label: "lab-roam",
          sub: "the phone's stand-in · chapter 03",
          cmd: function (v) { return { c: v ? "limactl start lab-roam" : "limactl stop lab-roam" }; } },
        { t: "hr" },
        { t: "toggle", p: "machines.evil-box.online", label: "evil-box", danger: true,
          sub: "a hostile machine, on your network",
          cmd: function (v) { return { c: v ? "limactl start evil-box" : "limactl stop evil-box" }; } },
        { t: "toggle", p: "machines.evil-box.onTailnet", label: "…hand it a node key",
          sub: "as if one leaked from a backup", danger: true,
          dep: "machines.evil-box.online",
          cmd: function (v) { return { c: v ? "sudo tailscale up --authkey=tskey-LEAKED" : "sudo tailscale logout", w: "evil-box" }; } },
        { t: "toggle", p: "machines.evil-box.signed", label: "…and sign it with tailnet lock",
          sub: "what an attacker cannot do without a signing key", danger: true,
          dep: "machines.evil-box.onTailnet",
          cmd: function (v) { return { c: v ? "tailscale lock sign nodekey:evil" : "tailscale lock revoke-keys nodekey:evil" }; } },
        { t: "toggle", p: "segmentShared", label: "Put evil-box on lab-ubuntu's segment",
          sub: "the on-path position — a café, an office switch",
          cmd: function (v) { return { c: v ? "limactl start --network=lima:shared evil-box" : "limactl start evil-box  # own NAT again" }; } }
      ]
    },
    {
      id: "network", title: "The network",
      note: "The three levers chapter 13 shapes with tc and nft.",
      rows: [{ t: "linkgrid" }]
    },
    {
      id: "policy", title: "Tailnet policy",
      note: "Who may talk to whom, before any host firewall is consulted.",
      rows: [
        { t: "seg", p: "acl.def", label: "Default action",
          options: [{ v: "deny", l: "deny" }, { v: "accept", l: "accept" }],
          cmd: function (v) { return { c: '# policy file: default action -> ' + v }; } },
        { t: "grants" },
        { t: "hr" },
        { t: "toggle", p: "acl.lock", label: "Tailnet lock",
          sub: "peers refuse a node key nobody signed",
          cmd: function (v) { return { c: v ? "tailscale lock init" : "tailscale lock disable" }; } },
        { t: "toggle", p: "acl.expiry", label: "Key expiry (180 days)",
          sub: "a stolen key stops working on its own",
          cmd: function (v) { return { c: "# admin console: key expiry " + (v ? "on" : "DISABLED") }; } },
        { t: "toggle", p: "acl.ssh", label: "Tailscale SSH",
          sub: "the tailnet checks the login, not just the route",
          cmd: function (v) { return { c: v ? "sudo tailscale up --ssh" : "sudo tailscale up --ssh=false", w: "lab-vps" }; } }
      ]
    },
    {
      id: "host", title: "The host — lab-vps",
      note: "Everything here runs on the box itself, after the tailnet has had its say.",
      rows: [
        { t: "toggle", p: "vps.ufwDefaultDeny", label: "UFW default deny (incoming)",
          cmd: function (v) { return { c: v ? "sudo ufw default deny incoming" : "sudo ufw default allow incoming", w: "lab-vps" }; } },
        { t: "toggle", p: "vps.allowTailscale0", label: "allow in on tailscale0",
          sub: "your way in once :22 is shut",
          cmd: function (v) { return { c: v ? "sudo ufw allow in on tailscale0" : "sudo ufw delete allow in on tailscale0", w: "lab-vps" }; } },
        { t: "toggle", p: "vps.allowPublic22", label: "allow 22/tcp from anywhere",
          sub: "the rule the whole guide builds towards deleting",
          cmd: function (v) { return { c: v ? "sudo ufw allow 22/tcp" : "sudo ufw delete allow 22/tcp", w: "lab-vps" }; } },
        { t: "hr" },
        { t: "toggle", p: "vps.dockerPublish", label: "docker run -d -p 8080:80 nginx",
          sub: "publishes a port UFW cannot see", danger: true,
          cmd: function (v) { return { c: v ? "docker run -d -p 8080:80 nginx" : "docker rm -f $(docker ps -q)", w: "lab-vps" }; } },
        { t: "hr" },
        { t: "seg", p: "vps.sshdListen", label: "sshd ListenAddress",
          options: [{ v: "all", l: "0.0.0.0" }, { v: "tailnet", l: "100.71.4.11 only" }],
          cmd: function (v) { return { c: "sudo sed -i 's/^#\\?ListenAddress.*/ListenAddress " +
            (v === "tailnet" ? "100.71.4.11" : "0.0.0.0") + "/' /etc/ssh/sshd_config && sudo systemctl reload ssh", w: "lab-vps" }; } },
        { t: "toggle", p: "vps.passwordAuth", label: "PasswordAuthentication yes", danger: true,
          cmd: function (v) { return { c: "# sshd_config: PasswordAuthentication " + (v ? "yes" : "no"), w: "lab-vps" }; } },
        { t: "toggle", p: "vps.permitRoot", label: "PermitRootLogin yes", danger: true,
          cmd: function (v) { return { c: "# sshd_config: PermitRootLogin " + (v ? "yes" : "no"), w: "lab-vps" }; } }
      ]
    },
    {
      id: "tailcat", title: "Tailcat — the escape hatch",
      note: "Chapter 01's data plane with no control plane over it. Nothing here is part " +
            "of the build; this is what somebody runs when the build is in their way.",
      rows: [
        { t: "toggle", p: "tailcat.on", label: "Somebody ran tailcat serve", danger: true,
          sub: "no account, no root, no daemon — one binary and an address",
          cmd: function (v) {
            return { c: v ? "tailcat serve ssh --ssh-authorized-keys=~/.ssh/authorized_keys"
                          : "# tailcat stopped — an ephemeral address dies with the process",
                     w: S.tailcat.host };
          } },
        { t: "seg", p: "tailcat.host", label: "…on which machine", dep: "tailcat.on",
          options: [{ v: "lab-ubuntu", l: "lab-ubuntu" },
                    { v: "lab-roam", l: "lab-roam" },
                    { v: "lab-vps", l: "lab-vps" }],
          cmd: function (v) { return { c: "# tailcat serve is running on " + v, w: v }; } },
        { t: "seg", p: "tailcat.service", label: "…serving what", dep: "tailcat.on",
          options: [{ v: "ssh", l: "ssh" },
                    { v: "no-auth-ssh", l: "no-auth" },
                    { v: "all", l: "all" }],
          cmd: function (v) {
            return { c: "tailcat serve " + v +
                        (v === "ssh" ? " --ssh-authorized-keys=~/.ssh/authorized_keys" : ""),
                     w: S.tailcat.host };
          } },
        { t: "hr" },
        { t: "toggle", p: "tailcat.allow", label: "--allow pins one client key",
          sub: "the address on its own stops being enough",
          dep: "tailcat.on",
          cmd: function (v) {
            return { c: v ? "tailcat serve … --allow=nodekey:cfb6bf…ddfd16"
                          : "# no --allow: the address is the whole credential",
                     w: S.tailcat.host };
          } },
        { t: "toggle", p: "tailcat.shared", label: "The address reached evil-box", danger: true,
          sub: "a paste in a chat, a shell history, a screenshot",
          dep: "tailcat.on",
          cmd: function (v) {
            return { c: v ? "# the address is now in somebody else's hands, and cannot be recalled"
                          : "# the address has not left your own machines" };
          } }
      ]
    }
  ];

  function buildControls(host) {
    var html = "";
    PANELS.forEach(function (panel) {
      html += '<section class="sb-panel" data-panel="' + panel.id + '">' +
        '<h3 class="pp-title">' + esc(panel.title) + "</h3>" +
        '<p class="pp-note">' + esc(panel.note) + "</p>";
      panel.rows.forEach(function (row, i) {
        html += renderRow(panel, row, i);
      });
      html += "</section>";
    });
    host.innerHTML = html;
  }

  function renderRow(panel, row, i) {
    var id = "pc-" + panel.id + "-" + i;
    if (row.t === "hr") return '<div class="pp-hr"></div>';

    if (row.t === "toggle") {
      return '<label class="pp-row pp-toggle' + (row.danger ? " is-danger" : "") + '" ' +
        'data-row="' + panel.id + ":" + i + '">' +
        '<input type="checkbox" id="' + id + '" data-path="' + row.p + '">' +
        '<span class="pp-text"><span class="pp-label">' + esc(row.label) + "</span>" +
        (row.sub ? '<span class="pp-sub">' + esc(row.sub) + "</span>" : "") +
        "</span></label>";
    }

    if (row.t === "seg") {
      var opts = row.options.map(function (o) {
        return '<button type="button" class="pp-seg-btn" data-path="' + row.p +
          '" data-value="' + o.v + '">' + esc(o.l) + "</button>";
      }).join("");
      return '<div class="pp-row pp-segrow" data-row="' + panel.id + ":" + i + '">' +
        '<span class="pp-label">' + esc(row.label) + "</span>" +
        '<div class="pp-seg" role="group" aria-label="' + esc(row.label) + '">' + opts + "</div></div>";
    }

    if (row.t === "grants") {
      var rows = GRANTS.map(function (g) {
        return '<label class="pp-row pp-toggle' + (g.danger ? " is-danger" : "") + '">' +
          '<input type="checkbox" data-path="acl.grants.' + g.key + '">' +
          '<span class="pp-text"><span class="pp-label pp-mono">' + esc(g.label) + "</span>" +
          (g.sub ? '<span class="pp-sub">' + esc(g.sub) + "</span>" : "") +
          "</span></label>";
      }).join("");
      return '<div class="pp-grants"><span class="pp-sublabel">Grants, in order — ' +
        "the first match wins</span>" + rows + "</div>";
    }

    if (row.t === "linkgrid") {
      var head = '<div class="lg-row lg-head"><span></span><span>eth0</span>' +
        "<span>loss</span><span>delay</span><span>udp/41641</span></div>";
      var body = CATALOG.filter(function (m) { return !m.hostile; }).map(function (m) {
        return '<div class="lg-row" data-machine="' + m.id + '">' +
          '<span class="lg-name">' + esc(m.label) + "</span>" +
          '<button type="button" class="lg-btn" data-link="' + m.id + '" data-field="up"></button>' +
          '<select class="lg-sel" data-link="' + m.id + '" data-field="loss" aria-label="' +
            m.label + ' packet loss">' +
            LOSS_STEPS.map(function (v) { return '<option value="' + v + '">' + v + "%</option>"; }).join("") +
          "</select>" +
          '<select class="lg-sel" data-link="' + m.id + '" data-field="delay" aria-label="' +
            m.label + ' delay">' +
            DELAY_STEPS.map(function (v) { return '<option value="' + v + '">' + v + "ms</option>"; }).join("") +
          "</select>" +
          '<button type="button" class="lg-btn" data-link="' + m.id + '" data-field="udpBlocked"></button>' +
          "</div>";
      }).join("");
      return '<div class="lg">' + head + body + "</div>";
    }
    return "";
  }

  function paintControls() {
    /* checkboxes */
    Array.prototype.forEach.call(root.querySelectorAll("[data-path]"), function (n) {
      var path = n.getAttribute("data-path");
      if (n.tagName === "INPUT") {
        n.checked = !!get(path);
      } else if (n.classList.contains("pp-seg-btn")) {
        var on = get(path) === n.getAttribute("data-value");
        n.classList.toggle("is-on", on);
        n.setAttribute("aria-pressed", on ? "true" : "false");
      }
    });

    /* dependent rows */
    PANELS.forEach(function (panel) {
      panel.rows.forEach(function (row, i) {
        if (!row.dep) return;
        var node = root.querySelector('[data-row="' + panel.id + ":" + i + '"]');
        if (!node) return;
        var ok = !!get(row.dep);
        node.classList.toggle("is-disabled", !ok);
        var input = node.querySelector("input");
        if (input) input.disabled = !ok;
        /* Segmented rows have buttons rather than an input, and greying one
           out without disabling it leaves a control that still answers. */
        Array.prototype.forEach.call(node.querySelectorAll(".pp-seg-btn"), function (b) {
          b.disabled = !ok;
        });
      });
    });

    /* link grid */
    Array.prototype.forEach.call(root.querySelectorAll("[data-link]"), function (n) {
      var id = n.getAttribute("data-link"), f = n.getAttribute("data-field");
      var v = S.links[id][f];
      if (n.tagName === "SELECT") { n.value = String(v); return; }
      if (f === "up") {
        n.textContent = v ? "up" : "DOWN";
        n.className = "lg-btn " + (v ? "is-ok" : "is-bad");
        n.setAttribute("aria-pressed", v ? "false" : "true");
      } else {
        n.textContent = v ? "dropped" : "allowed";
        n.className = "lg-btn " + (v ? "is-bad" : "is-ok");
        n.setAttribute("aria-pressed", v ? "true" : "false");
      }
    });

    /* probe selects */
    if (el.probeFrom) el.probeFrom.value = S.probe.from;
    if (el.probeTo) el.probeTo.value = S.probe.to;
    if (el.probePort) el.probePort.value = S.probe.port;
  }

  /* ---- wiring ------------------------------------------------------ */

  function findRow(path) {
    var found = null;
    PANELS.forEach(function (panel) {
      panel.rows.forEach(function (row) {
        if (row.p === path) found = row;
      });
    });
    return found;
  }

  function onControlChange(path, value) {
    set(path, value);
    var row = findRow(path);
    if (row && row.cmd) {
      var c = row.cmd(value);
      if (c && c.c) note(c.c, c.w);
    }
    if (path.indexOf("acl.grants.") === 0) {
      var key = path.split(".")[2];
      note('# policy file: grant "' + grantLabel(key) + '" ' + (value ? "added" : "removed"));
    }
    paintAll();
  }

  function grantLabel(key) {
    var g = GRANTS.filter(function (x) { return x.key === key; })[0];
    return g ? g.label : key;
  }

  function wire() {
    root.addEventListener("change", function (ev) {
      var n = ev.target;
      if (n.tagName === "INPUT" && n.type === "checkbox" && n.getAttribute("data-path")) {
        onControlChange(n.getAttribute("data-path"), n.checked);
        return;
      }
      if (n.tagName === "SELECT" && n.getAttribute("data-link")) {
        var id = n.getAttribute("data-link"), f = n.getAttribute("data-field");
        S.links[id][f] = parseInt(n.value, 10);
        noteShaping(id);
        paintAll();
        return;
      }
      if (n === el.probeFrom || n === el.probeTo || n === el.probePort) {
        S.probe.from = el.probeFrom.value;
        S.probe.to = el.probeTo.value;
        S.probe.port = el.probePort.value;
        paintAll();
      }
    });

    root.addEventListener("click", function (ev) {
      var b = ev.target.closest ? ev.target.closest("button") : null;
      if (!b || !root.contains(b)) return;

      if (b.classList.contains("pp-seg-btn")) {
        onControlChange(b.getAttribute("data-path"), b.getAttribute("data-value"));
        return;
      }
      if (b.classList.contains("lg-btn")) {
        var id = b.getAttribute("data-link"), f = b.getAttribute("data-field");
        S.links[id][f] = !S.links[id][f];
        if (f === "up") {
          note(S.links[id].up
            ? "sudo ip link set eth0 up"
            : "sudo sh -c 'ip link set eth0 down; sleep 20; ip link set eth0 up' &", id);
        } else {
          note(S.links[id].udpBlocked
            ? "sudo nft add rule inet lab out udp dport 41641 drop"
            : "sudo nft delete table inet lab", id);
        }
        paintAll();
        return;
      }
      if (b.getAttribute("data-tab")) {
        showTab(b.getAttribute("data-tab"));
        return;
      }
      if (b.getAttribute("data-attack")) {
        runAttack(b.getAttribute("data-attack"));
        return;
      }
      if (b.getAttribute("data-quick")) {
        var parts = b.getAttribute("data-quick").split(",");
        S.probe.from = parts[0]; S.probe.to = parts[1]; S.probe.port = parts[2];
        paintControls();
        runProbe();
        return;
      }
      if (b.getAttribute("data-preset")) { applyPreset(b.getAttribute("data-preset")); return; }
      if (b.getAttribute("data-act") === "audit") { runAudit(); return; }
      if (b.getAttribute("data-act") === "probe") { runProbe(); return; }
      if (b.getAttribute("data-act") === "reset") { resetAll(); return; }
      if (b.getAttribute("data-act") === "copy-script") { copyScript(b); return; }
    });
  }

  function noteShaping(id) {
    var l = S.links[id];
    if (!l.loss && !l.delay) { note("sudo tc qdisc del dev eth0 root", id); return; }
    note("sudo tc qdisc replace dev eth0 root netem" +
      (l.loss ? " loss " + l.loss + "%" : "") +
      (l.delay ? " delay " + l.delay + "ms " + Math.round(l.delay / 4.5) + "ms" : ""), id);
  }

  function showTab(name) {
    Array.prototype.forEach.call(root.querySelectorAll("[data-tab]"), function (b) {
      var on = b.getAttribute("data-tab") === name;
      b.classList.toggle("is-on", on);
      b.setAttribute("aria-selected", on ? "true" : "false");
    });
    Array.prototype.forEach.call(root.querySelectorAll("[data-pane]"), function (p) {
      p.classList.toggle("is-on", p.getAttribute("data-pane") === name);
    });
  }

  function runProbe() {
    var t = deliver({ from: S.probe.from, to: S.probe.to, port: S.probe.port });
    recordTrace(labelFor(S.probe.from, S.probe.to, S.probe.port), t);
    paintTopology();
    showTab("packets");
  }

  function labelFor(from, to, port) {
    if (String(port) === "22") return "ssh from " + from;
    return "connect to :" + port + " from " + from;
  }

  function resetAll() {
    S = defaults();
    script = [];
    log = [];
    paintScript();
    paintPackets();
    paintAll();
    verdict("", "Back to the starting configuration: three machines, default-deny, " +
      "public :22 still open, no attacker.");
  }

  function copyScript(btn) {
    var text = el.script ? el.script.textContent : "";
    function done() {
      btn.textContent = "Copied";
      setTimeout(function () { btn.textContent = "Copy the script"; }, 1400);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () {});
    }
  }

  /* ============================================================
     9 · Attacks
     ============================================================ */

  var frames = [];   /* what evil-box has captured so far */

  function ensure(path, value, why) {
    if (get(path) === value) return false;
    set(path, value);
    var row = findRow(path);
    if (row && row.cmd) {
      var c = row.cmd(value);
      if (c && c.c) note(c.c, c.w);
    }
    verdict("", why);
    return true;
  }

  var ATTACKS = {
    "scan-public": function () {
      ensure("machines.evil-box.online", true, "Started evil-box first.");
      var ports = ["22", "8080", "41641"];
      var opened = [];
      ports.forEach(function (p) {
        var t = deliver({ from: "evil-box", to: "lab-vps", port: p, bytes: 128 });
        if (t.ok) opened.push(p);
        recordTrace("nmap " + BY_ID["lab-vps"].pub + " -p " + p, t);
      });
      note("nmap -Pn -p 22,8080,41641 " + BY_ID["lab-vps"].pub, "evil-box");
      verdict(opened.length ? "bad" : "ok",
        opened.length
          ? "From the open internet, " + opened.length + " port" +
            (opened.length === 1 ? " answers" : "s answer") + ": " + opened.join(", ") +
            ". Every one of those is reachable by anyone, from anywhere."
          : "Every public port is closed. The only way in now is the tailnet — " +
            "which is the state chapter 08 is trying to get you to.");
    },

    /* A machine that joined the tailnet legitimately and should not have had
       broad access. The defence under test here is the ACL — so sign the key,
       or tailnet lock answers first and the lesson lands on the wrong rung. */
    "scan-tailnet": function () {
      ensure("machines.evil-box.online", true, "Started evil-box.");
      ensure("machines.evil-box.onTailnet", true,
        "Joined evil-box to the tailnet — a machine somebody added, not a break-in.");
      ensure("machines.evil-box.signed", true,
        "Signed its key, so tailnet lock is satisfied and the ACL is what answers.");
      var reached = [], rungs = {};
      ["lab-vps", "lab-ubuntu", "lab-roam"].forEach(function (target) {
        var t = deliver({ from: "evil-box", to: target, port: "22", bytes: 128 });
        if (t.ok) reached.push(target);
        rungs[t.rung] = true;
        recordTrace("ssh " + target + " (from evil-box, inside the tailnet)", t);
      });
      note("tailscale status; nmap -Pn -p 22 100.71.4.0/24", "evil-box");
      if (reached.length) {
        verdict("bad", "Being inside the tailnet was enough to reach " + reached.join(", ") +
          ". A flat tailnet is a flat network — the ACL is the only thing that makes " +
          "membership mean less than total access.");
      } else if (rungs[3]) {
        verdict("ok", "It holds a key the tailnet accepts, and still reaches nothing: " +
          "every attempt died at rung 3. That is the ACL doing work, at a rung the " +
          "host firewalls never even hear about.");
      } else {
        verdict("ok", "It never got as far as the policy — something earlier in the " +
          "ladder stopped it. Read the rung numbers in the packet log; a defence " +
          "answering at rung 1 or 2 tells you nothing about whether your ACL is any good.");
      }
    },

    /* The only attack here that does not attack the network. Everything the
       reader built stays exactly as they left it — the point is that none of
       it is consulted, so the interesting output is the list of rungs that
       never ran rather than the one that stopped it. */
    "tailcat-tunnel": function () {
      ensure("machines.evil-box.online", true, "Started evil-box.");
      ensure("tailcat.on", true,
        "Somebody on " + S.tailcat.host + " ran tailcat serve. No root, no daemon, " +
        "nothing added to the tailnet, nothing changed in your firewall.");
      ensure("tailcat.shared", true,
        "The address reached evil-box — pasted, screenshotted, or read out of a shell history.");

      var host = S.tailcat.host;
      var t = deliver({ from: "evil-box", to: host, port: "22", bytes: 4096 });
      recordTrace("tailcat ssh " + TAILCAT_ADDR[host] + "  (from evil-box)", t);
      note("tailcat ssh " + TAILCAT_ADDR[host], "evil-box");

      /* The same probe over the ordinary network, for the contrast. On a NAT'd
         machine this is the "there is no address to aim at" result the
         containers taught this model — and it is still true, which is exactly
         why the line above it matters. */
      var saved = S.tailcat.on;
      S.tailcat.on = false;
      var w = deliver({ from: "evil-box", to: host, port: "22", bytes: 4096 });
      S.tailcat.on = saved;
      recordTrace("ssh " + host + "  (the ordinary way, for comparison)", w);

      if (t.ok) {
        verdict("bad",
          "evil-box has a shell on " + host + ", and not one thing you configured was " +
          "asked about it. The ACL was never consulted — there is no control plane to " +
          "hold one. The firewall was never consulted — nothing arrived inbound. " +
          "Without tailcat the same probe stopped at rung " + w.rung + " of 5. Your " +
          "defences are all still there, all still correct, and all still off to one side.");
      } else if (t.rung === 5) {
        verdict("warn",
          "It got past every network defence you have and was stopped by an SSH key it " +
          "does not hold. That is chapter 02 doing the work on its own, at rung 5, with " +
          "rungs 3 and 4 never asked. It held — but count what is holding it: one lock, " +
          "not the layers you spent ten chapters building.");
      } else {
        verdict("ok",
          "Refused at rung " + t.rung + " of 5. --allow pins the server to one client " +
          "public key, so holding the address is not enough and a leaked string is worth " +
          "nothing. This is the only switch on this panel that puts an identity back " +
          "into the path.");
      }
    },

    "sniff": function () {
      ensure("machines.evil-box.online", true, "Started evil-box.");
      ensure("segmentShared", true,
        "Moved evil-box onto lab-ubuntu's segment — the on-path position.");
      var plaintext = "SSH-2.0-OpenSSH_10.0\r\nuser: hashem\r\nsudo systemctl restart nginx\r\n";
      note("sudo tcpdump -i eth0 -X udp port 41641", "evil-box");
      Crypto.seal("lab-ubuntu", "lab-vps", plaintext, 1).then(function (frame) {
        frames.push({ frame: frame, from: "lab-ubuntu", to: "lab-vps" });
        record({
          ok: false, rung: 2, danger: true,
          title: "tcpdump — evil-box, on the same wire",
          head: BY_ID["lab-ubuntu"].lan + ":41641 → " + BY_ID["lab-vps"].pub + ":41641",
          why: "Captured " + frame.bytes.length + " bytes of the session. " +
               "It is on the wire, it is complete, and it is unreadable.",
          lines: [
            "the plaintext underneath is " + plaintext.length + " bytes of an SSH session",
            Crypto.note
          ],
          hex: hex(frame.bytes, 32)
        });
        return Crypto.open("evil-box", "lab-ubuntu", frame)
          .then(function (text) {
            verdict("bad", "It opened the frame: " + text.slice(0, 40));
          })
          .catch(function (e) {
            record({
              ok: true, rung: 2,
              title: "…and evil-box tries to open it",
              head: "AES-GCM decrypt, with evil-box's own key",
              why: "Rejected. " + (e && e.name ? e.name : "Error") +
                   " — the tag did not verify, because the shared secret evil-box can " +
                   "derive is not the one that sealed this frame.",
              lines: [
                "evil-box has its own keypair and lab-ubuntu's public key.",
                "That gives it a different shared secret, and the cipher notices.",
                Crypto.mode === "none" ? Crypto.note
                  : "This failure happened in your browser just now, for a real reason."
              ]
            });
            verdict("ok", "The attacker holds every byte of the session and cannot read " +
              "one of them. This is the property the whole guide rests on.");
          });
      });
      verdict("", "Capturing…");
    },

    "replay": function () {
      if (!frames.length) { ATTACKS.sniff(); }
      setTimeout(function () {
        var f = frames[frames.length - 1];
        if (!f) return;
        note("tcpreplay -i eth0 captured.pcap", "evil-box");
        record({
          ok: true, rung: 2,
          title: "replay the captured frame, unchanged",
          head: "same ciphertext, same counter (" + f.frame.counter + ")",
          why: "Rejected by the receiver. WireGuard's counter for this session has " +
               "already moved past " + f.frame.counter + ", so the frame lands outside " +
               "the replay window and is dropped before it is even decrypted.",
          lines: [
            "the bytes are byte-for-byte valid — that is not the check that fails",
            "the anti-replay window is modelled here; the ciphertext above is real",
            "changing one byte instead would fail the AES-GCM tag, which is real"
          ],
          hex: hex(f.frame.bytes, 24)
        });
        verdict("ok", "Replay gets the attacker nothing. Capturing a valid frame and " +
          "sending it again is the cheapest attack there is, and it is answered by a " +
          "counter rather than by anything you configured.");
      }, 60);
    },

    "stolen-key": function () {
      ensure("machines.evil-box.online", true, "Started evil-box.");
      ensure("machines.evil-box.onTailnet", true,
        "evil-box now presents a node key lifted from a backup.");
      var t = deliver({ from: "evil-box", to: "lab-vps", port: "22", bytes: 256 });
      recordTrace("evil-box joins with a stolen node key", t);
      var refused = S.acl.lock && !S.machines["evil-box"].signed;
      if (refused && t.ok) {
        /* The interesting outcome, and the one this page used to hide: lock
           worked perfectly and bought nothing, because the attacker never
           needed the tailnet. */
        verdict("bad", "Tailnet lock did its job — nobody with a signing key vouched for " +
          "that node, so it got no tailnet session at all. It did not need one. Not being " +
          "on the tailnet leaves it exactly where any stranger stands, and from there " +
          "lab-vps still answers on :22: in at rung " + t.rung + ", over the ordinary " +
          "internet. Lock defends the tailnet. Closing public :22 is a separate job, and " +
          "it is chapter 08's.");
      } else if (refused) {
        verdict("ok", "Tailnet lock refused the key, so evil-box is not on the tailnet at " +
          "all — and the ordinary network gave it nothing either: stopped at rung " + t.rung +
          " of 5. Both halves had to hold, and the rung says which one did the stopping: " +
          "anything past rung 2 means the tailnet was never what turned it away.");
      } else if (!t.ok) {
        verdict("ok", "The key was accepted and it still got nowhere: stopped at rung " +
          t.rung + " of 5. Something after membership refused it.");
      } else {
        verdict("bad", "The stolen key was enough. With tailnet lock off and a permissive " +
          "grant, a leaked key is a login. Turn lock on and try again — then read which " +
          "rung answers, because it may not be the one you expect.");
      }
    },

    "expired-key": function () {
      set("machines.lab-roam.keyExpired", true);
      note("# 180 days pass, and nobody reauthenticated lab-roam");
      var t = deliver({ from: "lab-roam", to: "lab-vps", port: "22" });
      recordTrace("ssh from lab-roam, 180 days later", t);
      paintAll();
      if (!S.acl.expiry) {
        verdict("warn", "Key expiry is off, so lab-roam is still a full member 180 days " +
          "later — and would be if it had been stolen on day one.");
      } else if (t.ok) {
        verdict("warn", "lab-roam fell out of the tailnet on its own, with nobody doing " +
          "anything — that part worked exactly as it should. And it reached sshd anyway, " +
          "at rung " + t.rung + ", because :22 is open to the whole internet and a machine " +
          "that is no longer a member is just another stranger. Expiry ends membership. It " +
          "does not close a port.");
      } else {
        verdict("ok", "lab-roam fell out of the tailnet on its own, with nobody doing " +
          "anything, and there was no other way in: stopped at rung " + t.rung + " of 5. " +
          "That is the point of expiry — the lost phone stops being a member whether or " +
          "not you remember to remove it — and it counts for something only because " +
          "nothing else answered either. Read the rung to see what that was.");
      }
    },

    "rogue-exit": function () {
      ensure("machines.evil-box.online", true, "Started evil-box.");
      ensure("machines.evil-box.onTailnet", true, "Gave it a node key.");
      note("sudo tailscale up --advertise-exit-node", "evil-box");
      var accepted = S.acl.grants.any || S.acl.grants.untrusted;
      record({
        ok: !accepted, rung: 3, danger: accepted,
        title: "evil-box advertises itself as an exit node",
        head: "evil-box → the tailnet: route 0.0.0.0/0",
        why: accepted
          ? "Advertised, and your policy would let peers use it. Every byte of a " +
            "client's internet traffic would then leave through a machine you do not own."
          : "Advertised, and ignored. An exit node is a route offer, not a route — " +
            "an admin still has to approve it, and no client here is configured to use it.",
        lines: [
          "tailscale up --advertise-exit-node is free for anyone to run",
          "the defence is that approval is explicit and separate from membership",
          "check yours with: tailscale exit-node list"
        ]
      });
      verdict(accepted ? "bad" : "ok",
        accepted
          ? "A permissive grant plus an unapproved exit node is how a hostile member " +
            "becomes your default route. Tighten the grants and run it again."
          : "The offer is ignored. Membership got it onto the tailnet and bought it " +
            "nothing at the routing layer.");
    },

    "docker-bypass": function () {
      ensure("vps.ufwDefaultDeny", true, "UFW is default-deny, as chapter 08 leaves it.");
      ensure("vps.dockerPublish", true,
        "Published :8080 from a container on lab-vps — the ordinary thing to do.");
      ensure("machines.evil-box.online", true, "Started evil-box to scan from outside.");
      var t = deliver({ from: "evil-box", to: "lab-vps", port: "8080", bytes: 512 });
      recordTrace("curl http://" + BY_ID["lab-vps"].pub + ":8080/", t);
      note("sudo ufw status  # says 8080 is denied", "lab-vps");
      note("curl -sS http://" + BY_ID["lab-vps"].pub + ":8080/", "evil-box");
      verdict(t.ok ? "warn" : "ok",
        t.ok
          ? "UFW says deny. The port answers anyway. Docker writes into DOCKER-USER, " +
            "which iptables consults before UFW's chain, so publishing a port silently " +
            "punches through the firewall you were trusting. This is chapter 08's trap, " +
            "and it is the single most useful thing on this page."
          : "Nothing answered — the container is not publishing.");
    },

    "lock-out": function () {
      ensure("vps.allowPublic22", false,
        "Deleted the public :22 rule — the irreversible move.");
      ensure("vps.allowTailscale0", false,
        "…and, in the wrong order, removed the tailscale0 allow as well.");
      var overTailnet = deliver({ from: "lab-ubuntu", to: "lab-vps", port: "22" });
      recordTrace("ssh over the tailnet, after closing both", overTailnet);
      var overPublic = deliver({ from: "evil-box", to: "lab-vps", port: "22" });
      recordTrace("ssh to the public address, after closing both", overPublic);
      verdict("bad", "Both doors are shut and you are outside. On a VPS this is a " +
        "support ticket and a console session. Chapter 11's build order exists " +
        "precisely so that the tailnet route is proven working before the public " +
        "one is removed — never the other way round.");
    }
  };

  function runAttack(name) {
    var fn = ATTACKS[name];
    if (!fn) return;
    fn();
    paintAll();
    showTab("packets");
  }

  /* ============================================================
     10 · Named configurations, and scoring them

     A preset on its own teaches very little — you click it, the screen
     changes, you shrug. The value is in the audit: the same battery of
     checks fired at whatever is loaded, so two configurations can be
     compared with a number instead of a feeling.
     ============================================================ */

  function clone(o) { return JSON.parse(JSON.stringify(o)); }
  function dig(o, path) {
    return path.split(".").reduce(function (x, k) { return x == null ? undefined : x[k]; }, o);
  }
  function fmtVal(v) { return v === true ? "on" : v === false ? "off" : String(v); }

  function diffState(a, b) {
    var out = [];
    Object.keys(LABELS).forEach(function (path) {
      var x = dig(a, path), y = dig(b, path);
      if (x === y) return;
      out.push(LABELS[path] + ": " + fmtVal(x) + " → " + fmtVal(y));
    });
    var was = a.machines["lab-vps"].onTailnet, now = b.machines["lab-vps"].onTailnet;
    if (was !== now) out.push("the machines are on the tailnet: " + fmtVal(was) + " → " + fmtVal(now));
    return out;
  }

  /* The whole configuration as commands — so the Hardened preset's script
     tab is a runbook rather than a log of whatever you happened to click. */
  function scriptForState() {
    var v = S.vps, a = S.acl;
    if (S.machines["lab-vps"].onTailnet) {
      note("sudo tailscale up --hostname=lab-vps" + (a.ssh ? " --ssh" : ""), "lab-vps");
      note("sudo tailscale up --hostname=lab-ubuntu", "lab-ubuntu");
      note("sudo tailscale up --hostname=lab-roam", "lab-roam");
      note(a.lock ? "tailscale lock init" : "# tailnet lock is NOT enabled");
      note("# admin console: key expiry " + (a.expiry ? "on, 180 days" : "DISABLED"));
      note("# policy file: default action -> " + a.def);
      GRANTS.forEach(function (g) {
        if (a.grants[g.key]) note("#   grant: " + g.label);
      });
    } else {
      note("# no tailnet at all — the public address is the only way in");
    }
    note("sudo ufw default " + (v.ufwDefaultDeny ? "deny" : "allow") + " incoming", "lab-vps");
    if (v.allowTailscale0) note("sudo ufw allow in on tailscale0", "lab-vps");
    note(v.allowPublic22 ? "sudo ufw allow 22/tcp"
                         : "sudo ufw delete allow 22/tcp   # the irreversible one", "lab-vps");
    if (v.dockerPublish) note("docker run -d -p 8080:80 nginx", "lab-vps");
    note("# sshd_config: ListenAddress " +
      (v.sshdListen === "tailnet" ? BY_ID["lab-vps"].ts : "0.0.0.0"), "lab-vps");
    note("# sshd_config: PasswordAuthentication " + (v.passwordAuth ? "yes" : "no"), "lab-vps");
    note("# sshd_config: PermitRootLogin " + (v.permitRoot ? "yes" : "no"), "lab-vps");
    note("sudo sshd -t && sudo systemctl reload ssh", "lab-vps");
    if (S.tailcat.on) {
      note("# and, on " + S.tailcat.host + ", outside all of the above:");
      note("tailcat serve " + S.tailcat.service +
        (S.tailcat.service === "ssh" ? " --ssh-authorized-keys=~/.ssh/authorized_keys" : "") +
        (S.tailcat.allow ? " --allow=nodekey:cfb6bf…ddfd16" : ""), S.tailcat.host);
    }
  }

  function presetById(id) {
    var found = null;
    PRESETS.forEach(function (p) { if (p.id === id) found = p; });
    return found;
  }

  function stateFor(p, cleanLinks) {
    var s = clone(S);
    s.acl = clone(p.acl);
    s.vps = clone(p.vps);
    CATALOG.forEach(function (m) {
      if (m.hostile) return;
      s.machines[m.id].onTailnet = p.tailnet;
      s.machines[m.id].signed = p.tailnet;
      s.machines[m.id].online = true;
      s.machines[m.id].keyExpired = false;
    });
    s.machines["evil-box"] = { online: false, onTailnet: false, signed: false, keyExpired: false };
    s.segmentShared = false;
    /* A named configuration is a configuration, not a configuration plus
       whatever somebody left running on the side. */
    s.tailcat = defaults().tailcat;
    if (cleanLinks) s.links = defaults().links;
    return s;
  }

  function applyPreset(id) {
    var p = presetById(id);
    if (!p) return;
    var before = clone(S);
    S = stateFor(p, true);
    S.probe = { from: "lab-ubuntu", to: "lab-vps", port: "22" };

    script = [];
    note("# configuration: " + p.label + " — " + p.sub);
    scriptForState();

    var changes = diffState(before, S);
    log = [];
    record({
      ok: p.tone === "ok", danger: p.tone === "warn",
      title: p.label + " loaded",
      head: p.sub,
      why: p.note,
      lines: changes.length
        ? [changes.length + " setting" + (changes.length === 1 ? "" : "s") +
           " changed from what you had:"].concat(changes)
        : ["identical to what you already had"]
    });
    paintAll();
    verdict(p.tone === "ok" ? "ok" : p.tone === "warn" ? "warn" : "bad",
      p.label + " loaded — " + changes.length + " setting" +
      (changes.length === 1 ? "" : "s") + " changed. Press " +
      "“Audit this configuration” to see what it withstands.");
    showTab("packets");
  }

  /* ---- the audit -------------------------------------------------- */

  function asEvil(onTailnet, signed) {
    S.machines["evil-box"] = {
      online: true, onTailnet: onTailnet, signed: signed, keyExpired: false
    };
  }

  var GROUPS = {
    access: "Can you still do your job?",
    attack: "Does it hold against someone hostile?",
    config: "Is the machine itself sensibly set up?"
  };

  var AUDIT = [
    { kind: "access", want: true, label: "You can still get in",
      why: "The laptop reaches sshd over the tailnet.",
      fail: "You cannot reach your own server. A configuration that locks you out is " +
            "not secure, it is broken — and this is the failure people mistake for success.",
      run: function () { return deliver({ from: "lab-ubuntu", to: "lab-vps", port: "22" }).ok; } },

    { kind: "access", want: true, label: "…and so can the roaming client",
      why: "The phone's stand-in reaches it too.",
      fail: "The roaming client is locked out, which is the one machine the whole guide exists for.",
      run: function () { return deliver({ from: "lab-roam", to: "lab-vps", port: "22" }).ok; } },

    { kind: "attack", want: false, label: "A stranger cannot reach SSH",
      why: "The public address does not answer on :22.",
      fail: "Anyone on the internet can knock on your SSH port. They already are.",
      run: function () { asEvil(false, false);
        return deliver({ from: "evil-box", to: "lab-vps", port: "22" }).ok; } },

    { kind: "attack", want: false, label: "…nor a published container port",
      why: "Nothing is exposed on :8080.",
      fail: "A container's published port answers from the internet — through UFW, because " +
            "Docker's chain is consulted first. UFW will still tell you it is denied.",
      run: function () { asEvil(false, false);
        return deliver({ from: "evil-box", to: "lab-vps", port: "8080" }).ok; } },

    /* This asks whether the stolen key gets its holder to sshd, not whether the
       tailnet accepted it. Those came apart once lock and expiry stopped being
       liveness: a key nobody signed gets no session, and a machine with no
       session is an ordinary stranger, which is a thing chapter 08 has to
       answer rather than chapter 01. Both halves have to hold for this to. */
    { kind: "attack", want: false, label: "A stolen node key is refused",
      why: "An unsigned key gets no tailnet session — and no other route answers either.",
      fail: "A machine holding a key nobody vouched for still reaches sshd. Tailnet lock " +
            "keeps it off the tailnet; only a closed public :22 keeps it off the machine.",
      run: function () { asEvil(true, false);
        return deliver({ from: "evil-box", to: "lab-vps", port: "22" }).ok; } },

    { kind: "attack", want: false, label: "An untrusted member cannot reach the server",
      why: "It is on the tailnet and the policy still refuses it.",
      fail: "Being on the tailnet was enough to reach the server. Membership is not " +
            "authorisation unless the policy says so.",
      run: function () { asEvil(true, true);
        return deliver({ from: "evil-box", to: "lab-vps", port: "22" }).ok; } },

    { kind: "attack", want: false, label: "…nor your laptop",
      why: "The policy protects the clients too, not just the server.",
      fail: "One hostile member reaches your laptop. A flat tailnet is a flat network.",
      run: function () {
        asEvil(true, true);
        var t = deliver({ from: "evil-box", to: "lab-ubuntu", port: "22" });
        /* With no tailnet at all this holds for a reason that has nothing to do
           with your policy: the laptop is behind a NAT and there is no route to
           it. Worth saying, because it is the one check whose pass can flatter
           a configuration that has not earned it. */
        return { ok: t.ok, why: t.rung === 2
          ? "There is no route to the laptop from outside at all — it is behind " +
            "a NAT, not behind a policy. Join a tailnet and this check starts " +
            "measuring the policy instead."
          : null };
      } },

    { kind: "config", want: false, label: "Passwords cannot be used to log in",
      why: "PasswordAuthentication is off.",
      fail: "Password login is enabled. That is precisely what the scanners are trying, " +
            "thousands of times a day.",
      run: function () { return S.vps.passwordAuth; } },

    { kind: "config", want: false, label: "Root cannot log in directly",
      why: "PermitRootLogin is off.",
      fail: "Root can log in over the network, so one credential is the whole machine.",
      run: function () { return S.vps.permitRoot; } },

    { kind: "config", want: true, label: "A lost device stops being a member on its own",
      why: "Key expiry is on, so an unattended device drops out.",
      fail: "Key expiry is off. The phone you left in a taxi is a member forever, or until " +
            "you remember to remove it.",
      run: function () { return S.acl.expiry; } },

    { kind: "config", want: true, label: "sshd is not exposed on the public interface",
      why: "Bound to the tailnet address, or the public rule is gone.",
      fail: "sshd is listening on 0.0.0.0 with the public rule still in place — the exact " +
            "state chapter 08 is written to get you out of.",
      run: function () { return S.vps.sshdListen === "tailnet" || !S.vps.allowPublic22; } }
  ];

  /* A check answers with a boolean, or with { ok, why } when the reason it
     held depends on the configuration — a hostile machine that reaches nothing
     because the policy refused it has not proved the same thing as one that
     found no route at all, and saying so is the difference between a score and
     an explanation. */
  function checkResult(c) {
    var got, why = null;
    try {
      var r = c.run();
      if (r && typeof r === "object") { got = !!r.ok; why = r.why || null; }
      else got = !!r;
    } catch (e) { got = !c.want; }
    return { pass: got === c.want, why: why };
  }

  function scoreState(base) {
    var saved = S, n = 0;
    AUDIT.forEach(function (c) {
      S = clone(base);
      if (checkResult(c).pass) n++;
    });
    S = saved;
    return n;
  }

  /* Pure: run every check against the current state and put the state back.
     Never touches the DOM, so paintAll() can call it on every change. */
  function computeAudit() {
    var saved = clone(S);
    var results;
    try {
      results = AUDIT.map(function (c) {
        S = clone(saved);
        var r = checkResult(c);
        return { c: c, pass: r.pass, why: r.why };
      });
    } finally {
      S = saved;
    }
    return {
      results: results,
      compare: PRESETS.map(function (p) {
        return { label: p.label, score: scoreState(stateFor(p, true)) };
      })
    };
  }

  /* The button no longer computes anything — it just brings the tab forward
     and says out loud what the number already showing means. */
  function runAudit() {
    var results = computeAudit().results;
    var total = results.length;
    var pass = results.filter(function (r) { return r.pass; }).length;
    var lockedOut = results.some(function (r) { return r.c.kind === "access" && !r.pass; });
    showTab("audit");
    /* A perfect score with a tunnel open is the most misleading thing this
       page could print, so the tunnel gets said first. */
    var hatch = S.tailcat.on && !S.tailcat.allow
      ? " A tailcat tunnel is also open on " + S.tailcat.host + ", and no check below asks " +
        "about it — read the banner above the list before trusting this number."
      : "";
    verdict(lockedOut ? "bad" : (pass === total && !hatch) ? "ok" : "warn",
      (lockedOut
        ? pass + " of " + total + " checks held — but you are locked out of your own server, " +
          "so the score is meaningless. Closed is not the same as secure."
        : pass === total
          ? "All " + total + " held. Everything the attacker was allowed to try was refused, " +
            "and you can still work. This is the configuration the guide builds towards."
          : pass + " of " + total + " held. Each failure below names what it costs you — and " +
            "the number moves as you change anything above.") + hatch);
  }

  /* Deliberately a banner and not a twelfth check. The eleven are a rubric
     shared one-for-one with the containers in lab/, and only a real host can
     honestly be inspected for a tunnel process — so until that lands (issue
     #46) this names the gap rather than moving a number it has not earned.

     Note what driving it actually showed: the score is not uniformly blind.
     A tunnel on lab-vps drops it to 7/11 and one on lab-ubuntu to 10/11,
     because some checks happen to probe those machines — but the same tunnel
     on lab-roam leaves a clean 11/11. A score that moves only when the
     attacker's route happens to cross a check is the more honest lesson, and
     the wording below says so rather than claiming blanket blindness. */
  function tailcatBanner() {
    if (!S.tailcat.on) return "";
    var t = S.tailcat, tone, text;
    if (t.allow) {
      tone = "warn";
      text = "A tailcat tunnel is running on " + t.host + ", pinned to one client key with " +
             "--allow. That is the mitigated shape, and it is still a way in that nothing " +
             "below looks at.";
    } else if (t.service === "all" || t.service === "no-auth-ssh") {
      tone = "bad";
      text = "A tailcat tunnel is running on " + t.host + ", serving " + t.service + ", with " +
             "the address as the only credential" +
             (t.shared ? " — and evil-box is holding it" : "") + ". Anyone who has that " +
             "string has " + (t.service === "all" ? "the machine" : "a shell") + ".";
    } else {
      tone = "warn";
      text = "A tailcat tunnel is running on " + t.host + ". One SSH key stands between the " +
             "address and a shell, and nothing below knows the tunnel is there.";
    }
    return '<div class="sb-tailcat is-' + tone + '">' +
      "<b>No check below asks whether a tunnel is running.</b> " + esc(text) +
      " Some checks may still move, because the tunnel changed what evil-box can reach — but " +
      "only where a check happens to probe that particular machine. Move the same tunnel to " +
      "lab-roam, which nothing here probes, and the score reads a clean 11 / 11 with the " +
      "tunnel still open. That is the failure mode worth remembering: not a number that drops, " +
      "a number that has nothing to say.</div>";
  }

  function paintAudit() {
    if (!el.audit) return;
    var a = computeAudit();
    var results = a.results, compare = a.compare;
    var total = results.length;
    var pass = results.filter(function (r) { return r.pass; }).length;
    var lockedOut = results.some(function (r) { return r.c.kind === "access" && !r.pass; });
    var tone = lockedOut ? "bad" : pass === total ? "ok" : pass >= total - 3 ? "warn" : "bad";

    var scale = lockedOut
      ? "You cannot reach your own machines, so this number means nothing. Fix that first."
      : pass === total
        ? "Every check held. This is the target."
        : (total - pass) + " of " + total + " did not hold — see below.";

    var html = '<div class="sb-score is-' + tone + '">' +
      '<b>' + pass + " / " + total + "</b>" +
      "<span>checks held &middot; " + esc(scale) + "</span></div>" +
      '<p class="sb-scale">' +
      "<b>Higher is better, and " + total + " / " + total + " is the target.</b> " +
      "Each check is one thing this guide teaches you to close, and it counts as held only " +
      "when the configuration currently loaded refuses it. Two of them ask whether " +
      "<em>you</em> can still get in — without those, a machine with every door bricked shut " +
      "would score nearly full marks. The number recomputes on every change you make above, " +
      "so you can watch a single switch move it." +
      "</p>" + tailcatBanner();

    ["access", "attack", "config"].forEach(function (kind) {
      var rows = results.filter(function (r) { return r.c.kind === kind; });
      if (!rows.length) return;
      html += '<div class="sb-audit-group">' + esc(GROUPS[kind]) + "</div>";
      rows.forEach(function (r) {
        html += '<div class="sb-check is-' + (r.pass ? "ok" : "bad") + '">' +
          '<span class="ck-mark">' + (r.pass ? "✓" : "✗") + "</span>" +
          '<span class="ck-body"><span class="ck-label">' + esc(r.c.label) + "</span>" +
          '<span class="ck-why">' +
          esc(r.pass ? (r.why || r.c.why) : r.c.fail) + "</span></span></div>";
      });
    });

    if (compare && compare.length) {
      html += '<div class="sb-audit-group">For comparison, on a clean network</div>';
      html += '<div class="sb-compare">';
      compare.forEach(function (c) {
        var pct = Math.round((c.score / total) * 100);
        html += '<div class="cmp-row"><span class="cmp-name">' + esc(c.label) + "</span>" +
          '<span class="cmp-bar"><span style="width:' + pct + '%"></span></span>' +
          '<span class="cmp-score">' + c.score + "/" + total + "</span></div>";
      });
      html += "</div>";
      html += '<p class="pp-foot">Every one of those is a real configuration somebody is ' +
        "running right now. The gap between the second and the last is eleven switches.</p>";
    }
    el.audit.innerHTML = html;
  }

  /* ============================================================
     11 · URL state, so a configuration can be shared
     ============================================================ */

  function saveHash() {
    try {
      var slim = {
        m: S.machines, l: S.links, g: S.segmentShared,
        a: S.acl, v: S.vps, p: S.probe, c: S.tailcat
      };
      var json = JSON.stringify(slim);
      var b64 = btoa(unescape(encodeURIComponent(json)));
      history.replaceState(null, "", "#s=" + b64);
    } catch (e) { /* file:// can refuse replaceState — not worth breaking over */ }
  }

  function loadHash() {
    try {
      var m = location.hash.match(/#s=(.+)$/);
      if (!m) return;
      var json = decodeURIComponent(escape(atob(m[1])));
      var o = JSON.parse(json);
      if (o.m) S.machines = o.m;
      if (o.l) S.links = o.l;
      if (typeof o.g === "boolean") S.segmentShared = o.g;
      if (o.a) S.acl = o.a;
      if (o.v) S.vps = o.v;
      if (o.p) S.probe = o.p;
      if (o.c) S.tailcat = o.c;
    } catch (e) { S = defaults(); }
  }

  /* ============================================================
     12 · Boot
     ============================================================ */

  function boot() {
    el.controls = q("[data-sandbox-controls]");
    el.status = q('[data-pane="status"] pre');
    el.rules = q('[data-pane="rules"] pre');
    el.script = q('[data-pane="script"] pre');
    el.packets = q('[data-pane="packets"]');
    el.audit = q('[data-pane="audit"]');
    el.verdict = q(".sb-verdict");
    el.probeFrom = q("[data-probe-from]");
    el.probeTo = q("[data-probe-to]");
    el.probePort = q("[data-probe-port]");
    el.cryptoNote = q("[data-crypto-note]");

    loadHash();
    buildControls(el.controls);
    wire();
    paintScript();
    paintPackets();
    paintAll();
    showTab("status");
    root.classList.add("sb-on");
    if (reduced.matches) root.classList.add("sb-still");

    verdict("", "Three machines, a default-deny tailnet, and public :22 still open. " +
      "Change anything above and the readout on the right recomputes.");

    Crypto.init().then(function () {
      if (el.cryptoNote) el.cryptoNote.textContent = Crypto.note;
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
