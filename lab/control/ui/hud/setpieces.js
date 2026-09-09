/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Hashem Aldhaheri */

/* ============================================================
   The ten attacks, and the two demonstrations that are not attacks,
   as set-pieces.

   Ten genuinely different mechanisms — an anti-replay window, a netmap
   removal, a chain-ordering trap, a route offer that is not an approval,
   a tunnel that asks nothing — used to arrive as paragraphs in one column,
   where they all read as the same texture. Each of them has exactly one
   thing worth looking at. This file points the camera at that thing.

   The other two are not attacks. `outage` is the session layer, the half of
   this guide the board otherwise had nothing of, and it is the only shot
   here with two acts. `rotate-key` is maintenance, which is the one subject
   on this board judged by what it leaves undisturbed. Everything the ten
   obey, both of them obey.

   The grammar every set-piece here obeys, because a shot that breaks one
   of these teaches the wrong lesson:

     X is the ladder.    Nothing travels further right than the rung the
                         Result actually reports.
     Y is protection.    Height is a claim about whether a packet is
                         readable, so it has to be true.
     The shell is encryption.  Core plus lattice shell with a hex label, or
                         bare core with a legible one. Nothing else wears it.
     Colour is never the only channel.  Every state has a shape as well, and
                         every state the scene shows exists as text in the
                         HUD — the canvas is aria-hidden and the live region
                         carries the verdict.

   And the four honesty rules, which is where attacks are easiest to break:

     Nothing is drawn that was not measured. An empty capture draws an empty
       tray, because a successful capture is the interesting picture and that
       is exactly why it must not be animated when it did not happen.
     A failed attack is not a green tick. res.ok on an attack means the
       defence held; render the defence answering, and name it.
     res.danger outranks res.ok in tone. docker-bypass succeeding is a red frame.
     Time is not faked. The choreography is a fixed length. The millisecond
       figures stay the measured ones.

   Everything below reads fields off the Result the control server returned.
   There are no hard-coded outcomes: run the same attack against `weak` and
   against `hardened` and the frame differs, because the fields differ.

   The four rules are decisions about a Result rather than about geometry, so
   they live in ./reading.js as pure functions — where ../../../checks can
   assert them, which matters here more than most places: run() below catches
   anything a shot throws, so a broken rule looks like an action that simply
   has no set-piece.
   ============================================================ */

import { GEOM } from "./scene.js";
import { ev, tone, ladderMark, neverRan, head, scanReading, sniffReading,
         tailcatReading } from "./reading.js";

const { POS, GX, ANY, Y_PUB, Y_MACH, Y_NET, Y_DERP, TN_Y } = GEOM;

/* The four ports `nmap -p 22,80,8080,41641` asks about, stacked up lab-vps's
   face. The board has real sockets for two of them; the other two are props
   for the duration of the scan. */
const SCAN_PORTS = [
  { port: "22",    dy:  0.28 },
  { port: "80",    dy:  0.90 },
  { port: "8080",  dy: -0.34 },
  { port: "41641", dy: -0.96 }
];

/* ---------- small shared helpers --------------------------------- */

function V(board, x, y, z) { return new board.THREE.Vector3(x, y, z); }

/* The single door into the scene for everything a set-piece builds. Props go
   in stamped with the graphics context they were made against, so that if the
   GPU takes that context away the board knows not to try to free handles that
   died with it. */
function put(board, obj, x, y, z) {
  if (x != null) obj.position.set(x, y, z);
  board.adopt(obj);
  board.scratch.add(obj);
  return obj;
}

function text(board, s, x, y, z, opts) {
  const lb = board.mk.label(s, Object.assign({ px: 30, size: 0.4 }, opts || {}));
  return put(board, lb, x, y, z);
}

function curve(board, pts) { return new board.THREE.CatmullRomCurve3(pts); }

function ray(board, pts, color, opacity, dashed) {
  return put(board, board.mk.line(pts, color, opacity, !!dashed));
}

/* A bead that runs a curve for as long as the shot lasts. Motion, not a
   claim: it never travels further than the curve it was given, and the
   curve is what the Result allowed. */
function bead(board, path, color, speed, size) {
  const dot = put(board, board.mk.sphere(size || 0.12, color));
  dot.position.copy(path.getPointAt(0));
  if (board.reduced) { dot.position.copy(path.getPointAt(1)); return dot; }
  board.spin((dt, el) => {
    dot.position.copy(path.getPointAt(((el * (speed || 0.5)) % 1)));
  });
  return dot;
}

/* Every set-piece ends here: a held frame that names the defence that
   answered, in the same words whether or not anything moved. The two
   judgements it makes — which rung, and which tone — are reading.js's,
   because they are the two the rest of this file is easiest to break. */
function held(board, res, v) {
  board.setLadder(res.rung || 1, v.ladder || ladderMark(res), v.skipped);
  board.setVerdict({
    tone: tone(res),
    head: v.head,
    rule: v.rule || res.rule,
    why: res.why,
    nums: v.nums || [],
    transcript: (res.cmds && res.cmds.length) ? res.cmds[res.cmds.length - 1] : ""
  });
  board.setChip(v.chip || "attack · held frame", v.chipKind || "pub");
}

/* ev, head, neverRan, tone, ladderMark and the two readings are imported
   from ./reading.js. They are the parts of this file that decide rather
   than draw, they are the parts run()'s try/catch would hide a mistake in,
   and they are the parts checks/reading.test.mjs asserts. */

/* ============================================================
   1 · scan-public
   Low on the public plane, looking up at lab-vps's face. A fan of probe
   rays; open ports come back as lit dots. The attack surface IS the lit
   dots — so they are drawn from Evidence, one per port nmap actually
   reported open, and never from the prose in Why.
   ============================================================ */
function scanPublic(board, res) {
  const C = board.C, vz = POS["lab-vps"].z;
  board.fly(V(board, -3.0, Y_PUB + 0.7, vz + 12.6),
            V(board, GX.g5 - 1.0, Y_MACH - 0.1, vz));

  /* The standing dashed beams are what the rules imply. For the length of
     this shot they come down, because a measurement is about to replace them. */
  board.parts.beamHost.visible = false;

  const scan = scanReading(res, SCAN_PORTS.map((p) => p.port));

  const steps = [];
  SCAN_PORTS.forEach((p, i) => {
    const isOpen = ev(res, "open:" + p.port) > 0;
    const target = V(board, GX.g5, Y_MACH + p.dy, vz);
    const path = curve(board, [
      ANY.clone(),
      V(board, -3.0, Y_PUB + 0.3, ANY.z + 1.2),
      V(board, 2.4, Y_PUB + 0.35, vz - 1.6),
      isOpen ? V(board, GX.g4, Y_MACH + p.dy - 0.4, vz) : V(board, GX.g4 - 1.4, Y_PUB + 0.9, vz),
      isOpen ? target : V(board, GX.g4 - 0.4, Y_PUB + 1.5, vz)
    ]);
    steps.push({
      t: 0.15 * i,
      fn: () => {
        ray(board, path.getPoints(44), isOpen ? C.danger : C.faint, isOpen ? 0.85 : 0.3, !isOpen);
        if (!board.reduced) bead(board, path, isOpen ? C.danger : C.faint, 0.55, 0.1);
      }
    });
    steps.push({
      t: 0.15 * i + 0.5,
      fn: () => {
        /* A lit dot is a measurement. A ring with nothing in it is a port
           that did not answer — shape, not only colour. */
        if (isOpen) {
          const d = put(board, board.mk.sphere(0.19, C.danger), target.x, target.y, target.z);
          d.scale.setScalar(0.4);
          if (!board.reduced) board.spin((dt, el) => d.scale.setScalar(1 + Math.sin(el * 5) * 0.18));
          else d.scale.setScalar(1);
          text(board, ":" + p.port + " open", target.x - 0.4, target.y, target.z + 3.4,
               { px: 28, size: 0.36, color: C.danger });
        } else {
          const r = new board.THREE.Mesh(
            new board.THREE.RingGeometry(0.15, 0.19, 20),
            new board.THREE.MeshBasicMaterial({ color: C.faint, transparent: true,
                                                opacity: 0.6, side: board.THREE.DoubleSide }));
          r.rotation.y = Math.PI / 2;
          put(board, r, target.x, target.y, target.z);
          text(board, ":" + p.port + " no answer", target.x - 0.4, target.y, target.z + 3.4,
               { px: 26, size: 0.32, color: C.faint });
        }
      }
    });
  });
  board.timeline(steps);

  /* The gauge stops being a claim about the rules and becomes a count — but
     only if the scan ran, which is scanReading's call and not this shot's. */
  if (scan.ran) board.setExposure(scan.open, true);

  held(board, res, {
    head: head(res,
      "ufw default incoming policy: deny",
      "the host firewall let them through",
      "nothing was scanned — is evil-box running?"),
    nums: scan.nums,
    chip: "public segment · in the clear", chipKind: "pub"
  });
}

/* ============================================================
   2 · scan-tailnet
   Inside the tailnet plane, at the membrane. evil-box is through the door
   and every destination cell is still dark: membership is not
   authorisation — until `* → * : *` is on and every cell lights at once.
   ============================================================ */
function scanTailnet(board, res) {
  const C = board.C;
  board.fly(V(board, GX.g3 - 5.5, TN_Y + 2.0, 15.5), V(board, GX.g3 + 0.5, TN_Y - 0.2, 0.2));

  const st = board.state || { acl: { grants: {} } };
  const wideOpen = !!(st.acl.grants && st.acl.grants.any);
  const evilZ = POS["evil-box"].z;

  /* It is inside: a member, at tailnet height, on the near side of the wall. */
  const inPath = curve(board, [
    V(board, POS["evil-box"].x + 1.6, Y_MACH, evilZ),
    V(board, GX.g2, Y_MACH + 1.1, evilZ),
    V(board, GX.g2 + 1.8, TN_Y - 0.4, evilZ),
    V(board, GX.g3 - 1.6, TN_Y, evilZ)
  ]);
  ray(board, inPath.getPoints(40), C.warn, 0.7);
  text(board, "evil-box · a member", GX.g3 - 3.4, TN_Y + 0.75, evilZ,
       { px: 28, size: 0.36, color: C.warn });

  /* One cell per destination it tried to reach, on the far side of the wall.
     Which of them lit is per destination, from Evidence — "it reached one of
     the three" and "it reached all three" are different findings, and the
     danger flag cannot tell them apart. */
  const targets = ["lab-vps", "lab-ubuntu", "lab-roam"];
  const reached = targets.filter((id) => ev(res, "reached:" + id) > 0);
  const cells = targets.map((id) => {
    const z = POS[id].z;
    const cell = board.mk.slab(0.34, 0.9, 1.9, 0xffffff, 0.05);
    put(board, cell, GX.g3 + 0.6, TN_Y, z);
    board.mk.setSlab(cell, C.faint, 0.03, 0.35);
    const lb = text(board, id, GX.g3 + 2.6, TN_Y + 0.05, z, { px: 28, size: 0.36, color: C.faint });
    return { id, cell, lb, z };
  });

  const steps = [{
    t: 0.6,
    fn: () => {
      cells.forEach((c, i) => {
        /* Dark cells are the answer when the policy holds. A cell lights only
           because the lab reported reaching that particular machine. */
        const lit = reached.indexOf(c.id) !== -1;
        board.mk.setSlab(c.cell, lit ? C.danger : C.faint, lit ? 0.12 : 0.03, lit ? 0.95 : 0.35);
        c.lb.material.color.copy(lit ? C.danger : C.faint);
        if (lit) {
          const p = curve(board, [
            V(board, GX.g3 - 1.4, TN_Y, evilZ),
            V(board, GX.g3 + 0.6, TN_Y, (evilZ + c.z) / 2),
            V(board, GX.g3 + 2.2, TN_Y, c.z)
          ]);
          ray(board, p.getPoints(24), C.danger, 0.8);
          if (!board.reduced) bead(board, p, C.danger, 0.7 + i * 0.1, 0.1);
        }
      });
      if (wideOpen && board.parts.grantCells.any) {
        text(board, "* → * : *  — membership became total access",
             GX.g3 + 1.0, TN_Y - 2.1, 0.2, { px: 28, size: 0.36, color: C.danger });
      }
    }
  }];
  board.timeline(steps);

  held(board, res, {
    head: head(res,
      "no grant matched, and the default action is deny",
      wideOpen ? "the grant * → * : * — one rule, and membership became total access"
               : "the policy allowed it",
      "it never got onto the tailnet, so the policy was never the thing under test"),
    nums: [targets.length + " destinations tried",
           reached.length + " reached" + (reached.length ? ": " + reached.join(", ") : "")],
    chip: "inside the tailnet · wrapped", chipKind: "net"
  });
}

/* ============================================================
   3 · sniff
   Down at wire level on lab-ubuntu's segment. The tap siphons copies into
   a tray. The marker sent in the clear lands legible; the identical marker
   sent through the tunnel lands as an opaque brick. The control experiment
   as three objects rather than three numbers.

   If the capture came back empty the tray stays empty and the verdict says
   so — a successful capture is the interesting picture, which is exactly
   why it must not be drawn when there was not one.
   ============================================================ */
function sniff(board, res, ctx) {
  const C = board.C, uz = POS["lab-ubuntu"].z, ux = POS["lab-ubuntu"].x;
  board.fly(V(board, ux + 5.0, Y_MACH + 1.6, uz + 13.0), V(board, ux + 2.8, Y_MACH - 0.7, uz));

  const r = sniffReading(res);

  /* the wire, and the thing sitting on it */
  const wire = curve(board, [
    V(board, ux + 1.6, Y_MACH - 0.2, uz),
    V(board, GX.g2 - 1.2, Y_MACH - 0.3, uz),
    V(board, GX.g2, Y_MACH - 0.3, uz)
  ]);
  ray(board, wire.getPoints(24), C.muted, 0.6);

  const tap = board.mk.slab(0.5, 0.5, 0.9, 0xffffff, 0.14);
  put(board, tap, ux + 3.4, Y_MACH - 0.3, uz);
  board.mk.setSlab(tap, C.danger, 0.14, 0.9);
  text(board, "evil-box · tcpdump on this segment", ux + 3.4, Y_MACH + 0.5, uz,
       { px: 26, size: 0.32, color: C.danger });

  /* the tray the copies fall into */
  const tray = board.mk.slab(3.4, 0.08, 2.0, 0xffffff, 0.06);
  put(board, tray, ux + 3.4, Y_MACH - 1.9, uz);
  board.mk.setSlab(tray, C.line, 0.05, 0.5);
  text(board, r.trayLabel, ux + 3.4, Y_MACH - 2.2, uz + 1.4,
       { px: 26, size: 0.32, color: r.frames ? C.muted : C.faint });

  const steps = [];
  const drop = (x, dz, wrapped, labelText, color, t) => {
    steps.push({
      t,
      fn: () => {
        const g = new board.THREE.Group();
        const coreMesh = new board.THREE.Mesh(
          new board.THREE.IcosahedronGeometry(0.15, 1),
          new board.THREE.MeshBasicMaterial({ color, transparent: true }));
        g.add(coreMesh);
        if (wrapped) {
          /* The shell is encryption, and only encryption wears it. */
          const sh = new board.THREE.Mesh(
            new board.THREE.OctahedronGeometry(0.38, 0),
            new board.THREE.MeshBasicMaterial({ color: C.accent, wireframe: true,
                                                transparent: true, opacity: 0.9 }));
          g.add(sh);
        }
        put(board, g, x, Y_MACH - 1.72, uz + dz);
        text(board, labelText, x, Y_MACH - 1.2 + dz * 0.28, uz + dz + 1.6,
             { px: 26, size: 0.32, color });
      }
    });
  };

  /* Two objects or none. sniffReading decides which, so that "an empty
     capture draws an empty tray" is a rule with a test on it rather than a
     branch in a shot nothing runs. */
  if (r.note) {
    steps.push({ t: 0.4, fn: () => {
      text(board, r.note, ux + 3.4, Y_MACH - 1.4, uz, { px: 28, size: 0.36, color: C.warn });
    }});
  }
  r.drops.forEach((d, i) => {
    drop(i === 0 ? ux + 2.2 : ux + 4.6, i === 0 ? 0.7 : -0.7,
         d.wrapped, d.label, d.tone === "accent" ? C.accent : C.danger, 0.5 + i * 0.5);
  });
  board.timeline(steps);

  /* One particle per real frame off the wire. The motion is measured rather
     than invented, which is the whole ethic of this directory. The stream is
     live traffic now, not the frames the capture already holds, and it is
     labelled as such. */
  if (ctx && ctx.openStream && r.frames > 0 && !board.reduced) {
    let n = 0;
    const live = [];
    const stop = ctx.openStream("/api/stream/tcpdump?machine=evil-box", "packet", () => {
      if (n++ > 60) return;
      const d = put(board, board.mk.sphere(0.06, C.danger, 0.85),
                    ux + 3.4 + (Math.random() - 0.5) * 0.6, Y_MACH - 0.5, uz);
      live.push({ d, y: Y_MACH - 0.5 });
    });
    board.spin((dt) => {
      for (let i = live.length - 1; i >= 0; i--) {
        live[i].y -= dt * 1.6;
        live[i].d.position.y = live[i].y;
        if (live[i].y < Y_MACH - 1.8) { live[i].d.position.y = Y_MACH - 1.8; live.splice(i, 1); }
      }
    });
    /* The caller closes it when the next action starts; holding the handle
       here would only give a second place for it to be forgotten. */
    void stop;
  }

  held(board, res, {
    head: r.head,
    rule: r.rule,
    nums: r.nums,
    chip: "on the wire · in the clear", chipKind: "pub"
  });
}

/* ============================================================
   4 · replay
   Tight on the receiving machine. Copies fired; each bounces off the
   counter window and dissolves. The cheapest attack there is, answered
   without a rule.
   ============================================================ */
function replay(board, res) {
  const C = board.C, vz = POS["lab-vps"].z, vx = POS["lab-vps"].x;
  board.fly(V(board, vx - 8.0, Y_MACH + 4.0, vz + 12.0), V(board, vx - 1.2, Y_MACH + 0.1, vz));

  const replayed = res.packets || 0;
  const delta = res.retransmits || 0;

  /* the counter window: the thing that answers, drawn as a thing */
  const win = new board.THREE.Mesh(
    new board.THREE.CircleGeometry(1.25, 40),
    new board.THREE.MeshBasicMaterial({ color: C.accent, transparent: true, opacity: 0.1,
                                        side: board.THREE.DoubleSide }));
  win.rotation.y = -Math.PI / 2;
  put(board, win, vx - 2.2, Y_MACH + 0.1, vz);
  const rim = new board.THREE.Mesh(
    new board.THREE.RingGeometry(1.2, 1.28, 40),
    new board.THREE.MeshBasicMaterial({ color: C.accent, transparent: true, opacity: 0.9,
                                        side: board.THREE.DoubleSide }));
  rim.rotation.y = -Math.PI / 2;
  put(board, rim, vx - 2.2, Y_MACH + 0.1, vz);
  text(board, "WireGuard's counter for this session", vx - 2.2, Y_MACH + 1.7, vz,
       { px: 26, size: 0.34, color: C.accent });

  if (replayed === 0) {
    board.timeline([{ t: 0.3, fn: () => {
      text(board, "no WireGuard frames in the capture — nothing was put back on the wire",
           vx - 2.6, Y_MACH - 1.2, vz, { px: 28, size: 0.36, color: C.warn });
    }}]);
    held(board, res, {
      head: neverRan(res)
        ? "INCONCLUSIVE · nothing ran — is evil-box running? `make attack`"
        : "INCONCLUSIVE · there was nothing to replay",
      nums: neverRan(res) ? [] : ["0 frames replayed"],
      chip: "on the wire · in the clear", chipKind: "pub"
    });
    return;
  }

  /* Twenty is what the loop count is, and twenty is what is drawn. The
     number in the HUD is the measured one either way. */
  const SHOTS = Math.min(20, replayed);
  const copies = [];
  const steps = [];
  for (let i = 0; i < SHOTS; i++) {
    steps.push({
      t: 0.05 * i,
      fn: () => {
        const g = new board.THREE.Group();
        g.add(new board.THREE.Mesh(
          new board.THREE.IcosahedronGeometry(0.11, 1),
          new board.THREE.MeshBasicMaterial({ color: C.accent, transparent: true })));
        g.add(new board.THREE.Mesh(
          new board.THREE.OctahedronGeometry(0.28, 0),
          new board.THREE.MeshBasicMaterial({ color: C.accent, wireframe: true,
                                              transparent: true, opacity: 0.8 })));
        const z = vz + (i % 5 - 2) * 0.42;
        const y = Y_MACH + 0.1 + (Math.floor(i / 5) - 1.5) * 0.42;
        put(board, g, vx - 6.4, y, z);
        copies.push({ g, y, z, u: 0, hit: false });
      }
    });
  }
  board.timeline(steps);

  if (board.reduced) {
    /* Hold the answer rather than fly to it: every copy is already at the
       window, which is the frame the moving version ends on. */
    copies.forEach((c) => { c.g.position.x = vx - 3.5; });
  } else {
    board.spin((dt) => {
      copies.forEach((c) => {
        if (c.hit) {
          c.g.scale.multiplyScalar(1 - dt * 2.4);
          c.g.position.x -= dt * 1.1;
          if (c.g.scale.x < 0.05) c.g.visible = false;
          return;
        }
        c.g.position.x += dt * 4.2;
        c.g.rotation.y += dt * 3;
        if (c.g.position.x >= vx - 3.5) { c.g.position.x = vx - 3.5; c.hit = true; }
      });
    });
  }

  held(board, res, {
    head: head(res, "the anti-replay window discarded them",
               "lab-vps accepted a replayed frame"),
    rule: res.rule,
    nums: [replayed + " frames replayed", "tailscale0 rx moved by " + delta],
    chip: "on the wire · in the clear", chipKind: "pub"
  });
}

/* ============================================================
   5 · stolen-key
   At the membrane's edge. Lock on: no cell exists for the key, refused at
   the door. Lock off: a cell lights and it is inside — and what happens
   next is a different gate's business, which is why the rung matters more
   than the boolean here.
   ============================================================ */
function stolenKey(board, res) {
  const C = board.C, ez = POS["evil-box"].z;
  board.fly(V(board, GX.g3 - 4.5, TN_Y + 2.5, ez + 15.0), V(board, GX.g3 + 0.3, TN_Y - 0.2, ez));

  const st = board.state || { acl: {} };
  const lockOn = !!st.acl.lock;

  /* the key, arriving at the door */
  const key = new board.THREE.Group();
  key.add(new board.THREE.Mesh(
    new board.THREE.TorusGeometry(0.2, 0.055, 8, 24),
    new board.THREE.MeshBasicMaterial({ color: C.warn, transparent: true })));
  const shaft = new board.THREE.Mesh(
    new board.THREE.BoxGeometry(0.62, 0.07, 0.07),
    new board.THREE.MeshBasicMaterial({ color: C.warn, transparent: true }));
  shaft.position.x = 0.42; key.add(shaft);
  put(board, key, GX.g3 - 3.6, TN_Y, ez);
  text(board, "a node key nobody authorised", GX.g3 - 3.6, TN_Y + 0.8, ez,
       { px: 26, size: 0.34, color: C.warn });

  const steps = [{
    t: 0.5,
    fn: () => {
      if (lockOn) {
        /* No cell at this z. The wall is where the key stops. */
        const bar = board.mk.slab(0.3, 1.3, 2.3, 0xffffff, 0.16);
        put(board, bar, GX.g3, TN_Y, ez);
        board.mk.setSlab(bar, C.accent, 0.16, 0.95);
        text(board, "tailnet lock · no cell exists for this key",
             GX.g3 + 0.4, TN_Y + 1.15, ez, { px: 28, size: 0.36, color: C.accent });
        if (!board.reduced) {
          board.spin((dt, el) => { key.position.x = GX.g3 - 0.9 + Math.abs(Math.sin(el * 1.4)) * 2.6; });
        } else {
          key.position.x = GX.g3 - 0.9;
        }
      } else {
        const cell = board.mk.slab(0.42, 1.1, 2.3, 0xffffff, 0.05);
        put(board, cell, GX.g3, TN_Y, ez);
        board.mk.setSlab(cell, C.danger, 0.04, 0.95);
        text(board, "no lock · the key is enough to be a member",
             GX.g3 + 0.6, TN_Y + 1.15, ez, { px: 28, size: 0.36, color: C.danger });
        const through = curve(board, [
          V(board, GX.g3 - 3.6, TN_Y, ez),
          V(board, GX.g3, TN_Y, ez),
          V(board, GX.g3 + 2.6, TN_Y, ez)
        ]);
        ray(board, through.getPoints(24), C.danger, 0.8);
        if (!board.reduced) board.spin((dt, el) => {
          key.position.copy(through.getPointAt((el * 0.35) % 1));
        });
        else key.position.copy(through.getPointAt(1));
      }
    }
  }, {
    /* And then, whatever the door said, the rung says what stopped it. */
    t: 1.3,
    fn: () => {
      const reached = res.ok ? 5 : (res.rung || 1);
      const gateX = [GX.g1, GX.g2, GX.g3, GX.g4, GX.g5][reached - 1];
      text(board, "stopped at rung " + reached + " of 5",
           gateX, TN_Y - 1.5, ez + 1.2,
           { px: 28, size: 0.38, color: res.danger ? C.danger : C.ok });
    }
  }];
  board.timeline(steps);

  held(board, res, {
    head: head(res,
      lockOn ? "tailnet lock refused the key, and nothing else answered either"
             : "the key worked, and it still got nowhere",
      lockOn ? "the key was refused, and public :22 answered anyway"
             : "a leaked key is a login when nothing vouches for node keys"),
    nums: ["lock " + (lockOn ? "on" : "off"), "rung " + (res.rung || 1) + " of 5"],
    chip: lockOn ? "refused at the door" : "inside the tailnet · wrapped",
    chipKind: lockOn ? "pub" : "net"
  });
}

/* ============================================================
   6 · expired-key
   Wide, on the tailnet plane. lab-roam's key crumbles and the machine
   drifts out of the plane on its own. The lost phone that removes itself.
   ============================================================ */
function expiredKey(board, res) {
  const C = board.C, rz = POS["lab-roam"].z;
  board.fly(V(board, -2.0, Y_NET + 7.0, 20.0), V(board, -2.0, Y_NET - 1.0, 0.2));

  const roam = board.parts.machines["lab-roam"];

  /* atkExpiredKey has three endings and two of them are ok=false at the same
     rung, so the rung cannot separate them — Evidence can. `dropped` is
     whether the machine actually fell out of the tailnet; `probeOK` is
     whether the probe afterwards got in. Only both together mean "expiry
     worked and the public door undid it", and drawing that path for the
     third ending would be inventing a result the lab did not produce. */
  const dropped = ev(res, "dropped") > 0;
  const reachedSSHD = dropped && ev(res, "probeOK") > 0;
  const stillHasSession = !res.ok && !dropped;

  /* the key, crumbling */
  const shards = [];
  const steps = [{
    t: 0.3,
    fn: () => {
      text(board, "180 days pass, and nobody reauthenticated",
           POS["lab-roam"].x + 2.2, TN_Y + 0.9, rz, { px: 28, size: 0.36, color: C.warn });
      for (let i = 0; i < 14; i++) {
        const s = put(board, board.mk.sphere(0.07, C.warn, 0.9),
          POS["lab-roam"].x + 1.2 + (Math.random() - 0.5) * 0.5,
          TN_Y + (Math.random() - 0.5) * 0.5,
          rz + (Math.random() - 0.5) * 0.5);
        shards.push({ s, vy: -0.6 - Math.random() * 0.9, vx: (Math.random() - 0.5) * 0.8 });
      }
      if (board.reduced) shards.forEach((f) => { f.s.position.y = Y_PUB + 0.3; });
      else board.spin((dt) => {
        shards.forEach((f) => {
          if (f.s.position.y <= Y_PUB + 0.3) return;
          f.s.position.y += f.vy * dt * 2.2;
          f.s.position.x += f.vx * dt;
          f.s.material.opacity = Math.max(0.1, f.s.material.opacity - dt * 0.25);
        });
      });
    }
  }, {
    /* It drifts out of the plane. Nobody touched the machine — but only if
       the lab reported that it did. */
    t: 1.0,
    fn: () => {
      if (!dropped) {
        text(board, "lab-roam is still holding its session — give it a few more seconds",
             POS["lab-roam"].x + 1.0, TN_Y + 1.6, rz, { px: 28, size: 0.38, color: C.warn });
        return;
      }
      board.parts.tunnelHost.visible = false;
      if (board.reduced) { roam.g.position.y = Y_PUB + 1.2; }
      else board.spin((dt) => {
        if (roam.g.position.y > Y_PUB + 1.2) roam.g.position.y -= dt * 1.4;
      });
      text(board, "lab-roam · no longer a member",
           POS["lab-roam"].x, Y_PUB + 2.4, rz, { px: 28, size: 0.38, color: C.faint });
    }
  }, {
    t: 1.9,
    fn: () => {
      /* Expiry ends membership. Whether it closed a door is a different
         question, and the rung is the one that answers it. */
      if (reachedSSHD) {
        const p = curve(board, [
          V(board, POS["lab-roam"].x + 1.6, Y_PUB + 1.0, rz),
          V(board, GX.g2 + 2.0, Y_PUB, rz),
          V(board, GX.g4, Y_PUB + 0.4, POS["lab-vps"].z),
          V(board, GX.g5, Y_MACH + 0.28, POS["lab-vps"].z)
        ]);
        ray(board, p.getPoints(40), C.danger, 0.85);
        if (!board.reduced) bead(board, p, C.danger, 0.4, 0.13);
        text(board, "and it reached sshd anyway — :22 is open to everyone",
             GX.g2 + 2.6, Y_PUB + 1.4, (rz + POS["lab-vps"].z) / 2,
             { px: 28, size: 0.36, color: C.danger });
      } else if (stillHasSession) {
        text(board, "the node was expired and still has a session — nothing is proved yet",
             GX.g2 + 2.6, Y_PUB + 1.4, rz, { px: 28, size: 0.36, color: C.warn });
      }
    }
  }];
  board.timeline(steps);

  held(board, res, {
    head: res.ok
      ? "HELD · key expiry removed it from the tailnet, and nothing else let it in"
      : reachedSSHD
        ? "THROUGH · expiry ended membership, and public :22 let it straight back in"
        : "INCONCLUSIVE · the node was expired and still has a session",
    rule: res.rule,
    ladder: reachedSSHD ? "breached" : "stopped",
    nums: ["rung " + (res.rung || 1) + " of 5"],
    chip: "expired · outside the tailnet", chipKind: "pub"
  });
}

/* ============================================================
   7 · rogue-exit
   Above the plane, looking down. evil-box raises an offer and nothing
   bends towards it. Approve it and every arc reroutes through it and
   turns red. A route offer and an approval are two different things.
   ============================================================ */
function rogueExit(board, res) {
  const C = board.C, ez = POS["evil-box"].z;
  board.fly(V(board, -1.0, Y_DERP + 14.0, 6.0), V(board, -1.0, TN_Y - 0.5, 0.2));

  const approved = !!res.danger;

  /* the offer, raised */
  const beacon = new board.THREE.Mesh(
    new board.THREE.ConeGeometry(0.9, 2.6, 20, 1, true),
    new board.THREE.MeshBasicMaterial({ color: approved ? C.danger : C.warn, transparent: true,
                                        opacity: 0.22, side: board.THREE.DoubleSide,
                                        wireframe: true }));
  put(board, beacon, POS["evil-box"].x + 1.0, TN_Y + 1.4, ez);
  text(board, "--advertise-exit-node  · 0.0.0.0/0 offered",
       POS["evil-box"].x + 1.0, TN_Y + 3.0, ez, { px: 28, size: 0.38, color: approved ? C.danger : C.warn });

  /* the arcs that exist: the sessions the lab actually measured */
  const st = board.state || { machines: {} };
  const riders = ["lab-ubuntu", "lab-roam"].filter((id) => {
    const ms = st.machines[id];
    return ms && ms.onTailnet && ms.pathTo;
  });

  board.parts.tunnelHost.visible = false;
  const steps = [{
    t: 0.7,
    fn: () => {
      riders.forEach((id, i) => {
        const z = POS[id].z;
        const straight = [
          V(board, POS[id].x + 1.6, TN_Y, z),
          V(board, GX.g3, TN_Y, (z + POS["lab-vps"].z) / 2),
          V(board, GX.g4, TN_Y - 0.6, POS["lab-vps"].z),
          V(board, GX.g5, Y_MACH + 0.28, POS["lab-vps"].z)
        ];
        const viaEvil = [
          V(board, POS[id].x + 1.6, TN_Y, z),
          V(board, POS["evil-box"].x + 1.4, TN_Y + 0.4, (z + ez) / 2),
          V(board, POS["evil-box"].x + 1.6, TN_Y + 0.2, ez),
          V(board, GX.g3, TN_Y, (ez + POS["lab-vps"].z) / 2),
          V(board, GX.g4, TN_Y - 0.6, POS["lab-vps"].z),
          V(board, GX.g5, Y_MACH + 0.28, POS["lab-vps"].z)
        ];
        const path = curve(board, approved ? viaEvil : straight);
        ray(board, path.getPoints(50), approved ? C.danger : C.accent, approved ? 0.85 : 0.6);
        if (!board.reduced) bead(board, path, approved ? C.danger : C.accent, 0.3 + i * 0.06, 0.11);
      });
      text(board, approved
        ? "every route now leaves through a machine you do not own"
        : "advertised, and ignored — nothing bent towards it",
        GX.g3 - 1.0, TN_Y - 2.2, 0.2,
        { px: 28, size: 0.38, color: approved ? C.danger : C.accent });
    }
  }];
  board.timeline(steps);

  held(board, res, {
    head: head(res, "an exit node is a route offer, not a route",
               "the route was approved, and approval is what routes traffic",
               "evil-box is not on the tailnet, so it had nothing to advertise a route from — " +
               "turn tailnet lock off, or load a configuration that issues it a key"),
    nums: [riders.length + " sessions on the tailnet"],
    chip: "inside the tailnet · wrapped", chipKind: "net"
  });
}

/* ============================================================
   8 · docker-bypass
   Side-on at the shutter. The red beam goes AROUND the closed slats,
   through a channel that opened behind them. Chapter 08's trap in one
   look: a published container port is forwarded, not delivered locally,
   and the FORWARD chain jumps into Docker's chains before it reaches
   ufw's.
   ============================================================ */
function dockerBypass(board, res) {
  const C = board.C, vz = POS["lab-vps"].z;
  board.fly(V(board, GX.g4 - 1.0, Y_MACH + 2.0, vz + 14.0), V(board, GX.g4 + 1.4, Y_MACH - 0.3, vz - 0.8));

  const through = !!res.danger;
  const sock = board.parts.sockets["8080"].g.position;

  /* The subject of this shot is one slat, so that slat keeps its name and
     the other two stay context. Naming all three is how a frame with one
     claim turns back into a list. */
  board.parts.slats.docker.lb.material.opacity = 0.95;

  /* ufw's own answer, in front of the reader, so the contradiction is
     visible rather than asserted */
  text(board, "ufw status verbose: deny (incoming)", GX.g4 - 1.4, Y_MACH + 2.1, vz + 3.4,
       { px: 28, size: 0.38, color: C.accent });

  const steps = [{
    t: 0.4,
    fn: () => {
      if (!through) {
        const dead = curve(board, [
          ANY.clone(),
          V(board, GX.g2 + 2.0, Y_PUB, vz - 2.0),
          V(board, GX.g4 - 2.2, Y_PUB + 0.6, vz),
          V(board, GX.g4 - 0.6, Y_MACH - 0.5, vz)
        ]);
        ray(board, dead.getPoints(40), C.danger, 0.8);
        if (!board.reduced) bead(board, dead, C.danger, 0.45, 0.12);
        text(board, "the slats held — nothing answered on :8080",
             GX.g4 + 0.6, Y_MACH - 1.9, vz + 3.4, { px: 28, size: 0.4, color: C.ok });
        return;
      }

      /* The channel that opened behind the slats. It is drawn behind them
         on purpose: the packet never touches the shutter. */
      const chanZ = vz - 1.9;
      const chan = board.mk.slab(2.6, 0.55, 0.55, 0xffffff, 0.06);
      put(board, chan, GX.g4 + 0.4, Y_MACH - 0.34, chanZ);
      board.mk.setSlab(chan, C.danger, 0.05, 0.75);
      text(board, "the FORWARD chain jumps in here, before ufw's",
           GX.g4 + 0.2, Y_MACH + 0.55, chanZ - 1.6, { px: 26, size: 0.32, color: C.danger });

      const around = curve(board, [
        ANY.clone(),
        V(board, GX.g2 + 2.0, Y_PUB, vz - 2.4),
        V(board, GX.g4 - 3.0, Y_PUB + 0.5, chanZ),
        V(board, GX.g4 - 1.4, Y_MACH - 0.34, chanZ),
        V(board, GX.g4 + 1.6, Y_MACH - 0.34, chanZ),
        V(board, GX.g5 - 0.6, Y_MACH - 0.34, vz - 0.9),
        V(board, sock.x, sock.y, sock.z)
      ]);
      ray(board, around.getPoints(60), C.danger, 0.9);
      if (!board.reduced) bead(board, around, C.danger, 0.28, 0.14);
      const hit = put(board, board.mk.sphere(0.2, C.danger), sock.x, sock.y, sock.z);
      if (!board.reduced) board.spin((dt, el) => hit.scale.setScalar(1 + Math.sin(el * 5) * 0.2));
      text(board, "ufw says deny. The port answers anyway.",
           GX.g4 + 1.4, Y_MACH - 1.9, vz + 3.4, { px: 30, size: 0.46, color: C.danger });
    }
  }];
  board.timeline(steps);

  held(board, res, {
    head: head(res, "nothing was listening on :8080, so there was nothing to reach",
               "DOCKER-USER accepted it before ufw's chain ever ran",
               "the trap was never set up — is evil-box running? `make attack`"),
    nums: ["port 8080", through ? "answered" : "no answer"],
    chip: "public segment · in the clear", chipKind: "pub"
  });
}

/* ============================================================
   9 · lock-out
   Pull back to the full board. Every red beam dies, and so does every
   cyan tunnel. The machine goes grey and the padlock is on the outside.
   AIRTIGHT, AND USELESS.
   ============================================================ */
function lockOut(board, res) {
  const C = board.C, vz = POS["lab-vps"].z, vx = POS["lab-vps"].x;
  board.home();

  const stillIn = !!res.ok;   /* the tailnet route survived, so you are not outside */

  /* Every other set-piece pushes the standing beams and tunnels back into
     context. This one is about them going out, so they come back up first. */
  [board.parts.beamHost, board.parts.tunnelHost].forEach((h) => {
    h.children.forEach((c) => { if (c.isSprite) c.material.opacity = 0.85; });
  });

  const steps = [{
    t: 0.5,
    fn: () => {
      board.parts.beamHost.visible = false;
      if (!stillIn) board.parts.tunnelHost.visible = false;
      Object.keys(board.parts.slats).forEach((k) => {
        const sv = board.parts.slats[k];
        if (k === "docker") return;
        sv.g.rotation.z = 0;
        board.mk.setSlab(sv.plate, C.line, 0.22, 0.95);
        sv.lb.material.color.copy(C.faint);
      });
    }
  }, {
    t: 1.2,
    fn: () => {
      if (stillIn) {
        text(board, "the tailnet route survived — you are still in",
             vx - 1.0, Y_MACH + 2.6, vz, { px: 30, size: 0.46, color: C.ok });
        return;
      }
      /* grey, and shut */
      const m = board.parts.machines["lab-vps"];
      board.mk.setSlab(m.body, C.faint, 0.05, 0.5);
      m.name.material.color.copy(C.faint);
      m.ring.material.color.copy(C.faint);

      /* the padlock, on the outside */
      const lock = new board.THREE.Group();
      const body = new board.THREE.Mesh(
        new board.THREE.BoxGeometry(0.75, 0.6, 0.35),
        new board.THREE.MeshBasicMaterial({ color: C.danger, transparent: true, opacity: 0.9 }));
      lock.add(body);
      const shackle = new board.THREE.Mesh(
        new board.THREE.TorusGeometry(0.24, 0.06, 8, 24, Math.PI),
        new board.THREE.MeshBasicMaterial({ color: C.danger, transparent: true, opacity: 0.9 }));
      shackle.position.y = 0.3; lock.add(shackle);
      put(board, lock, vx - 2.6, Y_MACH + 1.5, vz + 1.2);
      text(board, "and you are on this side of it", vx - 2.6, Y_MACH + 0.7, vz + 1.2,
           { px: 26, size: 0.34, color: C.danger });
    }
  }];
  board.timeline(steps);

  held(board, res, {
    /* Not "held": nothing defended anything here. Both rules are gone and you
       are either outside or lucky, and the frame should say which. */
    head: stillIn
      ? "STILL IN · both rules are gone and the tailnet route survived — find what is still allowing tailscale0"
      : "AIRTIGHT, AND USELESS · both doors are shut and you are outside",
    ladder: stillIn ? "breached" : "stopped",
    rule: res.rule,
    nums: ["ufw 22/tcp removed", "ufw tailscale0 removed"],
    chip: stillIn ? "inside the tailnet · wrapped" : "no path at all",
    chipKind: stillIn ? "net" : "pub"
  });
}

/* ============================================================
   10 · outage — the session layer, in two acts

   The only set-piece here that is not an attack. Nothing is attacking
   anything: two real sessions are opened from lab-roam to lab-vps, and the
   network underneath them is taken apart twice to find out which of them
   notices.

   It is two acts because the lesson is two claims, and the first one is the
   one readers arrive with backwards:

     act one · the blackout   twenty seconds with no link at all. Both
                              tunnels go slack and dark, neither breaks, and
                              both come back ticking. A blackout is not what
                              kills SSH.
     act two · the roam       the address changes underneath both. SSH's
                              connection is a four-tuple and one corner of it
                              stopped existing; Mosh is holding state, and
                              state does not care which address the next
                              datagram arrives from.

   Act one has to resolve before act two starts, and both have to reach the
   live region, or the surprise collapses back into the paragraph this
   set-piece exists to replace. So the timeline holds a beat between them and
   each act sets the verdict itself.

   On Y, which is the rule this shot is most able to break: SSH and Mosh are
   both encrypted, so both lanes ride above the machine plane and both wear
   the shell, and nothing here is a comparison of confidentiality. But this
   runs at lab-vps's PUBLIC address on purpose — demoOutage says why at
   length — so neither lane is up in the tailnet plane, and the shot says so
   out loud rather than leaving the empty space to imply it. The slack in act
   one sags towards the machine plane and stops above it: a stalled tunnel is
   still a sealed one.
   ============================================================ */

/* One lane each, at one height, separated in z. Two heights would be a claim
   that one of them is better protected than the other, and that is not the
   difference this is about. */
const SESS_Y = Y_MACH + 1.5, SSH_DZ = -1.6, MOSH_DZ = 1.6, SAG = 1.25;

/* The four helpers below are shared with rotate-key, which draws a session of
   its own. `y` is the one thing that shot has to change: its session runs over
   the tailnet address rather than a public one, so its lane belongs up in the
   tailnet plane, and Y on this board is a claim about protection rather than a
   layout convenience. Left out, it is the outage height. */
function sessionPath(board, dz, sag, y) {
  const rz = POS["lab-roam"].z, vz = POS["lab-vps"].z, s = sag || 0;
  const top = y == null ? SESS_Y : y;
  return curve(board, [
    V(board, -6.5, Y_MACH + 0.15, rz + dz * 0.5),
    V(board, -3.4, top - s * 0.5, rz + dz),
    V(board,  0.4, top - s,       dz),
    V(board,  4.2, top - s * 0.5, vz + dz),
    V(board,  6.5, Y_MACH + 0.15, vz + dz * 0.5)
  ]);
}

/* Core plus lattice shell — the board's one word for "sealed". Both sessions
   wear it for the whole shot, the fragments of the one that breaks included:
   SSH's traffic stops arriving, it does not stop being encrypted, and bare
   cores scattering would say the wrong thing entirely. */
function sealed(board, color, r) {
  const g = new board.THREE.Group();
  g.add(new board.THREE.Mesh(
    new board.THREE.IcosahedronGeometry(r, 1),
    new board.THREE.MeshBasicMaterial({ color, transparent: true })));
  g.add(new board.THREE.Mesh(
    new board.THREE.OctahedronGeometry(r * 2.4, 0),
    new board.THREE.MeshBasicMaterial({ color: board.C.accent, wireframe: true,
                                        transparent: true, opacity: 0.9 })));
  return g;
}

/* Dim to a fraction of whatever the thing was built at, rather than to an
   absolute — so going translucent and coming back is one number each way and
   the shell keeps sitting behind the core where it belongs. */
function fade(obj, k) {
  obj.traverse((n) => {
    if (!n.material) return;
    if (n.userData.baseOp == null) n.userData.baseOp = n.material.opacity;
    n.material.opacity = n.userData.baseOp * k;
  });
}

/* A session's packet, gated on flags the acts flip rather than on a clock of
   its own: "the link is down" is then one state, instead of two animations
   that have to agree with each other. */
function riding(board, L, color, speed, gate) {
  const dot = put(board, sealed(board, color, 0.13));
  const where = (u) => (gate.slack ? L.slackPath : L.path).getPointAt(u);
  dot.position.copy(where(0));
  if (board.reduced) { dot.position.copy(where(0.55)); return dot; }
  let u = 0;
  board.spin((dt) => {
    if (gate.on) u = (u + dt * speed) % 1;
    dot.position.copy(where(u));
  });
  return dot;
}

function outage(board, res) {
  const C = board.C, rz = POS["lab-roam"].z;
  board.fly(V(board, -1.4, 5.4, 22.0), V(board, -0.6, 1.5, -0.4));

  /* Four numbers, one per session per act, straight off Evidence. The whole
     argument is the two comparisons between them, so nothing below
     re-derives one from prose and nothing invents one that is missing. */
  const sshB = ev(res, "sshAfterBlackout"), moshB = ev(res, "moshAfterBlackout");
  const sshR = ev(res, "sshAfterRoam"),     moshR = ev(res, "moshAfterRoam");

  const sshRan = sshB > 0 || sshR > 0, moshRan = moshB > 0 || moshR > 0;
  const ranAtAll = sshRan || moshRan;
  /* "Kept counting" is a comparison between the two acts, not a guess from
     the final number: a session that died at the roam reports the same tick
     it reported after the blackout. */
  const sshKept = sshRan && sshR > sshB, moshKept = moshRan && moshR > moshB;

  const detail = res.detail || {};
  const before = detail.addrBefore || "", after = detail.addrAfter || "";
  const named = !!(before && after);

  /* The one command per act, found by the command itself rather than by an
     index into Cmds that the next edit to demoOutage would quietly shift. */
  const cmd = (needle) =>
    (res.cmds || []).filter((c) => c.indexOf(needle) !== -1)[0] || "";

  const caption = (s, color) =>
    text(board, s, -0.6, 5.8, 6.8, { px: 34, size: 0.5, color: color || C.text });

  /* Y is protection, and up there is where protection comes from everywhere
     else on this board. Neither of these sessions is up there, and that is a
     claim the shot makes rather than one the empty space has to imply. */
  text(board, "the tailnet plane — neither of these sessions is on it",
       4.8, Y_NET + 0.4, 2.6, { px: 26, size: 0.34, color: C.faint });

  /* ---- the ending where nothing ran -------------------------------
     demoOutage has an ending in which neither session ever printed a tick:
     the machines were down, or :22 never answered at all. The blackout and
     the roam still happened to the network, but there were no tunnels for
     them to happen to, and animating two is the same lie as animating a
     capture that came back empty. */
  if (!ranAtAll) {
    [SSH_DZ, MOSH_DZ].forEach((dz) => {
      ray(board, sessionPath(board, dz, 0).getPoints(50), C.faint, 0.28, true);
    });
    caption("neither session printed a tick", C.warn);
    text(board, "no tunnel was ever established, so neither act proved anything",
         -0.6, 5.2, 6.8, { px: 28, size: 0.36, color: C.faint });
    held(board, res, {
      head: "INCONCLUSIVE · neither session printed a tick",
      rule: res.rule || "two sessions to lab-vps's public address, and neither one started",
      ladder: "stopped",
      nums: ["ssh 0 ticks", "mosh 0 ticks"]
    });
    board.setChip("no session at all", "");
    return;
  }

  /* ---- the two lanes ----------------------------------------------
     A lane is drawn taut only for a session the lab measured. Mosh printing
     nothing is demoOutage's named failure mode — a firewall that permits :22
     and nothing else — and it gets a lane that never formed rather than one
     that survives a blackout it was never in. */
  const gate = { on: true, slack: false };
  const lanes = [
    { id: "ssh",  dz: SSH_DZ,  ran: sshRan,  b: sshB,  r: sshR,  kept: sshKept,
      u: 0.34, speed: 0.34, what: "ssh · one tcp connection, four-tuple and all" },
    { id: "mosh", dz: MOSH_DZ, ran: moshRan, b: moshB, r: moshR, kept: moshKept,
      u: 0.62, speed: 0.42, what: "mosh · udp datagrams, state at both ends" }
  ].map((L) => {
    /* "It printed a tick at some point" and "it was up for act one" are two
       different facts, and only the second one entitles the shot to draw this
       lane going slack and coming back. A session that printed nothing until
       the second act rode out no blackout that anybody measured. */
    L.up1 = L.b > 0;
    L.path = sessionPath(board, L.dz, 0);
    L.slackPath = sessionPath(board, L.dz, SAG);
    L.line = ray(board, L.path.getPoints(50), L.ran ? C.accent : C.faint,
                 L.ran ? 0.75 : 0.25, !L.ran);
    if (L.ran) {
      L.slack = ray(board, L.slackPath.getPoints(50), C.faint, 0.45);
      L.slack.visible = false;
      L.dot = riding(board, L, C.accent, L.speed, gate);
      if (!L.up1) {
        /* Not up yet, so not drawn as up. Act two turns it on. */
        L.line.visible = false;
        L.dot.visible = false;
        L.ghost = ray(board, L.path.getPoints(50), C.faint, 0.22, true);
      }
    }
    const at = L.path.getPointAt(L.u);
    L.name = text(board, L.ran ? L.what : L.id + " · printed nothing at all",
                  at.x, at.y + 0.52, at.z,
                  { px: 26, size: 0.34, color: L.ran ? C.accent : C.faint });
    /* One readout per lane per act, built now and shown when its act runs, so
       act two replaces act one's numbers instead of stacking on top of them. */
    L.readB = text(board, L.up1 ? L.id + " reached tick " + L.b
                                : L.id + " had printed nothing yet",
                   at.x, at.y + 0.94, at.z,
                   { px: 28, size: 0.38, color: L.up1 ? C.text : C.faint });
    L.readR = text(board, !L.ran ? L.id + " never started"
                     : L.kept ? L.id + " ran on to tick " + L.r
                              : L.id + " stopped at tick " + L.r,
                   at.x, at.y + 0.94, at.z,
                   { px: 28, size: 0.38, color: L.kept ? C.ok : C.danger });
    L.readB.visible = false; L.readR.visible = false;
    return L;
  });
  const ssh = lanes[0], mosh = lanes[1];

  /* lab-roam's address, which act two changes underneath both sessions. Drawn
     only when demoOutage said what the two addresses were: the board cannot
     know them — the machine is back on its old one by the time the browser
     reads the lab again — and a plausible-looking pair is worse than none. */
  const roam = board.parts.machines["lab-roam"];
  let addrBefore = null, addrAfter = null;
  if (named && roam) {
    if (roam.addr) roam.addr.visible = false;
    addrBefore = text(board, "lab-roam · " + before, POS["lab-roam"].x, Y_MACH - 0.9, rz,
                      { px: 30, size: 0.36, color: C.muted });
    addrAfter = text(board, "lab-roam · " + after, POS["lab-roam"].x, Y_MACH - 0.9, rz,
                     { px: 30, size: 0.36, color: C.warn });
    addrAfter.visible = false;
  }

  /* ---- act one · the blackout -------------------------------------- */
  const bothBack = ssh.up1 && mosh.up1;
  const oneHead = bothBack
    ? "ACT ONE · both came back ticking — a blackout is not what kills SSH"
    : ssh.up1
      ? "ACT ONE · ssh came back ticking, and mosh printed nothing"
      : mosh.up1
        ? "ACT ONE · mosh came back ticking, and ssh printed nothing"
        : "ACT ONE · neither session had printed anything yet";
  const oneWhy = bothBack
    ? "Twenty seconds with no link at all, and both sessions rode it out: ssh reached tick " +
      sshB + ", mosh reached tick " + moshB + ". TCP does not give up on a stalled connection " +
      "anywhere near that fast, so a tunnel, a lift or a dead spot is not what ends your session."
    : ssh.up1
      ? "ssh reached tick " + sshB + " and mosh printed nothing, which almost always means the " +
        "UDP range never opened — the failure mode where a firewall permits :22 and nothing else, " +
        "so you log in and then it eats every keystroke."
      : mosh.up1
        ? "mosh reached tick " + moshB + " and ssh printed nothing, so there is no comparison to " +
          "make yet — this half proves nothing on its own."
        : "Neither session had printed a tick by the end of the blackout, so this act measured " +
          "nothing and the shot draws nothing. Whatever the second act shows, it does not rest " +
          "on this one.";

  let capOne = null, capSub = null, capTwo = null;
  const steps = [];

  steps.push({ t: 0.5, fn: () => {
    capOne = caption("ACT ONE · the link dies for twenty seconds", C.warn);
    capSub = text(board, "eth0 down · both tunnels slack and dark, neither one broken",
                  -0.6, 5.2, 6.8, { px: 28, size: 0.36, color: C.faint });
    gate.on = false; gate.slack = true;
    lanes.forEach((L) => {
      if (!L.up1) return;
      L.line.visible = false;
      L.slack.visible = true;
      fade(L.dot, 0.3);
      L.dot.position.copy(L.slackPath.getPointAt(0.5));
    });
  }});

  steps.push({ t: 1.9, fn: () => {
    gate.on = true; gate.slack = false;
    lanes.forEach((L) => {
      if (!L.up1) return;
      L.slack.visible = false;
      L.line.visible = true;
      fade(L.dot, 1);
      L.dot.position.copy(L.path.getPointAt(0.55));
    });
    if (capSub) capSub.visible = false;
  }});

  steps.push({ t: 2.6, fn: () => {
    if (capOne) capOne.visible = false;
    capOne = caption(oneHead, bothBack ? C.ok : C.warn);
    /* A lane that never printed anything at all is already labelled as such
       and does not need a second line saying it again. */
    lanes.forEach((L) => { if (L.ran) L.readB.visible = true; });
    /* The rung is how far the sessions travelled, and demoOutage reports 5
       once either of them printed a tick: sshd answered and a shell ran a
       loop. Delivered, not held — nothing was defending anything here. */
    board.setLadder(res.rung || 1, "delivered");
    board.setChip("public address · both sessions encrypted", "");
    board.setVerdict({
      tone: bothBack ? "ok" : "warn",
      head: oneHead,
      rule: "act one of two · twenty seconds with no link, and what survives it",
      why: oneWhy,
      nums: ["ssh " + sshB + " ticks", "mosh " + moshB + " ticks"],
      transcript: cmd("ip link set eth0 down")
    });
  }});

  /* A beat, and it is load-bearing. Act one is the surprise, and it only
     reads as one if it is allowed to finish being an answer before the next
     question starts. */

  /* ---- act two · the roam ------------------------------------------- */
  steps.push({ t: 4.3, fn: () => {
    if (capOne) capOne.visible = false;
    capTwo = caption("ACT TWO · the address changes underneath both", C.warn);
    lanes.forEach((L) => {
      L.readB.visible = false;
      /* A session that only started printing after the blackout comes up now,
         which is the first act it was measurably in. */
      if (!L.ran || L.up1) return;
      if (L.ghost) L.ghost.visible = false;
      L.line.visible = true;
      L.dot.visible = true;
      const at = L.path.getPointAt(L.u);
      text(board, L.id + " only started printing here", at.x, at.y - 0.7, at.z,
           { px: 26, size: 0.33, color: C.warn });
    });
    if (addrBefore && addrAfter) { addrBefore.visible = false; addrAfter.visible = true; }
  }});

  steps.push({ t: 5.1, fn: () => {
    /* Mosh goes translucent and holds. Still there and still sealed — it just
       has nowhere to put the next datagram for a moment. */
    if (mosh.ran) { fade(mosh.line, 0.22); fade(mosh.dot, 0.25); }

    if (!ssh.ran) return;
    if (ssh.kept) {
      /* Measured, and not the split this expects. Over a tailnet address SSH
         survives a roam too, and drawing the snap anyway because the shot is
         better that way is the one thing this file may not do. */
      text(board, "ssh followed the address change as well — was this run over the tailnet?",
           -0.6, 4.6, 6.8, { px: 28, size: 0.36, color: C.warn });
      return;
    }
    /* It snaps at the machine end, because that is the end whose address
       stopped existing. What was in flight is still encrypted; it is simply
       no longer going anywhere. */
    ssh.line.visible = false;
    ray(board, curve(board, [ssh.path.getPointAt(0), ssh.path.getPointAt(0.06),
                             ssh.path.getPointAt(0.13)]).getPoints(12), C.danger, 0.7);
    fade(ssh.dot, 0.35);
    const frags = [];
    for (let i = 0; i < 7; i++) {
      const at = ssh.path.getPointAt(0.2 + i * 0.11);
      const f = put(board, sealed(board, C.danger, 0.07), at.x, at.y, at.z);
      fade(f, 0.8);
      frags.push({ f, vx: (Math.random() - 0.4) * 0.9, vz: (Math.random() - 0.5) * 1.1 });
    }
    if (board.reduced) {
      frags.forEach((p) => { p.f.position.x += p.vx; p.f.position.z += p.vz; fade(p.f, 0.3); });
    } else {
      board.spin((dt) => {
        frags.forEach((p) => {
          p.f.position.x += p.vx * dt;
          p.f.position.z += p.vz * dt;
          p.f.traverse((n) => {
            if (n.material) n.material.opacity = Math.max(0.1, n.material.opacity - dt * 0.16);
          });
        });
      });
    }
    text(board, "still sealed, still going nowhere — the far end of the four-tuple is gone",
         0.6, SESS_Y - 0.8, SSH_DZ, { px: 26, size: 0.33, color: C.danger });
  }});

  steps.push({ t: 6.2, fn: () => {
    /* …and re-solidifies against the new address. */
    if (!mosh.ran) return;
    fade(mosh.line, 1);
    fade(mosh.dot, 1);
    if (mosh.kept) {
      text(board, named ? "mosh re-solidified against " + after
                        : "mosh re-solidified against the new address",
           2.2, SESS_Y + 1.5, MOSH_DZ, { px: 28, size: 0.36, color: C.ok });
    }
  }});

  steps.push({ t: 7.0, fn: () => {
    if (capTwo) capTwo.visible = false;
    lanes.forEach((L) => { L.readR.visible = true; });

    const lesson = ssh.ran && mosh.ran && !ssh.kept && mosh.kept;
    const twoHead = lesson
      /* No full stop on the end: setVerdict joins the head to the why with
         one, and every other head in this file leaves it to do that. */
      ? "ACT TWO · SSH is holding a connection to lose. Mosh is holding state"
      : ssh.kept && mosh.kept
        ? "ACT TWO · both sessions followed the address change"
        : mosh.kept
          ? "ACT TWO · mosh followed the address change, and ssh never started"
          : "ACT TWO · nothing followed the address change — read the tails in the packets tab";

    caption(twoHead, lesson ? C.ok : C.warn);
    held(board, res, {
      head: twoHead,
      rule: res.rule || "act two of two · the address changes, and one session notices",
      ladder: "delivered",
      nums: ["ssh " + sshB + " → " + sshR, "mosh " + moshB + " → " + moshR]
    });
    /* held() falls back to the red "in the clear" chip, and that is the one
       thing this shot must not say: both of these are encrypted, they are
       simply not on the tailnet. Neutral is the honest third answer. */
    board.setChip("public address · both sessions encrypted", "");
  }});

  board.timeline(steps);
}

/* ============================================================
   11 · rotate-key — maintenance, and the only claim it may make

   The second shot here that is not an attack, and the further of the two
   from one. `outage` at least has something going wrong in it. Nothing goes
   wrong here: rotating a node key is housekeeping, and housekeeping is
   judged entirely by what it does NOT disturb. So the claim is continuity,
   in three parts:

     the coordination server stops holding the key it held;
     the machine stays inside the tailnet plane, at the same address;
     and a session running over that address does not notice.

   The third is why this lane rides at TN_Y and the outage lanes do not.
   That shot runs at lab-vps's PUBLIC address on purpose and says so out
   loud; this one has to be on the tailnet, because a rotation a session
   cannot feel even in principle is not a demonstration of anything. Y is
   protection, and this lane genuinely is up there.

   Each of the three has an ending where the lab did not measure it, and
   each of those draws nothing rather than something plausible. A run that
   re-keyed nothing draws no re-key and says so — which is the only honest
   picture of a rotation that did not rotate, and the reason `keyRead` is a
   separate fact from `keyChanged` on the way over.
   ============================================================ */
function rotateKey(board, res) {
  const C = board.C, rz = POS["lab-roam"].z;
  board.fly(V(board, -1.4, 7.4, 21.5), V(board, -0.6, 2.6, -0.6));

  /* Every ending that touched the machine sets Evidence. Its absence is
     atkRotateKey bailing before it did — no pre-auth key on disk, or lab-roam
     not running — and there is nothing to draw but the reason. */
  if (!res.evidence) {
    ray(board, sessionPath(board, 0, 0, TN_Y).getPoints(50), C.faint, 0.22, true);
    text(board, "the rotation never ran", -0.6, 6.0, 6.8,
         { px: 34, size: 0.5, color: C.warn });
    held(board, res, {
      head: "INCONCLUSIVE · the rotation never ran",
      rule: res.rule || "nothing was re-registered",
      ladder: "stopped",
      nums: []
    });
    board.setChip("nothing was rotated", "");
    return;
  }

  const wasMember   = ev(res, "wasMember") > 0;
  const isMember    = ev(res, "isMember") > 0;
  const keyRead     = ev(res, "keyRead") > 0;
  const keyChanged  = keyRead && ev(res, "keyChanged") > 0;
  const expiryMoved = ev(res, "expiryMoved") > 0;
  const addrKept    = ev(res, "addrKept") > 0;

  const before = ev(res, "ticksBefore"), after = ev(res, "ticksAfter");
  /* Same rule as the outage lanes: "it kept counting" is a comparison between
     the two readings, never a guess from the second one. A session that died
     at the re-auth reports the tick it had already reached. */
  const sessionRan  = before > 0;
  const sessionKept = sessionRan && after > before;

  const d = res.detail || {};
  const caption = (s, color) =>
    text(board, s, -0.6, 6.4, 6.8, { px: 34, size: 0.5, color: color || C.text });

  /* ---- the lane ----------------------------------------------------
     Drawn only for a session the lab actually measured. There are two ways
     not to have one — lab-roam was outside the tailnet, so there was nothing
     to keep, or it was a member and ssh over the tailnet address printed
     nothing — and they are different sentences to read. */
  const gate = { on: true, slack: false };
  let lane = null;
  if (sessionRan) {
    const path = sessionPath(board, 0, 0, TN_Y);
    lane = { path, slackPath: path };
    lane.line = ray(board, path.getPoints(50), C.accent, 0.8);
    lane.dot = riding(board, lane, C.accent, 0.34, gate);
    const at = path.getPointAt(0.5);
    lane.name = text(board, "ssh · lab-roam → lab-vps, over the tailnet address",
                     at.x, at.y + 0.52, at.z, { px: 26, size: 0.34, color: C.accent });
    lane.readB = text(board, "tick " + before, at.x, at.y + 0.96, at.z,
                      { px: 28, size: 0.38, color: C.text });
    lane.readA = text(board, sessionKept ? "ran on to tick " + after
                                         : "stopped at tick " + before,
                      at.x, at.y + 0.96, at.z,
                      { px: 28, size: 0.38, color: sessionKept ? C.ok : C.danger });
    lane.readA.visible = false;
  } else {
    ray(board, sessionPath(board, 0, 0, TN_Y).getPoints(50), C.faint, 0.22, true);
    text(board, wasMember
           ? "no session was measured over the tailnet, so continuity went untested"
           : "lab-roam was outside the tailnet — there was no session here to keep",
         -0.6, 5.6, 6.8, { px: 28, size: 0.36, color: C.faint });
  }

  /* ---- the key ------------------------------------------------------
     A key is a credential, not a packet, so it is a bead and a label and
     never the lattice shell: the shell is this board's one word for
     encryption and nothing else may wear it. */
  const keyX = POS["lab-roam"].x + 1.6, keyY = TN_Y + 1.15;
  let oldKey = null, oldLb = null;
  if (keyRead) {
    oldKey = put(board, board.mk.sphere(0.15, C.accent, 0.9), keyX, keyY, rz);
    oldLb = text(board, "node key · " + d.keyBefore, keyX + 1.7, keyY, rz,
                 { px: 28, size: 0.36, color: C.muted });
  } else {
    text(board, "the coordination server reported no node key either side of this",
         keyX + 0.6, keyY, rz, { px: 26, size: 0.34, color: C.faint });
  }

  const steps = [];
  let cap = null;

  /* ---- one · the key rotates --------------------------------------- */
  steps.push({ t: 0.6, fn: () => {
    cap = caption(wasMember ? "tailscale up --force-reauth, underneath everything"
                            : "tailscale up — the machine that removed itself, re-registering",
                  C.warn);
    if (!keyRead || !oldKey) return;

    if (!keyChanged) {
      /* Measured, and not the picture this shot would rather draw. Animating
         a rotation the coordination server did not report is exactly the lie
         the four rules exist to stop, so it stays where it is and says so. */
      board.mk.tint(oldLb, C.warn);
      text(board, expiryMoved
             ? "the same node key, with a later expiry — refreshed, not re-keyed"
             : "the same node key, before and after — nothing re-keyed here",
           keyX + 0.6, keyY - 0.72, rz, { px: 26, size: 0.34, color: C.warn });
      return;
    }

    /* It changed. The old one stops being the one that counts and falls out
       of the plane; the new one takes the place it had. */
    board.mk.tint(oldLb, C.faint);
    if (board.reduced) {
      oldKey.position.y = Y_PUB + 0.4;
      oldKey.material.opacity = 0.2;
    } else {
      board.spin((dt) => {
        if (oldKey.position.y <= Y_PUB + 0.4) return;
        oldKey.position.y -= dt * 1.6;
        oldKey.material.opacity = Math.max(0.12, oldKey.material.opacity - dt * 0.3);
      });
    }
    put(board, board.mk.sphere(0.15, C.ok, 0.95), keyX, keyY, rz);
    text(board, "node key · " + d.keyAfter, keyX + 1.7, keyY - 0.5, rz,
         { px: 28, size: 0.36, color: C.ok });
    text(board, "the old one is no longer the one the tailnet accepts",
         keyX + 0.6, keyY - 1.05, rz, { px: 26, size: 0.34, color: C.faint });
  }});

  /* ---- two · and it stays a member --------------------------------- */
  steps.push({ t: 2.0, fn: () => {
    if (cap) cap.visible = false;
    if (!isMember) {
      /* The failure ending, and the one place this shot looks like
         expired-key: the machine is outside the plane and nothing put it
         back. Drawn the same way, because it is the same picture. */
      cap = caption("lab-roam did not come back onto the tailnet", C.danger);
      board.parts.tunnelHost.visible = false;
      const roam = board.parts.machines["lab-roam"];
      if (roam) {
        if (board.reduced) roam.g.position.y = Y_PUB + 1.2;
        else board.spin((dt) => {
          if (roam.g.position.y > Y_PUB + 1.2) roam.g.position.y -= dt * 1.4;
        });
      }
      return;
    }
    cap = caption(wasMember ? "still a member, and it never left"
                            : "a member again", C.ok);
    /* A tie from the machine up into the plane it did not leave. The
       contrast being drawn is with expired-key, where the machine drops out
       of this exact plane while nobody touches it. */
    ray(board, [V(board, POS["lab-roam"].x, Y_MACH + 0.5, rz),
                V(board, POS["lab-roam"].x, TN_Y - 0.1, rz)], C.ok, 0.7);
    text(board, addrKept ? "same node, same address · " + (d.addrAfter || "")
           : d.addrAfter ? "on the tailnet at " + d.addrAfter
                         : "on the tailnet",
         POS["lab-roam"].x + 1.4, Y_MACH + 1.1, rz,
         { px: 28, size: 0.36, color: addrKept ? C.ok : C.warn });
    if (wasMember && !addrKept && d.addrBefore) {
      text(board, "and the address moved — it was " + d.addrBefore,
           POS["lab-roam"].x + 1.4, Y_MACH + 0.55, rz,
           { px: 26, size: 0.34, color: C.warn });
    }
  }});

  /* ---- three · and nothing dropped --------------------------------- */
  steps.push({ t: 3.4, fn: () => {
    if (!lane) return;
    lane.readB.visible = false;
    lane.readA.visible = true;
    if (sessionKept) {
      text(board, "the rotation happened underneath it — same connection, "
                  + (after - before) + " more ticks",
           0.4, TN_Y - 0.8, 0, { px: 26, size: 0.34, color: C.ok });
      return;
    }
    /* It stopped. The lane goes dark rather than vanishing: the session was
       there, and what it stopped doing is arriving. */
    gate.on = false;
    fade(lane.line, 0.28);
    fade(lane.dot, 0.3);
    board.mk.tint(lane.name, C.faint);
    text(board, "nothing arrived after the re-auth — this rotation was not free",
         0.4, TN_Y - 0.8, 0, { px: 26, size: 0.34, color: C.danger });
  }});

  board.timeline(steps);

  /* HELD and THROUGH are the attack vocabulary and neither one fits: nothing
     was attacking and nothing was defending. The heads below name what the
     run showed about continuity, which is the only question asked here. */
  const heading = !isMember
    ? "FAILED · lab-roam did not come back onto the tailnet"
    : sessionKept
      ? (keyChanged
          ? "CONTINUOUS · the key rotated and the session never noticed"
          : "CONTINUOUS · the session never noticed — and nothing re-keyed")
      : sessionRan
        ? "DROPPED · the session stopped at the re-auth"
        : !wasMember
          ? "RESTORED · one command, and it is a member again"
          : keyChanged
            ? "ROTATED · a new node key, and no session to test it against"
            : "INCONCLUSIVE · it re-registered, and nothing was shown to change";

  const nums = ["rung " + (res.rung || 1) + " of 5"];
  if (sessionRan) nums.unshift("ssh " + before + " → " + after);

  held(board, res, {
    head: heading,
    rule: res.rule,
    ladder: sessionKept || ev(res, "probeOK") > 0 ? "delivered" : "stopped",
    nums: nums,
    /* The tailnet chip, because that is where this happened and where the
       lane rode. The failure ending is the one time it is not true. */
    chip: isMember ? "tailnet · membership unbroken" : "outside the tailnet",
    chipKind: isMember ? "net" : "pub"
  });
}

/* ============================================================
   10 · tailcat-tunnel

   Every other shot on this board points the camera at a defence
   answering. This one points it at two that were never asked, which is a
   harder picture: absence has no geometry.

   So the lane is the argument. It leaves the serving machine going *up*,
   to the relay, and comes back down to evil-box — and both of its ends
   are on the left of the board, at rung 1, because that is where those
   machines are and the tunnel never travels the ladder at all. Gates 3
   and 4 stand to the right of it, lit for nobody, with their own word on
   them. Nothing crosses them, nothing is drawn breaking them, and the
   ladder strip carries the third state rather than painting them passed.

   The height is the other half. Tailcat's traffic is WireGuard, so it
   rides in the protected plane like the tailnet's does — the shell is
   encryption and this is encryption. What it does not have is a control
   plane above it, and the plane it rides in is drawn with nothing over
   it: the membrane the tailnet's own lane passes through is not on this
   path, because there is nothing here to be a member of.
   ============================================================ */
function tailcatTunnel(board, res) {
  const C = board.C;
  const r = tailcatReading(res);
  const host = (res.detail && res.detail.host) || "lab-ubuntu";
  const hz = (POS[host] || POS["lab-ubuntu"]).z;
  const ez = POS["evil-box"].z;

  /* Centred on the two machines the tunnel joins, and low enough that the
     lane's climb to the relay reads as a climb. The ladder stays in frame on
     purpose: it is the thing the lane is not using, and a shot that cropped it
     out would be making the point by hiding the evidence for it. */
  const mx = (POS[host].x + POS["evil-box"].x) / 2, mz = (hz + ez) / 2;
  board.fly(V(board, mx - 3.4, TN_Y + 3.0, mz + 17.5), V(board, mx, Y_NET - 0.9, mz));

  if (!r.ran) {
    text(board, "no tunnel ran", GX.g1 + 0.6, Y_MACH + 1.8, (hz + ez) / 2,
         { px: 30, size: 0.46, color: C.faint });
    held(board, res, { head: r.head, nums: [], chip: "nothing ran", chipKind: "pub" });
    return;
  }

  /* The one outbound connection the machine made, which is the whole of
     what a tunnel looks like from the outside. It is drawn first and it is
     drawn dashed, because it is a socket rather than a packet. */
  const out = curve(board, [
    V(board, POS[host].x + 0.6, Y_MACH + 0.4, hz),
    V(board, GX.g2 - 0.4, Y_NET - 0.4, hz - 1.2),
    V(board, GX.derp, Y_DERP - 0.4, -2.6)
  ]);
  ray(board, out.getPoints(40), C.accent, 0.5, true);
  text(board, "ss -tnp: one connection out, to the relay",
       GX.g2 - 1.2, Y_NET + 0.9, hz - 2.6, { px: 26, size: 0.33, color: C.accent });

  /* Gates 3 and 4, standing where they always stand, saying what they did.
     The label is the reading's, so a run that measured an inbound packet
     says that instead — the claim and the picture cannot come apart. */
  [{ x: GX.g3, z: 5.4 }, { x: GX.g4, z: 5.4 }].forEach((g) => {
    text(board, r.skipLabel, g.x, Y_MACH + 2.4, g.z,
         { px: 26, size: 0.34, color: r.contradicted ? C.danger : C.faint });
  });

  const steps = [{
    t: 0.5,
    fn: () => {
      /* The tunnel itself, up over the relay and back down. It rides at
         tailnet height because it is encrypted, and it passes nothing on
         the way: no membrane, no gate, no slat. */
      const lane = curve(board, [
        V(board, POS[host].x + 0.8, Y_MACH + 0.5, hz),
        V(board, GX.g2 - 0.2, TN_Y, hz - 1.0),
        V(board, GX.derp, Y_DERP - 0.2, -2.6),
        V(board, GX.g2 - 0.2, TN_Y, ez + 1.0),
        V(board, POS["evil-box"].x + 0.8, Y_MACH + 0.5, ez)
      ]);
      const col = r.shell ? C.danger : r.refused ? C.ok : C.accent;
      ray(board, lane.getPoints(70), col, 0.95);
      if (!board.reduced) bead(board, lane, col, 0.4, 0.16);

      /* Drawn only when it was measured. A relay-only run is a true and
         quieter picture, and claiming the punch when it did not complete
         would be inventing the alarming half. */
      if (r.direct) {
        const punch = curve(board, [
          V(board, POS[host].x + 0.8, Y_MACH + 0.5, hz),
          V(board, GX.g2 - 1.8, TN_Y - 1.4, (hz + ez) / 2),
          V(board, POS["evil-box"].x + 0.8, Y_MACH + 0.5, ez)
        ]);
        ray(board, punch.getPoints(50), col, 0.7);
        text(board, "and then straight across — the punch completed",
             GX.g2 - 3.0, TN_Y - 2.0, (hz + ez) / 2,
             { px: 26, size: 0.33, color: col });
      }

      /* The measured zero, next to the machine it was measured on. This is
         the line that makes "the firewall was never asked" a reading. */
      text(board, r.inbound + " inbound on " + host + " eth0:22, all run",
           POS[host].x + 1.4, Y_MACH - 1.5, hz + 2.6,
           { px: 28, size: 0.38, color: r.contradicted ? C.danger : C.ok });
      text(board, r.ifaces + " interfaces named tailcat — there is nothing to filter on",
           POS[host].x + 1.4, Y_MACH - 2.2, hz + 2.6,
           { px: 26, size: 0.33, color: C.faint });
    }
  }];
  board.timeline(steps);

  held(board, res, {
    head: r.head,
    nums: r.nums,
    skipped: r.skipped,
    ladder: r.shell ? "breached" : "stopped",
    chip: "tailcat · encrypted, and outside every rung",
    chipKind: "net"
  });
}

/* ============================================================
   the register

   Keyed off the ids in AttackList. A new attack in attacks.go shows up
   here as a missing set-piece — reported once, at the console, rather
   than silently rendering nothing — and still works, because app.js
   keeps the text trace as the fallback.
   ============================================================ */
export const SETPIECES = {
  "scan-public":   scanPublic,
  "scan-tailnet":  scanTailnet,
  "sniff":         sniff,
  "replay":        replay,
  "stolen-key":    stolenKey,
  "expired-key":   expiredKey,
  "rogue-exit":    rogueExit,
  "docker-bypass": dockerBypass,
  "tailcat-tunnel": tailcatTunnel,
  "lock-out":      lockOut,
  /* Neither of these is one of the ten and neither is an attack. `outage` is
     here because the session layer is half of what this guide is about and the
     board had none of it; `rotate-key` is here because it was the last button
     that got a paragraph where its neighbours got a shot — and because nothing
     reported that, for as long as the gap check was handed AttackList and both
     of these were dispatchable without being in it. */
  "outage":        outage,
  "rotate-key":    rotateKey
};

export function hasSetpiece(id) { return Object.prototype.hasOwnProperty.call(SETPIECES, id); }

/* Returns true if a set-piece ran. A false here is not an error: the caller
   falls back to the text trace, which is the same path the flat view uses. */
export function run(board, id, res, ctx) {
  const fn = SETPIECES[id];
  if (!fn) return false;
  board.clearScratch();
  /* One shot, one claim. The board's own labels stay on as context — they are
     the only thing telling you where you are — but they stop competing with
     the sentence the set-piece is here to say. */
  board.dimStanding(0.14);
  try {
    fn(board, res, ctx);
    board.hold();
  } catch (e) {
    /* A broken shot must not take the page with it. The trace still lands. */
    console.error("set-piece " + id + " failed:", e);
    board.clearScratch();
    return false;
  }
  return true;
}

/* Which dispatchable ids have no set-piece yet. app.js reports this once at
   startup so a new action is noticed rather than quietly falling through.

   It is handed the ids of the server's dispatch table, not AttackList. That
   distinction is the whole of ticket 33: `rotate-key` and `outage` are both
   posted to /api/action and neither is in AttackList, so a check walking the
   attack list could not see them however carefully it was written — and one of
   them went a release with no set-piece and nothing said a word. Ids or
   AttackList-shaped objects both work, because being strict about the shape
   here would only ever turn a report into a silence again. */
export function missing(actions) {
  return (actions || [])
    .map((a) => (typeof a === "string" ? a : a && a.id))
    .filter((id) => id && !hasSetpiece(id));
}
