/* ============================================================
   The nine attacks, as set-pieces.

   Nine genuinely different mechanisms — an anti-replay window, a netmap
   removal, a chain-ordering trap, a route offer that is not an approval —
   used to arrive as nine paragraphs in one column, where they all read as
   the same texture. Each of them has exactly one thing worth looking at.
   This file points the camera at that thing.

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
   ============================================================ */

import { GEOM } from "./scene.js";

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
   answered, in the same words whether or not anything moved. */
function held(board, res, v) {
  /* res.ok on an attack means the defence held, not that anything was
     delivered — so the ladder marks the rung the Result reports, and marks
     it as answered rather than as a delivery. */
  board.setLadder(res.rung || 1, v.ladder || (res.danger ? "breached" : "stopped"));
  board.setVerdict({
    tone: res.danger ? "bad" : res.ok ? "ok" : "warn",
    head: v.head,
    rule: v.rule || res.rule,
    why: res.why,
    nums: v.nums || [],
    transcript: (res.cmds && res.cmds.length) ? res.cmds[res.cmds.length - 1] : ""
  });
  board.setChip(v.chip || "attack · held frame", v.chipKind || "pub");
}

/* The three outcomes an attack can have, phrased so the head always names
   something rather than reporting a boolean. */
function head(res, defence, through, inconclusive) {
  if (res.danger) return "THROUGH · " + (through || defence);
  if (res.ok) return "HELD · " + defence;
  return "INCONCLUSIVE · " + (inconclusive || "nothing was proved either way");
}

const ev = (res, key) => (res.evidence && res.evidence[key]) || 0;

/* needEvil and evilJoin return before the attack does anything, at rung 1.
   Every attack below sets a higher rung the moment it actually runs, so this
   separates "the defence was tested and nothing was proved" from "the
   attacker never got off the ground" — which are different sentences to read
   at eleven at night. */
const neverRan = (res) => !res.ok && !res.danger && (res.rung || 1) <= 1;

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

  const scanned = ev(res, "scanned");
  const open = SCAN_PORTS.filter((p) => ev(res, "open:" + p.port) > 0);

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
     only if the scan ran. atkScanPublic reports rung 4; the "evil-box is not
     in this stack" path reports rung 1 and measured nothing, and saying
     "nmap found nothing open" about a scan that never happened is the same
     lie as animating a capture that came back empty. */
  const scanRan = (res.rung || 0) >= 4;
  if (scanRan) board.setExposure(open.map((p) => p.port), true);

  held(board, res, {
    head: head(res,
      "ufw default incoming policy: deny",
      "the host firewall let them through",
      "nothing was scanned — is evil-box running?"),
    nums: scanRan ? [scanned + " ports scanned", open.length + " open"] : [],
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

  const frames = ev(res, "frames");
  const cleartext = ev(res, "cleartext");
  const tunnelled = ev(res, "tunnelled");

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
  text(board, frames ? frames + " frames captured" : "nothing captured",
       ux + 3.4, Y_MACH - 2.2, uz + 1.4,
       { px: 26, size: 0.32, color: frames ? C.muted : C.faint });

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

  if (frames === 0) {
    steps.push({ t: 0.4, fn: () => {
      text(board, "the tray is empty — this proves nothing either way",
           ux + 3.4, Y_MACH - 1.4, uz, { px: 28, size: 0.36, color: C.warn });
    }});
  } else if (cleartext === 0) {
    /* The control arm failed. Saying nothing here and drawing the good run
       anyway would be the single most dishonest frame in the whole thing. */
    steps.push({ t: 0.4, fn: () => {
      text(board, "the control marker is missing too — the capture is not seeing this traffic",
           ux + 3.4, Y_MACH - 1.4, uz, { px: 28, size: 0.36, color: C.warn });
    }});
  } else {
    drop(ux + 2.2, 0.7, false, "LABMARKER-CLEARTEXT  ×" + cleartext, C.danger, 0.5);
    if (tunnelled === 0) {
      drop(ux + 4.6, -0.7, true, "a7 3f 91 c0 …  the same marker, sealed", C.accent, 1.0);
    } else {
      drop(ux + 4.6, -0.7, false, "LABMARKER-TUNNELLED  ×" + tunnelled, C.danger, 1.0);
    }
  }
  board.timeline(steps);

  /* One particle per real frame off the wire. The motion is measured rather
     than invented, which is the whole ethic of this directory. The stream is
     live traffic now, not the frames the capture already holds, and it is
     labelled as such. */
  if (ctx && ctx.openStream && frames > 0 && !board.reduced) {
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

  const nums = [frames + " frames", cleartext + " cleartext", tunnelled + " tunnelled"];
  held(board, res, {
    head: neverRan(res) ? "INCONCLUSIVE · nothing was captured — is evil-box running? `make attack`"
      : frames === 0 ? "INCONCLUSIVE · the capture came back empty"
      : cleartext === 0 ? "INCONCLUSIVE · the control marker never appeared either"
      : head(res, "WireGuard transport data — sealed for a key evil-box does not have",
             "the marker crossed the wire in the clear"),
    /* atkSniff names no rule when the tunnelled marker turns up, because
       nothing ruled on it — so the frame says what that means instead of
       leaving an em dash where the defence should be. */
    rule: res.rule || (tunnelled > 0
      ? "nothing sealed it — the marker was readable on the wire"
      : "the wire, and what a capture on it can and cannot read"),
    nums,
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
  "lock-out":      lockOut
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

/* Which ids in AttackList have no set-piece yet. app.js reports this once at
   startup so a new attack is noticed rather than quietly falling through. */
export function missing(attackList) {
  return (attackList || []).map((a) => a.id).filter((id) => !hasSetpiece(id));
}
