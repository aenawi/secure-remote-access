/* ============================================================
   Five Gates — the board.

   The five-rung ladder chapter 12 teaches, as a place a packet has to
   travel through. Two rules, and everything else follows from them:

     X is the ladder.   How far something travels is the rung it reached.
     Y is protection.   Above the machine plane is wrapped; below it is
                        in the clear. A packet's height is a claim about
                        whether it is readable, so it had better be true.

   This is the design in lab/design/five-gates.html with the model taken
   out of it. That page works out its own answers; this one is handed
   them. Every gate below renders the configuration the control server
   read back from a container, and every ride is a Result that a real
   `nc` and a real `tcpdump` produced. Nothing here decides anything.

   The canvas is aria-hidden. Every state the scene shows also exists as
   text in the HUD, and the verdict goes to the live region, because a
   picture nobody can read is not an accessibility strategy.
   ============================================================ */

import { THREE } from "./three.module.js";

const V3 = THREE.Vector3;

/* ---------- geometry ----------------------------------------------
   The four machines sit at fixed places. Three of them are on the left,
   at rung 1; lab-vps is on the right, past every gate. */
const POS = {
  "lab-roam":   new V3(-8, 0, -4.4),
  "evil-box":   new V3(-8, 0,  0),
  "lab-ubuntu": new V3(-8, 0,  4.4),
  "lab-vps":    new V3( 8, 0,  4.4)
};
const Y_PUB = -3.7, Y_MACH = 0.55, Y_NET = 4.1, Y_DERP = 6.2;
const TN_Y = Y_NET + 0.55;              /* the height traffic travels at inside the tailnet */
const GX = { g1: -8, g2: -4.9, derp: -2.0, g3: 0, g4: 4.5, g5: 7.0 };
const ANY = new V3(-9.4, Y_PUB, -2.6);  /* where a stranger stands */

const HOME_POS = new V3(0.6, 9.4, 25.5), HOME_AT = new V3(0, 1.3, 0.4);

const GATE_POSTS = [
  { x: GX.g1, t: "1 · alive" }, { x: GX.g2, t: "2 · path" }, { x: GX.g3, t: "3 · policy" },
  { x: GX.g4, t: "4 · firewall" }, { x: GX.g5, t: "5 · listener" }
];
const RUNG_NAMES = ["liveness", "path", "policy", "firewall", "listener"];

/* One slat per firewall rule, so an open slat is a rule you can read. */
const SLATS = [
  { key: "public22", text: "ufw · 22/tcp from Anywhere",   y:  0.62 },
  { key: "tailnet",  text: "ufw · ALLOW IN on tailscale0", y:  0.00 },
  { key: "docker",   text: "DOCKER-USER · :8080",          y: -0.62 }
];

/* A grant is a doorway at the z of the machine it lets through, so the hole
   you pass through is the grant you own. */
const CELL_Z = {
  laptop: POS["lab-ubuntu"].z, roam: POS["lab-roam"].z,
  untrusted: POS["evil-box"].z, any: 0.2
};

/* The two ports the board has sockets for. A scan asks about more than this;
   the scan-public set-piece builds the rest as props. */
const SOCKET_PORTS = [["22", 0.28], ["8080", -0.34]];

export const GEOM = { POS, GX, ANY, Y_PUB, Y_MACH, Y_NET, Y_DERP, TN_Y, HOME_POS, HOME_AT };

/* ============================================================
   createBoard
   ============================================================ */
export function createBoard(canvas, hud) {
  const reducedQuery = window.matchMedia("(prefers-reduced-motion: reduce)");

  /* Declared here rather than beside the loop, because the context handlers
     further down have to be able to stop and restart it. */
  const clock = new THREE.Clock();
  let running = true;

  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(38, 16 / 9, 0.1, 200);

  const camPos = HOME_POS.clone(), camAt = HOME_AT.clone();
  const wantPos = HOME_POS.clone(), wantAt = HOME_AT.clone();

  /* ---------- theme tokens --------------------------------------
     Read from the page's own custom properties, so the board follows the
     theme button rather than carrying a second palette that can drift. */
  const C = {};
  function readTokens() {
    const cs = getComputedStyle(document.documentElement);
    const col = (n) => new THREE.Color(cs.getPropertyValue(n).trim() || "#888");
    C.accent = col("--accent");
    C.danger = col("--danger");
    C.warn   = col("--warn");
    C.ok     = col("--ok");
    C.line   = col("--border-strong");
    C.text   = col("--text");
    C.muted  = col("--text-muted");
    C.faint  = col("--text-faint");
    C.card   = col("--bg-raised");
  }
  readTokens();

  /* ---------- the context, and losing it -------------------------
     A GPU can take the context away — a driver reset, a laptop switching
     between two graphics chips, a compositor under pressure. three.js
     re-uploads what it needs when the context comes back; what it cannot
     know is that the objects this file is holding were built against the
     dead one, so disposing them afterwards is a no-op that logs an error
     per object. Everything built by the primitives below carries the
     generation it was made in, and disposal skips the ones that died with
     the context — their GPU memory went with it, so nothing leaks. */
  let contextGen = 0;
  const stamp = (o) => { o.userData.gen = contextGen; return o; };
  /* Everything a set-piece builds inline goes through here on its way into
     the scene, so the rule is uniform: if it is in the graph, it knows which
     context it was built against. */
  const adopt = (o) => { o.traverse(stamp); return o; };
  /* The two sprites that are replaced rather than cleared — a machine's
     address and the packet's own label — are freed here rather than inline,
     so they get the same generation guard as everything clearGroup touches. */
  function dropSprite(sp) {
    if (!sp) return;
    if (sp.parent) sp.parent.remove(sp);
    if (sp.userData.gen != null && sp.userData.gen !== contextGen) return;
    if (sp.material.map) sp.material.map.dispose();
    sp.material.dispose();
  }

  canvas.addEventListener("webglcontextlost", () => {
    /* three.js registers its own handler and calls preventDefault, which is
       what allows a restore at all. This one only stops the loop, because
       rendering into a dead context achieves nothing and throws. */
    running = false;
  });
  canvas.addEventListener("webglcontextrestored", () => {
    contextGen++;
    running = true;
    clock.getDelta();          /* swallow the gap, so nothing jumps a frame */
    paintBoard();
    frame();
  });

  /* ---------- primitives ---------------------------------------- */
  function line(pts, color, opacity, dashed) {
    const g = new THREE.BufferGeometry().setFromPoints(pts);
    const m = dashed
      ? new THREE.LineDashedMaterial({ color, transparent: true, opacity, dashSize: 0.34, gapSize: 0.26 })
      : new THREE.LineBasicMaterial({ color, transparent: true, opacity });
    const l = new THREE.Line(g, m);
    if (dashed) l.computeLineDistances();
    return stamp(l);
  }

  function slab(w, h, d, color, opacity) {
    const mesh = new THREE.Mesh(
      new THREE.BoxGeometry(w, h, d),
      new THREE.MeshBasicMaterial({ color, transparent: true, opacity, depthWrite: false })
    );
    const edge = new THREE.LineSegments(
      new THREE.EdgesGeometry(mesh.geometry),
      new THREE.LineBasicMaterial({ color, transparent: true, opacity: Math.min(1, opacity * 4 + 0.25) })
    );
    const g = new THREE.Group();
    g.add(mesh); g.add(edge);
    g.userData.fill = mesh.material;
    g.userData.edge = edge.material;
    stamp(mesh); stamp(edge);
    return stamp(g);
  }

  /* Text as a canvas sprite. Monospace, because everything the lab prints is. */
  function label(text, opts) {
    opts = opts || {};
    const px = opts.px || 44, pad = 10;
    const cv = document.createElement("canvas");
    let ctx = cv.getContext("2d");
    const font = (opts.weight || 500) + " " + px + "px ui-monospace, 'JetBrains Mono', monospace";
    ctx.font = font;
    const w = Math.ceil(ctx.measureText(text).width) + pad * 2;
    cv.width = w; cv.height = px + pad * 2;
    ctx = cv.getContext("2d");
    ctx.font = font; ctx.textBaseline = "middle";
    ctx.fillStyle = "#ffffff";
    ctx.fillText(text, pad, cv.height / 2);
    const tex = new THREE.CanvasTexture(cv);
    tex.minFilter = THREE.LinearFilter; tex.generateMipmaps = false;
    const mat = new THREE.SpriteMaterial({
      map: tex, transparent: true, depthTest: false,
      opacity: opts.opacity == null ? 1 : opts.opacity
    });
    const sp = new THREE.Sprite(mat);
    const scale = opts.size || 0.42;
    sp.scale.set(scale * cv.width / cv.height, scale, 1);
    sp.renderOrder = 20;
    if (opts.color) sp.material.color.copy(opts.color);
    return stamp(sp);
  }

  function sphere(r, color, opacity) {
    return stamp(new THREE.Mesh(
      new THREE.SphereGeometry(r, 12, 12),
      new THREE.MeshBasicMaterial({ color, transparent: true, opacity: opacity == null ? 1 : opacity })
    ));
  }

  const tint = (sprite, color) => sprite.material.color.copy(color);
  function setSlab(g, color, fillOp, edgeOp) {
    g.userData.fill.color.copy(color); g.userData.fill.opacity = fillOp;
    g.userData.edge.color.copy(color); g.userData.edge.opacity = edgeOp;
  }

  /* ---------- the three planes ----------------------------------- */
  const publicPlane = new THREE.Group(); scene.add(publicPlane);
  {
    const grid = new THREE.GridHelper(24, 18);
    grid.material.transparent = true; grid.material.opacity = 0.2;
    grid.position.set(0, Y_PUB, 0.6); grid.scale.z = 0.44;
    publicPlane.add(grid);
    const pane = new THREE.Mesh(new THREE.PlaneGeometry(24, 10.5),
      new THREE.MeshBasicMaterial({ transparent: true, opacity: 0.07, depthWrite: false, side: THREE.DoubleSide }));
    pane.rotation.x = -Math.PI / 2; pane.position.set(0, Y_PUB - 0.02, 0.6);
    publicPlane.add(pane);
    const lb = label("PUBLIC · in the clear", { px: 36, size: 0.56 });
    lb.position.set(3.4, Y_PUB + 0.25, 6.0); publicPlane.add(lb);
    publicPlane.userData = { grid: grid.material, pane: pane.material, lb };
  }

  const netPlane = new THREE.Group(); scene.add(netPlane);
  {
    const s = slab(21, 0.05, 13, 0x3ddbc7, 0.05);
    s.position.set(0, Y_NET, 0.2); netPlane.add(s);
    const lb = label("TAILNET · wrapped", { px: 36, size: 0.56 });
    lb.position.set(-6.6, Y_NET + 0.6, -5.4); netPlane.add(lb);
    netPlane.userData = { s, lb };
  }

  /* ---------- machines, and gate 1 · the power ring --------------- */
  const machines = {};
  const MACHINE_META = [
    { id: "lab-roam",   role: "the phone's stand-in" },
    { id: "evil-box",   role: "a hostile machine" },
    { id: "lab-ubuntu", role: "the laptop" },
    { id: "lab-vps",    role: "the public box" }
  ];
  MACHINE_META.forEach((m) => {
    const g = new THREE.Group();
    g.position.copy(POS[m.id]); g.position.y = Y_MACH;
    const body = slab(2.9, 1.0, 2.0, 0xffffff, 0.10); g.add(body);
    const nm = label(m.id, { px: 48, weight: 700, size: 0.66 }); nm.position.set(0, 1.05, 0); g.add(nm);
    const rl = label(m.role, { px: 32, size: 0.44, opacity: 0.8 }); rl.position.set(0, 0.5, 0); g.add(rl);
    const ring = new THREE.Mesh(new THREE.TorusGeometry(1.95, 0.045, 8, 48),
      new THREE.MeshBasicMaterial({ transparent: true, opacity: 0.9 }));
    ring.rotation.x = -Math.PI / 2; ring.position.y = -0.58; g.add(ring);
    scene.add(g);
    machines[m.id] = { id: m.id, g, body, name: nm, role: rl, ring, addr: null, homeZ: POS[m.id].z };
  });

  /* ---------- gate 2 · the NAT walls ------------------------------ */
  const nats = {};
  [["lab-roam", "nat-roam"], ["evil-box", "nat-evil"], ["lab-ubuntu", "nat-ubuntu"]].forEach(([id, name]) => {
    const g = new THREE.Group();
    g.position.set(GX.g2, 0.1, POS[id].z);
    const wall = slab(0.26, 3.4, 2.4, 0xffffff, 0.07); g.add(wall);
    const lb = label(name, { px: 30, size: 0.42, opacity: 0.85 }); lb.position.set(0, 2.05, 0); g.add(lb);
    scene.add(g);
    nats[id] = { g, wall, lb, name };
  });

  /* ---------- gate 3 · the membrane, and one cell per grant ------- */
  const MEMB_Y = TN_Y;
  const membrane = slab(0.14, 2.9, 11.5, 0xffffff, 0.10);
  membrane.position.set(GX.g3, MEMB_Y, 0.2); scene.add(membrane);

  const grantCells = {};   /* filled in by setState, once /api/meta has the grants */
  const grantHost = new THREE.Group(); scene.add(grantHost);

  /* ---------- the DERP relay -------------------------------------- */
  const derp = new THREE.Group();
  derp.position.set(GX.derp, Y_DERP, -2.6);
  const derpBox = slab(2.2, 0.75, 1.6, 0xffffff, 0.12); derp.add(derpBox);
  const derpLb = label("DERP relay", { px: 34, size: 0.5 }); derpLb.position.set(0, -0.8, 0); derp.add(derpLb);
  scene.add(derp);

  /* ---------- gate 4 · the shutter -------------------------------- */
  const shutter = new THREE.Group();
  shutter.position.set(GX.g4, Y_MACH, POS["lab-vps"].z);
  scene.add(shutter);
  const slats = {};
  SLATS.forEach((s) => {
    const g = new THREE.Group(); g.position.set(0, s.y, 0);
    const plate = slab(0.16, 0.5, 2.6, 0xffffff, 0.22); g.add(plate);
    const lb = label(s.text, { px: 30, size: 0.38 }); lb.position.set(0, 0.02, 1.9); g.add(lb);
    shutter.add(g);
    slats[s.key] = { key: s.key, g, plate, lb };
  });

  /* ---------- gate 5 · the sockets -------------------------------- */
  const sockets = {};
  SOCKET_PORTS.forEach(([port, dy]) => {
    const g = new THREE.Group();
    g.position.set(GX.g5, Y_MACH + dy, POS["lab-vps"].z);
    const m = new THREE.Mesh(new THREE.CylinderGeometry(0.17, 0.17, 0.18, 16),
      new THREE.MeshBasicMaterial({ transparent: true, opacity: 0.9 }));
    m.rotation.z = Math.PI / 2; g.add(m);
    const lb = label(":" + port, { px: 32, size: 0.44 }); lb.position.set(0, 0.02, 0.9); g.add(lb);
    scene.add(g);
    sockets[port] = { port, g, m, lb };
  });

  /* ---------- the ladder, on the board ---------------------------
     Five posts along the front edge at the five gate positions. The strip
     under the viewport is a ruler for this same axis. */
  const POST_Z = -7.7;
  const posts = GATE_POSTS.map((gp) => {
    const l = line([new V3(gp.x, Y_PUB - 0.1, POST_Z), new V3(gp.x, TN_Y + 0.5, POST_Z)], 0xffffff, 0.2, true);
    scene.add(l);
    const lb = label(gp.t, { px: 32, size: 0.5 });
    lb.position.set(gp.x, TN_Y + 1.0, POST_Z); scene.add(lb);
    return { l, lb };
  });

  /* ---------- the stranger ---------------------------------------- */
  const strangerLb = label("A STRANGER", { px: 32, size: 0.48 });
  strangerLb.position.copy(ANY).add(new V3(0, 0.7, 0)); scene.add(strangerLb);
  const strangerDot = sphere(0.17, 0xffffff);
  strangerDot.position.copy(ANY); scene.add(strangerDot);

  const beamHost = new THREE.Group(); scene.add(beamHost);
  const tunnelHost = new THREE.Group(); scene.add(tunnelHost);
  let beams = [], tunnels = [];

  /* Set-piece props live here and are thrown away whole between shots. */
  const scratch = new THREE.Group(); scene.add(scratch);

  /* ---------- the packet ------------------------------------------
     Core plus lattice shell with a hex label when it is wrapped; bare core
     with a legible label when it is not. Nothing else may wear the shell. */
  const packet = new THREE.Group();
  const core = new THREE.Mesh(new THREE.IcosahedronGeometry(0.17, 1),
    new THREE.MeshBasicMaterial({ transparent: true }));
  packet.add(core);
  const shell = new THREE.Mesh(new THREE.OctahedronGeometry(0.42, 0),
    new THREE.MeshBasicMaterial({ wireframe: true, transparent: true, opacity: 0.9 }));
  packet.add(shell);
  let pktLb = label("GET /secret", { px: 30, size: 0.32 });
  pktLb.position.set(0, 0.62, 0); packet.add(pktLb);
  packet.visible = false; scene.add(packet);

  const TRAIL = 48;
  const trailGeom = new THREE.BufferGeometry();
  trailGeom.setAttribute("position", new THREE.BufferAttribute(new Float32Array(TRAIL * 3), 3));
  const trail = new THREE.Line(trailGeom, new THREE.LineBasicMaterial({ transparent: true, opacity: 0.55 }));
  trail.visible = false; trail.frustumCulled = false; scene.add(trail);
  let trailPts = [];

  const burst = new THREE.Mesh(new THREE.RingGeometry(0.2, 0.28, 32),
    new THREE.MeshBasicMaterial({ transparent: true, side: THREE.DoubleSide }));
  burst.visible = false; scene.add(burst);

  function swapPacketLabel(text, color) {
    dropSprite(pktLb);
    pktLb = label(text, { px: 30, size: 0.32, color });
    pktLb.position.set(0, 0.62, 0); packet.add(pktLb);
  }

  /* ============================================================
     painting the board from the configuration

     Every gate renders its state continuously, before any probe runs, so
     flipping a switch moves something you can see. The values come from
     /api/state, which is what the control server read back off the
     containers — not a guess about what the switches ought to have done.
     ============================================================ */
  let state = null, meta = null;
  let lastExposure = { ports: [], measured: false };

  function member(id) {
    const ms = state && state.machines && state.machines[id];
    return !!(ms && ms.onTailnet);
  }
  function live(id) {
    const ms = state && state.machines && state.machines[id];
    const lk = state && state.links && state.links[id];
    return !!(ms && ms.online && (!lk || lk.up));
  }

  /* The one inference this board makes, and it is the same one the audit
     makes: given ufw's rules and what sshd is bound to, would a stranger on
     the public segment get an answer on this port? It is a claim about the
     configuration, drawn dashed, and scan-public replaces it with what nmap
     actually measured. */
  function configSaysOpen(port) {
    if (!state) return false;
    const v = state.vps;
    if (port === "8080") return !!v.dockerPublish;   /* DOCKER-USER, before ufw's chain */
    if (port !== "22") return false;
    if (v.sshdListen === "tailnet") return false;    /* sshd never sees an eth0 packet */
    if (v.allowPublic22) return true;
    return !v.ufwDefaultDeny;
  }

  /* Throw a group away, descendants included. Two things to be careful of:
     slab() and the set-piece props are Groups, so a shallow pass would leave
     their meshes on the GPU; and every Sprite in three.js shares one
     singleton geometry, so disposing that would take every label in the
     scene with it. Each sprite's canvas texture is its own, and does go. */
  function clearGroup(g) {
    for (let i = g.children.length - 1; i >= 0; i--) {
      const c = g.children[i];
      g.remove(c);
      c.traverse((o) => {
        /* Unstamped objects were built inline by a set-piece and belong to
           the live context. Stamped ones from an older generation died with
           the context that made them. */
        if (o.userData.gen != null && o.userData.gen !== contextGen) return;
        if (o.geometry && !o.isSprite) o.geometry.dispose();
        if (o.material) {
          const mats = Array.isArray(o.material) ? o.material : [o.material];
          mats.forEach((m) => { if (m.map) m.map.dispose(); m.dispose(); });
        }
      });
    }
  }

  function buildGrantCells() {
    if (!meta || !meta.grants) return;
    clearGroup(grantHost);
    Object.keys(grantCells).forEach((k) => delete grantCells[k]);
    meta.grants.forEach((gr) => {
      const wide = gr.key === "any";
      const y = wide ? MEMB_Y - 1.1 : MEMB_Y;
      const z = CELL_Z[gr.key] == null ? 0.2 : CELL_Z[gr.key];
      const cell = slab(0.42, wide ? 0.42 : 1.1, wide ? 11.2 : 2.4, 0xffffff, 0.3);
      cell.position.set(GX.g3, y, z); grantHost.add(cell);
      const lb = label(gr.label, { px: 32, size: 0.38 });
      lb.position.set(GX.g3, y + (wide ? -0.5 : 0.92), z); grantHost.add(lb);
      grantCells[gr.key] = { key: gr.key, cell, lb, def: gr, z, y };
    });
  }

  function buildBeams() {
    clearGroup(beamHost); beams = [];
    if (!state) return;
    ["22", "8080"].forEach((port) => {
      if (!configSaysOpen(port)) return;
      const sock = sockets[port].g.position;
      const curve = new THREE.CatmullRomCurve3([
        ANY.clone(),
        new V3(-3.0, Y_PUB + 0.25, ANY.z + 1.0),
        new V3(2.4, Y_PUB + 0.25, sock.z - 1.4),
        new V3(sock.x - 1.4, Y_PUB + 1.6, sock.z),
        sock.clone()
      ]);
      /* Dashed, because this is what the rules say rather than what a scan
         found. scan-public draws the measured version solid. */
      beamHost.add(line(curve.getPoints(48), C.danger, 0.7, true));
      const dot = sphere(0.11, C.danger);
      beamHost.add(dot);
      const lb = label(":" + port + " — the rules say a stranger gets in",
        { px: 28, size: 0.32, color: C.danger });
      lb.position.set(sock.x - 4.4, Y_PUB + 2.1 + beams.length * 0.5, sock.z);
      beamHost.add(lb);
      beams.push({ curve, dot, phase: beams.length * 0.4 });
    });

    /* The beam a stranger does not get: nat-ubuntu forwards nothing in. */
    const stop = new V3(GX.g2 - 0.2, Y_PUB + 1.0, POS["lab-ubuntu"].z);
    beamHost.add(line([ANY.clone(), new V3(-8.2, Y_PUB + 0.4, 1.2), stop], C.faint, 0.45, true));
    const dlb = label("nat-ubuntu forwards nothing in — no address to aim at",
      { px: 26, size: 0.3, color: C.faint });
    dlb.position.set(GX.g2 - 2.4, Y_PUB + 1.5, POS["lab-ubuntu"].z);
    beamHost.add(dlb);
  }

  /* The standing tunnels are the one part of the board that is pure
     measurement: `tailscale status` on each machine said whether it has an
     active session to lab-vps and whether that session is direct or relayed.
     No session, no tunnel — however permissive the policy looks. */
  function buildTunnels() {
    clearGroup(tunnelHost); tunnels = [];
    if (!state) return;
    ["lab-ubuntu", "lab-roam"].forEach((id) => {
      const ms = state.machines[id];
      if (!ms || !ms.onTailnet || !ms.pathTo) return;
      if (!member("lab-vps")) return;
      const kind = ms.pathTo === "relay" ? "relay" : "direct";
      const curve = rideCurve({ from: id, to: "lab-vps", path: kind }, 5);
      tunnelHost.add(line(curve.getPoints(70), C.accent, kind === "relay" ? 0.45 : 0.6, false));
      const N = 26;
      const pg = new THREE.BufferGeometry();
      pg.setAttribute("position", new THREE.BufferAttribute(new Float32Array(N * 3), 3));
      const pnts = new THREE.Points(pg, new THREE.PointsMaterial({
        color: C.accent, size: 0.13, transparent: true, opacity: 0.95, sizeAttenuation: true
      }));
      pnts.frustumCulled = false;
      tunnelHost.add(pnts);
      tunnels.push({ curve, geom: pg, n: N, phase: tunnels.length * 0.5 });
    });
  }

  function paintBoard() {
    if (!state) return;
    restoreStanding();
    let anyTailnet = false;

    /* A set-piece is allowed to move a machine — expired-key drops lab-roam
       out of the tailnet plane — so every one of them is put back here
       rather than only the one that usually moves. */
    MACHINE_META.forEach((m) => {
      const v = machines[m.id];
      v.g.position.set(POS[m.id].x, Y_MACH, POS[m.id].z);
    });

    MACHINE_META.forEach((m) => {
      const ms = state.machines[m.id] || {};
      const v = machines[m.id];
      const isLive = live(m.id), isMember = member(m.id);
      if (isMember) anyTailnet = true;

      v.g.visible = m.id !== "evil-box" || !!ms.online;
      const col = !isLive ? C.faint : m.id === "evil-box" ? C.danger : isMember ? C.accent : C.warn;
      setSlab(v.body, col, isLive ? 0.11 : 0.05, isLive ? 0.85 : 0.3);
      tint(v.name, isLive ? C.text : C.faint);
      tint(v.role, C.muted);
      v.ring.material.color.copy(isLive ? C.ok : C.danger);
      v.ring.material.opacity = isLive ? 0.55 : 0.9;

      /* The address a machine answers on is a fact about the path, not about
         the machine, so it is redrawn rather than kept. All three come from
         the container; none of them is made up here. */
      const txt = !ms.online ? "stopped"
        : isMember && ms.tsAddr ? ms.tsAddr
        : ms.wanAddr ? ms.wanAddr + (nats[m.id] ? " (behind " + nats[m.id].name + ")" : "")
        : ms.lanAddr || "no address";
      dropSprite(v.addr);
      const nu = label(txt, { px: 32, size: 0.34, opacity: 0.85, color: isMember ? C.accent : C.muted });
      nu.position.set(0, -0.85, 0);
      v.g.add(nu); v.addr = nu;

      if (nats[m.id]) {
        nats[m.id].g.visible = v.g.visible;
        setSlab(nats[m.id].wall, C.line, 0.06, 0.5);
        tint(nats[m.id].lb, C.muted);
      }
    });

    /* evil-box moves onto lab-ubuntu's segment when the lab puts it there. */
    const shared = state.segmentShared && state.machines["evil-box"] && state.machines["evil-box"].online;
    machines["evil-box"].g.position.z = shared ? POS["lab-ubuntu"].z - 1.9 : POS["evil-box"].z;
    machines["evil-box"].homeZ = machines["evil-box"].g.position.z;

    publicPlane.userData.grid.color.copy(C.danger);
    publicPlane.userData.pane.color.copy(C.danger);
    tint(publicPlane.userData.lb, C.danger);
    setSlab(netPlane.userData.s, C.accent, anyTailnet ? 0.05 : 0.015, anyTailnet ? 0.4 : 0.12);
    tint(netPlane.userData.lb, anyTailnet ? C.accent : C.faint);

    /* gate 3 — default-deny makes the wall solid; each live grant opens a cell */
    const denyAll = state.acl.def === "deny";
    setSlab(membrane, denyAll ? C.accent : C.warn, denyAll ? 0.14 : 0.03, denyAll ? 0.55 : 0.18);
    Object.keys(grantCells).forEach((key) => {
      const gc = grantCells[key];
      const on = !!(state.acl.grants && state.acl.grants[key]);
      gc.cell.visible = on || denyAll;
      const col = !on ? C.faint : gc.def.danger ? C.danger : C.ok;
      setSlab(gc.cell, col, on ? 0.02 : 0.16, on ? 0.9 : 0.28);
      tint(gc.lb, on ? col : C.faint);
      gc.lb.material.opacity = on ? 1 : 0.35;
    });

    /* gate 4 — a slat per rule; open slats stand aside */
    const open = {
      public22: state.vps.allowPublic22,
      tailnet: state.vps.allowTailscale0,
      docker: state.vps.dockerPublish
    };
    Object.keys(slats).forEach((key) => {
      const sv = slats[key];
      const isOpen = !!open[key];
      sv.g.rotation.z = isOpen ? -1.15 : 0;
      const col = !isOpen ? C.line : key === "docker" ? C.danger : key === "public22" ? C.warn : C.accent;
      setSlab(sv.plate, col, isOpen ? 0.06 : 0.22, isOpen ? 0.45 : 0.95);
      tint(sv.lb, isOpen ? col : C.faint);
      sv.lb.material.opacity = isOpen ? 1 : 0.45;
    });

    /* gate 5 — a socket lights only if something binds an address the public
       path can reach. sshd bound to the tailnet address never sees eth0. */
    const pubSSH = state.vps.sshdListen !== "tailnet";
    sockets["22"].m.material.color.copy(pubSSH ? C.ok : C.accent);
    sockets["22"].m.material.opacity = 0.95;
    tint(sockets["22"].lb, pubSSH ? C.text : C.accent);
    sockets["8080"].m.material.color.copy(state.vps.dockerPublish ? C.danger : C.faint);
    sockets["8080"].m.material.opacity = state.vps.dockerPublish ? 0.95 : 0.35;
    tint(sockets["8080"].lb, state.vps.dockerPublish ? C.danger : C.faint);

    setSlab(derpBox, C.warn, 0.1, 0.6); tint(derpLb, C.warn);
    strangerDot.material.color.copy(C.danger);
    tint(strangerLb, C.danger);

    buildBeams();
    buildTunnels();

    const openPorts = ["22", "8080"].filter(configSaysOpen);
    setExposure(openPorts, false);
    paintAccess();
  }

  /* ---------- the always-on readouts ------------------------------ */
  function paintAccess() {
    if (!hud || !state) return;
    const lap = member("lab-ubuntu") && !!state.machines["lab-ubuntu"].pathTo;
    const phone = member("lab-roam") && !!state.machines["lab-roam"].pathTo;
    hud.dotLaptop.className = "hud-dot " + (lap ? "on" : "off");
    hud.dotPhone.className = "hud-dot " + (phone ? "on" : "off");
    hud.accessNote.textContent = lap && phone ? "laptop and phone have a session"
      : !lap && !phone ? "neither has a session to lab-vps"
      : lap ? "laptop only" : "phone only";
    hud.access.className = "hud-gauge " + (lap || phone ? "good" : "bad");
    paintPosture(lap || phone);
  }

  function paintPosture(haveWayIn) {
    if (!hud) return;
    const exposed = lastExposure.ports.length > 0;
    const word = haveWayIn
      ? (exposed ? "EXPOSED" : "HOLDING")
      : (exposed ? "EXPOSED, AND YOU ARE LOCKED OUT" : "AIRTIGHT, AND USELESS");
    hud.posture.textContent = word;
    hud.posture.className = "hud-posture " + (word === "HOLDING" ? "good" : "bad");
  }

  /* measured=true means a scan reported these; false means it is what the
     rules imply. The readout says which, because the difference is the
     whole point of running the scan. */
  function setExposure(ports, measured) {
    lastExposure = { ports: ports.slice(), measured: !!measured };
    if (!hud) return;
    hud.exposedN.textContent = String(ports.length);
    const list = ports.map((p) => ":" + p).join(" and ");
    hud.exposedNote.textContent = ports.length
      ? list + (ports.length > 1 ? " answer" : " answers") + " a stranger" +
        (measured ? " — measured by nmap" : " — by the rules, not yet scanned")
      : (measured ? "nmap found nothing open" : "the rules leave nothing open — not yet scanned");
    hud.exposed.className = "hud-gauge " + (ports.length ? "bad" : "good");
    const lap = state && member("lab-ubuntu") && !!state.machines["lab-ubuntu"].pathTo;
    const phone = state && member("lab-roam") && !!state.machines["lab-roam"].pathTo;
    paintPosture(!!(lap || phone));
  }

  /* Every label in the scene is a sprite with depthTest off, so that a name
     is never hidden behind the thing it names. That is right for the wide
     view and wrong for a close one, where the whole board's worth of text
     lands on top of the shot. A set-piece therefore pushes the standing
     labels back to a ghost and draws its own single claim over them. */
  function standingLabels() {
    const out = [];
    const push = (sp, weight) => { if (sp) out.push([sp, weight]); };
    push(publicPlane.userData.lb, 1); push(netPlane.userData.lb, 1);
    MACHINE_META.forEach((m) => {
      const v = machines[m.id];
      push(v.name, 1.6); push(v.role, 1); push(v.addr, 1);
    });
    /* The beams and the tunnels are rebuilt on every repaint, so their labels
       are found rather than remembered. */
    [beamHost, tunnelHost].forEach((h) => {
      h.children.forEach((c) => { if (c.isSprite) push(c, 1); });
    });
    Object.keys(nats).forEach((k) => push(nats[k].lb, 1));
    Object.keys(grantCells).forEach((k) => push(grantCells[k].lb, 1));
    Object.keys(slats).forEach((k) => push(slats[k].lb, 1));
    Object.keys(sockets).forEach((k) => push(sockets[k].lb, 2));
    push(derpLb, 1); push(strangerLb, 2);
    posts.forEach((p) => push(p.lb, 2));
    return out;
  }
  let dimmed = false;
  function restoreStanding() {
    if (!dimmed) return;
    standingLabels().forEach(([sp]) => {
      if (sp.userData.preDim != null) {
        sp.material.opacity = sp.userData.preDim;
        delete sp.userData.preDim;
      }
    });
    dimmed = false;
  }
  /* Remembers what it dimmed, so two set-pieces in a row do not multiply the
     board down to nothing and the next repaint puts it back. */
  function dimStanding(k) {
    restoreStanding();
    standingLabels().forEach(([sp, weight]) => {
      sp.userData.preDim = sp.material.opacity;
      sp.material.opacity = Math.min(1, sp.material.opacity * k * weight);
    });
    dimmed = true;
  }

  /* ---------- the HUD text --------------------------------------- */
  function setChip(text, kind) {
    if (!hud) return;
    hud.chip.textContent = text;
    hud.chip.className = "hud-chip" + (kind ? " " + kind : "");
  }

  /* The ladder never claims a rung the Result did not report. `reached` is
     that rung and nothing else; `outcome` says what happened when it got
     there, and there are three answers rather than two:

       delivered  it went all the way through, and that was the point (a probe)
       stopped    something answered here — a defence, or a closed door
       breached   nothing answered here, and it kept going (an attack got in)

     stopped and breached are both red, so they are also drawn with different
     border styles: colour is never the only channel. */
  function setLadder(reached, outcome) {
    if (hud) {
      for (let i = 1; i <= 5; i++) {
        const seg = hud.rungs[i - 1];
        seg.className = "hud-rung";
        if (!reached) continue;
        if (i < reached) seg.classList.add("passed");
        if (i === reached) seg.classList.add(outcome || "stopped");
      }
    }
    posts.forEach((p, i) => {
      const n = i + 1;
      const end = outcome === "delivered" ? C.ok : C.danger;
      const col = !reached ? C.faint : n < reached ? C.accent : n === reached ? end : C.faint;
      p.l.material.color.copy(col);
      p.l.material.opacity = !reached ? 0.26 : n <= reached ? 0.8 : 0.14;
      p.lb.material.color.copy(col);
      p.lb.material.opacity = !reached ? 0.7 : n <= reached ? 1 : 0.3;
    });
  }

  /* The verdict is the contract with a reader who cannot see the canvas: the
     same words, in the same order, whether or not anything moved. */
  function setVerdict(v) {
    if (!hud) return;
    hud.verdict.hidden = false;
    hud.verdict.className = "hud-verdict " + (v.tone || "");
    hud.vRung.textContent = v.head || "";
    hud.vRule.textContent = v.rule || "—";
    hud.vWhy.textContent = v.why || "";
    hud.nums.textContent = (v.nums || []).join("   ·   ");
    hud.transcript.textContent = v.transcript || "";
    hud.live.textContent = (v.head ? v.head + ". " : "") + (v.why || "");
  }

  /* A probe and an attack read the same Result and mean opposite things by
     it. ok on a probe is a delivery; ok on an attack is a defence holding,
     and nothing was delivered at all. Saying DELIVERED for the second is the
     same lie the ladder used to tell. */
  function verdictFor(res, isAttack) {
    const reached = res.rung || 1;
    const nums = [];
    if (res.rttMs) nums.push(res.rttMs.toFixed(1) + " ms");
    if (res.lossPct) nums.push(res.lossPct + "% loss");
    if (res.packets) nums.push(res.packets + " packets");
    if (res.retransmits) nums.push(res.retransmits + " retx");
    if (res.bytes) nums.push(res.bytes + " bytes");
    const named = RUNG_NAMES[Math.min(5, Math.max(1, reached)) - 1];
    return {
      /* danger outranks ok: a defence that succeeded at letting an attacker
         through is not a green frame. */
      tone: res.danger ? "bad" : res.ok ? "ok" : "warn",
      head: isAttack
        ? (res.danger ? "THROUGH · nothing answered it at rung " + reached
          : res.ok ? "HELD · answered at rung " + reached + " of 5 · " + named
          : "INCONCLUSIVE · nothing was proved either way")
        : (res.ok ? "DELIVERED · rung 5 of 5"
          : "STOPPED AT RUNG " + reached + " OF 5 · " + named),
      rule: res.rule, why: res.why, nums,
      transcript: (res.cmds && res.cmds.length) ? res.cmds[res.cmds.length - 1] : ""
    };
  }

  /* The HUD half of showing a Result, with nothing moving. Every path that
     puts a Result on the board goes through here, so the board can never be
     left displaying the previous action's frame under a new action's name. */
  function report(res, isAttack) {
    clearScratch();
    setLadder(res.rung, res.danger ? "breached"
      : isAttack ? "stopped"
      : res.ok ? "delivered" : "stopped");
    setChip(chipFor(res), res.path === "direct" || res.path === "relay" ? "net" : "pub");
    setVerdict(verdictFor(res, isAttack));
  }

  /* ============================================================
     the ride
     ============================================================ */
  function rideCurve(t, stopRung) {
    const from = POS[t.from] ? t.from : "evil-box";
    const to = POS[t.to] ? t.to : "lab-vps";
    const zs = POS[from].z, zd = POS[to].z;
    const kind = t.path || "public";
    const pts = [new V3(POS[from].x + 1.6, Y_MACH, zs)];

    if (kind === "lan") {
      pts.push(new V3(POS[from].x + 2.4, Y_MACH - 0.15, (zs + zd) / 2));
      pts.push(new V3(POS[to].x + 1.6, Y_MACH, zd));
      return new THREE.CatmullRomCurve3(pts);
    }
    if (kind === "public") {
      pts.push(new V3(GX.g2, Y_MACH - 1.6, zs));
      pts.push(new V3(GX.g2 + 2.0, Y_PUB, zs));
      if (stopRung >= 4) {
        pts.push(new V3(GX.g4 - 1.6, Y_PUB, zd));
        pts.push(new V3(GX.g4, Y_MACH - 0.1, zd));
      } else {
        pts.push(new V3(GX.g4 - 2.2, Y_PUB + 0.2, zd));
      }
      if (stopRung >= 5) pts.push(new V3(GX.g5, Y_MACH, zd));
      return new THREE.CatmullRomCurve3(pts);
    }
    /* tailnet: climb into the protected plane, then along it */
    pts.push(new V3(GX.g2, Y_MACH + 1.1, zs));
    pts.push(new V3(GX.g2 + 1.6, TN_Y - 0.5, zs));
    pts.push(new V3(GX.g2 + 2.6, TN_Y, zs));
    if (kind === "relay") {
      pts.push(new V3(GX.derp, Y_DERP - 0.5, zs * 0.4 - 2.0));
      pts.push(new V3(GX.derp + 1.5, TN_Y + 0.3, zs));
    }
    if (stopRung >= 3) pts.push(new V3(GX.g3, MEMB_Y, zs));
    else pts.push(new V3(GX.g3 - 1.4, TN_Y, zs));
    if (stopRung >= 4) {
      pts.push(new V3(GX.g3 + 2.6, TN_Y, (zs + zd) / 2));
      pts.push(new V3(GX.g4 - 1.2, TN_Y - 1.2, zd));
      pts.push(new V3(GX.g4, Y_MACH + 0.5, zd));
    }
    if (stopRung >= 5) pts.push(new V3(GX.g5, Y_MACH, zd));
    return new THREE.CatmullRomCurve3(pts);
  }

  let ride = null;

  /* The X the packet may reach is bounded by the rung the Result reports.
     Never further right than the answer says it got. */
  function ridePacket(res, opts) {
    opts = opts || {};
    const stopRung = res.ok ? 5 : (res.rung || 1);
    const wrapped = res.path === "direct" || res.path === "relay";
    const curve = rideCurve(res, stopRung);

    burst.visible = false;
    trailPts = [];
    packet.visible = stopRung >= 2 || res.ok;
    trail.visible = packet.visible && !reduced();
    core.material.color.copy(wrapped ? C.accent : C.danger);
    shell.visible = false;

    if (!packet.visible) return null;   /* rung 1: nothing ever left */

    /* Time is not faked: the choreography is a fixed length and the
       millisecond figures in the HUD stay the measured ones. */
    ride = {
      res, curve, u: 0, done: false, wrapped,
      dur: reduced() ? 0 : (res.path === "relay" ? 3.4 : opts.dur || 2.6),
      onEnd: opts.onEnd || null
    };
    if (reduced()) {
      /* Hold the final frame instead of flying to it. */
      ride.u = 1;
      const p = curve.getPointAt(1);
      packet.position.copy(p);
      finishRide(p);
    }
    return ride;
  }

  function finishRide(p) {
    ride.done = true;
    if (ride.res.ok && !ride.res.danger) {
      machines[ride.res.to] && machines[ride.res.to].ring.material.color.copy(C.ok);
      packet.visible = false;
    } else if (ride.res.ok) {
      packet.visible = true;   /* it got in, and that is the bad news */
    } else {
      burst.position.copy(p);
      burst.lookAt(camera.position);
      burst.material.color.copy(C.danger);
      burst.visible = true; burst.scale.setScalar(1);
      packet.visible = false;
    }
    if (ride.onEnd) ride.onEnd();
  }

  /* ============================================================
     camera and choreography
     ============================================================ */
  const reduced = () => reducedQuery.matches;

  function fly(pos, at) {
    wantPos.copy(pos); wantAt.copy(at);
    if (reduced()) { camPos.copy(pos); camAt.copy(at); }
  }
  function home() { fly(HOME_POS, HOME_AT); }

  /* A set-piece is a list of {t, fn} in seconds. Under reduced motion every
     step runs at once and the last one is the frame that is held — the shot
     is skipped, never the content. */
  let timers = [], spinners = [];
  function timeline(steps) {
    cancelTimeline();
    const sorted = steps.slice().sort((a, b) => a.t - b.t);
    if (reduced()) { sorted.forEach((s) => s.fn()); return; }
    sorted.forEach((s) => {
      timers.push(setTimeout(s.fn, Math.max(0, s.t) * 1000));
    });
  }
  function cancelTimeline() {
    timers.forEach(clearTimeout);
    timers = [];
  }
  /* A per-frame callback that lives until the next set-piece clears it. */
  function spin(fn) { spinners.push(fn); }

  /* Between shots the board goes back to what the configuration says. A
     set-piece is allowed to hide a machine or move one; none of that is
     allowed to survive into the next one. */
  let holding = false;
  function clearScratch() {
    cancelTimeline();
    holding = false;
    spinners = [];
    clearGroup(scratch);
    ride = null;
    packet.visible = false;
    trail.visible = false;
    burst.visible = false;
    shell.visible = false;
    tunnelHost.visible = true;
    beamHost.visible = true;
    paintBoard();
  }

  function frame() {
    if (!running) return;
    requestAnimationFrame(frame);
    const dt = Math.min(clock.getDelta(), 0.05), el = clock.elapsedTime;

    const k = reduced() ? 1 : 1 - Math.pow(0.001, dt);
    camPos.lerp(wantPos, k); camAt.lerp(wantAt, k);
    camera.position.copy(camPos); camera.lookAt(camAt);

    if (!reduced()) {
      beams.forEach((b) => {
        b.dot.position.copy(b.curve.getPointAt((el * 0.42 + b.phase) % 1));
        b.dot.scale.setScalar(0.8 + Math.sin(el * 4) * 0.15);
      });
      tunnels.forEach((tu) => {
        const arr = tu.geom.attributes.position.array;
        for (let i = 0; i < tu.n; i++) {
          const p = tu.curve.getPointAt(((i / tu.n) + el * 0.11 + tu.phase) % 1);
          arr[i * 3] = p.x; arr[i * 3 + 1] = p.y; arr[i * 3 + 2] = p.z;
        }
        tu.geom.attributes.position.needsUpdate = true;
      });
    } else if (tunnels.length && tunnels[0].geom.attributes.position.array[0] === 0) {
      /* Reduced motion still needs the beads placed once, or the tunnel is
         an invisible line of points at the origin. */
      tunnels.forEach((tu) => {
        const arr = tu.geom.attributes.position.array;
        for (let i = 0; i < tu.n; i++) {
          const p = tu.curve.getPointAt(i / tu.n);
          arr[i * 3] = p.x; arr[i * 3 + 1] = p.y; arr[i * 3 + 2] = p.z;
        }
        tu.geom.attributes.position.needsUpdate = true;
      });
    }

    if (ride && !ride.done) {
      ride.u = Math.min(1, ride.u + dt / Math.max(0.001, ride.dur));
      const p = ride.curve.getPointAt(ride.u);
      packet.position.copy(p);
      packet.rotation.y += dt * 2.2; core.rotation.x += dt * 3;

      /* Elevation is the whole story: above the machine plane means wrapped. */
      const wrapped = p.y > Y_NET - 0.9 && ride.wrapped;
      if (wrapped !== shell.visible) {
        shell.visible = wrapped;
        shell.material.color.copy(C.accent);
        core.material.color.copy(wrapped ? C.accent : C.danger);
        swapPacketLabel(wrapped ? "a7 3f 91 c0 …" : "GET /secret", wrapped ? C.accent : C.danger);
      }

      if (trail.visible) {
        trailPts.unshift(p.clone());
        if (trailPts.length > TRAIL) trailPts.pop();
        const a = trailGeom.attributes.position.array;
        for (let i = 0; i < TRAIL; i++) {
          const q = trailPts[Math.min(i, trailPts.length - 1)] || p;
          a[i * 3] = q.x; a[i * 3 + 1] = q.y; a[i * 3 + 2] = q.z;
        }
        trailGeom.attributes.position.needsUpdate = true;
        trail.material.color.copy(shell.visible ? C.accent : C.danger);
      }
      if (ride.u >= 1) finishRide(p);
    }

    if (burst.visible && !reduced()) {
      burst.scale.multiplyScalar(1 + dt * 2.6);
      burst.material.opacity = Math.max(0, 1 - (burst.scale.x - 1) / 4);
      burst.lookAt(camera.position);
      if (burst.material.opacity <= 0.01) burst.visible = false;
    }

    if (!reduced()) {
      MACHINE_META.forEach((m) => {
        const v = machines[m.id];
        if (!v.g.visible) return;
        v.ring.scale.setScalar(live(m.id) ? 1 + Math.sin(el * 1.6 + m.id.length) * 0.012 : 1);
      });
    }

    for (let i = 0; i < spinners.length; i++) spinners[i](dt, el);

    renderer.render(scene, camera);
  }

  /* ---------- wiring ---------------------------------------------- */
  function resize() {
    const r = canvas.parentElement.getBoundingClientRect();
    if (!r.width || !r.height) return;
    renderer.setSize(r.width, r.height, false);
    camera.aspect = r.width / Math.max(1, r.height);
    camera.updateProjectionMatrix();
  }
  window.addEventListener("resize", resize);

  /* Drag to orbit, gently — this is an instrument, not a flight sim. */
  let drag = null;
  canvas.addEventListener("pointerdown", (e) => {
    drag = { x: e.clientX, y: e.clientY };
    canvas.setPointerCapture(e.pointerId);
  });
  canvas.addEventListener("pointerup", () => { drag = null; });
  canvas.addEventListener("pointercancel", () => { drag = null; });
  canvas.addEventListener("pointermove", (e) => {
    if (!drag) return;
    const dx = (e.clientX - drag.x) * 0.02, dy = (e.clientY - drag.y) * 0.02;
    drag = { x: e.clientX, y: e.clientY };
    const off = wantPos.clone().sub(wantAt);
    const a = Math.atan2(off.z, off.x) - dx * 0.12;
    const r = Math.sqrt(off.x * off.x + off.z * off.z);
    off.x = Math.cos(a) * r; off.z = Math.sin(a) * r;
    off.y = Math.max(2, Math.min(22, off.y + dy * 1.4));
    wantPos.copy(wantAt).add(off);
    if (reduced()) camPos.copy(wantPos);
  });

  resize();
  frame();

  /* ---------- the board's public surface -------------------------- */
  const board = {
    THREE, C, GEOM,
    scene, camera, renderer, scratch,
    parts: { machines, nats, sockets, slats, grantCells, membrane, derp, derpBox, derpLb,
             posts, packet, core, shell, beamHost, tunnelHost, publicPlane, netPlane,
             strangerDot, strangerLb, shutter },
    mk: { line, slab, label, sphere, tint, setSlab },
    adopt,

    get state() { return state; },
    get reduced() { return reduced(); },
    /* True while a set-piece's final frame is up. The status stream checks
       this before repainting: the frame is an answer to a question somebody
       asked, and a poll arriving two seconds later must not erase it. */
    get holding() { return holding; },
    hold() { holding = true; },

    setMeta(m) { meta = m; buildGrantCells(); paintBoard(); },
    setState(s) { state = s; paintBoard(); },
    refreshTokens() { readTokens(); paintBoard(); },

    fly, home, timeline, spin, clearScratch, setExposure, setChip, setLadder,
    repaint: paintBoard, dimStanding,
    setVerdict, verdictFor, ridePacket, rideCurve, resize,
    configSaysOpen, member, live,

    report,

    /* The plain probe path: settle the camera on the pair and ride. */
    probe(res, isAttack) {
      report(res, isAttack);
      /* A rung-3 denial does not block the packet, it deletes the
         destination from the sender's netmap. Vanishing the box is the
         honest picture of that. */
      if (!res.ok && res.rung === 3 && machines[res.to]) machines[res.to].g.visible = false;
      settleCamera(res);
      ridePacket(res);
    },

    dispose() {
      running = false;
      cancelTimeline();
      window.removeEventListener("resize", resize);
      renderer.dispose();
    }
  };

  function settleCamera(res) {
    const from = POS[res.from] ? res.from : "evil-box";
    const to = POS[res.to] ? res.to : "lab-vps";
    const zc = (POS[to].z + POS[from].z) / 2, low = res.path === "public" || !res.path;
    fly(new V3(0.9, low ? 3.4 : 8.8, zc + 21.0), new V3(0.2, low ? -1.6 : 1.9, zc));
  }

  function chipFor(res) {
    switch (res.path) {
      case "direct": return "direct · punched";
      case "relay":  return 'relay · DERP "lab"';
      case "public": return "public segment · in the clear";
      case "lan":    return "same wire · no routing";
      default:       return "no path at all";
    }
  }

  return board;
}
