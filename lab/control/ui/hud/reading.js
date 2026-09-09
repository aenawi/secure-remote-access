/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Hashem Aldhaheri */

/* ============================================================
   What a Result says, before anything is drawn.

   The four honesty rules at the top of setpieces.js are decisions, and
   every one of them is a decision about a Result rather than about
   geometry: whether `danger` outranks `ok`, what an empty capture is
   allowed to draw, whether a scan that never ran may report a count.

   Those decisions used to sit inline in the shots, which is the one place
   in this directory where a mistake is invisible. `run()` wraps every
   set-piece in a try/catch so a broken shot cannot take the page down —
   it logs, clears, and the text trace lands instead. That is the right
   behaviour and it stays. It also means a typo in a rule looks, to
   anyone driving the lab, almost exactly like an action that never had a
   set-piece at all.

   So the rules live here instead: no imports, no three.js, no board, no
   DOM, no canvas. Everything below is a pure function of a Result, which
   is what lets ../../../checks/reading.test.mjs assert all of it under
   `node --test` in a few milliseconds, with the lab down.

   The board still draws. This only decides what it is allowed to draw.
   ============================================================ */

/* Evidence is a flat map of counts the control server measured. A key that
   is not there is zero — never "some", and never a reason to draw. */
export const ev = (res, key) => ((res && res.evidence && res.evidence[key]) || 0);

/* Rung 1 is the floor: it means nothing travelled. */
export const rung = (res) => (res && res.rung) || 1;

/* res.danger outranks res.ok. An attack that succeeded is a red frame even
   though the Result also says the command ran fine — docker-bypass is the
   case that matters, where `ok` means "the exploit worked". Reading `ok`
   first would paint the worst outcome on the board green. */
export function tone(res) {
  if (res && res.danger) return "bad";
  if (res && res.ok) return "ok";
  return "warn";
}

/* The ladder marks the rung the Result reports, and marks it as answered
   rather than as a delivery: res.ok on an attack means the defence held. */
export const ladderMark = (res) => ((res && res.danger) ? "breached" : "stopped");

/* needEvil and evilJoin return before the attack does anything, at rung 1.
   Every attack sets a higher rung the moment it actually runs, so this
   separates "the defence was tested and nothing was proved" from "the
   attacker never got off the ground" — different sentences to read at
   eleven at night. */
export const neverRan = (res) => !!res && !res.ok && !res.danger && rung(res) <= 1;

/* The three outcomes an attack can have, phrased so the head always names
   something rather than reporting a boolean. */
export function head(res, defence, through, inconclusive) {
  if (res && res.danger) return "THROUGH · " + (through || defence);
  if (res && res.ok) return "HELD · " + defence;
  return "INCONCLUSIVE · " + (inconclusive || "nothing was proved either way");
}

/* ---------- 1 · scan-public --------------------------------------
   The attack surface IS the lit dots, so they come from Evidence, one per
   port nmap actually reported open, and never from the prose in Why.

   `ran` is the honesty rule. atkScanPublic reports rung 4; the "evil-box is
   not in this stack" path reports rung 1 and measured nothing, and saying
   "nmap found nothing open" about a scan that never happened is the same
   lie as animating a capture that came back empty. */
export function scanReading(res, ports) {
  const ran = rung(res) >= 4;
  const scanned = ev(res, "scanned");
  const open = (ports || []).filter((p) => ev(res, "open:" + p) > 0);
  return {
    ran,
    scanned,
    open,
    nums: ran ? [scanned + " ports scanned", open.length + " open"] : []
  };
}

/* ---------- 3 · sniff --------------------------------------------
   The control experiment as three objects rather than three numbers: the
   marker sent in the clear, and the identical marker sent through the
   tunnel. Which is worth drawing only when both arms of it ran.

     tray "empty"  nothing was captured at all.
     tray "blind"  frames arrived, but the control marker is not among them,
                   so the capture is not seeing this traffic and the good
                   run is not evidence of anything.
     tray "pair"   both arms ran, and the pair can be drawn.

   A successful capture is the interesting picture, and that is exactly why
   it must not be drawn when there was not one: outside "pair" the tray
   stays empty and the frame says why. */
export function sniffReading(res) {
  const frames = ev(res, "frames");
  const cleartext = ev(res, "cleartext");
  const tunnelled = ev(res, "tunnelled");

  const tray = frames === 0 ? "empty" : cleartext === 0 ? "blind" : "pair";

  const note =
    tray === "empty" ? "the tray is empty — this proves nothing either way" :
    /* The control arm failed. Saying nothing here and drawing the good run
       anyway would be the single most dishonest frame in the whole thing. */
    tray === "blind" ? "the control marker is missing too — the capture is not seeing this traffic" :
    "";

  const drops = tray !== "pair" ? [] : [
    { slot: "control", wrapped: false, tone: "danger",
      label: "LABMARKER-CLEARTEXT  ×" + cleartext },
    /* The shell is encryption, and only encryption wears it — so the second
       object is sealed only when the tunnelled marker never turned up
       readable. If it did, both objects are legible and both are red. */
    tunnelled === 0
      ? { slot: "same-marker", wrapped: true,  tone: "accent",
          label: "a7 3f 91 c0 …  the same marker, sealed" }
      : { slot: "same-marker", wrapped: false, tone: "danger",
          label: "LABMARKER-TUNNELLED  ×" + tunnelled }
  ];

  return {
    frames, cleartext, tunnelled, tray, note, drops,
    trayLabel: frames ? frames + " frames captured" : "nothing captured",
    nums: [frames + " frames", cleartext + " cleartext", tunnelled + " tunnelled"],
    head:
      neverRan(res) ? "INCONCLUSIVE · nothing was captured — is evil-box running? `make attack`" :
      frames === 0 ? "INCONCLUSIVE · the capture came back empty" :
      cleartext === 0 ? "INCONCLUSIVE · the control marker never appeared either" :
      head(res, "WireGuard transport data — sealed for a key evil-box does not have",
           "the marker crossed the wire in the clear"),
    /* atkSniff names no rule when the tunnelled marker turns up, because
       nothing ruled on it — so the frame says what that means instead of
       leaving an em dash where the defence should be. */
    rule: (res && res.rule) || (tunnelled > 0
      ? "nothing sealed it — the marker was readable on the wire"
      : "the wire, and what a capture on it can and cannot read")
  };
}

/* ---------- 10 · tailcat-tunnel ----------------------------------
   The only action on this board whose subject is what did *not* happen,
   which makes it the one most easily drawn as a lie. Three rules:

   `skipped` is the point. Rungs 3 and 4 are below the rung reached and
   neither was consulted, so neither may be painted as a gate that
   approved this. There is a third ladder state for exactly this and
   nothing else uses it.

   `inbound` is measured, so it is allowed to be drawn — and it is the one
   number that turns "the firewall was never asked" from a claim into a
   reading. tcpdump watched the serving machine's own interface for the
   whole run. A non-zero count means something did arrive inbound and the
   claim above is wrong for this run, so the frame has to say so rather
   than draw the tidy picture anyway. That is the same rule the capture's
   control marker obeys.

   `direct` is the half a model cannot answer. A tunnel that only ever
   relayed is a true and less alarming picture than one that punched
   through two NATs, and drawing the punch when it did not happen would
   be inventing the interesting half. */
export function tailcatReading(res) {
  /* atkTailcatTunnel reports rung 2 or rung 5 the moment it actually runs;
     the "evil-box is not in this stack" path and a tunnel that would not
     start both report rung 1 and measured nothing at all. */
  const ran = !neverRan(res);
  const inbound = ev(res, "inbound");
  const shell = ev(res, "shell") > 0;
  const refused = rung(res) === 2;

  /* A run that measured an inbound packet has not shown what this shot is
     about, whatever else it showed. Saying so costs the picture and keeps
     the claim. */
  const contradicted = inbound > 0;

  return {
    ran,
    shell,
    refused,
    inbound,
    contradicted,
    direct: ev(res, "direct") > 0,
    ifaces: ev(res, "ifaces"),
    ordinaryRung: ev(res, "ordinaryRung"),
    /* Only when the run actually happened. An action that returned at rung 1
       because evil-box is not in the stack skipped nothing — it never
       started, and marking two rungs "never asked" about it would be the
       scan reporting ports it never probed. */
    skipped: neverRan(res) ? [] : [3, 4],
    skipLabel: contradicted
      ? inbound + " arrived inbound — this run does not show rung 4 being skipped"
      : "never asked",
    nums: neverRan(res) ? [] : [
      inbound + " inbound on :22",
      ev(res, "ifaces") + " tailcat interfaces",
      ev(res, "direct") > 0 ? "direct" : "relayed",
      "the ordinary way: rung " + ev(res, "ordinaryRung") +
        (ev(res, "ordinaryOK") > 0 ? " · in" : " · stopped")
    ],
    head:
      neverRan(res) ? "INCONCLUSIVE · no tunnel ran — is evil-box running? `make attack`" :
      refused ? "HELD · --allow pinned the server to one client key" :
      shell ? "THROUGH · a shell, and nothing you configured was asked" :
      "HELD · an SSH key, at rung 5, with rungs 3 and 4 never asked"
  };
}
