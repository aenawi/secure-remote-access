/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Hashem Aldhaheri */

/* ============================================================
   The board rules, asserted.

   Four honesty rules are written down at the top of hud/setpieces.js, and
   until now three of them were guarded on the Go side only — which guards
   what the server reports, not what the board does with it. These are the
   ones about what the board does with it:

     Nothing is drawn that was not measured.
     A failed attack is not a green tick.
     res.danger outranks res.ok in tone.

   They live in hud/reading.js as pure functions of a Result, so they can
   be asserted here without three.js, a canvas, a container or a lab.

       node --test checks/

   Every Result below is the shape the control server actually returns:
   ok, danger, rung, rule, why, and a flat evidence map of what was
   measured. Nothing is mocked, because there is nothing to mock.
   ============================================================ */

import test from "node:test";
import assert from "node:assert/strict";

import {
  ev, rung, tone, ladderMark, neverRan, head, scanReading, sniffReading
} from "../control/ui/hud/reading.js";

/* ---------- tone, and the rule that decides it ------------------- */

test("danger outranks ok — docker-bypass succeeding is a red frame", () => {
  /* atkDockerBypass reports ok:true when the exploit ran cleanly and
     danger:true because it worked. Reading ok first paints the worst
     outcome on this board green. */
  const brokeOut = { ok: true, danger: true, rung: 5 };
  assert.equal(tone(brokeOut), "bad");
  assert.equal(ladderMark(brokeOut), "breached");
});

test("a failed attack is not a green tick — ok means the defence held", () => {
  const heldFrame = { ok: true, danger: false, rung: 3 };
  assert.equal(tone(heldFrame), "ok");
  assert.equal(ladderMark(heldFrame), "stopped");
  assert.match(head(heldFrame, "the ACL"), /^HELD · the ACL$/);
});

test("neither flag is inconclusive, not a pass", () => {
  const nothingProved = { ok: false, danger: false, rung: 1 };
  assert.equal(tone(nothingProved), "warn");
  assert.equal(ladderMark(nothingProved), "stopped");
  assert.equal(head(nothingProved, "the ACL"),
               "INCONCLUSIVE · nothing was proved either way");
});

test("head names something in all three outcomes", () => {
  assert.equal(head({ danger: true }, "the ACL", "the ACL was wide open"),
               "THROUGH · the ACL was wide open");
  /* A THROUGH with no phrase of its own falls back to the defence rather
     than to an empty string. */
  assert.equal(head({ danger: true }, "the ACL"), "THROUGH · the ACL");
  assert.equal(head({ ok: false, danger: false }, "the ACL", null, "evil-box is not running"),
               "INCONCLUSIVE · evil-box is not running");
});

/* ---------- what "it never ran" means ---------------------------- */

test("neverRan separates the attacker not starting from the defence holding", () => {
  /* needEvil returns at rung 1 having done nothing. */
  assert.equal(neverRan({ ok: false, danger: false, rung: 1 }), true);
  assert.equal(neverRan({ ok: false, danger: false }), true, "no rung is the floor");
  /* Everything that actually ran sets a higher rung, or a flag, or both. */
  assert.equal(neverRan({ ok: false, danger: false, rung: 3 }), false);
  assert.equal(neverRan({ ok: true, danger: false, rung: 1 }), false);
  assert.equal(neverRan({ ok: false, danger: true, rung: 1 }), false);
});

test("absent evidence is zero, not missing and not some", () => {
  assert.equal(ev({ evidence: { frames: 12 } }, "frames"), 12);
  assert.equal(ev({ evidence: { frames: 12 } }, "cleartext"), 0);
  assert.equal(ev({ ok: true }, "frames"), 0);
  assert.equal(rung({}), 1);
  assert.equal(rung({ rung: 4 }), 4);
});

/* ---------- scan-public: nothing drawn that was not measured ----- */

const PORTS = ["22", "80", "8080", "41641"];

test("a scan that ran reports its counts, and only the ports that answered", () => {
  const scanned = scanReading({
    ok: false, danger: true, rung: 4,
    evidence: { scanned: 4, "open:22": 1, "open:80": 1 }
  }, PORTS);
  assert.equal(scanned.ran, true);
  assert.deepEqual(scanned.open, ["22", "80"]);
  assert.deepEqual(scanned.nums, ["4 ports scanned", "2 open"]);
});

test("a scan that never ran reports no numbers at all", () => {
  /* atkScanPublic reports rung 4. The "evil-box is not in this stack" path
     reports rung 1 and measured nothing — and "nmap found nothing open"
     about a scan that never happened is the same lie as animating a
     capture that came back empty. */
  const never = scanReading({ ok: false, danger: false, rung: 1, evidence: {} }, PORTS);
  assert.equal(never.ran, false);
  assert.deepEqual(never.nums, []);
  assert.deepEqual(never.open, []);
});

test("open ports come from evidence, never from the danger flag", () => {
  const nothingOpen = scanReading({ ok: true, danger: false, rung: 4,
                                    evidence: { scanned: 4 } }, PORTS);
  assert.deepEqual(nothingOpen.open, []);
  assert.deepEqual(nothingOpen.nums, ["4 ports scanned", "0 open"]);
});

/* ---------- sniff: an empty capture draws an empty tray ---------- */

test("an empty capture draws an empty tray", () => {
  /* The whole point: a successful capture is the interesting picture, which
     is exactly why it must not be drawn when there was not one. */
  const r = sniffReading({ ok: false, danger: false, rung: 1, evidence: { frames: 0 } });
  assert.equal(r.tray, "empty");
  assert.deepEqual(r.drops, [], "nothing falls into an empty tray");
  assert.equal(r.trayLabel, "nothing captured");
  assert.match(r.note, /the tray is empty/);
  assert.match(r.head, /^INCONCLUSIVE · nothing was captured/);
});

test("an empty capture stays empty even when the Result cries danger", () => {
  /* danger sets the tone of the frame. It does not conjure frames onto the
     wire, and it must not put objects in the tray. */
  const r = sniffReading({ ok: false, danger: true, rung: 5, evidence: { frames: 0 } });
  assert.equal(r.tray, "empty");
  assert.deepEqual(r.drops, []);
  assert.equal(tone({ ok: false, danger: true, rung: 5 }), "bad");
  assert.equal(r.head, "INCONCLUSIVE · the capture came back empty");
});

test("a capture missing the control marker draws nothing either", () => {
  /* Frames arrived but the cleartext marker is not among them, so the
     capture is not seeing this traffic. Drawing the good run here would be
     the single most dishonest frame in the whole thing. */
  const r = sniffReading({ ok: true, rung: 4,
                           evidence: { frames: 240, cleartext: 0, tunnelled: 0 } });
  assert.equal(r.tray, "blind");
  assert.deepEqual(r.drops, []);
  assert.equal(r.trayLabel, "240 frames captured");
  assert.match(r.note, /the capture is not seeing this traffic/);
  assert.equal(r.head, "INCONCLUSIVE · the control marker never appeared either");
});

test("both arms measured: the readable marker, and the same marker sealed", () => {
  const r = sniffReading({ ok: true, rung: 4,
                           evidence: { frames: 240, cleartext: 3, tunnelled: 0 } });
  assert.equal(r.tray, "pair");
  assert.equal(r.drops.length, 2);
  assert.deepEqual(r.drops[0], { slot: "control", wrapped: false, tone: "danger",
                                 label: "LABMARKER-CLEARTEXT  ×3" });
  /* The shell is encryption, and only encryption wears it. */
  assert.equal(r.drops[1].wrapped, true);
  assert.equal(r.drops[1].tone, "accent");
  assert.match(r.head, /^HELD · WireGuard transport data/);
  assert.deepEqual(r.nums, ["240 frames", "3 cleartext", "0 tunnelled"]);
});

test("a tunnelled marker read off the wire wears no shell, and says why", () => {
  /* atkSniff names no rule in this case, because nothing ruled on it. */
  const r = sniffReading({ ok: false, danger: true, rung: 4,
                           evidence: { frames: 240, cleartext: 3, tunnelled: 2 } });
  assert.equal(r.tray, "pair");
  assert.equal(r.drops[1].wrapped, false, "an unencrypted marker must not look sealed");
  assert.equal(r.drops[1].tone, "danger");
  assert.equal(r.drops[1].label, "LABMARKER-TUNNELLED  ×2");
  assert.match(r.head, /^THROUGH · the marker crossed the wire in the clear$/);
  assert.equal(r.rule, "nothing sealed it — the marker was readable on the wire");
});

test("the server's own rule wins when it named one", () => {
  const r = sniffReading({ ok: true, rung: 4, rule: "wgVersion: WireGuard transport data",
                           evidence: { frames: 9, cleartext: 1, tunnelled: 0 } });
  assert.equal(r.rule, "wgVersion: WireGuard transport data");
});
