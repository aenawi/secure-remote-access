/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Hashem Aldhaheri */

/* ============================================================
   Does a recording play back as the thing that was recorded?

   replay.js is the one file in the UI whose being wrong is invisible. A
   board drawn from the configuration of two scrubs ago looks exactly like a
   board drawn from the right one; a timeline that opens with four minutes of
   dead air looks like a slow laptop; a moment list off by one frame looks
   like a set-piece that does not fire. None of those throws, none of them
   logs, and all of them make a posted recording wrong for whoever watches it.

   So the pure half is tested here: parsing a file, where the frames land on
   the clock, which frames are moments, and which snapshots a seek has to put
   back. The transport's clock is not — it is a setInterval reading
   performance.now(), and asserting a timer is asserting the machine.

   replay.js is a classic script that hands itself over on `window`, so it is
   run in a vm context with a `window` rather than imported. Nothing in the
   part being tested touches the document.

   The last test is a different kind of check: it reads the ids the board
   needs out of hud/scene.js and looks for every one of them in both pages
   that create a board. That list used to be eighteen querySelector calls
   inside app.js, and a second page copying them is exactly how a player
   would end up with a board that draws the whole shot and never says why.
   ============================================================ */

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const read = (rel) => readFileSync(join(root, rel), "utf8");

/* An array built inside the vm context has that context's Array as its
   prototype, so deepStrictEqual calls it structurally identical and not equal
   — which is true and is not the question being asked. Comparing the contents
   as one string sidesteps the realm entirely, and the failure message is more
   readable than a diff of two arrays that look the same. */
const same = (got, want, why) =>
  assert.equal(Array.prototype.join.call(got, " "), want.join(" "), why);

/* wire.js and replay.js, in a context that is its own window. */
function load() {
  const sandbox = {
    console, JSON, Math, Date, URL, performance, isFinite,
    setTimeout, clearTimeout, setInterval, clearInterval
  };
  sandbox.window = sandbox;
  const ctx = vm.createContext(sandbox);
  vm.runInContext(read("lab/control/ui/wire.js"), ctx, { filename: "wire.js" });
  vm.runInContext(read("lab/control/ui/replay.js"), ctx, { filename: "replay.js" });
  return sandbox;
}

const { LabReplay, LabWire } = load();

/* A minute of a lab: the header, a snapshot, an attack ten seconds in, a
   second snapshot, a probe forty seconds in. The timestamps are the shape a
   real recording has — the hello is older than everything else, because the
   connection was open before anybody pressed record. */
const T0 = 1757660000000;
const FILE = [
  { seq: 1, at: T0 - 120000, type: "hello", data: { types: LabWire.TYPES, dropped: 0, page: { meta: { catalog: [] } } } },
  { seq: 2, at: T0, type: "state", data: { vps: { allowPublic22: true } } },
  { seq: 3, at: T0 + 3000, type: "stat", data: [] },
  { seq: 4, at: T0 + 10000, type: "verdict", data: { id: "scan-public", kind: "action", result: { ok: false, danger: true, rung: 5, why: "it answered" } } },
  { seq: 5, at: T0 + 12000, type: "packet", data: { line: "10.0.0.1 > 10.0.0.2" } },
  { seq: 6, at: T0 + 20000, type: "state", data: { vps: { allowPublic22: false } } },
  { seq: 7, at: T0 + 40000, type: "flow", data: { id: "probe", kind: "probe", result: { ok: true, rung: 5, from: "lab-ubuntu", to: "lab-vps", port: "22" } } }
].map((e) => JSON.stringify(e)).join("\n") + "\n";

test("a .jsonl file of frames parses into frames", () => {
  const rec = LabReplay.parse(FILE);
  assert.equal(rec.events.length, 7);
  assert.equal(rec.skipped, 0);
  assert.equal(rec.events[3].type, "verdict");
});

test("the hello is a header and takes no time", () => {
  const rec = LabReplay.parse(FILE);
  /* Its own `at` is two minutes before the first frame about the lab. Counting
     it as the start would open this recording with two minutes of nothing,
     which is what a recording of a session already in progress always is. */
  assert.equal(rec.offsets[0], 0, "the hello is at zero");
  assert.equal(rec.offsets[1], 0, "and so is the first frame about the lab");
  assert.equal(rec.offsets[3], 10000, "the attack is ten seconds in");
  assert.equal(rec.duration, 40000);
});

test("a recording written by curl still has its SSE prefixes on, and still parses", () => {
  /* `curl -N .../api/stream/hud` writes `event:` and `data:` lines with a
     blank one between. That is the documented way to make a recording without
     a browser, so a file shaped like it is a recording rather than damage. */
  const sse = [
    "event: hello",
    'data: {"seq":1,"at":' + T0 + ',"type":"hello","data":{}}',
    "",
    "event: state",
    'data: {"seq":2,"at":' + (T0 + 1000) + ',"type":"state","data":{"a":1}}',
    ""
  ].join("\n");

  const rec = LabReplay.parse(sse);
  assert.equal(rec.events.length, 2);
  assert.equal(rec.skipped, 0, "an event: line is framing, not damage");
  assert.equal(rec.events[1].type, "state");
});

test("a half-written last line costs one line, not the recording", () => {
  const rec = LabReplay.parse(FILE + '{"seq":8,"at":1,"type":"pac');
  assert.equal(rec.events.length, 7, "everything that parsed is still there");
  assert.equal(rec.skipped, 1);
});

test("a clock that goes backwards does not make the timeline go backwards", () => {
  /* Two producers in the server stamp their own frames, and a file stitched
     together by hand can be in any order at all. A negative gap is a player
     that either hangs or replays. */
  const rec = LabReplay.parse([
    JSON.stringify({ at: T0, type: "state", data: {} }),
    JSON.stringify({ at: T0 + 5000, type: "packet", data: {} }),
    JSON.stringify({ at: T0 + 1000, type: "packet", data: {} })
  ].join("\n"));

  same(rec.offsets, [0, 5000, 5000]);
  assert.equal(rec.duration, 5000);
});

test("a frame with no clock belongs to the moment before it", () => {
  const rec = LabReplay.parse([
    JSON.stringify({ at: T0, type: "state", data: {} }),
    JSON.stringify({ type: "packet", data: { line: "x" } })
  ].join("\n"));
  same(rec.offsets, [0, 0], "not 1970, which is where a zero would put it");
});

test("the moments are the Results, with what ran beside them", () => {
  const rec = LabReplay.parse(FILE);
  assert.equal(rec.moments.length, 2);

  assert.equal(rec.moments[0].id, "scan-public");
  assert.equal(rec.moments[0].kind, "action");
  assert.equal(rec.moments[0].at, 10000);
  /* danger outranks ok, here as everywhere: this one got through. */
  assert.equal(rec.moments[0].danger, true);
  assert.equal(rec.moments[0].rung, 5);

  assert.equal(rec.moments[1].type, "flow");
  assert.equal(rec.moments[1].from, "lab-ubuntu");
});

test("a page payload rides in the first line, so the file needs no server", () => {
  const rec = LabReplay.parse(FILE);
  assert.ok(rec.page, "a recording with no page cannot draw a board");
  assert.ok(rec.page.meta, "and the board needs the meta most of all");
});

/* ---- the seek that is wrong invisibly ------------------------- */

test("the prelude is the snapshot that was standing, not everything since", () => {
  const rec = LabReplay.parse(FILE);

  /* At the probe — index 6 — the configuration standing is the second state,
     the one where public :22 was shut. A player that replayed from the start
     would arrive here having fired the attack's set-piece on the way. */
  const pre = LabReplay.prelude(rec, 6);
  const types = Array.from(pre, (e) => e.type);

  same(types, ["hello", "state", "stat"], "in the order a reader wants them");
  assert.equal(pre[1].data.vps.allowPublic22, false, "the second state, not the first");
  assert.ok(types.indexOf("packet") < 0, "a packet is a moment and has no standing value");
  assert.ok(types.indexOf("verdict") < 0, "and neither has a verdict");
});

test("the prelude before the beginning is empty", () => {
  const rec = LabReplay.parse(FILE);
  assert.equal(LabReplay.prelude(rec, 0).length, 0);
});

/* ---- the player, without its clock ---------------------------- */

/* Collect everything the player hands out, in order. */
function watch(player) {
  const got = [];
  player.on("*", (data, ev) => got.push(ev.type));
  return got;
}

test("a player opens on the board rather than on nothing", () => {
  const rec = LabReplay.parse(FILE);
  const seen = [];
  /* Listening before creating is not possible — the opening frames are handed
     out in the constructor — so this reads what the transport says instead. */
  const p = LabReplay.createPlayer(rec);
  const t = p.transport();

  assert.equal(t.index, 2, "the hello and the first state are already out");
  assert.equal(t.playing, false, "and nothing is running");
  assert.equal(t.duration, 40000);
  p.destroy();
  assert.equal(seen.length, 0);
});

test("seeking forward skips the packets and keeps the configuration", () => {
  const p = LabReplay.createPlayer(LabReplay.parse(FILE));
  const got = watch(p);

  p.seek(30000);
  /* Between the second state and the probe. Nothing in between is replayed;
     the snapshots that were standing are. */
  same(got, ["hello", "state", "stat"]);
  assert.equal(p.transport().index, 6);
  p.destroy();
});

test("seeking backwards puts the earlier configuration back", () => {
  const p = LabReplay.createPlayer(LabReplay.parse(FILE));
  p.seek(30000);
  const got = watch(p);

  p.seek(5000);
  /* Before the attack, after the first state. The first state is what was
     standing then — and re-applying it is the whole job, because the board is
     currently drawn from the second one. */
  const states = got.filter((t) => t === "state");
  assert.equal(states.length, 1, "one state, not every state since the start");
  p.destroy();
});

test("jumping to a moment plays the moment, not the frame after it", () => {
  const rec = LabReplay.parse(FILE);
  const p = LabReplay.createPlayer(rec);
  const got = watch(p);

  p.seekTo(rec.moments[0].index);
  assert.ok(got.includes("verdict"), "landing one frame late never fires the shot");
  p.destroy();
});

test("next and prev walk the moments and stop at the ends", () => {
  const rec = LabReplay.parse(FILE);
  const p = LabReplay.createPlayer(rec);

  p.next();
  assert.equal(p.transport().at, 10000, "the attack");
  p.next();
  assert.equal(p.transport().at, 40000, "the probe");
  p.next();
  assert.equal(p.transport().at, 40000, "and no further than the file goes");

  p.prev();
  assert.equal(p.transport().at, 10000, "back to the attack, not stuck on the probe");
  p.destroy();
});

test("the player has the feed's surface, so a widget cannot tell the difference", () => {
  const p = LabReplay.createPlayer(LabReplay.parse(FILE));
  for (const name of ["on", "off", "want", "status", "latest"]) {
    assert.equal(typeof p[name], "function", "a feed has " + name + "()");
  }

  /* want() cannot start a tcpdump on a file, and it still has to hand back
     the release function every correct widget calls in destroy(). */
  assert.equal(typeof p.want({ capture: "evil-box" }), "function");

  const s = p.status();
  assert.equal(s.replay, true, "and it says which kind of feed it is");
  assert.equal(s.dropped, 0, "the server's count, as of when this was made");
  assert.ok(Array.isArray(s.types));
  p.destroy();
});

test("a listener that throws does not stop the ones after it", () => {
  const p = LabReplay.createPlayer(LabReplay.parse(FILE));
  let reached = false;
  p.on("state", () => { throw new Error("a widget with a bug"); });
  p.on("state", () => { reached = true; });

  p.seek(25000);
  assert.equal(reached, true);
  p.destroy();
});

test("an empty file is a player, not an exception", () => {
  const p = LabReplay.createPlayer(LabReplay.parse(""));
  assert.equal(p.transport().count, 0);
  assert.equal(p.transport().duration, 0);
  p.seek(1000);
  p.next();
  p.prev();
  p.destroy();
});

/* ---- the markup both pages have to carry ---------------------- */

test("every id the board writes into is in both pages that create a board", () => {
  /* Read out of scene.js rather than imported: importing it pulls in three.js,
     which wants a browser. The list is a plain literal for exactly this. */
  const src = read("lab/control/ui/hud/scene.js");
  const block = /export const HUD_IDS = \[([\s\S]*?)\];/.exec(src);
  assert.ok(block, "hud/scene.js no longer exports HUD_IDS as a literal");

  const ids = block[1].match(/"([^"]+)"/g).map((s) => s.slice(1, -1));
  assert.ok(ids.length >= 20, "eighteen readouts and five rungs, near enough");

  for (const page of ["lab/control/ui/index.html", "lab/control/ui/replay.html"]) {
    const html = read(page);
    for (const id of ids) {
      assert.ok(html.includes('id="' + id + '"'),
        page + " has no element with id " + id + ", so the board cannot write there");
    }
  }
});

test("refs() names every id in HUD_IDS, and nothing that is not there", () => {
  /* The two halves of the same list, and they drift in the direction nobody
     notices: an id added to the markup and to refs() but not to HUD_IDS is an
     id the check above stops watching. */
  const src = read("lab/control/ui/hud/scene.js");
  const ids = /export const HUD_IDS = \[([\s\S]*?)\];/.exec(src)[1]
    .match(/"([^"]+)"/g).map((s) => s.slice(1, -1));

  const refs = /export function refs\(root\) \{([\s\S]*?)\n\}/.exec(src);
  assert.ok(refs, "hud/scene.js no longer exports refs()");

  const named = new Set((refs[1].match(/one\("([^"]+)"/g) || [])
    .map((s) => s.replace(/one\("/, "").replace(/"$/, "")));
  /* The rungs are built in a loop, so their ids are assembled rather than
     written. Everything else is named outright. */
  for (const id of ids) {
    if (/^hud-rung-\d$/.test(id)) continue;
    assert.ok(named.has(id), "refs() does not look up " + id);
  }
});

/* ---- recording a session already in progress ------------------ */

test("the snapshots a recording opens with are stamped when they were written", () => {
  /* The bug this pins: `state` is sent only when it changed, so the last one
     the page saw can be ten minutes old. Written with its own clock it makes
     a four-second recording claim ten minutes and spend all but the end of it
     showing nothing — which is what the live lab produced the first time this
     was driven for real. */
  const old = Date.now() - 600000;
  const feed = {
    latest: () => [
      { seq: 9, at: old, type: "hello", data: { types: LabWire.TYPES } },
      { seq: 10, at: old, type: "state", data: { vps: {} } }
    ],
    on: () => () => {}
  };

  const rec = LabReplay.createRecorder(feed);
  rec.stop();
  const parsed = LabReplay.parse(rec.text());

  assert.equal(parsed.events.length, 2);
  assert.equal(parsed.duration, 0, "two frames written together are no time apart");
  /* And the measurement's own clock is not thrown away. */
  assert.equal(parsed.events[1].wasAt, old, "when it was measured still travels");
  assert.ok(parsed.events[1].at > old, "but `at` is when it was written");
});

test("a recorder with nothing to seed from is still a recorder", () => {
  /* A feed that has not been greeted yet has no snapshot to hand over, and
     pressing record in that moment must not be the case that throws. */
  const rec = LabReplay.createRecorder({ on: () => () => {} });
  assert.equal(rec.count(), 0);
  assert.equal(rec.text(), "");
  assert.equal(rec.download(), false, "and there is nothing to save");
  rec.stop();
});
