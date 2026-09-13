/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Hashem Aldhaheri */

/* ============================================================
   Does the board read the wire the way both pages used to read it?

   hud/driver.js is the one copy of a mapping that used to be two: app.js
   made it from the replies to its own POSTs and replay-app.js made it from
   the frames in a file. Merging them is only worth anything if the merged
   version keeps the two rules the copies agreed on, and those two rules are
   exactly the ones that fail silently.

     `set` and `preset` draw no shot. On the live page a switch flip moves
       the board by changing the lab and letting the next snapshot redraw it.
       A driver that played a shot per verdict would draw something no reader
       ever saw — and it would look like a feature, not a bug.

     A held frame outranks a snapshot. run() calls hold() the moment a shot
       starts, and setState repaints the standing board underneath it: back
       goes the machine expired-key moved, off comes the dim the shot drew
       over. A snapshot arriving under a held frame therefore waits.

   Neither throws when it is wrong. The board simply says something that did
   not happen, which is the failure this whole repository is against.

   The board and the feed are both fakes here, and deliberately: what is
   being tested is a mapping between two objects, and a real board needs a
   GPU. run() is injected for the same reason — the real one is imported by
   the module either way, and this file asserts which id it was handed and
   when, not what three.js did with it.
   ============================================================ */

import test from "node:test";
import assert from "node:assert/strict";

let driver = null, linkError = "", browserOnly = "";
try {
  driver = await import("../control/ui/hud/driver.js");
} catch (e) {
  /* Same split as setpieces.test.mjs: a SyntaxError at link time is an
     import naming something that is not exported, and that is ours. */
  if (e && e.name === "SyntaxError") linkError = e.message;
  else browserOnly = "hud/ does not evaluate outside a browser here: " + e.message;
}
const needsBrowser = driver ? false : (browserOnly || false);

test("hud/driver.js links — every import names something that is exported", () => {
  assert.equal(linkError, "", "hud/driver.js failed to link: " + linkError);
});

/* A board that records rather than draws. `holding` is a plain field so a
   test can put a held frame up without running a set-piece. */
function fakeBoard() {
  return {
    holding: false,
    calls: [],
    setState(s) { this.calls.push(["setState", s.tag]); },
    probe(res, isAttack) { this.calls.push(["probe", res.tag, !!isAttack]); },
    report(res, isAttack) { this.calls.push(["report", res.tag, !!isAttack]); }
  };
}

/* A feed that is only a fan-out. want() hands back a release the same way
   the real one does, and `open` is how many of them have not been called —
   which on the real feed is how many tcpdumps are running. */
function fakeFeed() {
  const listeners = {};
  const feed = {
    open: 0,
    on(type, fn) {
      (listeners[type] || (listeners[type] = [])).push(fn);
      return () => {
        const i = listeners[type].indexOf(fn);
        if (i >= 0) listeners[type].splice(i, 1);
      };
    },
    want() {
      feed.open++;
      let done = false;
      return () => { if (!done) { done = true; feed.open--; } };
    },
    send(type, data) { (listeners[type] || []).slice().forEach((fn) => fn(data)); },
    count(type) { return (listeners[type] || []).length; }
  };
  return feed;
}

/* A set-piece runner that says yes to the ids it was given and no to the
   rest, which is what the real one does with SETPIECES. */
function fakeRun(known) {
  const ran = [];
  const run = (board, id) => { if (known.indexOf(id) < 0) return false; ran.push(id); return true; };
  run.ran = ran;
  return run;
}

const verdict = (kind, id, tag) => ({ kind, id, result: { tag: tag || id } });

test("a verdict that named an action plays its set-piece", { skip: needsBrowser }, () => {
  const board = fakeBoard(), feed = fakeFeed(), run = fakeRun(["sniff"]);
  driver.create({ board, feed, run });

  feed.send("verdict", verdict("action", "sniff"));
  assert.deepEqual(run.ran, ["sniff"]);
  assert.equal(board.calls.length, 0, "the set-piece drew, so nothing else should have");
});

test("a switch and a configuration draw no shot at all", { skip: needsBrowser }, () => {
  /* The rule that is easiest to get wrong by being helpful. Both of these
     carry a real Result and both of them are on the wire; neither is
     something the board has ever rendered as an event. */
  const board = fakeBoard(), feed = fakeFeed(), run = fakeRun(["sniff"]);
  driver.create({ board, feed, run });

  feed.send("verdict", verdict("set", "vps.allowPublic22"));
  feed.send("verdict", verdict("preset", "hardened"));

  assert.deepEqual(run.ran, [], "a set or a preset is not a shot");
  assert.equal(board.calls.length, 0, "and it is not a fallback either");
});

test("an action with no set-piece falls back rather than leaving the last frame up",
  { skip: needsBrowser }, () => {
    const board = fakeBoard(), feed = fakeFeed(), run = fakeRun([]);
    const shots = [];
    driver.create({ board, feed, run, onShot: (s) => shots.push(s) });

    /* Two machines: ride it. */
    feed.send("verdict", { kind: "action", id: "new-one",
      result: { tag: "a", from: "evil-box", to: "lab-vps" } });
    /* No machines named: the board can only report it. */
    feed.send("verdict", { kind: "action", id: "another", result: { tag: "b" } });

    assert.deepEqual(board.calls, [["probe", "a", true], ["report", "b", true]]);
    assert.deepEqual(shots.map((s) => s.played), [false, false],
      "the page is told, because that is when it opens the text trace");
  });

test("a probe is a flow, and it is not an attack", { skip: needsBrowser }, () => {
  const board = fakeBoard(), feed = fakeFeed(), run = fakeRun([]);
  driver.create({ board, feed, run });

  feed.send("flow", { kind: "probe", id: "probe", result: { tag: "p" } });
  assert.deepEqual(board.calls, [["probe", "p", false]]);
});

test("a snapshot under a held frame waits, and goes on before the next shot",
  { skip: needsBrowser }, () => {
    /* The whole of the rule, in the order it happens: a shot holds a frame,
       the three-second poll lands underneath it, and the frame survives. Then
       the next shot starts, and it starts on the configuration the poll
       carried rather than on the one standing before the last shot. */
    const board = fakeBoard(), feed = fakeFeed(), run = fakeRun(["sniff", "replay"]);
    driver.create({ board, feed, run });

    feed.send("state", { tag: "first" });
    assert.deepEqual(board.calls, [["setState", "first"]]);

    board.holding = true;                       /* a set-piece is up */
    feed.send("state", { tag: "second" });
    assert.deepEqual(board.calls, [["setState", "first"]],
      "the held frame is the answer to a question somebody asked");

    feed.send("verdict", verdict("action", "replay"));
    assert.deepEqual(board.calls, [["setState", "first"], ["setState", "second"]],
      "and the shot draws over the configuration that arrived, not the old one");
  });

test("a snapshot that waited goes on at the next tick once the frame is gone",
  { skip: needsBrowser }, () => {
    /* Without this a reader who flips a switch under a held frame and then
       runs nothing else keeps a board drawn from before the flip. `stat` is
       the only source sent every tick whether or not anything moved, which
       is why it is the one that says the frame has since been cleared. */
    const board = fakeBoard(), feed = fakeFeed(), run = fakeRun([]);
    const d = driver.create({ board, feed, run });

    board.holding = true;
    d.state({ tag: "flipped" });                /* the page read the lab back */
    assert.equal(board.calls.length, 0);

    feed.send("stat", {});
    assert.equal(board.calls.length, 0, "still held, so it still waits");

    board.holding = false;
    feed.send("stat", {});
    assert.deepEqual(board.calls, [["setState", "flipped"]]);
  });

test("one watch at a time, and the last one is released", { skip: needsBrowser }, () => {
  /* A set-piece that keeps reading after its frame has gone draws packets
     that belong to something else, and a want() that is never released
     leaves a tcpdump running inside a container. */
  const board = fakeBoard(), feed = fakeFeed();
  let seen = 0;
  const run = (b, id, res, ctx) => {
    ctx.watch({ capture: "evil-box" }, "packet", () => { seen++; });
    return true;
  };
  const d = driver.create({ board, feed, run });

  feed.send("verdict", verdict("action", "one"));
  feed.send("packet", { line: "x" });
  assert.equal(seen, 1);
  assert.equal(feed.count("packet"), 1);

  assert.equal(feed.open, 1);

  feed.send("verdict", verdict("action", "two"));
  assert.equal(feed.count("packet"), 1, "the first shot's listener went with it");
  assert.equal(feed.open, 1, "and so did its request for the capture");

  d.destroy();
  assert.equal(feed.count("packet"), 0);
  assert.equal(feed.open, 0, "nothing is left running inside a container");
  assert.equal(feed.count("state"), 0, "destroy() drops every subscription");
});

test("a page with no feed still gets a board that draws the configuration",
  { skip: needsBrowser }, () => {
    /* feed.js not loading must not also cost the board. The live page reads
       the lab back over the API on every change and hands the snapshot
       straight to state(); what is lost is the shots, which are on the wire. */
    const board = fakeBoard();
    const d = driver.create({ board, feed: null, run: fakeRun([]) });
    d.state({ tag: "only" });
    assert.deepEqual(board.calls, [["setState", "only"]]);
    d.stop();
    d.destroy();
  });

test("no board is a driver that does nothing rather than one that throws",
  { skip: needsBrowser }, () => {
    const d = driver.create({ feed: fakeFeed() });
    d.state({ tag: "x" });
    d.stop();
    d.destroy();
  });
