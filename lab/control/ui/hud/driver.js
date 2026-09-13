/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Hashem Aldhaheri */

/* ============================================================
   The board, reading the wire.

   Four types on the feed say something the board can draw, and the mapping
   from one to the other is short enough to write out in full:

     state    the configuration, drawn continuously  ->  board.setState
     verdict  a Result from /api/action              ->  the set-piece for its id
              a Result from /api/set or /api/preset  ->  nothing on the board
     flow     a Result from /api/probe               ->  board.probe
     packet   one line of tcpdump                    ->  whatever asked to watch

   That mapping used to exist twice. app.js made it from the replies to its
   own POSTs and replay-app.js made it from the frames in a file, both against
   the same wire, and the two had to stay identical or a recording stopped
   looking like the session it recorded. This file is the one copy. Both pages
   create a board, hand it here with a feed, and stop knowing how a frame
   becomes a drawing.

   `feed` is the widget contract's feed and nothing more: on(), want(), and
   the release functions they hand back. window.LabFeed satisfies it and so
   does the player replay.js builds out of a file, which is what lets a
   recording draw with no lab running.

   What this file does not do is paint the page. A verdict has a sentence in
   it as well as a shot, and where that sentence goes — a live region, a
   transport rail, a text trace — is the page's business and differs between
   the two. The board is the whole of the responsibility here.

   Two rules that look like details and are not. Both were found while
   building the player, and both are the reason a driver has to exist rather
   than each page keeping its own three listeners.

   `set` and `preset` draw no shot. On the live page a switch flip moves the
   board by changing the lab and letting the next `state` snapshot redraw it;
   the board has never rendered a switch as an event. A driver that played a
   shot per verdict would draw something no reader ever saw.

   A held frame outranks a snapshot. `run()` in setpieces.js calls hold() the
   moment a shot starts, so `board.holding` is true for the whole of it, and
   `setState` would repaint the standing board underneath — putting back a
   machine the shot moved and undoing the dim it drew over. So a snapshot
   arriving under a held frame waits. It is kept rather than dropped, and it
   goes on just before the next shot clears the board, which is the order the
   live page used to get by fetching the state before playing the shot.
   ============================================================ */

import { run as runSetpiece } from "./setpieces.js";

/* Build a driver over one board and one feed.

     board    what createBoard() returned. Required.
     feed     window.LabFeed, or a player. Optional: with no feed nothing is
              subscribed and state() still works, which is a page whose
              feed.js did not load rather than a page with no board.
     active   () -> boolean. Asked before a shot is drawn, never before a
              snapshot. The live page has a flat view the reader can be
              sitting in, and a set-piece played onto a hidden canvas is a
              set-piece nobody sees the start of. Defaults to always.
     onShot   ({ id, result, played }) after a verdict drew something. `played`
              is false when no set-piece exists for that id and the fallback
              drew instead — which is when the live page opens the text trace.
     run      the set-piece runner, for a test. Defaults to setpieces.js'.

   Returns { state, stop, destroy }. Nothing here throws at a caller. */
export function create(options) {
  const o = options || {};
  const board = o.board;
  const feed = o.feed || null;
  const active = typeof o.active === "function" ? o.active : () => true;
  const onShot = typeof o.onShot === "function" ? o.onShot : () => {};
  const play = typeof o.run === "function" ? o.run : runSetpiece;

  if (!board) return { state() {}, stop() {}, destroy() {} };

  /* The one set-piece watch, dropped the moment the next one starts. A shot
     that keeps reading after its frame has gone is a shot drawing packets
     that belong to something else.

     A set-piece says what it wants to watch and the feed works out whether
     anything has to be started for it: two things wanting the capture is one
     capture, and a shot ending while the packets pane is still on takes
     nothing away from the pane. */
  let watching = null;

  /* A snapshot that arrived under a held frame. See the header. */
  let pending = null;

  function stop() {
    if (!watching) return;
    const gone = watching;
    watching = null;
    gone.off();
    gone.release();
  }

  const ctx = {
    watch(sources, type, onEvent) {
      stop();
      if (!feed) return function () {};
      /* `want` is a no-op on a recording — whether the packets are in the
         file was decided when it was made — and it is still called, because a
         set-piece should not have to know which kind of feed it was given. */
      const mine = { off: feed.on(type, onEvent), release: feed.want(sources) };
      watching = mine;
      return function () { if (watching === mine) stop(); };
    }
  };

  /* A configuration to draw, from the wire or from a page that has just read
     the lab back over the API. Both go through here so the held-frame rule
     has one home. */
  function state(s) {
    if (!s) return;
    if (board.holding) { pending = s; return; }
    pending = null;
    board.setState(s);
  }

  /* Put on the snapshot a held frame made wait, if there is one. Called
     before a shot clears the board, so the configuration under the new shot
     is the current one rather than the one standing before the last shot. */
  function flush() {
    if (!pending) return;
    const s = pending;
    pending = null;
    board.setState(s);
  }

  /* Draw a Result that named an action. Returns whether a set-piece ran. */
  function shot(id, res) {
    stop();
    flush();
    if (play(board, id, res, ctx)) return true;
    /* No set-piece for this one yet. The board must still stop showing the
       last one's held frame — an unnamed action sitting under the previous
       action's verdict is worse than no picture. Ride it if it named two
       machines; otherwise just report it. */
    if (res.from && res.to) board.probe(res, true);
    else board.report(res, true);
    return false;
  }

  const offs = [];
  function listen(type, fn) { if (feed) offs.push(feed.on(type, fn)); }

  listen("state", state);

  listen("verdict", function (d) {
    if (!d || !d.result) return;
    if (d.kind !== "action") return;           /* a switch is not an event */
    if (!active()) return;
    onShot({ id: d.id, result: d.result, played: shot(d.id, d.result) });
  });

  listen("flow", function (d) {
    if (!d || !d.result) return;
    if (!active()) return;
    stop();
    flush();
    board.probe(d.result);
  });

  /* The wire's heartbeat. `stat` is the one polled source sent every tick
     whether or not it moved, so it is the only thing that says time has
     passed without also saying something changed — which is what a snapshot
     waiting under a frame that has since been cleared needs to hear. Without
     it a reader who flips a switch under a held frame and then runs nothing
     else keeps a board drawn from the configuration before the flip. */
  listen("stat", function () { if (pending && !board.holding) flush(); });

  return {
    state: state,
    stop: stop,
    destroy() {
      for (const off of offs) {
        try { off(); } catch (e) { /* a feed already torn down */ }
      }
      offs.length = 0;
      stop();
      pending = null;
    }
  };
}
