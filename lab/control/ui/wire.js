/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Hashem Aldhaheri */

/* ============================================================
   The wire's vocabulary — two lists, and the only copy of either.

   feed.js reads them to know what to listen for on a connection it has not
   been greeted on yet. replay.js reads them to know which frames a recording
   has to open with, and which ones a scrub backwards has to put back. Neither
   page can be told by the other: the live page has a server and the player
   does not, so a second copy of LATCHING was the alternative, and a stale copy
   of it is a player that draws yesterday's board after every scrub with
   nothing anywhere saying why.

   `FeedTypes` in lab/control/feed.go is the authority and this is not trying
   to be. The server's list arrives in the opening `hello` and feed.js uses
   that from the next connection onwards. TYPES here is what a page has to
   guess with before it has been greeted, and the list this build shipped with
   is the only honest guess available.

   A classic script, loaded before feed.js and before replay.js, because those
   are classic scripts too and neither page has a build step to resolve an
   import with.
   ============================================================ */
(function () {
  "use strict";

  /* Every type the wire carries. Mirrors FeedTypes in feed.go; a Go test
     pins that list, and the player reports a type it was not expecting
     rather than dropping it silently. */
  var TYPES = [
    "hello", "state", "status", "netcheck", "stat",
    "verdict", "flow", "packet", "log", "note"
  ];

  /* The types where only the most recent one matters, in the order a reader
     wants them: what the wire is, then what the lab is.

     These are the wire's snapshots rather than its lines. `state`, `status`
     and `netcheck` are sent only when they changed — three seconds of an
     unchanged `tailscale status` is not news — so the last one of each is the
     current answer and every one before it is history. Everything else is a
     moment: a packet, a log line, a verdict. There is no "last packet" that
     describes anything.

     Two things need the distinction, and both are in replay.js. A recorder
     that starts mid-session has missed the snapshots, and without them writes
     a recording that opens on an empty board. A player scrubbed backwards has
     to re-apply the snapshot that was standing at that point, rather than
     replay every packet since the beginning to get there. */
  var LATCHING = ["hello", "state", "status", "netcheck", "stat"];

  window.LabWire = {
    TYPES: TYPES,
    LATCHING: LATCHING,
    isLatching: function (type) { return LATCHING.indexOf(type) >= 0; }
  };
})();
