/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Hashem Aldhaheri */

/* ============================================================
   The feed, on this side of the wire.

   One EventSource on /api/stream/hud, and everything on the page that wants
   live data asks this rather than opening its own. Before this file there
   were four endpoints and four call sites, each with its own `new
   EventSource`, its own `JSON.parse(ev.data)` and its own idea of when to
   close — which is four chances to leak a connection and four places to fix
   a bug in how the lab is read.

   The whole surface is three calls:

     on(type, fn)        -> off()      listen to one event type
     want(sources)       -> release()  ask for a source that costs something
     status()                          what the connection is doing

   `on` is free: the cheap sources — state, status, netcheck, stat, verdict,
   flow — are always on the wire, so listening is a callback and nothing more.

   `want` is for the two that are not free. A tcpdump is a process inside a
   container and a log tail is another, so the server only runs them when the
   URL asked, and the URL is how it is asked. Requests are reference
   counted and the most recent one wins: two things wanting a capture is one
   capture, and the last of them to ask picks the machine. Releasing the last
   request drops the source and leaves the rest of the wire alone.

   A change of sources means reconnecting, because there is no subscription
   state on the server to change — that is deliberate, and it is what makes a
   recording of the wire say what was being watched. Reconnects are coalesced
   to the end of the turn, so flipping two switches at once is one
   connection rather than two.

   Everything here survives having no server: EventSource retries on its own
   and a page with a dead feed is a page whose readouts are stale, which is
   what it was. Nothing here throws at a caller.

   A classic script, not a module, and deliberately: app.js is classic and
   runs before the board's module lands, so the feed cannot be something the
   page has to wait for. It hands itself over on window.LabFeed.
   ============================================================ */
(function () {
  "use strict";

  /* The names this build knows to listen for before the server has said.
     The server's own list arrives in `hello` and is used from the next
     connection onwards, so a server that grows a type is picked up without
     this list being edited — but the first connection has to guess, and
     guessing the list it shipped with is the only honest guess available. */
  var KNOWN_TYPES = [
    "hello", "state", "status", "netcheck", "stat",
    "verdict", "flow", "packet", "log", "note"
  ];

  function createFeed(path) {
    var url = path || "/api/stream/hud";

    var es = null;                /* the one connection, or null */
    var listeners = {};           /* type -> [fn] */
    var wants = {};               /* token -> {capture, iface, filter, logs, logsAll} */
    var nextToken = 1;
    var pending = false;          /* a reconnect is already queued for this turn */

    var last = {                  /* what the connection last told us */
      open: false,
      href: "",
      hello: null,
      seq: 0,
      opened: 0,
      errors: 0
    };

    /* ---- listeners --------------------------------------------------
       Kept per type rather than as one list with a filter, because the
       always-on sources tick every three seconds and a page with a dozen
       widgets should not run a dozen predicates to decide that a `stat` is
       not a `verdict`. */
    function on(type, fn) {
      if (typeof fn !== "function") return function () {};
      (listeners[type] || (listeners[type] = [])).push(fn);
      return function () { off(type, fn); };
    }

    function off(type, fn) {
      var list = listeners[type];
      if (!list) return;
      var i = list.indexOf(fn);
      if (i >= 0) list.splice(i, 1);
    }

    /* One listener throwing must not stop the ones after it. A widget with a
       bug is a widget with a bug; it is not a reason for the board to stop
       being told what the lab is doing. */
    function fanOut(type, ev) {
      var list = listeners[type];
      if (!list || !list.length) return;
      for (var i = 0; i < list.length; i++) {
        try {
          list[i](ev.data, ev);
        } catch (e) {
          if (window.console) console.error("feed listener for " + type + ": " + e);
        }
      }
    }

    /* ---- what the URL should be -------------------------------------
       The union of what everybody wants, with the most recent request
       winning where two disagree. Tokens count up, so the highest token that
       named a thing is the newest opinion about it. */
    function query() {
      var tokens = Object.keys(wants).map(Number).sort(function (a, b) { return a - b; });
      var w = {};
      tokens.forEach(function (t) {
        var s = wants[t];
        if (s.capture) { w.capture = s.capture; w.iface = s.iface || ""; w.filter = s.filter || ""; }
        if (s.logs) { w.logs = s.logs; w.logsAll = s.logsAll ? "1" : ""; }
      });

      var parts = [];
      ["capture", "iface", "filter", "logs", "logsAll"].forEach(function (k) {
        if (w[k]) parts.push(encodeURIComponent(k) + "=" + encodeURIComponent(w[k]));
      });
      return parts.length ? url + "?" + parts.join("&") : url;
    }

    /* ---- the connection ---------------------------------------------- */
    function connect() {
      pending = false;
      var href = query();

      /* Already on the right URL and not in an error state: nothing to do.
         This is what makes a release-then-want pair — which is what a
         set-piece ending and the next one starting looks like — cost no
         connection at all. */
      if (es && last.href === href && es.readyState !== 2) return;

      drop();
      last.href = href;

      try {
        es = new EventSource(href);
      } catch (e) {
        es = null;
        last.open = false;
        return;
      }

      var mine = es;
      es.onopen = function () {
        if (es !== mine) return;
        last.open = true;
        last.opened++;
      };
      es.onerror = function () {
        if (es !== mine) return;
        last.open = false;
        last.errors++;
        /* EventSource reconnects on its own, and on its own schedule. Doing
           it by hand here is how you get two connections. */
      };

      /* One handler per type rather than one `onmessage`: the server names
         every frame, so `addEventListener` is doing the dispatch the browser
         is already built to do, and an unknown type costs nothing. */
      var types = (last.hello && last.hello.types) || KNOWN_TYPES;
      types.forEach(function (type) { listen(mine, type); });
    }

    function listen(source, type) {
      source.addEventListener(type, function (raw) {
        if (es !== source) return;      /* a frame from a connection we replaced */
        var ev;
        try {
          ev = JSON.parse(raw.data);
        } catch (e) {
          return;                       /* a half-written frame; the next one is whole */
        }
        if (!ev || typeof ev !== "object") return;

        if (typeof ev.seq === "number") last.seq = ev.seq;
        if (ev.type === "hello") last.hello = ev.data || null;

        fanOut(ev.type || type, ev);
        fanOut("*", ev);
      });
    }

    function drop() {
      if (!es) return;
      var gone = es;
      es = null;
      last.open = false;
      try { gone.close(); } catch (e) {}
    }

    /* Coalesced to the end of the turn. Two switches flipped in one click
       handler, or a set-piece releasing a capture as the next one asks for
       it, should be one connection rather than a pair of them opened and
       thrown away. */
    function reconnectSoon() {
      if (pending) return;
      pending = true;
      setTimeout(connect, 0);
    }

    /* ---- the sources that cost something ---------------------------- */
    function want(sources) {
      if (!sources || (!sources.capture && !sources.logs)) return function () {};
      var token = nextToken++;
      wants[token] = sources;
      reconnectSoon();

      var released = false;
      return function () {
        if (released) return;
        released = true;
        delete wants[token];
        reconnectSoon();
      };
    }

    function status() {
      return {
        open: last.open,
        href: last.href,
        seq: last.seq,
        opens: last.opened,
        errors: last.errors,
        /* The server's count of what it threw away because a reader could not
           keep up, as of the last hello. A number that is not zero means a
           gap somewhere, and a consumer that cares should say so rather than
           draw a straight line across it. */
        dropped: (last.hello && last.hello.dropped) || 0,
        types: (last.hello && last.hello.types) || null,
        sources: (last.hello && last.hello.sources) || null
      };
    }

    connect();

    return {
      on: on,
      off: off,
      want: want,
      status: status,
      /* For a page being torn down, and for a test. A closed feed reopens on
         the next want(). */
      close: drop,
      reconnect: reconnectSoon
    };
  }

  /* One per page. The feed is the page's data layer rather than the board's,
     so it lives beside app.js and not under hud/: the flat drawing, the
     readout panes and the board all read the same wire, and two of those
     three exist when there is no WebGL. */
  window.LabFeed = createFeed();
  window.LabFeed.create = createFeed;
})();
