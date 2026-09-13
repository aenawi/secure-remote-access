/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Hashem Aldhaheri */

/* ============================================================
   Record the wire, and play it back.

   This is the point of putting the lab on one wire. A recording is a file of
   the frames that went past — one JSON object per line, `.jsonl` — and this
   file is both halves of it: the recorder that writes one from a live feed,
   and the player that reads one and hands it out through exactly the surface
   the live feed has. So a captured attack is a file somebody can post, and
   anybody can watch it with no containers, no Docker and no lab.

       on(type, fn)        -> off()      the same three calls feed.js has
       want(sources)       -> release()
       status()

   `want` is the one that cannot mean anything here, and it is kept rather
   than dropped: whether the packets are in the recording was decided when it
   was made, and the hello says which capture was running. A widget written
   against the live feed then works on a recording without knowing which one
   it has — which is the whole reason the surface is the same shape.

   On top of that surface is a transport, because a recording is a thing you
   scrub:

       play() pause() toggle()      seek(ms) seekTo(index) next() prev()
       setRate(x)                   onChange(fn) -> off()

   Two things here are less obvious than they look.

   **A scrub is not a fast replay.** The wire's snapshots — state, status,
   netcheck, stat — are only sent when they changed, so the picture at any
   point in a recording is the last one of each *before* that point, not the
   sum of everything since the start. Seeking therefore puts those back and
   then plays on, and skips every packet and every verdict in between. Playing
   a minute of tcpdump at 60× to arrive at the right board is the alternative,
   and it is both slower and wrong: every set-piece it passed through would
   fire.

   **The hello is a header, not a moment.** It describes the connection, and
   on a recording made from a session already in progress it is older than
   everything else in the file. Counting it as the first moment would open
   every such recording with a stretch of dead air as long as the session had
   been going. So it is emitted the instant it is reached and takes no time at
   all, and the clock starts at the first frame that is about the lab.

   A classic script, like feed.js, and for the same reason: the player page
   runs it before any module lands. It hands itself over on window.LabReplay.
   ============================================================ */
(function () {
  "use strict";

  var WIRE = window.LabWire;
  if (!WIRE) throw new Error("replay.js needs wire.js, loaded before it");

  function noop() {}

  /* ============================================================
     Reading a file
     ============================================================ */

  /* Parse a recording. Never throws: a file somebody edited by hand, or
     truncated by ^C halfway through a line, is still mostly a recording, and
     the honest thing is to play the part that parses and say how many lines
     did not. A player that refuses the whole file over its last line is a
     player that loses the attack you actually captured.

     Returns the shape the player and the page both read:

       events    the frames, in file order, each {seq, at, type, data}
       offsets   ms from the start of the recording, one per event, monotonic
       duration  ms from the first frame about the lab to the last
       hello     the first hello's payload, or null
       page      hello.page: the meta, themes and widgets the board needs
       moments   the verdicts and flows, with where they are
       skipped   lines that were not a frame
       strays    type names that are not in this build's vocabulary */
  function parse(text) {
    var raw = String(text == null ? "" : text).split("\n");
    var events = [], skipped = 0, strays = {};

    for (var n = 0; n < raw.length; n++) {
      var line = raw[n].trim();
      if (!line) continue;

      /* `curl`ing the wire into a file is the documented way to make a
         recording without a browser, and what that writes is SSE: an
         `event:` line, a `data:` line, a blank one. So a file with the
         prefixes still on it is a recording rather than a broken one, and
         the `event:` lines are dropped without being counted as damage —
         the type is inside the frame as well, which is why the envelope
         carries it. */
      if (line.slice(0, 6) === "data: ") line = line.slice(6).trim();
      else if (line.charAt(0) !== "{") {
        if (line.slice(0, 6) !== "event:" && line.slice(0, 3) !== "id:" &&
            line.charAt(0) !== ":") skipped++;
        continue;
      }

      var ev;
      try {
        ev = JSON.parse(line);
      } catch (e) {
        skipped++;
        continue;
      }
      if (!ev || typeof ev !== "object" || typeof ev.type !== "string") {
        skipped++;
        continue;
      }
      /* A frame with no clock belongs to the moment before it. Hand-written
         fixtures are the case — nobody writing one by hand types
         milliseconds since 1970 — and treating it as 1970 would put the
         whole recording behind a 56-year gap. */
      if (typeof ev.at !== "number" || !isFinite(ev.at)) {
        ev.at = events.length ? events[events.length - 1].at : 0;
      }
      if (WIRE.TYPES.indexOf(ev.type) < 0) strays[ev.type] = (strays[ev.type] || 0) + 1;
      events.push(ev);
    }

    /* The clock starts at the first frame that is about the lab. See the
       header: a hello is a header and takes no time. */
    var startAt = 0;
    for (var s = 0; s < events.length; s++) {
      if (events[s].type !== "hello") { startAt = events[s].at; break; }
      startAt = events[s].at;
    }

    var offsets = [], run = 0;
    for (var k = 0; k < events.length; k++) {
      if (events[k].type !== "hello") {
        /* Monotonic on purpose. Two producers in the server stamp their own
           frames and a recording stitched together by hand can be in any
           order at all; a timeline that goes backwards is a player that
           either hangs or replays. Clamping says "no earlier than the frame
           before it", which is the weakest claim that still plays. */
        var off = events[k].at - startAt;
        if (off > run) run = off;
      }
      offsets.push(run);
    }

    var hello = null;
    for (var h = 0; h < events.length; h++) {
      if (events[h].type === "hello") { hello = events[h].data || null; break; }
    }

    return {
      events: events,
      offsets: offsets,
      duration: offsets.length ? offsets[offsets.length - 1] : 0,
      hello: hello,
      page: (hello && hello.page) || null,
      moments: momentsIn(events, offsets),
      skipped: skipped,
      strays: strays
    };
  }

  /* The things worth jumping to: every Result the lab returned, which is
     every switch flipped, every configuration applied, every attack run and
     every probe measured.

     They are the reason the recording exists, and a reader should not have to
     find them by dragging a scrubber and watching for the board to move. */
  function momentsIn(events, offsets) {
    var out = [];
    for (var i = 0; i < events.length; i++) {
      var ev = events[i];
      if (ev.type !== "verdict" && ev.type !== "flow") continue;
      var d = ev.data || {};
      var res = d.result || {};
      out.push({
        index: i,
        at: offsets[i],
        type: ev.type,
        id: d.id || "",
        kind: d.kind || "",
        ok: !!res.ok,
        danger: !!res.danger,
        rung: res.rung || 0,
        rule: res.rule || "",
        why: res.why || "",
        from: res.from || "",
        to: res.to || "",
        port: res.port || ""
      });
    }
    return out;
  }

  /* The snapshots standing immediately before `index`, in the order a reader
     wants them applied: the wire, then the lab.

     Pure, and separated out because it is the one piece of this file whose
     being wrong is invisible — a board showing the configuration from two
     scrubs ago looks exactly like a board showing the right one. It is tested
     in lab/checks/replay.test.mjs for that reason. */
  function prelude(recording, index) {
    var events = (recording && recording.events) || [];
    var stop = Math.min(index, events.length);
    var found = {};
    for (var i = 0; i < stop; i++) {
      if (WIRE.isLatching(events[i].type)) found[events[i].type] = events[i];
    }
    var out = [];
    for (var t = 0; t < WIRE.LATCHING.length; t++) {
      var ev = found[WIRE.LATCHING[t]];
      if (ev) out.push(ev);
    }
    return out;
  }

  /* ============================================================
     Writing one
     ============================================================ */

  /* Record a live feed. Starts immediately — there is no arm-then-start,
     because the moment worth capturing is usually the one that just
     happened.

     It opens no connection and asks the server for nothing. The frames are
     already arriving; this listens to the same fan-out every widget listens
     to, which means a recording is exactly what the page saw, including the
     capture somebody had switched on and not including the one they did not.

     `feed.latest()` is what makes recording a session already in progress
     worth doing: the snapshots the page is currently drawn from are written
     first, so the recording opens on the board in front of the reader rather
     than on an empty one waiting three seconds for the next poll. */
  function createRecorder(feed, options) {
    var o = options || {};
    /* Fifty thousand frames is about twelve megabytes of tcpdump, and about
       four hours of a quiet lab. Past that this stops rather than growing
       until the tab dies, and says so — a recording that silently lost its
       ending is worse than a short one that admits where it stops. */
    var cap = o.max > 0 ? o.max : 50000;

    var lines = [];
    var full = false;
    var startedAt = Date.now();

    function add(ev) {
      if (lines.length >= cap) { full = true; return; }
      try {
        lines.push(JSON.stringify(ev));
      } catch (e) {
        /* A frame that will not stringify is a frame with a cycle in it,
           which nothing on this wire has. Dropping one line beats ending
           the recording. */
      }
    }

    /* The snapshots the page is already drawn from, put on the recording as
       its opening frames — and stamped with the moment they were put there,
       not the moment they were measured.

       That distinction is the difference between a watchable file and a
       useless one. `state`, `status` and `netcheck` are sent only when they
       changed, so the last one the page saw can be ten minutes old; writing it
       with its own clock makes the recording claim ten minutes and spend all
       but the last four seconds of it showing nothing. The frame is being
       issued now, so `at` is now.

       Nothing is lost and nothing is invented: when the two differ the
       measurement's own time travels as `wasAt`. A consumer that does not know
       the field ignores it, which is the envelope's whole promise — and the
       one consumer that should care is a reader asking how stale the board was
       when somebody pressed record. */
    if (feed && typeof feed.latest === "function") {
      var seed = feed.latest();
      for (var i = 0; i < seed.length; i++) add(reissue(seed[i], startedAt));
    }

    var off = feed && typeof feed.on === "function"
      ? feed.on("*", function (data, ev) { add(ev); })
      : noop;

    var stopped = false;

    return {
      /* Stop listening. The lines are kept, so text() and download() still
         work afterwards — which is the ordinary order: press stop, then
         save. */
      stop: function () {
        if (stopped) return;
        stopped = true;
        off();
      },
      stopped: function () { return stopped; },
      count: function () { return lines.length; },
      /* True when the cap was reached and frames are being dropped. The page
         says so on the button, because this is exactly the kind of thing
         nobody notices until they play the file back. */
      full: function () { return full; },
      startedAt: function () { return startedAt; },
      text: function () { return lines.length ? lines.join("\n") + "\n" : ""; },

      /* Hand the file to the browser. A Blob and a synthetic click, which is
         the only way a page with no server behind it can put a file on
         somebody's disk — and this page has a server but the file does not
         exist on it, because the recording was assembled here from what
         arrived here. */
      download: function (name) {
        var text = this.text();
        if (!text) return false;
        var url = URL.createObjectURL(new Blob([text], { type: "application/x-ndjson" }));
        var a = document.createElement("a");
        a.href = url;
        a.download = name || defaultName(startedAt);
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        /* Revoked on a turn of its own: revoking it in the same tick as the
           click is a race some browsers lose, and the symptom is a download
           that silently does not happen. */
        setTimeout(function () { URL.revokeObjectURL(url); }, 10000);
        return true;
      }
    };
  }

  /* One frame, re-issued at `at`. A copy rather than an edit: the object came
     off the live feed's fan-out and every widget on the page is holding the
     same one. */
  function reissue(ev, at) {
    var out = { seq: ev.seq, at: at, type: ev.type, data: ev.data };
    if (typeof ev.at === "number" && ev.at !== at) out.wasAt = ev.at;
    return out;
  }

  /* lab-20260912-174233.jsonl — sortable, and it says when rather than what,
     because what is in the file and a reader renaming it is the normal case. */
  function defaultName(ms) {
    var d = new Date(ms || Date.now());
    function two(n) { return (n < 10 ? "0" : "") + n; }
    return "lab-" + d.getFullYear() + two(d.getMonth() + 1) + two(d.getDate()) +
      "-" + two(d.getHours()) + two(d.getMinutes()) + two(d.getSeconds()) + ".jsonl";
  }

  /* ============================================================
     Playing one
     ============================================================ */

  /* How often the clock is read. Every frame due since the last read is
     handed out together, which buckets a burst of tcpdump into 60ms groups —
     imperceptible, and it is what keeps this one timer rather than one
     timeout per frame with a cancel on every seek. */
  var TICK = 60;

  function now() {
    return (window.performance && window.performance.now)
      ? window.performance.now() : Date.now();
  }

  function createPlayer(recording) {
    var rec = recording && recording.events ? recording : parse("");
    var events = rec.events, offsets = rec.offsets;

    var listeners = {};
    var watchers = [];

    var at = 0;           /* ms into the recording */
    var next = 0;         /* the first frame not yet handed out */
    var playing = false;
    var rate = 1;
    var seen = 0;         /* frames handed out, for the wire card */
    var seq = 0;
    var timer = null;
    var clock = 0;
    var staged = -1;      /* the index the snapshots on screen belong to */

    /* ---- the feed's surface, unchanged ---------------------------- */

    function on(type, fn) {
      if (typeof fn !== "function") return noop;
      (listeners[type] || (listeners[type] = [])).push(fn);
      return function () { off(type, fn); };
    }

    function off(type, fn) {
      var list = listeners[type];
      if (!list) return;
      var i = list.indexOf(fn);
      if (i >= 0) list.splice(i, 1);
    }

    /* One listener throwing must not stop the ones after it, same as the live
       feed: a widget with a bug is a widget with a bug, and it is not a
       reason for the board to stop being told what is on the wire. */
    function fanOut(type, ev) {
      var list = listeners[type];
      if (!list || !list.length) return;
      for (var i = 0; i < list.length; i++) {
        try {
          list[i](ev.data, ev);
        } catch (e) {
          if (window.console) console.error("replay listener for " + type + ": " + e);
        }
      }
    }

    function emit(ev) {
      seen++;
      if (typeof ev.seq === "number") seq = ev.seq;
      fanOut(ev.type, ev);
      fanOut("*", ev);
    }

    /* A recording cannot be asked to start a tcpdump. Whether the packets are
       in the file was settled when it was made, and hello.capture says which
       machine was being listened to. The release function comes back anyway
       so a widget that calls it in destroy() — which is every correct one —
       works here without knowing which kind of feed it was handed. */
    function want() { return noop; }

    function status() {
      var h = rec.hello || {};
      return {
        /* There is nothing to be disconnected from, so this is not the live
           feed's question. The wire card reads `replay` and says what it is
           looking at instead of claiming a connection. */
        open: true,
        replay: true,
        playing: playing,
        href: "",
        seq: seq,
        seen: seen,
        opens: 1,
        errors: 0,
        /* The server's count, as of when the recording was made. A recording
           with a number here has a hole in it, and that is worth knowing
           before anybody draws a conclusion from it. */
        dropped: h.dropped || 0,
        types: h.types || WIRE.TYPES,
        sources: h.sources || null
      };
    }

    /* ---- the clock ------------------------------------------------ */

    function drain() {
      while (next < events.length && offsets[next] <= at) {
        emit(events[next]);
        next++;
      }
      /* Whatever was just handed out included any snapshot in it, so the
         snapshots on screen now belong to this position. Recorded here rather
         than only in stage() so that ordinary forward play keeps the note
         true — otherwise the first seek after a minute of playing re-applies
         a prelude that is already on screen. */
      staged = next;
    }

    function step() {
      var t = now();
      var target = at + (t - clock) * rate;
      clock = t;

      if (target >= rec.duration) {
        at = rec.duration;
        drain();
        /* The end is a stop, not a loop. A recording that restarts on its own
           is one nobody can read the last frame of. */
        pause();
        changed();
        return;
      }
      at = target;
      drain();
      changed();
    }

    function play() {
      if (playing) return;
      /* Pressing play at the end starts again, because that is what the
         button is for at that point and the alternative is a control that
         looks live and does nothing.

         seekTo(0) rather than seek(0): the two differ over the frames that
         are due at the very instant the recording starts, and on a recording
         of one attack that is the attack. */
      if (next >= events.length) seekTo(0);
      playing = true;
      clock = now();
      timer = setInterval(step, TICK);
      changed();
    }

    function pause() {
      if (timer) clearInterval(timer);
      timer = null;
      if (!playing) return;
      playing = false;
      changed();
    }

    /* ---- moving about --------------------------------------------- */

    /* Put the snapshots that were standing at `index` back on screen.
       Skipped when they are already the ones on screen, which is what makes
       dragging the scrubber cheap: between two frames of the recording there
       is nothing to re-apply, and re-applying a state snapshot means the
       board rebuilding every gate it draws. */
    function stage(index) {
      if (staged === index) return;
      staged = index;
      var pre = prelude(rec, index);
      for (var i = 0; i < pre.length; i++) emit(pre[i]);
    }

    /* The first frame that has not happened yet at `ms`. */
    function indexAfter(ms) {
      var i = 0;
      while (i < offsets.length && offsets[i] <= ms) i++;
      return i;
    }

    function seek(ms) {
      var target = ms < 0 ? 0 : ms > rec.duration ? rec.duration : ms;
      next = indexAfter(target);
      at = target;
      stage(next);
      drain();
      changed();
    }

    /* Seek so that `index` is the next frame to be handed out, and then hand
       it out. Used by the moment list, where the point of the jump is the
       verdict itself — landing one frame after it would put the board where
       the reader asked and never play the shot that got it there. */
    function seekTo(index) {
      var i = index < 0 ? 0 : index >= events.length ? events.length - 1 : index;
      if (i < 0) return;
      next = i;
      at = offsets[i];
      stage(i);
      drain();
      changed();
    }

    function moment(dir) {
      var list = rec.moments;
      if (!list.length) return;
      if (dir > 0) {
        for (var i = 0; i < list.length; i++) {
          if (list[i].index >= next) { seekTo(list[i].index); return; }
        }
        seek(rec.duration);
        return;
      }
      for (var j = list.length - 1; j >= 0; j--) {
        /* Strictly before the frame we are about to hand out, or pressing
           back on a moment lands on the same one for ever. */
        if (list[j].index < next - 1) { seekTo(list[j].index); return; }
      }
      seek(0);
    }

    function setRate(x) {
      var r = Number(x);
      if (!isFinite(r) || r <= 0) return;
      rate = r;
      changed();
    }

    /* ---- telling the page ----------------------------------------- */

    function onChange(fn) {
      if (typeof fn !== "function") return noop;
      watchers.push(fn);
      return function () {
        var i = watchers.indexOf(fn);
        if (i >= 0) watchers.splice(i, 1);
      };
    }

    function transport() {
      return {
        playing: playing,
        at: at,
        duration: rec.duration,
        index: next,
        count: events.length,
        rate: rate,
        seen: seen,
        done: next >= events.length
      };
    }

    function changed() {
      var t = transport();
      for (var i = 0; i < watchers.length; i++) {
        try {
          watchers[i](t);
        } catch (e) {
          if (window.console) console.error("replay onChange: " + e);
        }
      }
    }

    /* Nothing has been handed out yet, and the first frame is due at zero, so
       this puts the header and the opening snapshot on screen without
       starting the clock. A player that shows nothing until you press play is
       a player that looks broken while it is working. */
    stage(0);
    drain();

    return {
      /* the feed's surface */
      on: on,
      off: off,
      want: want,
      status: status,
      latest: function () { return prelude(rec, next); },

      /* the transport */
      play: play,
      pause: pause,
      toggle: function () { if (playing) pause(); else play(); },
      seek: seek,
      seekTo: seekTo,
      next: function () { moment(1); },
      prev: function () { moment(-1); },
      setRate: setRate,
      transport: transport,
      onChange: onChange,

      /* what is being played */
      recording: function () { return rec; },
      close: function () { pause(); listeners = {}; },
      destroy: function () { pause(); listeners = {}; watchers = []; }
    };
  }

  window.LabReplay = {
    parse: parse,
    prelude: prelude,
    createRecorder: createRecorder,
    createPlayer: createPlayer,
    defaultName: defaultName
  };
})();
