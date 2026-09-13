/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Hashem Aldhaheri */

/* ============================================================
   The player's page.

   app.js is the control surface: it posts to the API, reads the lab back, and
   plays the shot the reply describes. This is the same drawing with all of
   that taken out. Nothing here posts anything, because there is nothing to
   post to — the recording already happened, and this file's whole job is to
   turn a file of frames into the board somebody would have been looking at.

   Which means the mapping from a frame to a drawing is the interesting part,
   and it is deliberately the same mapping app.js makes:

     state    the configuration, drawn continuously  ->  board.setState
     verdict  a Result from /api/action              ->  the set-piece for its id
              a Result from /api/set or /api/preset  ->  the verdict line only
     flow     a Result from /api/probe               ->  board.probe
     packet   one line of tcpdump                    ->  whatever asked to watch

   `set` and `preset` draw no shot on purpose, and that is not a simplification.
   On the live page a switch flip moves the board by changing the lab and
   letting the next state snapshot redraw it — the board never renders a switch
   as an event. A player that played a shot for every flip would be a player
   showing something the reader never saw.

   Everything here survives a page with no WebGL, a recording with no page
   payload in it, and a file that is half a recording. What it will not survive
   is being opened from `file://`, and nothing can: `<script type="module">` is
   blocked there, which is why the header of replay.html says to serve the
   directory.
   ============================================================ */
(function () {
  "use strict";

  var $ = function (s) { return document.querySelector(s); };
  var esc = function (s) {
    return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  };

  /* ---- the page's ground ------------------------------------------
     The same two axes the live page has, and the same keys in
     localStorage, so a reader who set the page dark and picked a board
     palette there opens this one the way they left that one. */
  var saved = null;
  try { saved = localStorage.getItem("lab-theme"); } catch (e) {}
  if (saved) document.documentElement.setAttribute("data-theme", saved);

  $("#theme").addEventListener("click", function () {
    var now = document.documentElement.getAttribute("data-theme");
    var next = now === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("lab-theme", next); } catch (e) {}
    if (board) board.refreshTokens();
  });

  /* ---- the board -------------------------------------------------- */
  var board = null, boardBroken = false;
  var player = null, recording = null;
  var watching = null;      /* the one set-piece watch, same rule as app.js */

  function startBoard() {
    if (board || boardBroken || !window.LabHUD) return;
    try {
      board = window.LabHUD.createBoard($("#stage-gl"), window.LabHUD.refs(document));
    } catch (e) {
      boardBroken = true;
      say("bad", "The board needs WebGL and this browser did not give it one, so there " +
        "is nothing to draw a recording on. The live page has a flat drawing; this one " +
        "does not, because a recording of a 3D shot is what it is for.");
      return;
    }
    measure();
    syncZoom();
    startThemes();
    /* A file may already be open: the picker and ?src= both work before the
       module lands, because reading a file is not the board's business. */
    if (recording) applyPage();
  }

  if (window.LabHUD) startBoard();
  else window.addEventListener("labhud-ready", startBoard);

  /* ---- the board's palette, and the cards ------------------------
     Seeded from the recording rather than fetched, because there is no server
     to fetch from. Until a file is open there is one option in the markup,
     which is honest: nothing has said what was embedded when the recording
     was made. */
  function startThemes() {
    var api = window.LabHUD && window.LabHUD.themes;
    var sel = $("#hud-theme");
    if (!api || !sel) return;

    api.init(board, recording && recording.page ? recording.page.themes : null)
      .then(function (applied) {
        mountLayout(applied);
        var list = api.list();
        if (!list.length) return;
        sel.innerHTML = list.map(function (t) {
          return '<option value="' + esc(t.id) + '">' + esc(t.name) + "</option>";
        }).join("");
        sel.value = applied;
        sel.title = (api.get(applied) || {}).note || "";
      });

    if (sel.dataset.wired) return;
    sel.dataset.wired = "1";
    sel.addEventListener("change", function () {
      api.apply(sel.value, board).then(function (applied) {
        mountLayout(applied);
        sel.value = applied;
        sel.title = (api.get(applied) || {}).note || "";
      });
    });
  }

  /* The cards a theme docked, handed the player instead of the live feed.
     That substitution is the whole seam: a widget reads `on`, `want` and
     `status`, the player has all three, and nothing in a widget has to know
     which of the two it was given. */
  function mountLayout(id) {
    var api = window.LabHUD && window.LabHUD.themes;
    var slots = window.LabHUD && window.LabHUD.slots;
    if (!api || !slots) return;

    /* Told every time, not once. The live page inits the docks with a feed
       that exists before the page does; here the player is built when a file
       is opened, which is after the board, after the theme store and after the
       first layout. A one-shot init handed the cards a null feed and left
       every one of them saying "no feed on this page" for the rest of the
       session — with the board beside them playing perfectly.

       Calling it again costs nothing: it sets two references, and apply()
       below rebuilds every card against them. */
    slots.init({ feed: player, onLayout: measure });

    var theme = api.get(id);
    slots.apply(theme && theme.layout);
  }

  /* ---- how much of the board is covered ---------------------------
     The same measurement app.js makes, against this page's furniture: one
     rail, the bar, the ladder and the transport. Two sets of tokens for the
     same reason — the docks are positioned from --rail-* and must not be fed
     their own size back — and the transport is in --pad-* only, so the
     verdict floats above it while the cards stay put. */
  var floatQ = window.matchMedia("(max-width: 1000px), (max-height: 620px)");

  /* The gap between floating things, the same number --hud-gap holds. Read
     once rather than per measurement: it is a token in style.css and nothing
     moves it while the page is open. */
  var GAP = 10;

  function measure() {
    var root = document.documentElement.style;
    var covered = { left: 0, right: 0, top: 0, bottom: 0 };
    var ladderH = 0, transportH = 0;

    if (!floatQ.matches) {
      var vp = $(".viewport").getBoundingClientRect();
      var bar = $(".topbar").getBoundingClientRect();
      var rail = $("#rail-right");
      var lad = $(".hud-ladder");
      var tr = $("#transport");

      if (rail) {
        var r = rail.getBoundingClientRect();
        covered.right = Math.max(0, vp.right - r.left);
      }
      covered.top = Math.max(0, bar.bottom - vp.top);
      root.setProperty("--bar-h", Math.round(bar.height) + "px");
      if (lad) {
        var lr = lad.getBoundingClientRect();
        ladderH = lr.height;
        covered.bottom = Math.max(0, vp.bottom - lr.top);
      }
      if (tr && !tr.hidden) transportH = tr.getBoundingClientRect().height + GAP;
    }

    /* Three answers about the bottom edge, and they are genuinely different.
       The ladder sits below the canvas and the transport floats over it, so:

         the camera   has to aim above the transport, which does cover the
                      canvas, and not above the ladder, which does not
         the docks    have to stop above both, or the bottom card ends up
                      underneath the transport — which is what happened
         the panels   have to clear whatever the docks ended up covering too

       The transport is positioned from --ladder-h alone, which is why its own
       height can go into --rail-b without the layout chasing itself. That is
       the same trap the docks documented from the other side. */
    root.setProperty("--ladder-h", Math.round(ladderH) + "px");
    root.setProperty("--rail-l", "0px");
    root.setProperty("--rail-r", Math.round(covered.right) + "px");
    root.setProperty("--rail-t", Math.round(covered.top) + "px");

    var furniture = ladderH + transportH;
    root.setProperty("--rail-b", Math.round(furniture) + "px");
    covered.bottom = Math.max(covered.bottom, transportH);

    var slots = window.LabHUD && window.LabHUD.slots;
    var padBottom = furniture;

    if (slots && !floatQ.matches) {
      var onCanvas = slots.covered($(".viewport").getBoundingClientRect());
      var onWindow = slots.covered($(".app").getBoundingClientRect());
      covered.left = Math.max(covered.left, onCanvas.left);
      covered.right = Math.max(covered.right, onCanvas.right);
      covered.top = Math.max(covered.top, onCanvas.top);
      covered.bottom = Math.max(covered.bottom, onCanvas.bottom);
      padBottom = Math.max(padBottom, onWindow.bottom);
    }

    root.setProperty("--pad-l", Math.round(covered.left) + "px");
    root.setProperty("--pad-r", Math.round(covered.right) + "px");
    root.setProperty("--pad-t", Math.round(covered.top) + "px");
    root.setProperty("--pad-b", Math.round(padBottom) + "px");
    if (board && board.setViewInset) board.setViewInset(covered);
  }

  if (window.ResizeObserver) {
    var ro = new ResizeObserver(function () {
      if (board) board.resize();
      measure();
    });
    ro.observe($(".viewport"));
    ro.observe($("#rail-right"));
    ro.observe($("#transport"));
  }
  window.addEventListener("resize", measure);
  if (floatQ.addEventListener) floatQ.addEventListener("change", measure);
  measure();

  function syncZoom() {
    if (!board) return;
    var i = $("#hud-zoom-in"), o = $("#hud-zoom-out");
    if (i) i.disabled = board.zoom > 0.995;
    if (o) o.disabled = board.zoom < 0.005;
  }
  $(".viewport").addEventListener("wheel", function () { setTimeout(syncZoom, 0); },
    { passive: true });

  /* ---- the page's own line ---------------------------------------- */
  function say(tone, msg, rung) {
    var v = $("#verdict");
    v.className = "verdict glass" + (tone ? " " + tone : "");
    v.innerHTML = (rung ? '<b class="rung">rung ' + rung + " of 5</b> — " : "") + esc(msg);
  }

  /* ============================================================
     Opening a file
     ============================================================ */

  function openText(text, label) {
    if (!window.LabReplay) {
      say("bad", "replay.js did not load, so there is nothing to read the file with.");
      return;
    }
    var rec = window.LabReplay.parse(text);
    if (!rec.events.length) {
      say("bad", "There is no frame in " + (label || "that file") + ". A recording is one " +
        "JSON object per line — the frames from /api/stream/hud.");
      return;
    }

    stopWatch();
    if (player) player.destroy();
    recording = rec;
    player = window.LabReplay.createPlayer(rec);

    applyPage();
    listen();
    paintFacts(label);
    paintMoments();

    $("#dropmat").hidden = true;
    $("#transport").hidden = false;
    measure();

    var n = rec.events.length;
    var mins = fmt(rec.duration);
    $("#rec-what").textContent = (label || "a file") + " · " + mins;
    say(rec.skipped ? "warn" : "", n + " frames, " + mins + " long, " +
      rec.moments.length + " moments" +
      (rec.skipped ? " — and " + rec.skipped + " lines that were not frames, skipped" : "") +
      ". Press play, or jump to a moment on the right.");
    paintTransport(player.transport());
  }

  /* What the recording says the page was made of. Handed to the board and to
     the theme store; both survive it being absent, which is what a recording
     made by an older build looks like. */
  function applyPage() {
    if (!board || !recording) return;
    var page = recording.page;
    if (page && page.meta) board.setMeta(page.meta);
    else {
      say("warn", "This recording carries no description of the lab, so the board cannot " +
        "cut a doorway per grant. It will still play. A recording made by this build " +
        "carries one in its first line.");
    }
    startThemes();
  }

  /* ---- one watch at a time, same rule as the live page ----------- */
  function stopWatch() {
    if (!watching) return;
    var gone = watching;
    watching = null;
    gone.off();
    gone.release();
  }

  function ctx() {
    return {
      watch: function (sources, type, onEvent) {
        stopWatch();
        if (!player) return function () {};
        /* `want` is a no-op on a recording — whether the packets are in the
           file was decided when it was made — and it is still called, because
           a set-piece should not have to know which kind of feed it is
           watching. If the capture was not running, no packet arrives and the
           shot draws the empty tray it is written to draw. */
        var offEvent = player.on(type, onEvent);
        var release = player.want(sources);
        var mine = { off: offEvent, release: release };
        watching = mine;
        return function () { if (watching === mine) stopWatch(); };
      }
    };
  }

  /* ---- frame to drawing ------------------------------------------- */
  function listen() {
    player.on("state", function (state) {
      /* A held set-piece frame is the answer to a question somebody asked, so
         the poll that lands three seconds later waits rather than wiping it.
         The same guard app.js has, for the same reason. */
      if (board && !board.holding) board.setState(state);
    });

    player.on("verdict", function (d) {
      if (!d || !d.result) return;
      var res = d.result;
      say(res.danger ? "bad" : res.ok ? "ok" : "warn", res.why || res.rule, res.rung);
      /* Only an action draws a shot. See the header: on the live page a
         switch and a configuration move the board through the state snapshot
         that follows them, and never as an event of their own. */
      if (d.kind !== "action") return;
      if (!board) return;
      stopWatch();
      if (window.LabHUD.run(board, d.id, res, ctx())) return;
      if (res.from && res.to) board.probe(res, true);
      else board.report(res, true);
    });

    player.on("flow", function (d) {
      if (!d || !d.result || !board) return;
      var res = d.result;
      say(res.danger ? "warn" : res.ok ? "ok" : "bad", res.why || res.rule, res.rung);
      stopWatch();
      board.probe(res);
    });

    player.onChange(paintTransport);
  }

  /* ============================================================
     The rail: what is in the file, and where the moments are
     ============================================================ */

  function paintFacts(label) {
    var h = recording.hello || {};
    var page = recording.page || {};
    var rows = [];

    rows.push(["file", label || "a recording"]);
    rows.push(["frames", String(recording.events.length)]);
    rows.push(["length", fmt(recording.duration)]);
    rows.push(["made by", h.serverAt ? new Date(h.serverAt).toLocaleString() : "unknown"]);
    rows.push(["on the wire", (h.sources || []).join(" · ") || "not stated"]);
    rows.push(["capture", h.capture || "none"]);
    rows.push(["logs", h.logs || "none"]);
    /* The one number that says whether to trust the rest. The server throws
       frames away rather than blocking the lab on a slow tab, so anything
       above zero is a hole in the recording — and a drawing across a hole is
       a drawing making things up. */
    rows.push(["dropped", (h.dropped || 0) ? h.dropped + " — there is a gap in this file"
      : "0"]);
    if (recording.skipped) rows.push(["skipped lines", String(recording.skipped)]);

    var strays = Object.keys(recording.strays || {});
    if (strays.length) {
      rows.push(["types this build does not know", strays.join(" · ")]);
    }
    if (!page.meta) rows.push(["describes the lab", "no — an older recording"]);

    /* Its own classes rather than the wire widget's, which look the same and
       are not available: a widget's stylesheet is only in the document when a
       theme docked that widget, so borrowing one is a rail that is styled on
       some themes and not on others. */
    $("#recfacts").innerHTML = '<div class="facts">' + rows.map(function (r) {
      var bad = r[0] === "dropped" && (h.dropped || 0);
      return '<div class="facts-k">' + esc(r[0]) + "</div>" +
        '<div class="facts-v' + (bad ? " is-bad" : "") + '">' + esc(r[1]) + "</div>";
    }).join("") + "</div>";
  }

  function paintMoments() {
    var list = recording.moments;
    if (!list.length) {
      $("#moments").innerHTML = '<p class="note">Nothing was run while this was being ' +
        "recorded — no switch, no attack, no probe. The board still plays whatever the " +
        "lab reported about itself.</p>";
      return;
    }
    $("#moments").innerHTML = '<p class="group">the moments</p>' + list.map(function (m, i) {
      var tone = m.danger ? "bad" : m.ok ? "ok" : "warn";
      var head = m.type === "flow"
        ? (m.from || "?") + " → " + (m.to || "?") + (m.port ? ":" + m.port : "")
        : m.id || m.kind;
      return '<button type="button" class="moment ' + tone + '" data-moment="' + i + '">' +
        '<span class="m-at mono">' + esc(fmt(m.at)) + "</span>" +
        '<span class="m-head">' + esc(head) + "</span>" +
        '<span class="m-kind mono">' + esc(m.kind) +
        (m.rung ? " · rung " + m.rung : "") + "</span>" +
        '<span class="m-why">' + esc(m.why || m.rule || "") + "</span>" +
        "</button>";
    }).join("");
  }

  /* ============================================================
     The transport
     ============================================================ */

  function fmt(ms) {
    var s = Math.max(0, Math.round((ms || 0) / 1000));
    var m = Math.floor(s / 60);
    var r = s % 60;
    return m + ":" + (r < 10 ? "0" : "") + r;
  }

  var scrubbing = false;

  function paintTransport(t) {
    var play = $("#t-play");
    play.textContent = t.playing ? "pause" : t.done ? "again" : "play";
    play.setAttribute("aria-label", t.playing ? "Pause" : "Play");
    $("#t-time").textContent = fmt(t.at) + " / " + fmt(t.duration) +
      "   " + t.index + "/" + t.count;
    if (!scrubbing) {
      $("#t-scrub").value = String(t.duration
        ? Math.round((t.at / t.duration) * 1000) : 0);
    }
    /* Which moment the reader is inside, so the list says where they are
       rather than only where they could go. */
    var here = -1;
    var list = recording ? recording.moments : [];
    for (var i = 0; i < list.length; i++) if (list[i].index < t.index) here = i;
    Array.prototype.forEach.call(document.querySelectorAll("[data-moment]"), function (b) {
      b.classList.toggle("on", Number(b.getAttribute("data-moment")) === here);
    });
  }

  $("#t-scrub").addEventListener("input", function () {
    if (!player) return;
    scrubbing = true;
    player.seek((Number(this.value) / 1000) * recording.duration);
  });
  ["change", "pointerup", "blur"].forEach(function (ev) {
    $("#t-scrub").addEventListener(ev, function () { scrubbing = false; });
  });

  $("#t-rate").addEventListener("change", function () {
    if (player) player.setRate(Number(this.value));
  });

  /* ============================================================
     Wiring
     ============================================================ */

  document.addEventListener("click", function (e) {
    var b = e.target.closest("button, a");
    if (!b) return;

    if (b.id === "pick-btn" || b.id === "pick-btn-2") { $("#pick").click(); return; }
    if (b.id === "hud-home") { if (board) board.home(); syncZoom(); return; }
    if (b.id === "hud-zoom-in") { if (board) board.zoomIn(); syncZoom(); return; }
    if (b.id === "hud-zoom-out") { if (board) board.zoomOut(); syncZoom(); return; }
    if (b.classList.contains("railtog")) { toggleRail("rail-right"); return; }

    if (!player) return;
    if (b.id === "t-play") { player.toggle(); return; }
    if (b.id === "t-next") { player.next(); return; }
    if (b.id === "t-prev") { player.prev(); return; }
    if (b.hasAttribute("data-moment")) {
      var m = recording.moments[Number(b.getAttribute("data-moment"))];
      if (m) {
        player.pause();
        player.seekTo(m.index);
      }
    }
  });

  function toggleRail(id) {
    var el = document.getElementById(id);
    if (!el) return;
    var shut = el.classList.toggle("shut");
    var tog = el.querySelector(".railtog");
    if (tog) {
      tog.setAttribute("aria-expanded", String(!shut));
      tog.innerHTML = shut ? "❮" : "❯";
      tog.setAttribute("aria-label", (shut ? "Unfold" : "Fold") + " the recording rail");
    }
    try { localStorage.setItem("lab-replay-rail", shut ? "shut" : "open"); } catch (e) {}
    measure();
    setTimeout(measure, 200);
  }

  var railWant = null;
  try { railWant = localStorage.getItem("lab-replay-rail"); } catch (e) {}
  if (railWant === "shut") toggleRail("rail-right");

  document.addEventListener("keydown", function (e) {
    if (e.target.matches("input, select, textarea, button, a")) return;
    if (board) {
      if (e.key === "h") { board.home(); syncZoom(); return; }
      if (e.key === "+" || e.key === "=") { board.zoomIn(); syncZoom(); e.preventDefault(); return; }
      if (e.key === "-" || e.key === "_") { board.zoomOut(); syncZoom(); e.preventDefault(); return; }
    }
    if (e.key === "]") { toggleRail("rail-right"); e.preventDefault(); return; }
    if (!player) return;
    /* The shortcuts a video player has, because that is what this is. */
    if (e.key === " ") { player.toggle(); e.preventDefault(); return; }
    if (e.key === "ArrowRight") { player.next(); e.preventDefault(); return; }
    if (e.key === "ArrowLeft") { player.prev(); e.preventDefault(); return; }
  });

  /* ---- getting a file in ------------------------------------------ */
  $("#pick").addEventListener("change", function () {
    var f = this.files && this.files[0];
    if (!f) return;
    read(f);
  });

  function read(file) {
    say("", "Reading " + file.name + "…");
    var fr = new FileReader();
    fr.onload = function () { openText(String(fr.result), file.name); };
    fr.onerror = function () {
      say("bad", "The browser would not read " + file.name + ".");
    };
    fr.readAsText(file);
  }

  /* Drop anywhere. A drop target the size of a card is a drop target people
     miss, and there is nothing else on this page a file could mean. */
  ["dragenter", "dragover"].forEach(function (ev) {
    document.addEventListener(ev, function (e) {
      e.preventDefault();
      document.documentElement.classList.add("dragging-file");
    });
  });
  ["dragleave", "drop"].forEach(function (ev) {
    document.addEventListener(ev, function (e) {
      if (ev === "dragleave" && e.relatedTarget) return;
      document.documentElement.classList.remove("dragging-file");
    });
  });
  document.addEventListener("drop", function (e) {
    e.preventDefault();
    var f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) read(f);
  });

  /* ?src=... so a recording can be posted beside this page and linked to.
     An ordinary fetch, which means same origin or a server that says
     otherwise — a link that does not work says so in one line rather than
     leaving an empty board. */
  (function fromQuery() {
    var m = /[?&]src=([^&]+)/.exec(window.location.search);
    if (!m) return;
    var src = decodeURIComponent(m[1]);
    say("", "Fetching " + src + "…");
    fetch(src)
      .then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.text();
      })
      .then(function (text) { openText(text, src); })
      .catch(function (err) {
        say("bad", "Could not fetch " + src + " (" + err.message + "). Drop the file " +
          "onto this page instead — that needs no server at all.");
      });
  })();
})();
