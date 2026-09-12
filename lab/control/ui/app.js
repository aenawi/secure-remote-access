/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright (C) 2026 Hashem Aldhaheri */

/* ============================================================
   The lab's control surface.

   Deliberately the same shape as assets/sandbox.js in the guide: a
   declarative panel spec rendered into switches, a probe, a list of
   attacks, and five readout tabs. The difference is where the answers
   come from. There, an engine works out the consequence. Here, a
   container is asked, and whatever it says is what you get — including
   when that disagrees with the model, which is the interesting case.
   ============================================================ */
(function () {
  "use strict";

  var meta = null, state = null, busy = false;

  var $ = function (s) { return document.querySelector(s); };
  var esc = function (s) {
    return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  };

  /* ---- theme ------------------------------------------------------ */
  var saved = null;
  try { saved = localStorage.getItem("lab-theme"); } catch (e) {}
  if (saved) document.documentElement.setAttribute("data-theme", saved);
  $("#theme").addEventListener("click", function () {
    var now = document.documentElement.getAttribute("data-theme");
    var next = now === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("lab-theme", next); } catch (e) {}
    /* The board reads the page's custom properties rather than carrying a
       second palette, so it has to be told the values moved. */
    if (board) board.refreshTokens();
  });

  /* ---- the board's palette ---------------------------------------
     A second axis, and not the same one. The button above is the page's
     ground; this is which of the embedded HUD themes paints the drawing.
     hud/themes.js owns both halves — what exists, and what is selected —
     because the server is what knows which folders were embedded.

     The picker is populated from the answer rather than from markup, so a
     theme added to hud/themes/ appears here after a rebuild with nothing
     else edited. index.html ships one <option> so the control is not an
     empty box in the moment before the module lands, or ever, if it does
     not: no LabHUD means no board to theme, and the page is the flat
     drawing, which is what it was before any of this. */
  function startThemes() {
    var api = window.LabHUD && window.LabHUD.themes;
    var sel = $("#hud-theme");
    if (!api || !sel) return;

    api.init(board).then(function (applied) {
      var list = api.list();
      if (!list.length) return;          /* keep the one option markup shipped */
      sel.innerHTML = list.map(function (t) {
        return '<option value="' + esc(t.id) + '">' + esc(t.name) + "</option>";
      }).join("");
      sel.value = applied;
      sel.title = (api.get(applied) || {}).note || "";
    });

    sel.addEventListener("change", function () {
      api.apply(sel.value, board).then(function (applied) {
        sel.value = applied;
        sel.title = (api.get(applied) || {}).note || "";
      });
    });
  }

  /* ---- the board --------------------------------------------------
     lab/control/ui/hud is an ES module, because three.js is one. It hands
     itself over on window.LabHUD and fires an event when it has loaded.
     Everything below works whether or not that ever happens: no board means
     the flat drawing and the packets tab, which is what this page was. */
  var board = null, view = "board", boardBroken = false;
  var hudStream = null;

  function hudRefs() {
    return {
      chip:        $("#hud-chip"),
      access:      $("#hud-access"),
      accessNote:  $("#hud-access-note"),
      dotLaptop:   $("#hud-dot-laptop"),
      dotPhone:    $("#hud-dot-phone"),
      exposed:     $("#hud-exposed"),
      exposedN:    $("#hud-exposed-n"),
      exposedNote: $("#hud-exposed-note"),
      posture:     $("#hud-posture"),
      verdict:     $("#hud-verdict"),
      vRung:       $("#hud-v-rung"),
      vRule:       $("#hud-v-rule"),
      vWhy:        $("#hud-v-why"),
      nums:        $("#hud-nums"),
      transcript:  $("#hud-transcript"),
      live:        $("#hud-live"),
      rungs: [1, 2, 3, 4, 5].map(function (n) { return $("#hud-rung-" + n); })
    };
  }

  /* One watch at a time for the board, dropped the moment the next action
     starts. A set-piece that keeps reading after its shot has gone is a
     set-piece drawing frames that belong to something else.

     A set-piece used to be handed a URL and left to open it. Now it says what
     it wants to watch and the feed works out whether anything has to be started
     for it: two things wanting the capture is one capture, and the shot ending
     while the packets pane is still on takes nothing away from the pane. That
     bookkeeping does not belong in a file about drawing. */
  function hudCtx() {
    return {
      watch: function (sources, type, onEvent) {
        stopHudStream();
        if (!feed) return function () {};
        var offEvent = feed.on(type, onEvent);
        var releaseWant = feed.want(sources);
        var mine = { off: offEvent, release: releaseWant };
        hudStream = mine;
        return function () { if (hudStream === mine) stopHudStream(); };
      }
    };
  }
  function stopHudStream() {
    if (!hudStream) return;
    var gone = hudStream;
    hudStream = null;
    gone.off();
    gone.release();
  }

  function boardOn() { return !!board && view === "board"; }

  /* The board needs the grants before it can cut a cell per grant, and the
     list of actions before it can say which ids have no set-piece. Whichever
     of the two arrives last calls this, because the module and /api/meta race
     and either order is normal.

     meta.actions, not meta.attacks. The dispatch table is longer than the
     attack list — `rotate-key` and `outage` are both posted to /api/action and
     neither is an attack — so a check walking the attacks could not report a
     gap in either of them, and for a while did not. */
  var warnedGaps = false;
  function applyMeta() {
    board.setMeta(meta);
    if (warnedGaps) return;
    warnedGaps = true;
    if (!meta.actions) {
      console.warn("/api/meta carried no action list, so no set-piece gap was checked");
      return;
    }
    var gaps = window.LabHUD.missing(meta.actions);
    if (gaps.length) {
      console.warn("actions with no set-piece, falling back to the text trace: " + gaps.join(", "));
    }
  }

  function setView(name) {
    view = name === "flat" || boardBroken ? "flat" : "board";
    var on = view === "board" && !!board;
    $("#stage3d").hidden = !on;
    $(".stage").hidden = on;
    $("#view-board").setAttribute("aria-pressed", String(on));
    $("#view-flat").setAttribute("aria-pressed", String(!on));
    $("#view-board").disabled = boardBroken;
    try { localStorage.setItem("lab-view", view); } catch (e) {}
    if (on) { board.resize(); if (state) board.setState(state); }
  }

  function startBoard() {
    if (board || boardBroken || !window.LabHUD) return;
    try {
      board = window.LabHUD.createBoard($("#stage-gl"), hudRefs());
    } catch (e) {
      /* No WebGL, or a driver that will not play. Say so once, quietly, and
         leave the page exactly as it was. */
      boardBroken = true;
      $("#view-note").textContent = "the board needs WebGL, and this browser did not give it one";
      setView("flat");
      /* Still worth selecting: the picker is the reader's setting, not the
         board's, and it has to survive a session that never got a board. */
      startThemes();
      return;
    }
    if (meta) applyMeta();
    if (state) board.setState(state);
    var saved = null;
    try { saved = localStorage.getItem("lab-view"); } catch (e) {}
    setView(saved === "flat" ? "flat" : "board");
    /* The rails were measured before there was a board to tell, which is the
       ordinary case: the layout settles long before WebGL does. */
    measureRails();
    syncZoom();
    startThemes();
  }

  if (window.LabHUD) startBoard();
  else window.addEventListener("labhud-ready", startBoard);

  /* ---- how much window the drawing gets --------------------------
     The band at the top is fixed, which only works if the reader can decide
     how tall "fixed" is. The grip moves it, the arrow keys move it, and a
     double-click gives it back to the stylesheet. It is remembered, because
     somebody who wants a tall board wants it on the next probe too. */
  var STAGE_MIN = 260;
  function stageMax() { return Math.max(STAGE_MIN, window.innerHeight - 280); }

  function setStageH(px) {
    if (px == null) {
      document.documentElement.style.removeProperty("--stage-h");
      try { localStorage.removeItem("lab-stage-h"); } catch (e) {}
    } else {
      px = Math.round(Math.max(STAGE_MIN, Math.min(stageMax(), px)));
      document.documentElement.style.setProperty("--stage-h", px + "px");
      try { localStorage.setItem("lab-stage-h", String(px)); } catch (e) {}
    }
    if (board) board.resize();
  }

  var storedH = null;
  try { storedH = parseInt(localStorage.getItem("lab-stage-h"), 10); } catch (e) {}
  if (storedH) setStageH(storedH);

  (function grip() {
    var g = $("#grip"), wrap = $("#stagewrap"), dragging = false;
    g.addEventListener("pointerdown", function (e) {
      dragging = true;
      g.classList.add("dragging");
      g.setPointerCapture(e.pointerId);
      e.preventDefault();
    });
    g.addEventListener("pointermove", function (e) {
      if (!dragging) return;
      setStageH(e.clientY - wrap.getBoundingClientRect().top);
    });
    ["pointerup", "pointercancel"].forEach(function (ev) {
      g.addEventListener(ev, function () { dragging = false; g.classList.remove("dragging"); });
    });
    g.addEventListener("dblclick", function () { setStageH(null); });
    g.addEventListener("keydown", function (e) {
      var step = e.key === "ArrowUp" ? -40 : e.key === "ArrowDown" ? 40 : 0;
      if (!step) {
        if (e.key === "Home") { setStageH(null); e.preventDefault(); }
        return;
      }
      setStageH(wrap.getBoundingClientRect().height + step);
      e.preventDefault();
    });
  })();

  /* scene.js listens for window resize, which is the only thing that used to
     change the canvas. Now the grip and the media query change it too, and
     neither of those is a window resize. */
  if (window.ResizeObserver) {
    new ResizeObserver(function () { if (board) board.resize(); })
      .observe(document.querySelector(".viewport"));
  }

  /* ---- the rails --------------------------------------------------
     The canvas runs the full window and the rails float over it, so the board
     has to be told which parts of itself are covered — otherwise it centres
     the diagram in the canvas, which is underneath a rail, and the reader
     orbits a picture they can only see two thirds of.

     One measurement, two consumers. The CSS reads --pad-* to keep the verdict
     and the view controls inside the gap; scene.js reads the same numbers
     through setViewInset to aim the camera at it. Measured from the live
     elements rather than computed from the width tokens, because a folded rail
     and a media query both change the answer and getBoundingClientRect already
     knows about all of them. */
  var RAILS = ["rail-left", "rail-right"];

  /* The same breakpoint as the stylesheet's narrow fallback. Below it nothing
     floats: the rails are stacked blocks in a scrolling page, they cover
     nothing, and the inset must go back to zero. */
  var floatQ = window.matchMedia("(max-width: 1000px), (max-height: 620px)");

  /* Two different questions, and they have different answers at the bottom
     edge. What covers the *canvas* is what the camera has to aim around; what
     is occupied at the bottom of the *window* is what a floating panel has to
     sit above. The rung ladder is the case that separates them: it sits below
     the viewport rather than over it, so it hides none of the board and the
     camera must not compensate for it — but the verdict still cannot be drawn
     on top of it. Collapsing the two is a diagram nudged permanently upward by
     the height of a strip that was never in the way. */
  function measureRails() {
    var root = document.documentElement.style;
    var covered = { left: 0, right: 0, top: 0, bottom: 0 };
    var ladderH = 0;

    if (!floatQ.matches) {
      var vp = document.querySelector(".viewport").getBoundingClientRect();
      var bar = document.querySelector(".topbar").getBoundingClientRect();
      var lad = document.querySelector(".hud-ladder");

      RAILS.forEach(function (id) {
        var el = document.getElementById(id);
        if (!el) return;
        var r = el.getBoundingClientRect();
        /* Overlap with the viewport, not the rail's own width: a rail that has
           scrolled or been clipped covers less than it measures. */
        if (id === "rail-left")  covered.left  = Math.max(0, r.right - vp.left);
        if (id === "rail-right") covered.right = Math.max(0, vp.right - r.left);
      });
      covered.top = Math.max(0, bar.bottom - vp.top);
      /* The bar is min-height, not height: it wraps on a narrow window and on
         a long safety notice, and the rails below start where it actually
         ended rather than where the token guessed it would. */
      root.setProperty("--bar-h", Math.round(bar.height) + "px");
      if (lad) {
        var lr = lad.getBoundingClientRect();
        ladderH = lr.height;
        covered.bottom = Math.max(0, vp.bottom - lr.top);
      }
    }

    root.setProperty("--ladder-h", Math.round(ladderH) + "px");
    root.setProperty("--pad-l", Math.round(covered.left) + "px");
    root.setProperty("--pad-r", Math.round(covered.right) + "px");
    root.setProperty("--pad-t", Math.round(covered.top) + "px");
    /* The floating panels clear the ladder; the camera, above, does not. */
    root.setProperty("--pad-b", Math.round(Math.max(covered.bottom, ladderH)) + "px");
    if (board && board.setViewInset) board.setViewInset(covered);
  }

  function toggleRail(id) {
    var el = document.getElementById(id);
    if (!el) return;
    var shut = el.classList.toggle("shut");
    var tog = el.querySelector(".railtog");
    if (tog) {
      tog.setAttribute("aria-expanded", String(!shut));
      /* The chevron points the way the rail is about to go, which on the right
         is the mirror of the left. */
      var out = id === "rail-left" ? "❮" : "❯";
      var back = id === "rail-left" ? "❯" : "❮";
      tog.innerHTML = shut ? back : out;
      tog.setAttribute("aria-label",
        (shut ? "Unfold the " : "Fold the ") +
        (id === "rail-left" ? "settings" : "readouts") + " rail");
    }
    try { localStorage.setItem("lab-" + id, shut ? "shut" : "open"); } catch (e) {}
    /* The width transition is 180ms; measuring now would read the old width.
       Waiting for transitionend would be exact and would also never fire when
       the reader has reduced motion on, so this re-measures on both edges. */
    measureRails();
    setTimeout(measureRails, 200);
  }

  RAILS.forEach(function (id) {
    var want = null;
    try { want = localStorage.getItem("lab-" + id); } catch (e) {}
    if (want === "shut") toggleRail(id);
  });

  if (window.ResizeObserver) {
    var ro = new ResizeObserver(measureRails);
    RAILS.forEach(function (id) {
      var el = document.getElementById(id);
      if (el) ro.observe(el);
    });
    ro.observe(document.querySelector(".viewport"));
  }
  window.addEventListener("resize", measureRails);
  if (floatQ.addEventListener) floatQ.addEventListener("change", measureRails);
  measureRails();

  /* Either end of the zoom range is a button that would do nothing, and a
     control that looks live and is not is worse than one that says so. */
  function syncZoom() {
    if (!board) return;
    var z = board.zoom;
    var i = $("#hud-zoom-in"), o = $("#hud-zoom-out");
    if (i) i.disabled = z > 0.995;
    if (o) o.disabled = z < 0.005;
  }
  document.querySelector(".viewport")
    .addEventListener("wheel", function () { setTimeout(syncZoom, 0); }, { passive: true });

  /* ---- talking to the control server ------------------------------ */
  function get(url) { return fetch(url).then(function (r) { return r.json(); }); }
  function text(url) { return fetch(url).then(function (r) { return r.text(); }); }
  function post(url, body) {
    return fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {})
    }).then(function (r) { return r.json(); });
  }

  function working(on) {
    busy = on;
    Array.prototype.forEach.call(document.querySelectorAll("button.btn, button.preset, button.attack"),
      function (b) { b.disabled = on; });
  }

  /* ---- the verdict line ------------------------------------------- */
  function verdict(tone, msg, rung) {
    var v = $("#verdict");
    /* glass is what the thing is made of, not what it is saying — rewriting
       the whole class list to change the tone took the material off with it
       and left the sentence lying directly on the board. */
    v.className = "verdict glass" + (tone ? " " + tone : "");
    v.innerHTML = (rung ? '<b class="rung">rung ' + rung + " of 5</b> — " : "") + esc(msg);
  }

  /* ---- panels ------------------------------------------------------
     Each panel the control server declares is one tab in the left column,
     labelled with its id — `machines`, `network`, `policy`, `host` — because
     the ids are already the short lowercase words the tab strip wants, and a
     second set of names kept in this file is a second set of names to get
     wrong. The full title stays as the heading inside the pane. */
  function renderPanels() {
    var html = "";
    meta.panels.forEach(function (p) {
      html += '<section class="cpane" data-cpane="' + esc(p.id) + '" data-label="' + esc(p.id) + '">' +
        "<h3>" + esc(p.title) + "</h3><p class='note'>" + esc(p.note) + "</p>";
      p.rows.forEach(function (row) { html += renderRow(row); });
      html += "</section>";
    });
    $("#panels").innerHTML = html;
    buildCTabs();
    paintPanels();
  }

  /* ---- the settings tabs ------------------------------------------
     Built from whatever panes are in the column, in the order they appear:
     the two written into index.html around the slot, and the server's own in
     between. Nothing here has to be told the list twice. */
  function buildCTabs() {
    var panes = document.querySelectorAll("#cpanes [data-cpane]");
    var html = "";
    Array.prototype.forEach.call(panes, function (p) {
      var id = p.getAttribute("data-cpane");
      html += '<button type="button" class="ctab" role="tab" data-ctab="' + esc(id) + '"' +
        ' aria-selected="false">' + esc(p.getAttribute("data-label") || id) + "</button>";
    });
    $("#ctabs").innerHTML = html;

    var want = null;
    try { want = localStorage.getItem("lab-ctab"); } catch (e) {}
    showCTab(document.querySelector('[data-cpane="' + want + '"]') ? want : "configs");
  }

  function showCTab(name) {
    Array.prototype.forEach.call(document.querySelectorAll(".ctab"), function (t) {
      var on = t.getAttribute("data-ctab") === name;
      t.classList.toggle("on", on);
      t.setAttribute("aria-selected", String(on));
    });
    Array.prototype.forEach.call(document.querySelectorAll("#cpanes [data-cpane]"), function (p) {
      p.classList.toggle("on", p.getAttribute("data-cpane") === name);
    });
  }

  /* Remembered only when somebody chose it. The strip is built twice — once
     with the two panes this file ships with, and again once the server's have
     arrived — and a restore that wrote back what it settled for would spend
     the first pass forgetting which tab you were on. */
  function pickCTab(name) {
    showCTab(name);
    try { localStorage.setItem("lab-ctab", name); } catch (e) {}
  }

  function renderRow(row) {
    if (row.t === "hr") return '<div class="hr"></div>';

    if (row.t === "toggle") {
      return '<div class="row' + (row.danger ? " danger" : "") + '"' +
        (row.dep ? ' data-dep="' + esc(row.dep) + '"' : "") + ">" +
        '<input type="checkbox" class="sw" data-path="' + esc(row.p) + '">' +
        "<label><b>" + esc(row.label) + "</b>" +
        (row.sub ? '<span class="sub">' + esc(row.sub) + "</span>" : "") +
        "</label></div>";
    }

    if (row.t === "seg") {
      return '<div class="row"><label><b>' + esc(row.label) + "</b>" +
        (row.sub ? '<span class="sub">' + esc(row.sub) + "</span>" : "") + "</label>" +
        '<div class="seg">' + row.options.map(function (o) {
          return '<button type="button" data-path="' + esc(row.p) + '" data-value="' +
            esc(o.v) + '">' + esc(o.l) + "</button>";
        }).join("") + "</div></div>";
    }

    if (row.t === "grants") {
      return meta.grants.map(function (g) {
        return '<div class="row' + (g.danger ? " danger" : "") + '">' +
          '<input type="checkbox" class="sw" data-path="acl.grants.' + esc(g.key) + '">' +
          '<label><b class="mono">' + esc(g.label) + "</b>" +
          (g.sub ? '<span class="sub">' + esc(g.sub) + "</span>" : "") +
          "</label></div>";
      }).join("");
    }

    if (row.t === "linkgrid") {
      var head = '<div class="lg-row head"><span></span><span>eth0</span><span>loss</span>' +
        "<span>delay</span><span>udp/41641</span></div>";
      var body = meta.catalog.filter(function (m) { return !m.hostile; }).map(function (m) {
        return '<div class="lg-row" data-machine="' + m.id + '">' +
          '<span class="lg-name">' + esc(m.label) + "</span>" +
          '<button type="button" data-link="' + m.id + '" data-field="up"></button>' +
          '<select data-link="' + m.id + '" data-field="loss" aria-label="' + esc(m.label) + ' loss">' +
            meta.lossSteps.map(function (v) { return '<option value="' + v + '">' + v + "%</option>"; }).join("") +
          "</select>" +
          '<select data-link="' + m.id + '" data-field="delay" aria-label="' + esc(m.label) + ' delay">' +
            meta.delaySteps.map(function (v) { return '<option value="' + v + '">' + v + "ms</option>"; }).join("") +
          "</select>" +
          '<button type="button" data-link="' + m.id + '" data-field="udpBlocked"></button>' +
          "</div>";
      }).join("");
      return '<div class="lg">' + head + body + "</div>";
    }
    return "";
  }

  function dig(o, path) {
    return path.split(".").reduce(function (x, k) { return x == null ? undefined : x[k]; }, o);
  }

  function paintPanels() {
    if (!state) return;

    Array.prototype.forEach.call(document.querySelectorAll("input.sw[data-path]"), function (n) {
      n.checked = !!dig(state, n.getAttribute("data-path"));
    });
    Array.prototype.forEach.call(document.querySelectorAll(".seg button[data-path]"), function (b) {
      b.classList.toggle("on", dig(state, b.getAttribute("data-path")) === b.getAttribute("data-value"));
    });
    Array.prototype.forEach.call(document.querySelectorAll(".row[data-dep]"), function (r) {
      r.classList.toggle("dep-off", !dig(state, r.getAttribute("data-dep")));
    });

    Array.prototype.forEach.call(document.querySelectorAll("[data-link]"), function (n) {
      var l = state.links[n.getAttribute("data-link")] || {};
      var f = n.getAttribute("data-field");
      if (n.tagName === "SELECT") { n.value = String(l[f] || 0); return; }
      if (f === "up") {
        n.textContent = l.up ? "up" : "down";
        n.className = l.up ? "on" : "off";
      } else {
        n.textContent = l.udpBlocked ? "dropped" : "allowed";
        n.className = l.udpBlocked ? "off" : "on";
      }
    });

    /* The machine line: addresses and the path each one actually took. */
    var bits = meta.catalog.map(function (m) {
      var ms = state.machines[m.id] || {};
      if (!ms.online) return m.label + " off";
      /* A machine whose router is stopped is online and reaches nothing, and
         this line used to read identically to one that was simply idle. */
      return m.label + " " + (ms.tsAddr || ms.wanAddr || ms.lanAddr || "?") +
        (ms.routerDown ? " (" + m.router + " down)" : "") +
        (ms.pathTo ? " (" + ms.pathTo + ")" : "");
    });
    $("#status-out").setAttribute("data-machines", bits.join(" · "));
    paintDiagram();
  }

  /* ---- the topology -----------------------------------------------
     Same geometry as assets/sandbox.js in the guide, deliberately: the two
     drawings should be the same picture of the same network. What differs is
     the input. There, a model decides the shape of the line. Here it is
     whichever path the last probe actually took, and the addresses are the ones
     the containers report about themselves. */

  var ANCHOR = { "lab-roam": 58, "evil-box": 132, "lab-ubuntu": 206, "lab-vps": 206 };
  var VPS_X = 676, LEFT_X = 164, LANE_Y = 274, CORRIDOR = 292;
  var svg = document.querySelector(".stage svg");
  var lastPath = null;   /* the probe result the drawing is currently showing */

  function el(name) { return svg ? svg.querySelector('[data-el="' + name + '"]') : null; }

  function routeD(kind, from, to) {
    if (from === to) return null;
    var a = from, b = to;
    if (a === "lab-vps") { a = to; b = "lab-vps"; }
    var sy = ANCHOR[a], dy = ANCHOR[b];
    if (sy == null || dy == null) return null;

    if (kind === "lan") return { in: "M89 160 L89 178" };

    /* Neither end is the public box: loop through the corridor between the NAT
       column and the tailnet rather than pretending to cross the page. */
    if (b !== "lab-vps") {
      return { in: "M" + LEFT_X + " " + sy + " L258 " + sy +
                   " C " + CORRIDOR + " " + sy + " " + CORRIDOR + " " + dy + " 258 " + dy +
                   " L" + LEFT_X + " " + dy };
    }
    if (kind === "relay") {
      var ey = Math.min(150, Math.max(36, sy));
      return {
        in: "M" + LEFT_X + " " + sy + " L258 " + sy +
            " C " + CORRIDOR + " " + sy + " " + CORRIDOR + " " + ey + " 322 " + ey,
        out: "M518 118 C 592 118 634 170 " + VPS_X + " " + dy
      };
    }
    if (kind === "direct") {
      return { in: "M" + LEFT_X + " " + sy + " L258 " + sy +
                   " C " + CORRIDOR + " " + sy + " " + CORRIDOR + " " + dy + " 322 " + dy +
                   " L" + VPS_X + " " + dy };
    }
    /* public: down into the band, across, and up into the box */
    return { in: "M" + LEFT_X + " " + sy + " L258 " + sy +
                 " C " + CORRIDOR + " " + sy + " " + CORRIDOR + " " + LANE_Y + " 316 " + LANE_Y +
                 " L640 " + LANE_Y + " C 668 " + LANE_Y + " 672 " + (dy + 34) + " " +
                 VPS_X + " " + (dy + 14) };
  }

  function paintDiagram() {
    if (!svg || !state || !meta) return;

    meta.catalog.forEach(function (m) {
      var ms = state.machines[m.id] || {};
      var link = state.links[m.id] || {};
      var live = !!(ms.online && link.up);
      var gone = !!(m.hostile && !ms.online);

      var g = el("node-" + m.id);
      if (g) {
        g.classList.toggle("is-off", !live);
        g.classList.toggle("is-hidden", gone);
      }
      var nat = el("nat-" + m.id);
      if (nat) {
        nat.classList.toggle("is-hidden", gone);
        /* Dimmed for the same reason a stopped machine is: the box is there and
           nothing is going through it. Everything behind it is stranded, and a
           NAT drawn at full strength says the opposite. */
        nat.classList.toggle("is-off", !!ms.routerDown);
      }

      /* The address a machine answers on is not a fact about the machine, it is
         a fact about the path you are taking to it. Show the tailnet address
         when it has a session, and the address the ordinary network would use
         when it does not. */
      var ip = el("ip-" + m.id);
      if (ip) {
        ip.textContent = !ms.online ? "stopped"
          : ms.tsAddr ? ms.tsAddr
          : (ms.wanAddr || ms.lanAddr || "?") + " (no tailnet)";
      }

      var cond = el("cond-" + m.id);
      if (cond) {
        var bits = [];
        if (!link.up) bits.push("eth0 DOWN");
        /* The condition the state had no word for: the machine is up, its
           router is not, and it reaches nothing off its own segment. */
        if (ms.routerDown) bits.push(m.router + " DOWN");
        if (link.loss) bits.push(link.loss + "% loss");
        if (link.delay) bits.push(link.delay + "ms");
        if (link.udpBlocked) bits.push("udp dropped");
        cond.textContent = bits.length ? bits.join(" · ") : m.role;
        cond.setAttribute("class", bits.length ? "svg-mono-warn sb-svg-cond" : "svg-sub");
      }
    });

    var evilUp = !!(state.machines["evil-box"] || {}).online;
    var seg = el("seg-shared"), segLabel = el("seg-label");
    if (seg) seg.classList.toggle("is-hidden", !state.segmentShared);
    if (segLabel) segLabel.classList.toggle("is-hidden", !state.segmentShared);
    var stub = el("path-evil-stub");
    if (stub) stub.classList.toggle("is-hidden", !evilUp);
    var tap = el("path-evil-tap");
    if (tap) tap.classList.toggle("is-hidden", !(evilUp && state.segmentShared));

    /* The route is whatever the last probe found. Before anything has been
       probed, fall back to the path the machines report they are already using
       — the state stream carries it, so the drawing is live from the moment the
       page loads rather than blank until you press something. */
    var view = lastPath;
    if (!view) {
      var seed = ["lab-ubuntu", "lab-roam"].filter(function (id) {
        return (state.machines[id] || {}).pathTo;
      })[0];
      if (seed) {
        view = { from: seed, to: "lab-vps", path: state.machines[seed].pathTo,
                 ok: true, live: true };
      }
    }
    var kind = view && view.path ? view.path : null;
    var d = kind ? routeD(kind, view.from, view.to) : null;

    ["direct", "relay", "public", "lan"].forEach(function (k) {
      Array.prototype.forEach.call(svg.querySelectorAll('[data-route="' + k + '"]'), function (p) {
        var leg = p.getAttribute("data-leg") === "out" ? "out" : "in";
        var geom = kind === k && d ? d[leg] : null;
        if (geom) p.setAttribute("d", geom);
        var on = !!geom;
        p.classList.toggle("is-live", on && !!view.ok);
        p.classList.toggle("is-dead", on && !view.ok);
        p.classList.toggle("is-hidden", !on);
      });
    });

    /* The chip sits inside the tailnet box, so it has to describe the tailnet's
       involvement rather than just name the path — otherwise "public segment"
       printed in there reads as though the tailnet were carrying it. */
    var usesTailnet = kind === "direct" || kind === "relay";
    var chip = el("chip-path"), chipBox = el("chip-path-box");
    if (chip) {
      var anyOnTailnet = meta.catalog.some(function (m) {
        return (state.machines[m.id] || {}).tsAddr;
      });
      chip.textContent = !view ? (anyOnTailnet ? "idle · run a probe" : "nothing on the tailnet")
        : !kind ? "no path at all"
        : kind === "relay" ? "relay · DERP \"lab\""
        : kind === "direct" ? "direct · punched"
        : kind === "lan" ? "not used · same wire"
        : "not used · public path";
      chip.setAttribute("class",
        !view ? "svg-sub" : !kind ? "svg-mono-danger"
          : usesTailnet ? "svg-mono-accent" : "svg-mono-warn");
    }
    if (chipBox) {
      chipBox.setAttribute("class", "svg-card " +
        (!view ? "svg-stroke" : !kind ? "svg-danger-s"
          : usesTailnet ? "svg-accent-s" : "svg-warn-s"));
    }
    var services = el("tailnet-services");
    if (services) services.classList.toggle("is-off", !usesTailnet);

    ["public-lane", "public-lane-label"].forEach(function (n) {
      var node = el(n);
      if (node) node.classList.toggle("is-live", kind === "public");
    });

    /* Kept short on purpose: the public-segment caption starts at x=258 and a
       long line here runs straight into it. */
    var focus = el("focus-label");
    if (focus) {
      focus.textContent = !view ? "no probe yet"
        : view.live ? view.from + " → " + view.to + " · live"
        : view.from + " → " + view.to + (view.port ? ":" + view.port : "") +
          " · rung " + view.rung + (view.rttMs ? " · " + view.rttMs.toFixed(1) + "ms" : "");
      focus.setAttribute("class",
        !view ? "svg-sub" : view.ok ? "svg-mono-accent" : "svg-mono-danger");
    }
  }

  function renderPresets() {
    $("#presets").innerHTML = meta.presets.map(function (p) {
      return '<button type="button" class="preset ' + esc(p.tone) + '" data-preset="' + esc(p.id) + '">' +
        "<b>" + esc(p.label) + "</b><span>" + esc(p.sub) + "</span></button>";
    }).join("");
  }

  function renderAttacks() {
    $("#attacks").innerHTML = meta.attacks.map(function (a) {
      return '<button type="button" class="attack' + (a.danger ? " danger" : "") +
        '" data-attack="' + esc(a.id) + '"><b>' + esc(a.label) + "</b><span>" +
        esc(a.sub) + "</span></button>";
    }).join("");
  }

  /* ---- the packet log --------------------------------------------- */
  function trace(res, title) {
    /* Anything that names two machines is a path the drawing can show, whether
       or not it worked. A failure with no path at all is worth drawing too —
       that is what "no path at all" in the chip means. */
    if (res.from && res.to) {
      lastPath = res;
      paintDiagram();
    }
    var tone = res.danger ? "warn" : res.ok ? "ok" : "bad";
    var head = [res.from, res.to].filter(Boolean).join(" → ") + (res.port ? ":" + res.port : "");
    var nums = [];
    if (res.rttMs) nums.push("rtt " + res.rttMs.toFixed(1) + "ms");
    if (res.lossPct) nums.push("loss " + res.lossPct + "%");
    if (res.packets) nums.push(res.packets + " packets");
    if (res.retransmits) nums.push(res.retransmits + " retransmits");
    if (res.bytes) nums.push(res.bytes + " bytes");
    if (res.path) nums.unshift(res.path);

    var el = document.createElement("div");
    el.className = "trace " + tone;
    el.innerHTML =
      '<div class="title">' + esc(title || res.rule || "") + "</div>" +
      (head ? '<div class="head">' + esc(head) + " · rung " + res.rung + " of 5</div>" : "") +
      '<div class="why">' + esc(res.why) + "</div>" +
      (res.rule && title ? '<div class="head">' + esc(res.rule) + "</div>" : "") +
      (nums.length ? '<div class="nums">' + esc(nums.join("  ·  ")) + "</div>" : "") +
      (res.raw ? "<pre>" + esc(res.raw) + "</pre>" : "") +
      (res.hex ? "<pre>" + esc(res.hex) + "</pre>" : "");

    var host = $("#traces");
    host.insertBefore(el, host.firstChild);
    while (host.children.length > 25) host.removeChild(host.lastChild);
  }

  function showTab(name) {
    Array.prototype.forEach.call(document.querySelectorAll(".tab"), function (t) {
      var on = t.getAttribute("data-tab") === name;
      t.classList.toggle("on", on);
      t.setAttribute("aria-selected", String(on));
    });
    Array.prototype.forEach.call(document.querySelectorAll(".pane"), function (p) {
      p.classList.toggle("on", p.getAttribute("data-pane") === name);
    });
    try { localStorage.setItem("lab-tab", name); } catch (e) {}
    if (name === "rules") text("/api/rules").then(function (t) { $("#rules-out").textContent = t; });
    if (name === "script") text("/api/script").then(function (t) { $("#script-out").textContent = t; });
  }

  /* ---- the audit --------------------------------------------------- */
  function renderAudit(rep) {
    if (!rep.checks || !rep.checks.length) {
      $("#audit-out").innerHTML = '<div class="callout warn"><div class="ct">Not scored</div><p>' +
        esc(rep.verdict) + "</p></div>";
      verdict(rep.tone || "warn", rep.verdict);
      return;
    }
    var stuckNote = rep.stuck
      ? ' <span class="muted">· ' + rep.stuck +
        " answered by this lab, not by your configuration</span>"
      : "";
    var html = '<p><span class="score">' + rep.passed + " / " + rep.total +
      '</span> <span class="muted">checks held</span>' + stuckNote + "</p>";

    /* A perfect score with a tunnel open is the most misleading thing this
       page could print, so the tunnel is said first — above the list, not
       inside it. It is not a twelfth check and must not read as one: it moves
       no number, and the sentence it carries is about what the number cannot
       see rather than about what it counted. */
    if (rep.hatch) {
      html += '<div class="hatch is-' + esc(rep.hatchTone || "warn") + '">' +
        "<b>Nothing below asks whether a tunnel is running.</b> " + esc(rep.hatch) +
        "</div>";
    }

    ["access", "attack", "config"].forEach(function (kind) {
      var rows = rep.checks.filter(function (c) { return c.kind === kind; });
      if (!rows.length) return;
      html += '<p class="group">' + esc(meta.groups[kind]) + "</p>";
      rows.forEach(function (c) {
        /* A stuck check scores exactly like any other — the number has to stay
           honest — but it is marked, and the mark reads both ways. "You cannot
           fix this" and "you have not fixed this" are different things to tell
           somebody at eleven at night; so are "you closed this" and "this was
           never yours to open", and the second pair is the more misleading. */
        var state = (c.pass ? "pass" : "fail") + (c.stuck ? " stuck" : "");
        var mark = c.pass ? "✓" : c.stuck ? "—" : "✗";
        html += '<div class="check ' + state + '">' +
          '<span class="mark">' + mark + "</span><div>" +
          "<div>" + esc(c.label) +
          (c.stuck ? ' <span class="tag">' +
            (c.pass ? "cannot fail here" : "cannot pass here") + "</span>" : "") + "</div>" +
          '<div class="why">' + esc(c.pass ? c.why : c.fail) + "</div>" +
          (c.rule ? '<div class="rule">' + (c.rung ? "rung " + c.rung + " · " : "") + esc(c.rule) + "</div>" : "") +
          "</div></div>";
      });
    });
    if (rep.note) html += '<p class="foot">' + esc(rep.note) + "</p>";
    $("#audit-out").innerHTML = html;
    verdict(rep.tone, rep.verdict);
  }

  /* ---- the live wire ------------------------------------------------
     One /api/stream/hud, owned by feed.js, and every readout below listens to
     it. This used to be four EventSources opened in four places — status here,
     tcpdump in the capture toggle, the tailscaled log in its own, and a fourth
     inside the board's set-piece context — which is four connections to leak
     and four copies of "parse the data and hope it is the shape I expect".

     The panes are the same panes. What changed is that a widget nobody has
     written yet can read the same lab without opening anything. */
  var feed = window.LabFeed || null;
  function tailInto(el, line) {
    el.textContent += (el.textContent ? "\n" : "") + line;
    var lines = el.textContent.split("\n");
    if (lines.length > 400) el.textContent = lines.slice(-400).join("\n");
    el.scrollTop = el.scrollHeight;
  }

  /* The two text panes, each fed off the one wire.

     A pane is attached once and then left attached: a listener is a callback,
     and the expensive half — the process inside the container — is started and
     stopped by asking the feed for the source, not by adding and removing
     handlers. What the switch controls is the cost, not the wiring.

     Two filters, both load-bearing:

       - `on()` checks the switch, because a line can still be in flight when
         it goes off and a pane that keeps growing while hidden is a pane that
         will be wrong when it is shown again.
       - `d.source` checks which source the note came from. On four streams a
         note could only have come from the stream it arrived on; on one wire a
         capture pane headed `tail -f /var/log/tailscaled.log` is what dropping
         this line gets you. */
  var attached = {};
  function attachPane(key, el, lineType, source, on) {
    if (attached[key]) return;
    attached[key] = true;
    feed.on(lineType, function (d) { if (on() && d) tailInto(el, d.line); });
    feed.on("note", function (d) { if (on() && d && d.source === source) tailInto(el, "# " + d.line); });
  }

  /* The feed hands back a release function per request; kept per pane so a
     second flip cannot lose the first one's. */
  var release = {};
  function releaseSource(k) { if (release[k]) { release[k](); delete release[k]; } }

  function openFeed() {
    if (!feed) {
      verdict("bad", "feed.js did not load, so the readouts will not update on their own.");
      return;
    }
    var status = "", netcheck = "";
    function paint() {
      var m = $("#status-out").getAttribute("data-machines") || "";
      $("#status-out").textContent = status + "\n\n" + netcheck + (m ? "\n\n# " + m : "");
    }
    feed.on("status", function (d) { status = d.text; paint(); });
    feed.on("netcheck", function (d) { netcheck = d.text; paint(); });
    feed.on("state", function (d) {
      state = d;
      paintPanels();
      /* This is the only thing that notices a change nobody clicked — a
         container stopping, `make weak` from another terminal, a session
         flipping from relay to direct. But a held set-piece frame is the
         answer to a question somebody asked, so a poll arriving afterwards
         waits rather than wiping it. */
      if (board && !board.holding) board.setState(state);
    });
  }

  /* ---- wiring ------------------------------------------------------ */
  function setPath(path, value) {
    working(true);
    return post("/api/set", { path: path, value: value }).then(function (res) {
      verdict(res.ok ? (res.danger ? "warn" : "ok") : "bad", res.why || res.rule, res.rung || 0);
      if (res.raw || res.cmds) trace(res, res.rule);
      return refresh();
    }).finally(function () { working(false); });
  }

  function refresh() {
    return get("/api/state").then(function (s) {
      state = s;
      paintPanels();
      /* Every gate on the board renders the configuration continuously, so a
         switch has to move the picture without anything being probed. */
      if (board) board.setState(state);
    });
  }

  /* Every action that produces a Result ends here, so the board can never be
     left blank or holding the previous action's frame under a new verdict.
     Reads the lab back first, then plays the shot: the other order repaints
     the board from the configuration a moment after the set-piece has drawn
     what it measured, and the measurement loses. */
  function playResult(id, res) {
    return refresh().then(function () {
      if (!boardOn()) return;
      var ran = window.LabHUD.run(board, id, res, hudCtx());
      if (ran) return;
      /* No set-piece for this one yet. The board must still stop showing the
         last one's held frame — an unnamed action sitting under the previous
         action's verdict is worse than no picture. Ride it if it named two
         machines; otherwise just report it. */
      if (res.from && res.to) board.probe(res, true);
      else board.report(res, true);
      showTab("packets");
    });
  }

  document.addEventListener("change", function (e) {
    var n = e.target;
    if (n.classList && n.classList.contains("sw")) {
      setPath(n.getAttribute("data-path"), n.checked);
      return;
    }
    if (n.tagName === "SELECT" && n.getAttribute("data-link")) {
      setPath("links." + n.getAttribute("data-link") + "." + n.getAttribute("data-field"),
        parseInt(n.value, 10));
      return;
    }
    /* The two toggles that cost a process inside a container. Asking the feed
       for the source is what makes the server start it; the listeners stay
       attached either way, because a listener is a callback and the pane is
       hidden when the toggle is off. */
    if (n.id === "cap-on") {
      var out = $("#cap-out");
      out.hidden = !n.checked;
      if (!n.checked) { releaseSource("cap"); return; }
      out.textContent = "";
      if (!feed) { tailInto(out, "# feed.js did not load, so there is nothing to listen with."); return; }
      attachPane("cap", out, "packet", "capture", function () { return $("#cap-on").checked; });
      release.cap = feed.want({ capture: "evil-box" });
      return;
    }
    if (n.id === "logs-on") {
      var lo = $("#logs-out");
      lo.hidden = !n.checked;
      if (!n.checked) { releaseSource("logs"); return; }
      lo.textContent = "";
      if (!feed) { tailInto(lo, "# feed.js did not load, so there is nothing to listen with."); return; }
      attachPane("logs", lo, "log", "logs", function () { return $("#logs-on").checked; });
      release.logs = feed.want({ logs: "lab-ubuntu" });
    }
  });

  document.addEventListener("click", function (e) {
    var b = e.target.closest("button");
    if (!b) return;

    /* Reading is not an action on the lab, so all of it works while one is
       running: the other drawing, the camera, either tab strip, and the
       documentation. Everything below the guard changes something. */
    if (b.id === "view-board") { setView("board"); return; }
    if (b.id === "view-flat")  { setView("flat"); return; }
    if (b.id === "hud-home")   { if (board) board.home(); syncZoom(); return; }
    if (b.id === "hud-zoom-in")  { if (board) board.zoomIn();  syncZoom(); return; }
    if (b.id === "hud-zoom-out") { if (board) board.zoomOut(); syncZoom(); return; }
    if (b.classList.contains("railtog")) { toggleRail(b.getAttribute("data-rail")); return; }
    if (b.id === "to-guide")   { showTab("guide"); return; }
    if (b.classList.contains("tab"))  { showTab(b.getAttribute("data-tab")); return; }
    if (b.classList.contains("ctab")) { pickCTab(b.getAttribute("data-ctab")); return; }

    if (busy) return;

    if (b.hasAttribute("data-value") && b.hasAttribute("data-path")) {
      setPath(b.getAttribute("data-path"), b.getAttribute("data-value"));
      return;
    }

    if (b.hasAttribute("data-link")) {
      var l = state.links[b.getAttribute("data-link")] || {};
      var f = b.getAttribute("data-field");
      setPath("links." + b.getAttribute("data-link") + "." + f, f === "up" ? !l.up : !l.udpBlocked);
      return;
    }

    if (b.hasAttribute("data-preset")) {
      working(true);
      verdict("", "Applying that configuration to the containers — this is a real reconfiguration, give it a moment…");
      post("/api/preset", { id: b.getAttribute("data-preset") }).then(function (res) {
        trace(res, "configuration: " + res.rule);
        verdict(res.ok ? "warn" : "bad", res.why, 0);
        return refresh();
      }).finally(function () { working(false); });
      return;
    }

    if (b.hasAttribute("data-attack")) {
      var id = b.getAttribute("data-attack");
      var label = b.querySelector("b").textContent;
      working(true);
      stopHudStream();
      if (!boardOn()) showTab("packets");
      verdict("", "Running it…");
      post("/api/action", { id: id }).then(function (res) {
        /* The text trace always lands. It is the flat view's only output, it
           is what a reader gets when a set-piece does not exist for this id,
           and it is the record in the packets tab either way. */
        trace(res, label);
        verdict(res.danger ? "bad" : res.ok ? "ok" : "warn", res.why, res.rung);
        return playResult(id, res);
      }).finally(function () { working(false); });
      return;
    }

    if (b.hasAttribute("data-quick")) {
      var q = b.getAttribute("data-quick").split(",");
      $("#p-from").value = q[0]; $("#p-to").value = q[1]; $("#p-port").value = q[2];
      $("#probe-btn").click();
      return;
    }

    switch (b.id) {
      case "probe-btn":
        working(true);
        stopHudStream();
        if (!boardOn()) showTab("packets");
        verdict("", "Knocking, and watching the far end…");
        post("/api/probe", {
          from: $("#p-from").value, to: $("#p-to").value, port: $("#p-port").value
        }).then(function (res) {
          trace(res);
          verdict(res.danger ? "warn" : res.ok ? "ok" : "bad", res.why, res.rung);
          if (boardOn()) board.probe(res);
        }).finally(function () { working(false); });
        break;

      case "audit-btn":
        working(true);
        showTab("audit");
        $("#audit-out").innerHTML = '<p class="muted">Running eleven checks against real ' +
          "containers. Five of them join and unjoin the attacker, so this takes a minute.</p>";
        verdict("", "Auditing…");
        get("/api/audit").then(renderAudit).finally(function () { working(false); });
        break;

      case "reset-btn":
        working(true);
        stopHudStream();
        if (board) board.clearScratch();
        post("/api/action", { id: "reset" }).then(function (res) {
          trace(res, "reset");
          verdict("ok", res.why, 0);
          return refresh();
        }).finally(function () { working(false); });
        break;

      case "outage-btn":
        working(true);
        stopHudStream();
        if (!boardOn()) showTab("packets");
        verdict("", "Two sessions from lab-roam, then twenty seconds with no link. " +
          "This one takes about a minute, and it is worth watching.");
        post("/api/action", { id: "outage" }).then(function (res) {
          trace(res, "ssh and mosh, through a 20-second outage");
          verdict(res.ok ? "ok" : "warn", res.why, res.rung);
          return playResult("outage", res);
        }).finally(function () { working(false); });
        break;

      case "rotate-btn":
        working(true);
        stopHudStream();
        if (!boardOn()) showTab("packets");
        /* It opens a session over the tailnet first when there is one to open,
           rotates underneath it, and then waits to see whether it kept
           counting — so it is a minute, not the instant button it used to be
           back when it measured nothing. */
        verdict("", "Re-registering lab-roam, and watching whether anything running over " +
          "the tailnet notices. Give it a minute.");
        post("/api/action", { id: "rotate-key" }).then(function (res) {
          trace(res, "rotate the key");
          verdict(res.ok ? "ok" : "bad", res.why, res.rung);
          return playResult("rotate-key", res);
        }).finally(function () { working(false); });
        break;

      case "copy-btn":
        text("/api/script").then(function (t) {
          if (navigator.clipboard) navigator.clipboard.writeText(t);
          b.textContent = "Copied";
          setTimeout(function () { b.textContent = "Copy the script"; }, 1400);
        });
        break;
    }
  });

  document.addEventListener("keydown", function (e) {
    if (e.target.matches("input, select, textarea, button")) return;
    if (!board || !boardOn()) return;
    /* "=" as well as "+", because the unshifted key is the one people press.
       The rails get a bracket each, on the side they are on. */
    if (e.key === "h") { board.home(); syncZoom(); return; }
    if (e.key === "+" || e.key === "=") { board.zoomIn(); syncZoom(); e.preventDefault(); return; }
    if (e.key === "-" || e.key === "_") { board.zoomOut(); syncZoom(); e.preventDefault(); return; }
    if (e.key === "[") { toggleRail("rail-left"); e.preventDefault(); return; }
    if (e.key === "]") { toggleRail("rail-right"); e.preventDefault(); return; }
  });

  /* ---- go ----------------------------------------------------------
     The strip is built before anything is fetched, so a control server that
     never answers still leaves the probe and the attacks reachable rather than
     stranding them in a column with no tabs. */
  buildCTabs();

  get("/api/meta").then(function (m) {
    meta = m;
    renderPresets();
    renderAttacks();
    if (board) applyMeta();
    return refresh();
  }).then(function () {
    renderPanels();
    openFeed();
    startBoard();
    /* First visit opens the documentation rather than a log of a lab that has
       not done anything yet. After that it is wherever you last were. */
    var tab = null;
    try { tab = localStorage.getItem("lab-tab"); } catch (e) {}
    showTab(document.querySelector('[data-pane="' + tab + '"]') ? tab : "guide");
    verdict("", "The lab is up. Three machines, a default-deny policy, and public :22 still open — " +
      "the same place the sandbox starts.");
  }).catch(function (e) {
    verdict("bad", "Cannot reach the control server: " + e.message);
  });
})();
