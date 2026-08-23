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
  });

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
    v.className = "verdict" + (tone ? " " + tone : "");
    v.innerHTML = (rung ? '<b class="rung">rung ' + rung + " of 5</b> — " : "") + esc(msg);
  }

  /* ---- panels ------------------------------------------------------ */
  function renderPanels() {
    var html = "";
    meta.panels.forEach(function (p) {
      html += '<section class="panel" data-panel="' + p.id + '">' +
        "<h3>" + esc(p.title) + "</h3><p class='note'>" + esc(p.note) + "</p>";
      p.rows.forEach(function (row) { html += renderRow(row); });
      html += "</section>";
    });
    $("#panels").innerHTML = html;
    paintPanels();
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
      return m.label + " " + (ms.tsAddr || ms.wanAddr || ms.lanAddr || "?") +
        (ms.pathTo ? " (" + ms.pathTo + ")" : "");
    });
    $("#status-out").setAttribute("data-machines", bits.join(" · "));
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
      t.classList.toggle("on", t.getAttribute("data-tab") === name);
    });
    Array.prototype.forEach.call(document.querySelectorAll(".pane"), function (p) {
      p.classList.toggle("on", p.getAttribute("data-pane") === name);
    });
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
    var html = '<p><span class="score">' + rep.passed + " / " + rep.total +
      '</span> <span class="muted">checks held</span></p>';

    ["access", "attack", "config"].forEach(function (kind) {
      var rows = rep.checks.filter(function (c) { return c.kind === kind; });
      if (!rows.length) return;
      html += '<p class="group">' + esc(meta.groups[kind]) + "</p>";
      rows.forEach(function (c) {
        html += '<div class="check ' + (c.pass ? "pass" : "fail") + '">' +
          '<span class="mark">' + (c.pass ? "✓" : "✗") + "</span><div>" +
          "<div>" + esc(c.label) + "</div>" +
          '<div class="why">' + esc(c.pass ? c.why : c.fail) + "</div>" +
          (c.rule ? '<div class="rule">' + (c.rung ? "rung " + c.rung + " · " : "") + esc(c.rule) + "</div>" : "") +
          "</div></div>";
      });
    });
    if (rep.note) html += '<p class="foot">' + esc(rep.note) + "</p>";
    $("#audit-out").innerHTML = html;
    verdict(rep.tone, rep.verdict);
  }

  /* ---- live streams ------------------------------------------------ */
  var streams = {};
  function stopStream(k) { if (streams[k]) { streams[k].close(); delete streams[k]; } }
  function tailInto(el, line) {
    el.textContent += (el.textContent ? "\n" : "") + line;
    var lines = el.textContent.split("\n");
    if (lines.length > 400) el.textContent = lines.slice(-400).join("\n");
    el.scrollTop = el.scrollHeight;
  }

  function openStatusStream() {
    var es = new EventSource("/api/stream/status");
    streams.status = es;
    var status = "", netcheck = "";
    function paint() {
      var m = $("#status-out").getAttribute("data-machines") || "";
      $("#status-out").textContent = status + "\n\n" + netcheck + (m ? "\n\n# " + m : "");
    }
    es.addEventListener("status", function (e) { status = JSON.parse(e.data).text; paint(); });
    es.addEventListener("netcheck", function (e) { netcheck = JSON.parse(e.data).text; paint(); });
    es.addEventListener("state", function (e) { state = JSON.parse(e.data); paintPanels(); });
    es.onerror = function () { /* EventSource reconnects on its own */ };
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
    return get("/api/state").then(function (s) { state = s; paintPanels(); });
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
    if (n.id === "cap-on") {
      var out = $("#cap-out");
      out.hidden = !n.checked;
      if (!n.checked) { stopStream("cap"); return; }
      out.textContent = "";
      var es = new EventSource("/api/stream/tcpdump?machine=evil-box");
      streams.cap = es;
      es.addEventListener("packet", function (ev) { tailInto(out, JSON.parse(ev.data).line); });
      es.addEventListener("note", function (ev) { tailInto(out, "# " + JSON.parse(ev.data).line); });
      return;
    }
    if (n.id === "logs-on") {
      var lo = $("#logs-out");
      lo.hidden = !n.checked;
      if (!n.checked) { stopStream("logs"); return; }
      lo.textContent = "";
      var ls = new EventSource("/api/stream/logs?machine=lab-ubuntu");
      streams.logs = ls;
      ls.addEventListener("log", function (ev) { tailInto(lo, JSON.parse(ev.data).line); });
      ls.addEventListener("note", function (ev) { tailInto(lo, "# " + JSON.parse(ev.data).line); });
    }
  });

  document.addEventListener("click", function (e) {
    var b = e.target.closest("button");
    if (!b || busy) return;

    if (b.classList.contains("tab")) { showTab(b.getAttribute("data-tab")); return; }

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
      working(true);
      showTab("packets");
      verdict("", "Running it…");
      post("/api/action", { id: b.getAttribute("data-attack") }).then(function (res) {
        trace(res, b.querySelector("b").textContent);
        verdict(res.danger ? "bad" : res.ok ? "ok" : "warn", res.why, res.rung);
        return refresh();
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
        showTab("packets");
        verdict("", "Knocking, and watching the far end…");
        post("/api/probe", {
          from: $("#p-from").value, to: $("#p-to").value, port: $("#p-port").value
        }).then(function (res) {
          trace(res);
          verdict(res.danger ? "warn" : res.ok ? "ok" : "bad", res.why, res.rung);
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
        post("/api/action", { id: "reset" }).then(function (res) {
          trace(res, "reset");
          verdict("ok", res.why, 0);
          return refresh();
        }).finally(function () { working(false); });
        break;

      case "outage-btn":
        working(true);
        showTab("packets");
        verdict("", "Two sessions from lab-roam, then twenty seconds with no link. " +
          "This one takes about a minute, and it is worth watching.");
        post("/api/action", { id: "outage" }).then(function (res) {
          trace(res, "ssh and mosh, through a 20-second outage");
          verdict(res.ok ? "ok" : "warn", res.why, res.rung);
          return refresh();
        }).finally(function () { working(false); });
        break;

      case "rotate-btn":
        working(true);
        post("/api/action", { id: "rotate-key" }).then(function (res) {
          trace(res, "rotate the key");
          verdict(res.ok ? "ok" : "bad", res.why, res.rung);
          return refresh();
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

  /* ---- go ---------------------------------------------------------- */
  get("/api/meta").then(function (m) {
    meta = m;
    renderPresets();
    renderAttacks();
    return refresh();
  }).then(function () {
    renderPanels();
    openStatusStream();
    verdict("", "The lab is up. Three machines, a default-deny policy, and public :22 still open — " +
      "the same place the sandbox starts.");
  }).catch(function (e) {
    verdict("bad", "Cannot reach the control server: " + e.message);
  });
})();
